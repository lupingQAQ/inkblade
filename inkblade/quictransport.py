# -*- coding: utf-8 -*-
"""QUIC, HTTP/3 WebTransport and MASQUE CONNECT-UDP transports.

This module is deliberately separate from :mod:`inkblade.reverse` so that
``aioquic`` remains an optional dependency.  The controller imports it lazily
only when one of the three UDP transports is selected.

All three modes terminate TLS 1.3 with the same local CA/leaf certificate used
by the ``tls``/``wss``/``https`` transports.  The probe-side certificate pin is
enforced by the probe (Rust/quinn verifier); the controller does not invent a
second authentication system:

* ``quic``          - one QUIC bidirectional stream carries the existing
                      4-byte length + JSON frames, so the challenge-HMAC token
                      handshake and every RPC are shared with ``ProbeConnection``.
* ``webtransport``  - HTTP/3 extended CONNECT (``:protocol=webtransport``) and
                      one WebTransport bidirectional stream per probe.
* ``masque``        - RFC 9298 extended CONNECT (``:protocol=connect-udp``) +
                      HTTP Datagrams.  The controller relays UDP datagrams
                      through the authenticated probe's ``udp`` op.  It does
                      not claim RDMA/UCX verb support.

The classes here are transport adapters; they do not duplicate collect/exec/
upload/spawn/dial/socks/cleanup.  The controller hands every byte stream to
``inkblade.channel.ProbeConnection``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import queue
import socket
import threading
import time
from functools import partial
from typing import Any, Sequence
from urllib.parse import unquote

try:  # keep the controller error hierarchy usable by CLI/API consumers
    from .channel import ChannelError as _ChannelError
except Exception:  # pragma: no cover - direct module execution in tests
    _ChannelError = Exception

QUIC_ALPN = "inkblade-reverse/1"
H3_ALPN = ["h3"]
DEFAULT_WEBTRANSPORT_PATH = "/inkblade/wt"
DEFAULT_MASQUE_PATH = "/.well-known/masque/udp"
MASQUE_AUTH_WINDOW = 120.0
MAX_MASQUE_DATAGRAM = 65507
MAX_MASQUE_QUEUE = 256
MAX_STREAM_SOCKET_BACKLOG = 64


class QuicTransportError(_ChannelError):
    """Stable error codes for the CLI/API."""

    code = "quic_error"

    def __init__(self, message: str, *, code: str | None = None, data: Any = None):
        super().__init__(message, code=code, data=data)


def _aioquic():
    try:
        import aioquic  # noqa: F401
    except Exception as exc:  # pragma: no cover - exercised by import guard
        raise QuicTransportError(
            "QUIC/WebTransport/MASQUE need the optional 'aioquic' package "
            "(pip install aioquic)",
            code="quic_dependency",
        ) from exc


def masque_mac(token: str, nonce: str, timestamp: str, path: str) -> str:
    message = f"inkblade-masque/v1|{nonce}|{timestamp}|{path}".encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _header_map(headers: Sequence[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    return {name.lower(): value for name, value in headers}


def _peer_text(address: Any) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address or "unknown")


def _split_address(remote: str, default_port: int = 0) -> tuple[str, int]:
    text = str(remote or "")
    if text.startswith("[") and "]:" in text:
        host, _, port = text[1:].partition("]:")
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    return text or "unknown", default_port


class _SocketPairBridge:
    """Bridge one controller-side ProbeConnection to one QUIC stream.

    ``sock`` is passed to :class:`inkblade.channel.ProbeConnection`; ``peer`` is
    owned by this adapter.  Network input is written to ``peer`` by a dedicated
    thread so a slow probe cannot block the asyncio event loop.  Output is read
    from ``peer`` by another thread and submitted back to the owning protocol's
    event loop.
    """

    def __init__(
        self,
        protocol: "_QuicProtocol",
        stream_id: int,
        listener: Any,
        transport: str,
        remote: str,
        *,
        max_frame: int = 8 * 1024 * 1024,
    ):
        self.protocol = protocol
        self.stream_id = stream_id
        self.listener = listener
        self.transport = transport
        self.remote = remote
        self.max_frame = max_frame
        self.sock, self.peer = socket.socketpair()
        self.sock.settimeout(None)
        self.peer.settimeout(None)
        self._incoming: "queue.Queue[bytes | None]" = queue.Queue(maxsize=32)
        self._closed = threading.Event()
        self._probe_thread = threading.Thread(
            target=self._run_probe, name=f"quic-probe-{transport}", daemon=True
        )
        self._writer_thread = threading.Thread(
            target=self._run_writer, name=f"quic-writer-{transport}", daemon=True
        )
        self._reader_thread = threading.Thread(
            target=self._run_reader, name=f"quic-reader-{transport}", daemon=True
        )
        self.bytes_in = 0
        self.bytes_out = 0
        self._probe_thread.start()
        self._writer_thread.start()
        self._reader_thread.start()

    def _run_probe(self) -> None:
        address = _split_address(self.remote)
        try:
            self.listener._handle_connection(self.sock, address, self.transport)
        except BaseException as exc:  # noqa: BLE001 - adapter boundary
            self.listener.errors.append(f"{self.transport} bridge: {exc}")

    def _run_writer(self) -> None:
        while not self._closed.is_set():
            try:
                data = self._incoming.get(timeout=0.25)
            except queue.Empty:
                continue
            if data is None:
                try:
                    self.peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            if not data:
                continue
            try:
                self.peer.sendall(data)
                self.bytes_in += len(data)
            except OSError:
                return

    def _run_reader(self) -> None:
        while not self._closed.is_set():
            try:
                chunk = self.peer.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            self.bytes_out += len(chunk)
            try:
                self.protocol.submit_stream_data(self.stream_id, chunk)
            except Exception:
                break
        try:
            self.protocol.submit_stream_end(self.stream_id)
        except Exception:
            pass

    def feed(self, data: bytes, end_stream: bool = False) -> None:
        if self._closed.is_set():
            return
        if data:
            if len(data) > self.max_frame:
                self.close()
                return
            try:
                self._incoming.put_nowait(bytes(data))
            except queue.Full:
                # A blocked local probe is a failure, not a reason to grow an
                # unbounded controller buffer.
                self.close()
                return
        if end_stream:
            try:
                self._incoming.put_nowait(None)
            except queue.Full:
                self.close()

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        for sock in (self.sock, self.peer):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        try:
            self._incoming.put_nowait(None)
        except queue.Full:
            pass


class _MasqueUdpRelay:
    """Relay one CONNECT-UDP flow through the probe's ``udp`` op."""

    def __init__(
        self,
        protocol: "_QuicProtocol",
        stream_id: int,
        probe: Any,
        host: str,
        port: int,
    ):
        self.protocol = protocol
        self.stream_id = stream_id
        self.probe = probe
        self.host = host
        self.port = int(port)
        self.socket_id = 0
        self.local_port = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.datagrams_in = 0
        self.datagrams_out = 0
        self.error = ""
        self._queue: "queue.Queue[bytes | None]" = queue.Queue(maxsize=MAX_MASQUE_QUEUE)
        self._closed = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="masque-udp-relay", daemon=True
        )

    def start(self) -> "_MasqueUdpRelay":
        if self._closed.is_set():
            raise QuicTransportError("masque relay was closed before bind",
                                     code="udp_bind_failed")
        result = self.probe.request(
            "udp", {"action": "bind", "host": "0.0.0.0", "port": 0}, timeout=10.0
        )
        if self._closed.is_set():
            try:
                self.probe.request(
                    "udp", {"action": "close", "socket": int(result.get("socket") or 0)},
                    timeout=2.0,
                )
            except Exception:
                pass
            raise QuicTransportError("masque relay was closed during bind",
                                     code="udp_bind_failed")
        self.socket_id = int(result.get("socket") or 0)
        self.local_port = int(result.get("port") or 0)
        if not self.socket_id:
            raise QuicTransportError("probe did not return a udp socket",
                                     code="udp_bind_failed")
        self._thread.start()
        return self

    def feed(self, data: bytes) -> None:
        if self._closed.is_set():
            return
        if len(data) > MAX_MASQUE_DATAGRAM:
            self.error = "masque datagram too large"
            self.close()
            return
        try:
            self._queue.put_nowait(bytes(data))
        except queue.Full:
            self.error = "masque queue full"
            self.close()

    def _recv_loop(self) -> None:
        while not self._closed.is_set():
            try:
                data = self._queue.get(timeout=0.2)
            except queue.Empty:
                data = None
            if data is None:
                break
            if not data:
                continue
            try:
                self.probe.request(
                    "udp",
                    {
                        "action": "send",
                        "socket": self.socket_id,
                        "host": self.host,
                        "port": self.port,
                        "data_b64": base64.b64encode(data).decode("ascii"),
                    },
                    timeout=10.0,
                )
                self.bytes_in += len(data)
                self.datagrams_in += 1
            except Exception as exc:  # noqa: BLE001
                self.error = f"udp send: {exc}"
                break

    def _run(self) -> None:
        send_thread = threading.Thread(
            target=self._recv_loop, name="masque-udp-send", daemon=True
        )
        send_thread.start()
        while not self._closed.is_set():
            try:
                result = self.probe.request(
                    "udp",
                    {"action": "recv", "socket": self.socket_id, "timeout_ms": 200},
                    timeout=5.0,
                )
            except Exception as exc:  # noqa: BLE001
                self.error = f"udp recv: {exc}"
                break
            if result.get("timeout"):
                continue
            encoded = result.get("data_b64") or ""
            if not encoded:
                continue
            data = base64.b64decode(encoded)
            self.bytes_out += len(data)
            self.datagrams_out += 1
            try:
                self.protocol.send_masque_datagram(self.stream_id, data)
            except Exception as exc:  # noqa: BLE001
                self.error = f"masque datagram: {exc}"
                break
        self.close()

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        try:
            if self.socket_id:
                self.probe.request(
                    "udp", {"action": "close", "socket": self.socket_id}, timeout=5.0
                )
        except Exception:
            pass
        self.socket_id = 0

    def status(self) -> dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "target": f"{self.host}:{self.port}",
            "local_port": self.local_port,
            "datagrams_in": self.datagrams_in,
            "datagrams_out": self.datagrams_out,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "error": self.error,
            "closed": self._closed.is_set(),
        }


def _build_protocol_class():
    """Import aioquic lazily and construct the real protocol class."""

    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import (
        DatagramReceived,
        HeadersReceived,
        WebTransportStreamDataReceived,
    )
    from aioquic.quic import events

    class QuicProtocol(QuicConnectionProtocol):
        def __init__(self, quic, stream_handler=None, *, manager, mode):
            super().__init__(quic, stream_handler=stream_handler)
            self.manager = manager
            self.mode = mode
            self.remote = self._peer_address()
            self._h3 = None
            self._bridges: dict[int, _SocketPairBridge] = {}
            self._wt_sessions: set[int] = set()
            self._masque: dict[int, _MasqueUdpRelay] = {}
            self._transport_closed = False
            self.manager.add_protocol(self)

        # ------------------------------------------------------------ utils
        def _peer_address(self) -> str:
            try:
                paths = getattr(self._quic, "_network_paths", None) or []
                if paths:
                    return _peer_text(paths[0].addr)
            except Exception:
                pass
            return "unknown"

        def datagram_received(self, data, addr) -> None:
            self.remote = _peer_text(addr)
            super().datagram_received(data, addr)

        def _audit(self, event: str, detail: dict[str, Any]) -> None:
            try:
                self.manager.listener._audit(event, {
                    "remote": self.remote, "transport": self.mode, **detail,
                })
            except Exception:
                pass

        def _ensure_h3(self):
            if self._h3 is None:
                self._h3 = H3Connection(self._quic, enable_webtransport=True)
            return self._h3

        # ------------------------------------------------------------ events
        def quic_event_received(self, event) -> None:
            try:
                if isinstance(event, events.HandshakeCompleted):
                    if self.mode in ("webtransport", "masque"):
                        self._ensure_h3()
                        self.transmit()
                    self._audit("quic.handshake", {"alpn": getattr(event, "alpn_protocol", "")})
                    return
                if isinstance(event, events.ConnectionTerminated):
                    self._cleanup()
                    self._audit("quic.closed", {"reason": str(getattr(event, "reason_phrase", ""))})
                    return
                if self._h3 is not None:
                    if isinstance(
                        event, (events.StreamReset, events.StopSendingReceived)
                    ):
                        bridge = self._bridges.pop(event.stream_id, None)
                        if bridge is not None:
                            bridge.close()
                        relay = self._masque.pop(event.stream_id, None)
                        if relay is not None:
                            relay.close()
                    for h3_event in self._h3.handle_event(event):
                        self._handle_h3(h3_event)
                    self.transmit()
                    return
                if isinstance(event, events.StreamDataReceived):
                    self._raw_feed(event.stream_id, event.data, event.end_stream)
                elif isinstance(event, (events.StreamReset, events.StopSendingReceived)):
                    bridge = self._bridges.pop(event.stream_id, None)
                    if bridge is not None:
                        bridge.close()
                elif isinstance(event, events.DatagramFrameReceived):
                    pass
            except Exception as exc:  # noqa: BLE001 - never kill the loop
                self.manager.listener.errors.append(f"quic event: {exc}")

        # ------------------------------------------------------------ QUIC raw
        def _raw_feed(self, stream_id: int, data: bytes, end_stream: bool) -> None:
            bridge = self._bridges.get(stream_id)
            if bridge is None:
                bridge = _SocketPairBridge(
                    self, stream_id, self.manager.listener, "quic", self.remote
                )
                self._bridges[stream_id] = bridge
                self.manager.note_connection(stream_id, self.mode)
            bridge.feed(data, end_stream)

        def submit_stream_data(self, stream_id: int, data: bytes) -> None:
            try:
                self._loop.call_soon_threadsafe(self._send_stream_now, stream_id, data, False)
            except Exception:
                pass

        def submit_stream_end(self, stream_id: int) -> None:
            try:
                self._loop.call_soon_threadsafe(self._send_stream_now, stream_id, b"", True)
            except Exception:
                pass

        def _send_stream_now(self, stream_id: int, data: bytes, end_stream: bool) -> None:
            try:
                self._quic.send_stream_data(stream_id, data, end_stream=end_stream)
                self.transmit()
                if end_stream:
                    bridge = self._bridges.pop(stream_id, None)
                    if bridge is not None:
                        bridge.close()
            except Exception as exc:  # noqa: BLE001
                self.manager.listener.errors.append(f"quic stream send: {exc}")

        # ------------------------------------------------------------ HTTP/3
        def _handle_h3(self, event) -> None:
            if isinstance(event, HeadersReceived):
                self._handle_headers(event)
            elif isinstance(event, WebTransportStreamDataReceived):
                if event.session_id not in self._wt_sessions:
                    self._audit("webtransport.unknown_session", {
                        "session_id": event.session_id,
                        "stream_id": event.stream_id,
                    })
                    return
                bridge = self._bridges.get(event.stream_id)
                if bridge is None:
                    bridge = _SocketPairBridge(
                        self, event.stream_id, self.manager.listener,
                        "webtransport", self.remote,
                    )
                    self._bridges[event.stream_id] = bridge
                    self.manager.note_connection(event.stream_id, self.mode)
                bridge.feed(event.data, event.stream_ended)
            elif isinstance(event, DatagramReceived):
                relay = self._masque.get(event.stream_id)
                if relay is not None:
                    relay.feed(event.data)
                    self.manager.note_datagram()
            else:
                # DataReceived on a CONNECT-UDP request stream is not a
                # datagram; RFC 9298 uses capsules/datagrams.  Ignore capsules
                # rather than silently treating them as UDP payload.
                pass

        def _handle_headers(self, event) -> None:
            headers = _header_map(event.headers)
            method = headers.get(b":method", b"").upper()
            protocol = headers.get(b":protocol", b"")
            path = headers.get(b":path", b"").decode("utf-8", "replace")
            stream_id = event.stream_id
            if protocol == b"webtransport":
                if self.mode != "webtransport":
                    self._reject(stream_id, 404, "webtransport is not enabled")
                    return
                if method != b"CONNECT" or path != self.manager.webtransport_path:
                    self._reject(stream_id, 404, "unknown webtransport path")
                    return
                self._wt_sessions.add(stream_id)
                self._h3.send_headers(stream_id, [(b":status", b"200")])
                self.transmit()
                self.manager.note_webtransport_session()
                self._audit("webtransport.session", {"stream_id": stream_id, "path": path})
                return
            if protocol == b"connect-udp":
                if self.mode != "masque":
                    self._reject(stream_id, 404, "connect-udp is not enabled")
                    return
                if method != b"CONNECT":
                    self._reject(stream_id, 405, "CONNECT required")
                    return
                self._handle_connect_udp(stream_id, path, headers)
                return
            self._reject(stream_id, 404, "unsupported extended CONNECT")

        def _reject(self, stream_id: int, status: int, message: str) -> None:
            body = message.encode("utf-8")
            try:
                self._h3.send_headers(
                    stream_id,
                    [
                        (b":status", str(status).encode("ascii")),
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                    end_stream=False,
                )
                self._h3.send_data(stream_id, body, end_stream=True)
                self.transmit()
            except Exception as exc:  # noqa: BLE001
                self.manager.listener.errors.append(f"quic reject: {exc}")

        def _handle_connect_udp(
            self, stream_id: int, path: str, headers: dict[bytes, bytes]
        ) -> None:
            target = self.manager.parse_masque_target(path)
            if target is None:
                self._reject(stream_id, 404, "bad connect-udp path")
                return
            host, port = target
            nonce = headers.get(b"x-inkblade-nonce", b"").decode("ascii", "replace")
            timestamp = headers.get(b"x-inkblade-timestamp", b"").decode(
                "ascii", "replace"
            )
            mac = headers.get(b"x-inkblade-mac", b"").decode("ascii", "replace")
            if not self.manager.check_masque_auth(nonce, timestamp, mac, path):
                self._reject(stream_id, 401, "invalid masque auth")
                return
            requested_probe = headers.get(b"x-inkblade-probe", b"").decode(
                "utf-8", "replace"
            ).strip()
            try:
                probe = self.manager.choose_probe(requested_probe)
                if "udp" not in (probe.caps or []):
                    raise QuicTransportError(
                        "probe does not advertise the udp op", code="udp_not_supported"
                    )
            except Exception as exc:
                self._reject(stream_id, 409, str(exc))
                return
            relay = _MasqueUdpRelay(self, stream_id, probe, host, port)
            self._masque[stream_id] = relay
            threading.Thread(
                target=self._start_masque_relay,
                args=(stream_id, relay),
                name="masque-bind", daemon=True,
            ).start()

        def _start_masque_relay(self, stream_id: int, relay: _MasqueUdpRelay) -> None:
            try:
                relay.start()
            except Exception as exc:  # noqa: BLE001
                self.manager.listener.errors.append(f"masque bind: {exc}")
                self._masque.pop(stream_id, None)
                try:
                    self._loop.call_soon_threadsafe(
                        self._reject, stream_id, 503, f"udp relay unavailable: {exc}"
                    )
                except Exception:
                    pass
                return
            try:
                self._loop.call_soon_threadsafe(self._masque_ready, stream_id)
            except Exception:
                relay.close()

        def _masque_ready(self, stream_id: int) -> None:
            relay = self._masque.get(stream_id)
            if relay is None:
                return
            try:
                self._h3.send_headers(
                    stream_id,
                    [(b":status", b"200"), (b"capsule-protocol", b"?1")],
                )
                self.transmit()
            except Exception as exc:  # noqa: BLE001
                self.manager.listener.errors.append(f"masque response: {exc}")
                self._masque.pop(stream_id, None)
                relay.close()
                return
            self.manager.note_masque_relay(relay)
            self._audit("masque.session", {
                "stream_id": stream_id,
                "target": f"{relay.host}:{relay.port}",
                "probe_id": relay.probe.probe_id,
            })

        def send_masque_datagram(self, stream_id: int, data: bytes) -> None:
            if len(data) > MAX_MASQUE_DATAGRAM:
                self.manager.listener.errors.append("masque datagram too large")
                return

            def _send() -> None:
                relay = self._masque.get(stream_id)
                if relay is None:
                    return
                try:
                    self._h3.send_datagram(stream_id, data)
                    self.transmit()
                except Exception as exc:  # noqa: BLE001
                    self.manager.listener.errors.append(f"masque send: {exc}")

            try:
                self._loop.call_soon_threadsafe(_send)
            except Exception:
                pass

        # ------------------------------------------------------------ cleanup
        def _cleanup(self) -> None:
            if self._transport_closed:
                return
            self._transport_closed = True
            for bridge in list(self._bridges.values()):
                bridge.close()
            self._bridges.clear()
            for relay in list(self._masque.values()):
                relay.close()
            self._masque.clear()
            self.manager.drop_protocol(self)

    class _TypedProtocol(QuicProtocol):
        """Concrete alias used by aioquic's create_protocol callable."""

    return _TypedProtocol


_PROTOCOL_CLASS = None
_PROTOCOL_LOCK = threading.Lock()


def protocol_class():
    global _PROTOCOL_CLASS
    _aioquic()
    with _PROTOCOL_LOCK:
        if _PROTOCOL_CLASS is None:
            _PROTOCOL_CLASS = _build_protocol_class()
        return _PROTOCOL_CLASS


class QuicTransportServer:
    """Run one aioquic UDP listener in a dedicated asyncio thread."""

    def __init__(
        self,
        listener: Any,
        *,
        mode: str,
        bind: str,
        port: int,
        tls_material: dict[str, Any],
        webtransport_path: str = DEFAULT_WEBTRANSPORT_PATH,
        masque_path: str = DEFAULT_MASQUE_PATH,
        idle_timeout: float = 120.0,
        max_datagram_size: int = 65536,
    ):
        if mode not in ("quic", "webtransport", "masque"):
            raise QuicTransportError(f"unsupported QUIC mode {mode!r}",
                                     code="invalid_transport")
        self.listener = listener
        self.mode = mode
        self.bind = bind
        self.port = int(port)
        self.tls_material = dict(tls_material)
        self.webtransport_path = webtransport_path or DEFAULT_WEBTRANSPORT_PATH
        self.masque_path = masque_path or DEFAULT_MASQUE_PATH
        self.idle_timeout = float(idle_timeout)
        self.max_datagram_size = int(max_datagram_size)
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._started_at = time.time()
        self._lock = threading.Lock()
        self._protocols: set[Any] = set()
        self._connections = 0
        self._webtransport_sessions = 0
        self._masque_relays = 0
        self._datagrams = 0
        self._active_relays: list[dict[str, Any]] = []
        self.udp_blocked = False

    # ------------------------------------------------------------ lifecycle
    def start(self, timeout: float = 10.0) -> "QuicTransportServer":
        protocol_class()  # fail before spawning a thread when aioquic is absent
        self._thread = threading.Thread(
            target=self._run, name=f"quic-{self.mode}", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout):
            raise QuicTransportError(
                f"QUIC listener did not start within {timeout}s",
                code="quic_start_timeout",
            )
        if self._error is not None:
            raise QuicTransportError(str(self._error), code="quic_start_failed")
        return self

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._start())
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:  # noqa: BLE001 - surfaced to caller
            self._error = exc
            self._ready.set()
        finally:
            try:
                if self._server is not None:
                    self._server.close()
            except Exception:
                pass
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass

    async def _start(self) -> None:
        from aioquic.asyncio import serve
        from aioquic.quic.configuration import QuicConfiguration

        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=[QUIC_ALPN] if self.mode == "quic" else list(H3_ALPN),
            idle_timeout=self.idle_timeout,
        )
        if self.mode in ("webtransport", "masque"):
            configuration.max_datagram_frame_size = self.max_datagram_size
        configuration.load_cert_chain(
            self.tls_material["cert_file"], self.tls_material["key_file"]
        )
        self._server = await serve(
            self.bind,
            self.port,
            configuration=configuration,
            create_protocol=partial(
                protocol_class(), manager=self, mode=self.mode
            ),
        )
        transport = getattr(self._server, "_transport", None)
        if transport is not None:
            sockname = transport.get_extra_info("sockname")
            if sockname:
                self.port = int(sockname[1])

    def stop(self, timeout: float = 5.0) -> None:
        loop = self._loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._stop_loop)
        except Exception:
            pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=timeout)
        self._thread = None

    def _stop_loop(self) -> None:
        try:
            if self._server is not None:
                self._server.close()
        finally:
            loop = self._loop
            if loop is not None:
                loop.stop()

    # ------------------------------------------------------------ manager API
    def note_connection(self, stream_id: int, mode: str) -> None:
        with self._lock:
            self._connections += 1

    def note_webtransport_session(self) -> None:
        with self._lock:
            self._webtransport_sessions += 1

    def note_masque_relay(self, relay: _MasqueUdpRelay) -> None:
        with self._lock:
            self._masque_relays += 1
            self._active_relays.append(relay.status())
            self._active_relays = self._active_relays[-20:]

    def note_datagram(self) -> None:
        with self._lock:
            self._datagrams += 1

    def drop_protocol(self, protocol: Any) -> None:
        with self._lock:
            self._protocols.discard(protocol)
            self._active_relays = [
                relay for relay in self._active_relays
                if not relay.get("closed")
            ]

    def add_protocol(self, protocol: Any) -> None:
        with self._lock:
            self._protocols.add(protocol)

    def parse_masque_target(self, path: str) -> tuple[str, int] | None:
        prefix = self.masque_path.rstrip("/") + "/"
        if not path.startswith(prefix):
            return None
        rest = path[len(prefix):]
        if rest.endswith("/"):
            rest = rest[:-1]
        if "/" not in rest:
            return None
        host_raw, _, port_raw = rest.rpartition("/")
        host = unquote(host_raw)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            port = int(port_raw)
        except ValueError:
            return None
        if not host or not (0 < port <= 65535):
            return None
        return host, port

    def check_masque_auth(
        self, nonce: str, timestamp: str, mac: str, path: str
    ) -> bool:
        if not nonce or not timestamp or not mac:
            return False
        try:
            stamp = float(timestamp)
        except ValueError:
            return False
        if abs(time.time() - stamp) > MASQUE_AUTH_WINDOW:
            return False
        expected = masque_mac(self.listener.token, nonce, timestamp, path)
        return hmac.compare_digest(expected, mac)

    def choose_probe(self, requested: str) -> Any:
        listener = self.listener
        if requested:
            return listener.connection(requested)
        rows = [row for row in listener.records() if row.get("status") == "online"]
        if not rows:
            raise QuicTransportError("no reverse probe connected",
                                     code="probe_not_found")
        if len(rows) > 1:
            raise QuicTransportError(
                "multiple probes connected; pass x-inkblade-probe",
                code="probe_required",
            )
        return listener.connection(rows[0]["probe_id"])

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": self.mode,
                "bind": self.bind,
                "port": self.port,
                "alpn": QUIC_ALPN if self.mode == "quic" else H3_ALPN,
                "connections": self._connections,
                "webtransport_sessions": self._webtransport_sessions,
                "masque_relays": self._masque_relays,
                "datagrams": self._datagrams,
                "active_relays": list(self._active_relays),
                "active_protocols": len(self._protocols),
                "udp_blocked": self.udp_blocked,
                "started_at": self._started_at,
                "running": self._thread is not None,
            }


def udp_probe_blocked_message(detail: str = "") -> str:
    suffix = f" ({detail})" if detail else ""
    return (
        "udp-blocked: QUIC handshake received no response; UDP 443/9443 may be "
        f"blocked{suffix}; use --fallback tls|wss"
    )
