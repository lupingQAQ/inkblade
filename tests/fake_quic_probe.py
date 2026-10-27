# -*- coding: utf-8 -*-
"""Test-only aioquic clients for the QUIC/WebTransport/MASQUE transports.

These helpers let the Python test suite exercise the controller without a Rust
binary or a cluster.  They are not shipped and do not replace the real probe.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import queue
import secrets
import ssl
import threading
import time
from typing import Any
from urllib.parse import quote

try:
    from aioquic.asyncio.client import connect as aioquic_connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        DatagramReceived,
        HeadersReceived,
        WebTransportStreamDataReceived,
    )
    from aioquic.quic import events as quic_events
    from aioquic.quic.configuration import QuicConfiguration
    from cryptography.hazmat.primitives import serialization

    HAS_AIOQUIC = True
except Exception:  # pragma: no cover - optional dependency
    HAS_AIOQUIC = False

from inkblade.quictransport import QUIC_ALPN, masque_mac

from tests.fake_reverse_probe import FakeReverseProbe


class _H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, quic, stream_handler=None):
        super().__init__(quic, stream_handler=stream_handler)
        self.h3 = None
        self.events: asyncio.Queue = asyncio.Queue()
        self.on_datagram = None
        self.wt_streams: set[int] = set()
        self.wt_session_id = 0

    def quic_event_received(self, event) -> None:
        if (
            isinstance(event, quic_events.StreamDataReceived)
            and event.stream_id in self.wt_streams
        ):
            # WebTransport server->client data is raw stream bytes, not an
            # HTTP/3 DATA frame.  Bypass H3 framing for these streams.
            self.events.put_nowait(
                WebTransportStreamDataReceived(
                    data=event.data,
                    session_id=self.wt_session_id,
                    stream_id=event.stream_id,
                    stream_ended=event.end_stream,
                )
            )
            return
        if self.h3 is not None:
            for h3_event in self.h3.handle_event(event):
                if isinstance(h3_event, DatagramReceived):
                    if self.on_datagram is not None:
                        try:
                            self.on_datagram(h3_event)
                        except Exception:
                            pass
                self.events.put_nowait(h3_event)
        if isinstance(event, quic_events.ConnectionTerminated):
            self.events.put_nowait(None)


def _pin_matches(protocol: QuicConnectionProtocol, expected: str) -> None:
    if not expected:
        return
    certificate = getattr(getattr(protocol._quic, "tls", None), "_peer_certificate", None)
    if certificate is None:
        raise ValueError("certificate pin mismatch: no peer certificate")
    der = certificate.public_bytes(serialization.Encoding.DER)
    got = hashlib.sha256(der).hexdigest()
    cleaned = expected.strip().lower()
    if cleaned.startswith("sha256:"):
        cleaned = cleaned[len("sha256:"):]
    if not hmac.compare_digest(got, cleaned):
        raise ValueError(f"certificate pin mismatch: got {got}")


class QuicClientStream:
    """Synchronous byte stream backed by an aioquic QUIC/WebTransport stream."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        ca_file: str,
        pin: str = "",
        sni: str = "",
        transport: str = "quic",
        path: str = "/inkblade/wt",
        connect_timeout: float = 15.0,
    ):
        if not HAS_AIOQUIC:
            raise RuntimeError("aioquic is not installed")
        self.host = host
        self.port = int(port)
        self.ca_file = ca_file
        self.pin = pin
        self.sni = sni or host
        self.transport = transport
        self.path = path
        self.connect_timeout = float(connect_timeout)
        self.error: BaseException | None = None
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread = threading.Thread(target=self._main, daemon=True)
        self._incoming: "queue.Queue[bytes | None]" = queue.Queue()
        self._buffer = bytearray()
        self._cond = threading.Condition()
        self._closed = False
        self._eof = False
        self._protocol = None
        self._cm = None
        self._reader = None
        self._writer = None
        self._session_id = 0
        self._stream_id = 0
        self._send_queue: asyncio.Queue | None = None
        self._tasks: list[asyncio.Task] = []
        self._thread.start()
        if not self._ready.wait(self.connect_timeout + 10):
            raise TimeoutError("QUIC test client did not become ready")
        if self.error is not None:
            raise self.error

    # ------------------------------------------------------------ async setup
    def _main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._connect())
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
            self._ready.set()
        finally:
            try:
                loop.close()
            except Exception:
                pass

    async def _connect(self) -> None:
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=(
                [QUIC_ALPN] if self.transport == "quic" else list(H3_ALPN)
            ),
            max_datagram_frame_size=65536,
        )
        configuration.server_name = self.sni
        configuration.verify_mode = ssl.CERT_REQUIRED
        configuration.load_verify_locations(cafile=self.ca_file)
        create_protocol = (
            QuicConnectionProtocol if self.transport == "quic" else _H3ClientProtocol
        )
        self._cm = aioquic_connect(
            self.host,
            self.port,
            configuration=configuration,
            create_protocol=create_protocol,
            wait_connected=True,
        )
        self._protocol = await self._cm.__aenter__()
        _pin_matches(self._protocol, self.pin)
        self._send_queue = asyncio.Queue()
        if self.transport == "quic":
            self._reader, self._writer = await self._protocol.create_stream()
            self._tasks.append(asyncio.create_task(self._pump_raw_reader()))
            self._tasks.append(asyncio.create_task(self._pump_raw_writer()))
            return
        if self.transport != "webtransport":
            raise ValueError(f"unsupported test client transport {self.transport}")
        self._protocol.h3 = H3Connection(
            self._protocol._quic, enable_webtransport=True
        )
        session_id = self._protocol._quic.get_next_available_stream_id()
        self._session_id = session_id
        self._protocol.h3.send_headers(
            session_id,
            [
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", self.host.encode("ascii")),
                (b":path", self.path.encode("ascii")),
                (b":protocol", b"webtransport"),
            ],
        )
        self._protocol.transmit()
        await self._wait_status(session_id, 200)
        self._stream_id = self._protocol.h3.create_webtransport_stream(session_id)
        self._protocol.wt_streams.add(self._stream_id)
        self._protocol.wt_session_id = session_id
        self._protocol.transmit()
        self._tasks.append(asyncio.create_task(self._pump_wt_reader()))
        self._tasks.append(asyncio.create_task(self._pump_wt_writer()))

    async def _wait_status(self, stream_id: int, expected: int) -> None:
        deadline = time.monotonic() + self.connect_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP/3 response headers timed out")
            event = await asyncio.wait_for(self._protocol.events.get(), remaining)
            if event is None:
                raise ConnectionError("HTTP/3 connection closed")
            if isinstance(event, HeadersReceived) and event.stream_id == stream_id:
                mapping = {k.lower(): v for k, v in event.headers}
                status = int(mapping.get(b":status", b"0"))
                if status != expected:
                    raise ConnectionError(f"HTTP/3 status {status}, expected {expected}")
                return

    # ------------------------------------------------------------ byte pumps
    async def _pump_raw_reader(self) -> None:
        try:
            while True:
                data = await self._reader.read(65536)
                if not data:
                    break
                self._incoming.put(data)
        finally:
            self._incoming.put(None)

    async def _pump_raw_writer(self) -> None:
        try:
            while True:
                data = await self._send_queue.get()
                if data is None:
                    break
                self._writer.write(data)
                await self._writer.drain()
        except Exception:
            pass

    async def _pump_wt_reader(self) -> None:
        try:
            while True:
                event = await self._protocol.events.get()
                if event is None:
                    break
                if not isinstance(event, WebTransportStreamDataReceived):
                    continue
                if event.stream_id != self._stream_id:
                    continue
                if event.data:
                    self._incoming.put(event.data)
                if event.stream_ended:
                    break
        finally:
            self._incoming.put(None)

    async def _pump_wt_writer(self) -> None:
        try:
            while True:
                data = await self._send_queue.get()
                if data is None:
                    break
                self._protocol._quic.send_stream_data(self._stream_id, data)
                self._protocol.transmit()
        except Exception:
            pass

    # ------------------------------------------------------------ file-like
    def makefile(self, mode: str = "rb"):
        return self

    def settimeout(self, value) -> None:
        return None

    def shutdown(self, how) -> None:
        self.close()

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 65536
        with self._cond:
            while len(self._buffer) < size and not self._eof:
                try:
                    chunk = self._incoming.get(timeout=self.connect_timeout + 10)
                except queue.Empty:
                    raise TimeoutError("QUIC test client read timed out")
                if chunk is None:
                    self._eof = True
                    break
                self._buffer.extend(chunk)
            take = min(size, len(self._buffer))
            data = bytes(self._buffer[:take])
            del self._buffer[:take]
            return data

    def write(self, data: bytes) -> int:
        if self._closed or self._send_queue is None:
            raise ConnectionError("QUIC test stream is closed")
        payload = bytes(data)
        self._loop.call_soon_threadsafe(self._send_queue.put_nowait, payload)
        return len(payload)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(self._stop_loop)
            except Exception:
                pass
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _stop_loop(self) -> None:
        loop = self._loop
        if loop is None:
            return
        for task in self._tasks:
            task.cancel()

        async def _shutdown() -> None:
            try:
                if self._protocol is not None:
                    self._protocol.close()
                    await asyncio.wait_for(self._protocol.wait_closed(), 1.0)
            except Exception:
                pass
            try:
                if self._cm is not None:
                    await asyncio.wait_for(
                        self._cm.__aexit__(None, None, None), 0.5
                    )
            except Exception:
                pass
            loop.stop()

        try:
            loop.create_task(_shutdown())
        except Exception:
            loop.stop()


class MasqueClient:
    """A minimal RFC 9298 CONNECT-UDP test client."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        target_host: str,
        target_port: int,
        token: str,
        ca_file: str,
        pin: str = "",
        sni: str = "",
        probe_id: str = "",
        path_prefix: str = "/.well-known/masque/udp",
        connect_timeout: float = 15.0,
    ):
        if not HAS_AIOQUIC:
            raise RuntimeError("aioquic is not installed")
        self.host = host
        self.port = int(port)
        self.target_host = target_host
        self.target_port = int(target_port)
        self.token = token
        self.ca_file = ca_file
        self.pin = pin
        self.sni = sni or host
        self.probe_id = probe_id
        self.path_prefix = path_prefix.rstrip("/")
        self.connect_timeout = float(connect_timeout)
        self.error: BaseException | None = None
        self.status = 0
        self.path = (
            f"{self.path_prefix}/{quote(target_host, safe='[]:')}/{self.target_port}/"
        )
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread = threading.Thread(target=self._main, daemon=True)
        self._datagrams: "queue.Queue[bytes | None]" = queue.Queue()
        self._closed = False
        self._protocol = None
        self._cm = None
        self._session_id = 0
        self._thread.start()
        if not self._ready.wait(self.connect_timeout + 10):
            raise TimeoutError("MASQUE test client did not become ready")
        if self.error is not None:
            raise self.error

    def _main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._connect())
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
            self._ready.set()
        finally:
            try:
                loop.close()
            except Exception:
                pass

    async def _connect(self) -> None:
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=list(H3_ALPN),
            max_datagram_frame_size=65536,
        )
        configuration.server_name = self.sni
        configuration.verify_mode = ssl.CERT_REQUIRED
        configuration.load_verify_locations(cafile=self.ca_file)
        self._cm = aioquic_connect(
            self.host,
            self.port,
            configuration=configuration,
            create_protocol=_H3ClientProtocol,
            wait_connected=True,
        )
        self._protocol = await self._cm.__aenter__()
        _pin_matches(self._protocol, self.pin)
        self._protocol.h3 = H3Connection(
            self._protocol._quic, enable_webtransport=True
        )
        nonce = secrets.token_hex(8)
        timestamp = str(int(time.time()))
        mac = masque_mac(self.token, nonce, timestamp, self.path)
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", self.host.encode("ascii")),
            (b":path", self.path.encode("ascii")),
            (b":protocol", b"connect-udp"),
            (b"capsule-protocol", b"?1"),
            (b"x-inkblade-nonce", nonce.encode("ascii")),
            (b"x-inkblade-timestamp", timestamp.encode("ascii")),
            (b"x-inkblade-mac", mac.encode("ascii")),
        ]
        if self.probe_id:
            headers.append((b"x-inkblade-probe", self.probe_id.encode("utf-8")))
        session_id = self._protocol._quic.get_next_available_stream_id()
        self._session_id = session_id
        self._protocol.h3.send_headers(session_id, headers)
        self._protocol.transmit()
        deadline = time.monotonic() + self.connect_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MASQUE response headers timed out")
            event = await asyncio.wait_for(self._protocol.events.get(), remaining)
            if event is None:
                raise ConnectionError("MASQUE connection closed")
            if isinstance(event, HeadersReceived) and event.stream_id == session_id:
                mapping = {k.lower(): v for k, v in event.headers}
                self.status = int(mapping.get(b":status", b"0"))
                if self.status != 200:
                    raise ConnectionError(f"MASQUE status {self.status}")
                self._protocol.on_datagram = self._on_datagram
                return

    def _on_datagram(self, event: DatagramReceived) -> None:
        if event.stream_id == self._session_id:
            self._datagrams.put(bytes(event.data))

    def send_udp(self, payload: bytes) -> None:
        if self._closed:
            raise ConnectionError("MASQUE client is closed")

        def _send() -> None:
            self._protocol.h3.send_datagram(self._session_id, bytes(payload))
            self._protocol.transmit()

        self._loop.call_soon_threadsafe(_send)

    def recv_udp(self, timeout: float = 5.0) -> bytes:
        try:
            data = self._datagrams.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError("MASQUE datagram timed out") from exc
        if data is None:
            raise ConnectionError("MASQUE client closed")
        return data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(self._stop_loop)
            except Exception:
                pass
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _stop_loop(self) -> None:
        loop = self._loop
        if loop is None:
            return

        async def _shutdown() -> None:
            try:
                if self._protocol is not None:
                    self._protocol.close()
                    await asyncio.wait_for(self._protocol.wait_closed(), 1.0)
            except Exception:
                pass
            try:
                if self._cm is not None:
                    await asyncio.wait_for(
                        self._cm.__aexit__(None, None, None), 0.5
                    )
            except Exception:
                pass
            loop.stop()

        try:
            loop.create_task(_shutdown())
        except Exception:
            loop.stop()


class FakeQuicReverseProbe(FakeReverseProbe):
    """Fake probe that authenticates over a QUIC or WebTransport byte stream."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        probe_id: str,
        *,
        transport: str = "quic",
        ca_file: str | None = None,
        pin: str = "",
        sni: str | None = None,
        path: str = "/inkblade/wt",
        fallback_from: str = "",
        connect_timeout: float = 15.0,
        **kwargs: Any,
    ):
        super().__init__(
            host,
            port,
            token,
            probe_id,
            transport=transport,
            ca_file=ca_file,
            pin=pin,
            sni=sni,
            fallback_from=fallback_from,
            connect_timeout=connect_timeout,
            **kwargs,
        )
        self.path = path

    def run(self) -> None:
        try:
            stream = QuicClientStream(
                self.host,
                self.port,
                ca_file=str(self.ca_file),
                pin=self.pin,
                sni=self.sni,
                transport=self.transport,
                path=self.path,
                connect_timeout=self.connect_timeout,
            )
        except BaseException as exc:  # noqa: BLE001 - surface to the test
            self.error = exc
            self.ready.set()
            self.finished.set()
            return
        self._serve_stream(stream)

