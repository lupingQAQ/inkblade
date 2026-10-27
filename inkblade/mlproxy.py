# -*- coding: utf-8 -*-
"""ML-native proxy protocols.

P1 (this module): gRPC over TLS for Triton (8001) and Ray (8265).

The local client leg is TLS.  The controller accepts HTTP/2 gRPC streams,
requires a bearer token in gRPC metadata, injects that metadata toward the
target, and multiplexes bidirectional streams through the already-encrypted
reverse probe transport (``ProbeConnection.dial``).  The target leg is the
probe's TCP dial; target-side TLS is not terminated here (use the probe for
plaintext gRPC targets, or a TLS-terminating target endpoint).

``h2`` is an optional dependency: ``pip install h2``.  Without it the proxy
reports a clear configuration error instead of silently degrading.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .channel import (
    ChannelError,
    DialStream,
    ProbeConnection,
    ProbeTimeout,
)


class MlProxyError(ChannelError):
    code = "ml_proxy_error"


class GrpcAuthError(MlProxyError):
    code = "grpc_auth_failed"


def _require_h2():
    try:
        import h2.connection  # noqa: F401
        import h2.config  # noqa: F401
        import h2.events  # noqa: F401
        import h2.settings  # noqa: F401
    except Exception as exc:  # pragma: no cover - optional dependency
        raise MlProxyError(
            "gRPC proxy requires the optional 'h2' package (pip install h2)",
            code="missing_dependency",
        ) from exc


class _DialSocket:
    """Small socket-like adapter over one probe ``dial`` stream."""

    def __init__(self, stream: DialStream):
        self.stream = stream

    def sendall(self, data: bytes) -> None:
        self.stream.send(data)

    def recv(self, size: int, timeout: float = 1.0) -> bytes:
        try:
            chunk = self.stream.recv(timeout=timeout)
        except ProbeTimeout:
            return b""
        return b"" if chunk is None else chunk

    def close(self) -> None:
        self.stream.close()


def _bearer_token(headers: list[tuple[str, str]]) -> str:
    for name, value in headers:
        if name.lower() == "authorization":
            value = value.strip()
            if value.lower().startswith("bearer "):
                return value[7:].strip()
            return value
        if name.lower() == "x-inkblade-token":
            return value.strip()
    return ""


def _with_token(headers: list[tuple[str, str]], token: str) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    replaced = False
    for name, value in headers:
        if name.lower() in ("authorization", "x-inkblade-token"):
            if not replaced:
                output.append(("authorization", f"Bearer {token}"))
                output.append(("x-inkblade-token", token))
                replaced = True
            continue
        output.append((name, value))
    if not replaced:
        output.append(("authorization", f"Bearer {token}"))
        output.append(("x-inkblade-token", token))
    return output


def _recv_line(sock, limit: int = 512) -> str:
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(1)
        if not chunk:
            raise MlProxyError("connection closed during auth", code="disconnected")
        if chunk == b"\n":
            return data.decode("ascii", "replace").rstrip("\r")
        data.extend(chunk)
    raise MlProxyError("authentication line too long", code="protocol")


def _forward_mac(token: str, nonce: str) -> str:
    return hmac.new(
        token.encode("utf-8"), nonce.encode("ascii"), hashlib.sha256
    ).hexdigest()


def parse_port_spec(spec: str, *, max_ports: int = 64) -> list[int]:
    ports: list[int] = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
        if len(ports) >= max_ports:
            break
    ports = sorted({port for port in ports if 0 < port <= 65535})
    if not ports:
        raise MlProxyError("empty or invalid port specification",
                           code="invalid_port")
    return ports[:max_ports]


class _TcpRelayProxy:
    """Common TLS + HMAC-preamble relay used by P4/P6.

    The local client leg is TLS.  The client reads `INKBLADE-AUTH <nonce>` and
    returns HMAC-SHA256(token, nonce); only then does the proxy dial the target
    through the encrypted probe transport.  Raw TCP clients cannot pass the
    TLS handshake and are never relayed.
    """

    protocol = "tcp-relay-tls"

    def __init__(
        self,
        probe: ProbeConnection,
        *,
        token: str,
        bind_host: str = "127.0.0.1",
        tls_material: dict[str, Any] | None = None,
        tls_dir: str | Path | None = None,
        keepalive_s: float = 15.0,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
    ):
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise MlProxyError("TCP relay may only bind loopback", code="public_bind")
        if probe.transport == "tcp":
            raise MlProxyError("plaintext probe transport is lab-only",
                               code="plaintext_probe")
        if not token:
            raise MlProxyError("TCP relay requires a token", code="missing_token")
        self.probe = probe
        self.token = token
        self.bind_host = bind_host
        self.keepalive_s = max(0.0, float(keepalive_s))
        self.on_audit = on_audit
        self._tls_material = tls_material or GrpcTlsProxy._generate_tls(tls_dir)
        self._tls = GrpcTlsProxy._build_tls_context(self._tls_material)
        self._listeners: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._clients: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._keepalive_thread: threading.Thread | None = None
        self._rtt_last = None
        self._jitter = 0.0
        self._keepalive_failures = 0
        self._pings = 0
        self.started_at = time.time()
        self.connections = 0
        self.auth_failures = 0
        self.errors = 0
        self.port_map: list[dict[str, Any]] = []

    def _listen(self, port: int) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, int(port)))
        listener.listen(64)
        listener.settimeout(0.3)
        self._listeners.append(listener)
        return listener

    def _start_listener(self, local_port: int, target_host: str,
                        target_port: int) -> int:
        listener = self._listen(local_port)
        actual = int(listener.getsockname()[1])
        thread = threading.Thread(
            target=self._accept_loop,
            args=(listener, target_host, target_port),
            name="tcp-relay-accept", daemon=True,
        )
        self._threads.append(thread)
        thread.start()
        self.port_map.append({
            "local": actual, "target_host": target_host,
            "target_port": int(target_port),
        })
        return actual

    def _start_keepalive(self) -> None:
        if not self.keepalive_s:
            return
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, name="tcp-relay-keepalive", daemon=True
        )
        self._keepalive_thread.start()

    def _keepalive_loop(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self.probe.ping(timeout=min(5.0, self.keepalive_s))
                rtt = (time.time() - started) * 1000
                if self._rtt_last is not None:
                    self._jitter = (
                        0.8 * self._jitter
                        + 0.2 * abs(rtt - self._rtt_last)
                    )
                self._rtt_last = rtt
                self._pings += 1
            except Exception:
                self._keepalive_failures += 1
            self._stop.wait(self.keepalive_s)

    def _accept_loop(self, listener: socket.socket, target_host: str,
                     target_port: int) -> None:
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(15)
            try:
                client = self._tls.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.errors += 1
                self._audit("tcp_relay.tls_failed", {
                    "target": f"{target_host}:{target_port}",
                    "error": str(exc),
                })
                try:
                    client.close()
                except OSError:
                    pass
                continue
            with self._lock:
                self._clients.add(client)
                self.connections += 1
            thread = threading.Thread(
                target=self._handle_client,
                args=(client, target_host, target_port),
                name="tcp-relay-client", daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def _handle_client(self, client: ssl.SSLSocket, target_host: str,
                       target_port: int) -> None:
        try:
            nonce = secrets_token_hex()
            client.sendall(f"INKBLADE-AUTH {nonce}\n".encode("ascii"))
            client.settimeout(5)
            supplied = _recv_line(client)
            client.settimeout(None)
            if not hmac.compare_digest(supplied, _forward_mac(self.token, nonce)):
                self.auth_failures += 1
                client.sendall(b"INKBLADE-DENY auth-failed\n")
                raise MlProxyError("TCP relay HMAC rejected", code="auth_failed")
            client.sendall(b"INKBLADE-OK\n")
            stream = self.probe.dial(target_host, target_port, timeout_ms=10_000)
            self._audit("tcp_relay.connected", {
                "target": f"{target_host}:{target_port}",
            })
            self._relay(client, stream)
        except (OSError, ChannelError, MlProxyError):
            pass
        finally:
            with self._lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _relay(self, client: ssl.SSLSocket, stream: DialStream) -> None:
        done = threading.Event()

        def upstream() -> None:
            try:
                while not self._stop.is_set():
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    stream.send(chunk)
                stream.close_write()
            except (OSError, ChannelError):
                pass
            finally:
                done.set()

        thread = threading.Thread(target=upstream, name="tcp-relay-up", daemon=True)
        thread.start()
        try:
            while not self._stop.is_set():
                try:
                    chunk = stream.recv(timeout=1.0)
                except ProbeTimeout:
                    continue
                if chunk is None:
                    break
                client.sendall(chunk)
        except (OSError, ChannelError):
            pass
        finally:
            done.wait(timeout=2)
            stream.close()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _audit(self, event: str, detail: dict[str, Any]) -> None:
        if self.on_audit:
            try:
                self.on_audit({"ts": time.time(), "event": event, **detail})
            except Exception:
                pass

    def status(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "listen": f"{self.bind_host}:{self.port_map[0]['local']}"
                      if self.port_map else None,
            "ports": list(self.port_map),
            "probe_id": self.probe.probe_id,
            "probe_transport": self.probe.transport,
            "tls": {"enabled": True, "ca_file": self._tls_material.get("ca_file"),
                    "pin": self._tls_material.get("pin")},
            "auth": {"preamble": "HMAC-SHA256(token,nonce)"},
            "keepalive": {
                "interval_s": self.keepalive_s,
                "pings": self._pings,
                "failures": self._keepalive_failures,
                "rtt_ms_last": round(self._rtt_last, 2)
                if self._rtt_last is not None else None,
                "jitter_ms": round(self._jitter, 2),
            },
            "rdma_verbs": False,
            "connections": self.connections,
            "auth_failures": self.auth_failures,
            "errors": self.errors,
            "running": not self._stop.is_set(),
        }

    def stop(self) -> None:
        self._stop.set()
        for listener in self._listeners:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        for thread in list(self._threads):
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        if self._keepalive_thread is not None:
            self._keepalive_thread.join(timeout=1.0)
        self._audit("tcp_relay.stopped", {"protocol": self.protocol})


def secrets_token_hex() -> str:
    import secrets

    return secrets.token_hex(16)


class TcpStoreTlsProxy(_TcpRelayProxy):
    """P4: TCPStore/Gloo TLS relay (PyTorch 29500 shape)."""

    protocol = "tcpstore-tls"

    def __init__(self, probe: ProbeConnection, *, target_host: str,
                 target_port: int, **kwargs):
        super().__init__(probe, **kwargs)
        self.target_host = target_host
        self.target_port = int(target_port)

    def start(self) -> "TcpStoreTlsProxy":
        self._start_listener(0, self.target_host, self.target_port)
        self._start_keepalive()
        self._audit("tcpstore.started", {
            "target": f"{self.target_host}:{self.target_port}",
            "port": self.port_map[0]["local"],
        })
        return self


class NcclTlsProxy(_TcpRelayProxy):
    """P6: NCCL/UCX TCP control-flow profile relay.

    This is explicitly a TCP control-flow relay/profile.  It does not speak
    RDMA verbs, IB, RoCE, UCX transport or NCCL protocol framing.
    """

    protocol = "nccl-tcp-tls"

    def __init__(self, probe: ProbeConnection, *, target_host: str,
                 port_spec: str, protocol: str = "nccl",
                 max_ports: int = 64, local_base_port: int = 0, **kwargs):
        super().__init__(probe, **kwargs)
        self.target_host = target_host
        self.port_spec = port_spec
        self.profile = "ucx" if protocol == "ucx" else "nccl"
        self.protocol = f"{self.profile}-tcp-tls"
        self.target_ports = parse_port_spec(port_spec, max_ports=max_ports)
        self.local_base_port = int(local_base_port)

    def start(self) -> "NcclTlsProxy":
        for index, target_port in enumerate(self.target_ports):
            local = self.local_base_port + index if self.local_base_port else 0
            self._start_listener(local, self.target_host, target_port)
        self._start_keepalive()
        self._audit(f"{self.profile}.started", {
            "target": self.target_host,
            "ports": self.target_ports,
            "rdma_verbs": False,
        })
        return self



class GrpcTlsProxy:
    """Loopback gRPC-over-TLS proxy backed by one authenticated probe."""

    def __init__(
        self,
        probe: ProbeConnection,
        *,
        target_host: str,
        target_port: int,
        token: str,
        bind_host: str = "127.0.0.1",
        listen_port: int = 0,
        tls_material: dict[str, Any] | None = None,
        tls_dir: str | Path | None = None,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
    ):
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise MlProxyError("gRPC proxy may only bind loopback", code="public_bind")
        if probe.transport == "tcp":
            raise MlProxyError("plaintext probe transport is lab-only",
                               code="plaintext_probe")
        if not target_host or not (0 < int(target_port) <= 65535):
            raise MlProxyError("invalid gRPC target", code="invalid_target")
        if not token:
            raise MlProxyError("gRPC proxy requires a token", code="missing_token")
        _require_h2()
        self.probe = probe
        self.target_host = target_host
        self.target_port = int(target_port)
        self.token = token
        self.bind_host = bind_host
        self.listen_port = int(listen_port)
        self.on_audit = on_audit
        self._tls_material = tls_material or self._generate_tls(tls_dir)
        self._tls = self._build_tls_context(self._tls_material)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._clients: set[socket.socket] = set()
        self._client_threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.started_at = time.time()
        self.connections = 0
        self.streams = 0
        self.auth_failures = 0
        self.errors = 0

    def _generate_tls(self, tls_dir) -> dict[str, Any]:
        from .reverse import ensure_tls_material

        directory = Path(tls_dir) if tls_dir else (
            Path(tempfile.gettempdir()) / f"inkblade-grpc-proxy-{os.getpid()}"
        )
        return ensure_tls_material(directory, hosts=["localhost", "127.0.0.1"])

    @staticmethod
    def _build_tls_context(material: dict[str, Any]) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(material["cert_file"], material["key_file"])
        return context

    @property
    def port(self) -> int:
        return self.listen_port

    def start(self) -> "GrpcTlsProxy":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, self.listen_port))
        listener.listen(64)
        listener.settimeout(0.3)
        self._listener = listener
        self.listen_port = int(listener.getsockname()[1])
        self._thread = threading.Thread(
            target=self._accept_loop, name="grpc-proxy-accept", daemon=True
        )
        self._thread.start()
        self._audit("grpc.proxy.started", {
            "target": f"{self.target_host}:{self.target_port}",
            "port": self.listen_port,
            "transport": self.probe.transport,
        })
        return self

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                break
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(15)
            try:
                client = self._tls.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.errors += 1
                self._audit("grpc.tls_failed", {"error": str(exc)})
                try:
                    client.close()
                except OSError:
                    pass
                continue
            with self._lock:
                self._clients.add(client)
                self.connections += 1
            thread = threading.Thread(
                target=self._handle_client, args=(client, address),
                name="grpc-proxy-client", daemon=True,
            )
            self._client_threads.append(thread)
            thread.start()

    def _handle_client(self, client: ssl.SSLSocket, address) -> None:
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import (
            ConnectionTerminated,
            DataReceived,
            RequestReceived,
            StreamEnded,
            StreamReset,
            WindowUpdated,
        )

        client_h2 = H2Connection(config=H2Configuration(
            client_side=False, header_encoding="utf-8"
        ))
        client_h2.initiate_connection()
        client.sendall(client_h2.data_to_send())
        client_lock = threading.Lock()

        def client_send(data: bytes) -> None:
            if data:
                with client_lock:
                    client.sendall(data)

        target: _GrpcTargetConnection | None = None
        try:
            while not self._stop.is_set():
                data = client.recv(65536)
                if not data:
                    break
                events = client_h2.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        if target is None:
                            target = _GrpcTargetConnection(
                                self, client_h2, address, on_failure=self._fail,
                                client_send=client_send, client_lock=client_lock,
                            )
                            target.start()
                        target.request(event)
                    elif isinstance(event, DataReceived):
                        client_h2.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                        if target is not None:
                            target.data(event)
                    elif isinstance(event, StreamEnded):
                        if target is not None:
                            target.end_stream(event.stream_id)
                    elif isinstance(event, StreamReset):
                        if target is not None:
                            target.reset(event.stream_id)
                    elif isinstance(event, ConnectionTerminated):
                        break
                    elif isinstance(event, WindowUpdated):
                        pass
                with client_lock:
                    pending = client_h2.data_to_send()
                    if pending:
                        client.sendall(pending)
        except (OSError, ssl.SSLError):
            pass
        except Exception as exc:  # noqa: BLE001 - a malformed client is isolated
            self.errors += 1
            self._audit("grpc.client_error", {"error": str(exc)})
        finally:
            if target is not None:
                target.close()
            with self._lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _fail(self, client_h2, stream_id: int, status: int, message: str) -> None:
        headers = [
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-status", str(status)),
            ("grpc-message", message.replace(" ", "%20")),
        ]
        try:
            client_h2.send_headers(stream_id, headers, end_stream=True)
        except Exception:
            pass

    def _audit(self, event: str, detail: dict[str, Any]) -> None:
        if self.on_audit:
            try:
                self.on_audit({"ts": time.time(), "event": event, **detail})
            except Exception:
                pass

    def status(self) -> dict[str, Any]:
        return {
            "protocol": "grpc-tls",
            "target": f"{self.target_host}:{self.target_port}",
            "listen": f"{self.bind_host}:{self.listen_port}",
            "probe_id": self.probe.probe_id,
            "probe_transport": self.probe.transport,
            "tls": {
                "enabled": True,
                "ca_file": self._tls_material.get("ca_file"),
                "pin": self._tls_material.get("pin"),
            },
            "auth": {"metadata": "authorization Bearer / x-inkblade-token"},
            "connections": self.connections,
            "streams": self.streams,
            "auth_failures": self.auth_failures,
            "errors": self.errors,
            "running": not self._stop.is_set(),
        }

    def stop(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1)
        for thread in list(self._client_threads):
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        self._audit("grpc.proxy.stopped", {"connections": self.connections})


class _RespReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def _fill(self) -> bool:
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buffer.extend(chunk)
        return True

    def readline(self) -> bytes:
        while b"\r\n" not in self.buffer:
            if not self._fill():
                raise MlProxyError("redis connection closed", code="disconnected")
        line, _, rest = self.buffer.partition(b"\r\n")
        self.buffer = bytearray(rest)
        return line

    def read_exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            if not self._fill():
                raise MlProxyError("redis connection closed", code="disconnected")
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    def read_some(self) -> bytes:
        if self.buffer:
            data = bytes(self.buffer)
            self.buffer.clear()
            return data
        return self.sock.recv(65536)


class RedisTlsProxy:
    """P2: Redis RESP over TLS, authenticated with ``AUTH <token>``.

    The local client leg is TLS; after local AUTH the raw RESP stream is
    relayed through the probe's encrypted dial transport to Ray GCS/Redis.
    Target-side TLS is not terminated here.
    """

    def __init__(
        self,
        probe: ProbeConnection,
        *,
        target_host: str,
        target_port: int,
        token: str,
        bind_host: str = "127.0.0.1",
        listen_port: int = 0,
        tls_material: dict[str, Any] | None = None,
        tls_dir: str | Path | None = None,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
    ):
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise MlProxyError("Redis proxy may only bind loopback", code="public_bind")
        if probe.transport == "tcp":
            raise MlProxyError("plaintext probe transport is lab-only",
                               code="plaintext_probe")
        if not token:
            raise MlProxyError("Redis proxy requires a token", code="missing_token")
        self.probe = probe
        self.target_host = target_host
        self.target_port = int(target_port)
        self.token = token
        self.bind_host = bind_host
        self.listen_port = int(listen_port)
        self.on_audit = on_audit
        self._tls_material = tls_material or GrpcTlsProxy._generate_tls(tls_dir)
        self._tls = GrpcTlsProxy._build_tls_context(self._tls_material)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self.started_at = time.time()
        self.connections = 0
        self.auth_failures = 0
        self.errors = 0

    @property
    def port(self) -> int:
        return self.listen_port

    def start(self) -> "RedisTlsProxy":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, self.listen_port))
        listener.listen(64)
        listener.settimeout(0.3)
        self._listener = listener
        self.listen_port = int(listener.getsockname()[1])
        self._thread = threading.Thread(
            target=self._accept_loop, name="redis-proxy-accept", daemon=True
        )
        self._thread.start()
        self._audit("redis.proxy.started", {
            "target": f"{self.target_host}:{self.target_port}",
            "port": self.listen_port,
        })
        return self

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                break
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(15)
            try:
                client = self._tls.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.errors += 1
                self._audit("redis.tls_failed", {"error": str(exc)})
                try:
                    client.close()
                except OSError:
                    pass
                continue
            with self._lock:
                self._clients.add(client)
                self.connections += 1
            thread = threading.Thread(
                target=self._handle_client, args=(client, address),
                name="redis-proxy-client", daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def _handle_client(self, client: ssl.SSLSocket, address) -> None:
        reader = _RespReader(client)
        try:
            command = self._read_command(reader)
            if not command:
                return
            verb = command[0].upper()
            if verb != "AUTH" or len(command) not in (2, 3):
                client.sendall(b"-ERR AUTH required\r\n")
                raise GrpcAuthError("Redis client did not authenticate")
            supplied = command[-1]
            if not hmac.compare_digest(supplied.encode("utf-8"),
                                       self.token.encode("utf-8")):
                self.auth_failures += 1
                client.sendall(b"-ERR invalid password\r\n")
                raise GrpcAuthError("Redis AUTH token rejected")
            client.sendall(b"+OK\r\n")
            stream = self.probe.dial(
                self.target_host, self.target_port, timeout_ms=10_000
            )
            self._audit("redis.authenticated", {"remote": str(address),
                                                "target": f"{self.target_host}:{self.target_port}"})
            self._relay(client, reader, stream)
        except (OSError, ChannelError, MlProxyError):
            pass
        finally:
            with self._lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _read_command(reader: _RespReader) -> list[str]:
        line = reader.readline()
        if not line:
            return []
        if line.startswith(b"*"):
            count = int(line[1:] or b"0")
            if count < 1 or count > 16:
                raise MlProxyError("invalid Redis array length", code="protocol")
            args = []
            for _ in range(count):
                length_line = reader.readline()
                if not length_line.startswith(b"$"):
                    raise MlProxyError("invalid Redis bulk string", code="protocol")
                length = int(length_line[1:] or b"0")
                if length < 0 or length > 4096:
                    raise MlProxyError("invalid Redis bulk length", code="protocol")
                args.append(reader.read_exact(length + 2)[:-2].decode("utf-8", "replace"))
            return args
        return [part.decode("utf-8", "replace") for part in line.split()]

    def _relay(self, client: ssl.SSLSocket, reader: _RespReader,
               stream: DialStream) -> None:
        client.settimeout(None)
        done = threading.Event()

        def upstream() -> None:
            try:
                while not self._stop.is_set():
                    chunk = reader.read_some()
                    if not chunk:
                        break
                    stream.send(chunk)
                stream.close_write()
            except (OSError, ChannelError):
                pass
            finally:
                done.set()

        thread = threading.Thread(target=upstream, name="redis-up", daemon=True)
        thread.start()
        try:
            while not self._stop.is_set():
                try:
                    chunk = stream.recv(timeout=1.0)
                except ProbeTimeout:
                    continue
                if chunk is None:
                    break
                client.sendall(chunk)
        except (OSError, ChannelError):
            pass
        finally:
            done.wait(timeout=2)
            stream.close()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _audit(self, event: str, detail: dict[str, Any]) -> None:
        if self.on_audit:
            try:
                self.on_audit({"ts": time.time(), "event": event, **detail})
            except Exception:
                pass

    def status(self) -> dict[str, Any]:
        return {
            "protocol": "redis-resp-tls",
            "target": f"{self.target_host}:{self.target_port}",
            "listen": f"{self.bind_host}:{self.listen_port}",
            "probe_id": self.probe.probe_id,
            "probe_transport": self.probe.transport,
            "tls": {"enabled": True, "ca_file": self._tls_material.get("ca_file"),
                    "pin": self._tls_material.get("pin")},
            "auth": {"command": "AUTH", "token_source": "proxy-token-file"},
            "connections": self.connections,
            "auth_failures": self.auth_failures,
            "errors": self.errors,
            "running": not self._stop.is_set(),
        }

    def stop(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1)
        for thread in list(self._threads):
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        self._audit("redis.proxy.stopped", {"connections": self.connections})


class _GrpcTargetConnection:
    """One upstream HTTP/2 connection multiplexed over a probe dial stream."""

    def __init__(self, proxy: GrpcTlsProxy, client_h2, address, *,
                 on_failure: Callable[[Any, int, int, str], None],
                 client_send: Callable[[bytes], None],
                 client_lock: threading.Lock):
        from h2.config import H2Configuration
        from h2.connection import H2Connection

        self.proxy = proxy
        self.client_h2 = client_h2
        self.address = address
        self.on_failure = on_failure
        self.client_send = client_send
        self.client_lock = client_lock
        self.stream = proxy.probe.dial(
            proxy.target_host, proxy.target_port, timeout_ms=10_000
        )
        self.sock = _DialSocket(self.stream)
        self.target_h2 = H2Connection(config=H2Configuration(
            client_side=True, header_encoding="utf-8"
        ))
        self.target_h2.initiate_connection()
        self.sock.sendall(self.target_h2.data_to_send())
        self._lock = threading.Lock()
        self._streams: dict[int, int] = {}
        self._ended: set[int] = set()
        self._reader: threading.Thread | None = None
        self._closed = False

    def start(self) -> None:
        self._reader = threading.Thread(
            target=self._reader_loop, name="grpc-proxy-upstream", daemon=True
        )
        self._reader.start()

    def request(self, event) -> None:
        headers = list(event.headers)
        supplied = _bearer_token(headers)
        if not supplied or not hmac.compare_digest(
            supplied, self.proxy.token
        ):
            self.proxy.auth_failures += 1
            self.proxy._audit("grpc.auth_failed", {"remote": str(self.address)})
            self.on_failure(self.client_h2, event.stream_id, 16, "unauthenticated")
            return
        outbound = _with_token(headers, self.proxy.token)
        with self._lock:
            target_stream = self.target_h2.get_next_available_stream_id()
            self._streams[target_stream] = event.stream_id
            self.target_h2.send_headers(
                target_stream, outbound, end_stream=event.stream_ended
            )
            self.sock.sendall(self.target_h2.data_to_send())
        self.proxy.streams += 1
        self.proxy._audit("grpc.request", {
            "path": dict(headers).get(":path", ""),
            "remote": str(self.address),
        })

    def data(self, event) -> None:
        with self._lock:
            target_stream = self._streams.get(event.stream_id)
            if target_stream is None:
                return
            self.target_h2.send_data(
                target_stream, event.data, end_stream=bool(event.stream_ended)
            )
            self.sock.sendall(self.target_h2.data_to_send())

    def end_stream(self, client_stream: int) -> None:
        with self._lock:
            target_stream = self._streams.get(client_stream)
            if target_stream is None:
                return
            try:
                self.target_h2.end_stream(target_stream)
            except Exception:
                return
            self.sock.sendall(self.target_h2.data_to_send())

    def reset(self, client_stream: int) -> None:
        with self._lock:
            target_stream = self._streams.get(client_stream)
            if target_stream is None:
                return
            try:
                self.target_h2.reset_stream(target_stream)
            except Exception:
                pass
            self.sock.sendall(self.target_h2.data_to_send())

    def _reader_loop(self) -> None:
        from h2.events import (
            DataReceived,
            ResponseReceived,
            StreamEnded,
            StreamReset,
            TrailersReceived,
            WindowUpdated,
        )

        try:
            while not self._closed and not self.proxy._stop.is_set():
                chunk = self.sock.recv(65536)
                if not chunk:
                    continue
                events = self.target_h2.receive_data(chunk)
                for event in events:
                    client_stream = self._streams.get(
                        getattr(event, "stream_id", -1)
                    )
                    if isinstance(event, ResponseReceived):
                        if client_stream is not None:
                            with self.client_lock:
                                self.client_h2.send_headers(
                                    client_stream, list(event.headers)
                                )
                            self._flush_client()
                    elif isinstance(event, DataReceived):
                        self.target_h2.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                        if client_stream is not None:
                            with self.client_lock:
                                self.client_h2.send_data(
                                    client_stream, event.data,
                                    end_stream=bool(event.stream_ended),
                                )
                            self._flush_client()
                    elif isinstance(event, TrailersReceived):
                        if client_stream is not None:
                            with self.client_lock:
                                self.client_h2.send_headers(
                                    client_stream, list(event.headers),
                                    end_stream=True,
                                )
                            self._ended.add(event.stream_id)
                            self._flush_client()
                    elif isinstance(event, StreamEnded):
                        if client_stream is not None \
                                and event.stream_id not in self._ended:
                            with self.client_lock:
                                self.client_h2.end_stream(client_stream)
                            self._flush_client()
                    elif isinstance(event, StreamReset):
                        if client_stream is not None:
                            with self.client_lock:
                                self.client_h2.reset_stream(client_stream)
                            self._flush_client()
                    elif isinstance(event, WindowUpdated):
                        pass
                pending = self.target_h2.data_to_send()
                if pending:
                    self.sock.sendall(pending)
        except (OSError, ProbeTimeout, Exception):
            pass
        finally:
            self._closed = True

    def _flush_client(self) -> None:
        with self.client_lock:
            data = self.client_h2.data_to_send()
        if data:
            self.client_send(data)

    def close(self) -> None:
        self._closed = True
        try:
            self.sock.close()
        except Exception:
            pass
        if self._reader is not None and self._reader is not threading.current_thread():
            self._reader.join(timeout=1)
