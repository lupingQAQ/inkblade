# -*- coding: utf-8 -*-
"""Encrypted, probe-initiated reverse channel.

Transports (all carry the *same* 4-byte length + JSON frames and the same
challenge-HMAC token handshake):

* ``tls``   - raw framed protocol inside TLS (default);
* ``wss``   - TLS + RFC 6455 WebSocket binary messages;
* ``https`` - TLS + HTTP/1.1 long-poll (POST poll / POST result);
* ``quic``  - QUIC/TLS 1.3 bidirectional stream carrying the same frames
  (experimental UDP path; aioquic controller, quinn probe);
* ``webtransport`` - HTTP/3 extended CONNECT + one WebTransport bidi stream
  per probe (experimental; aioquic controller/client);
* ``masque`` - RFC 9298 CONNECT-UDP + HTTP Datagrams, relayed to the probe's
  ``udp`` op for RoCE/UCX auxiliary UDP (not RDMA verbs).

``quic``/``webtransport``/``masque`` use UDP.  When UDP is blocked the probe
reports ``udp-blocked`` and can fall back to encrypted ``tls``/``wss`` on the
same TCP port; the controller marks ``fallback: true`` and
``fallback_from: quic`` in the probe record.

There is no public plaintext transport.  ``lab_plaintext`` exists only for
in-process tests and requires ``INKBLADE_ALLOW_PLAINTEXT_LAB=1``; the CLI hides
it and labels it as lab-only.

The controller opens one port.  The probe always dials out, so the target Pod
needs no listener, root, hostPath, privileged container or kubeconfig, only
outbound TCP.  TLS server certificates are generated locally (CA + leaf); the
probe pins the leaf SHA-256 and still performs token challenge-HMAC inside TLS.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .channel import (
    MAX_FRAME,
    AuthError,
    ChannelError,
    ProbeConnection,
    ProbeTimeout,
    encode_frame,
    read_frame,
)

STATE_SCHEMA = "inkblade-reverse-probes-v1"
CONTROL_SCHEMA = "inkblade-reverse-control-v1"
DEFAULT_REMOTE_DIRS = ("/tmp", "/dev/shm")
TRANSPORTS = ("tls", "wss", "https")
QUIC_TRANSPORTS = ("quic", "webtransport", "masque")
ENCRYPTED_TRANSPORTS = TRANSPORTS + QUIC_TRANSPORTS
FALLBACK_TRANSPORTS = ("tls", "wss")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HTTP_BODY = 8 * 1024 * 1024
MAX_WS_MESSAGE = 8 * 1024 * 1024
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_READ_ONLY_MARKERS = (
    "read-only file system",
    "read only file system",
    "erofs",
    "errno 30",
    "os error 30",
)
_WRITE_DISABLED_MARKERS = (
    "require --allow-write",
    "requires --allow-write",
)


class ReverseChannelError(ChannelError):
    code = "reverse_error"


class ReverseTlsError(ReverseChannelError):
    code = "tls_error"


def reverse_dir(home: str | Path, workspace: str = "local-lab") -> Path:
    return Path(home).expanduser().resolve() / "evidence" / workspace / "reverse"


def reverse_paths(home: str | Path, workspace: str = "local-lab") -> dict[str, Path]:
    directory = reverse_dir(home, workspace)
    return {
        "dir": directory,
        "probes": directory / "probes.json",
        "control": directory / "control.json",
        "tls": directory / "tls",
    }


def _secure_write(path: Path, text: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}-{threading.get_ident()}")
    temporary.write_text(text, encoding="utf-8")
    try:
        os.chmod(temporary, mode)
    except OSError:
        pass
    os.replace(temporary, path)


def _atomic_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}-{threading.get_ident()}")
    temporary.write_bytes(data)
    try:
        os.chmod(temporary, mode)
    except OSError:
        pass
    os.replace(temporary, path)


def _is_read_only_error(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _READ_ONLY_MARKERS)


def _is_write_disabled(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _WRITE_DISABLED_MARKERS)


# ---------------------------------------------------------------------------
# TLS material
# ---------------------------------------------------------------------------
def tls_paths(directory: str | Path) -> dict[str, Path]:
    root = Path(directory)
    return {
        "dir": root,
        "ca": root / "ca.pem",
        "ca_key": root / "ca-key.pem",
        "cert": root / "server.pem",
        "key": root / "server-key.pem",
        "pin": root / "server.sha256",
    }


def _certificate_pin(cert_pem: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    certificate = x509.load_pem_x509_certificate(cert_pem.read_bytes())
    return hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def ensure_tls_material(
    directory: str | Path,
    *,
    hosts: Sequence[str] = (),
    days: int = 3650,
    expired: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Generate a CA + server leaf and return paths, SNI list and leaf pin."""
    paths = tls_paths(directory)
    required = (paths["ca"], paths["cert"], paths["key"])
    if not force and all(path.is_file() for path in required):
        try:
            pin = _certificate_pin(paths["cert"])
            return {
                "ca_file": str(paths["ca"]), "cert_file": str(paths["cert"]),
                "key_file": str(paths["key"]), "pin": pin,
                "hosts": list(hosts), "generated": False,
            }
        except Exception:
            pass
    try:
        import datetime
        import ipaddress

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except Exception as exc:  # pragma: no cover - dependency is present in CI
        raise ReverseTlsError(
            "TLS certificate generation needs the 'cryptography' package; "
            "provide --tls-ca/--tls-cert/--tls-key instead",
            code="tls_material",
        ) from exc

    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before = now - datetime.timedelta(days=30)
        not_after = now - datetime.timedelta(days=1)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=max(1, int(days)))

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "InkBlade Reverse CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    names = []
    for raw in hosts:
        value = str(raw).strip()
        if value and value not in names:
            names.append(value)
    for value in ("localhost", "127.0.0.1", "::1"):
        if value not in names:
            names.append(value)
    san: list[Any] = []
    for value in names:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            san.append(x509.DNSName(value))

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "inkblade-reverse")
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths["dir"].mkdir(parents=True, exist_ok=True)
    _atomic_bytes(paths["ca"], ca_cert.public_bytes(serialization.Encoding.PEM), mode=0o644)
    _atomic_bytes(
        paths["ca_key"],
        ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        mode=0o600,
    )
    _atomic_bytes(paths["cert"], server_cert.public_bytes(serialization.Encoding.PEM), mode=0o644)
    _atomic_bytes(
        paths["key"],
        server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        mode=0o600,
    )
    pin = hashlib.sha256(server_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    paths["pin"].write_text(pin + "\n", encoding="utf-8")
    return {
        "ca_file": str(paths["ca"]), "cert_file": str(paths["cert"]),
        "key_file": str(paths["key"]), "pin": pin,
        "hosts": names, "generated": True,
    }


def tls_context(material: dict[str, Any]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.load_cert_chain(material["cert_file"], material["key_file"])
    return context


# ---------------------------------------------------------------------------
# WebSocket (RFC 6455) adapter
# ---------------------------------------------------------------------------
class _WSFile:
    def __init__(self, stream: "WebSocketStream", mode: str):
        self.stream = stream
        self.mode = mode

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def write(self, data: bytes) -> int:
        self.stream.write(data)
        return len(data)

    def flush(self) -> None:
        self.stream.flush()

    def close(self) -> None:
        return None


class WebSocketStream:
    """Server-side WebSocket stream presenting a byte-stream file interface.

    Binary messages carry protocol bytes.  Frame boundaries do not matter to
    the framed reader, so split writes are concatenated safely.  Outgoing
    writes are buffered until flush (one protocol frame per binary message).
    """

    def __init__(self, sock, *, leftover: bytes = b"", max_message: int = MAX_WS_MESSAGE):
        self.sock = sock
        self._incoming = bytearray(leftover)
        self._read_buffer = bytearray()
        self._outgoing = bytearray()
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = False
        self.max_message = max_message

    # socket-compatible surface used by ProbeConnection
    def settimeout(self, value) -> None:
        self.sock.settimeout(value)

    def makefile(self, mode: str = "rb") -> _WSFile:
        return _WSFile(self, mode)

    def shutdown(self, how) -> None:
        try:
            self.sock.shutdown(how)
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------ byte stream
    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 65536
        with self._read_lock:
            while len(self._read_buffer) < size:
                if not self._next_message():
                    break
            chunk = bytes(self._read_buffer[:size])
            del self._read_buffer[:size]
            return chunk

    def write(self, data: bytes) -> None:
        with self._write_lock:
            self._outgoing.extend(data)

    def flush(self) -> None:
        with self._write_lock:
            if not self._outgoing:
                return
            payload = bytes(self._outgoing)
            self._outgoing.clear()
            self._send_frame(0x2, payload)

    # ------------------------------------------------------------ framing
    def _sock_read(self, count: int) -> bytes:
        while len(self._incoming) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self._incoming.extend(chunk)
        data = bytes(self._incoming[:count])
        del self._incoming[:count]
        return data

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(length)
        elif length <= 0xFFFF:
            header.append(126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(127)
            header.extend(struct.pack(">Q", length))
        self.sock.sendall(bytes(header) + payload)

    def _next_message(self) -> bool:
        while True:
            header = self._sock_read(2)
            fin = bool(header[0] & 0x80)
            opcode = header[0] & 0x0F
            masked = bool(header[1] & 0x80)
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._sock_read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._sock_read(8))[0]
            if length > self.max_message:
                raise ConnectionError("websocket message too large")
            mask = self._sock_read(4) if masked else b""
            payload = self._sock_read(length) if length else b""
            if masked:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 0x8:
                return False
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x1, 0x2):
                self._read_buffer.extend(payload)
                if fin:
                    return True
                continue
            if opcode == 0x0:
                self._read_buffer.extend(payload)
                if fin:
                    return True
                continue
            return False


def _read_http_head(sock, *, limit: int = 65536) -> tuple[str, dict[str, str], bytes]:
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("http peer closed")
        raw.extend(chunk)
        if len(raw) > limit:
            raise ConnectionError("http header too large")
    head, _, leftover = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    request_line = lines[0].split(" ")
    if len(request_line) < 3:
        raise ConnectionError("bad HTTP request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return request_line[0].upper(), headers, bytes(leftover)


def _websocket_upgrade(
    sock, expected_path: str, *, leftover: bytes = b""
) -> WebSocketStream:
    raw = bytearray(leftover)
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("websocket peer closed")
        raw.extend(chunk)
        if len(raw) > 65536:
            raise ConnectionError("websocket header too large")
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3 or parts[0].upper() != "GET":
        raise ConnectionError("websocket expects GET")
    target = urlsplit(parts[1]).path
    if expected_path and target != expected_path:
        raise ConnectionError(f"websocket path {target!r} does not match {expected_path!r}")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    if "websocket" not in headers.get("upgrade", "").lower():
        raise ConnectionError("missing websocket upgrade")
    if "upgrade" not in headers.get("connection", "").lower():
        raise ConnectionError("missing connection upgrade")
    if headers.get("sec-websocket-version") != "13":
        raise ConnectionError("unsupported websocket version")
    key = headers.get("sec-websocket-key", "")
    if not key:
        raise ConnectionError("missing websocket key")
    accept = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    ).decode("ascii")
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "Server: nginx\r\n\r\n"
    )
    sock.sendall(response.encode("ascii"))
    return WebSocketStream(sock, leftover=rest)


# ---------------------------------------------------------------------------
# HTTP long-poll support
# ---------------------------------------------------------------------------
def _http_response(sock, status: int, body: bytes, *, content_type: str = "application/json") -> None:
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
              409: "Conflict", 413: "Payload Too Large", 503: "Service Unavailable"}.get(status, "Error")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Server: nginx\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    sock.sendall(head.encode("ascii") + body)


def _read_http_request(reader, *, max_body: int = MAX_HTTP_BODY):
    line = reader.readline(65536)
    if not line:
        return None
    parts = line.decode("iso-8859-1").strip().split(" ")
    if len(parts) < 3:
        raise ConnectionError("bad HTTP request line")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    while True:
        header = reader.readline(65536)
        if not header:
            raise ConnectionError("http headers truncated")
        if header in (b"\r\n", b"\n"):
            break
        if b":" in header:
            name, value = header.split(b":", 1)
            headers[name.decode("iso-8859-1").strip().lower()] = value.decode(
                "iso-8859-1"
            ).strip()
    length = int(headers.get("content-length") or 0)
    if length > max_body:
        raise ValueError("http body too large")
    body = reader.read(length) if length else b""
    if len(body) < length:
        raise ConnectionError("http body truncated")
    return method, urlsplit(target).path, headers, body


class HttpsSession:
    """Bind one long-poll probe to the common framed ProbeConnection."""

    def __init__(self, listener: "ReverseListener", probe_id: str, parent_id: str | None,
                 remote: str):
        self.listener = listener
        self.probe_id = probe_id
        self.parent_id = parent_id
        self.remote = remote
        self.created_at = time.time()
        self.last_activity = time.time()
        self._condition = threading.Condition()
        self._outbox = bytearray()
        self._closed = False
        self._error: str | None = None
        self.server_sock, self.adapter_sock = socket.socketpair()
        self.server_sock.settimeout(None)
        self.adapter_sock.settimeout(None)
        self.probe = ProbeConnection.from_socket(
            self.server_sock, listener.token, timeout=listener.timeout,
            max_pending=listener.max_pending, remote=remote,
            on_audit=listener._forward_audit,
        )
        self._handshake_thread = threading.Thread(
            target=self._handshake, name="reverse-https-handshake", daemon=True
        )
        self._reader_thread = threading.Thread(
            target=self._adapter_reader, name="reverse-https-reader", daemon=True
        )

    def start(self) -> None:
        self._reader_thread.start()
        self._handshake_thread.start()

    def _handshake(self) -> None:
        try:
            self.probe.start()
        except Exception as exc:
            self._error = str(exc)
            self.listener._audit("https.auth_failed", {"probe_id": self.probe_id,
                                                       "remote": self.remote,
                                                       "error": str(exc)})
            self.close()
            return
        if self.probe.probe_id and self.probe.probe_id != self.probe_id:
            self._error = "probe_id mismatch"
            self.close()
            return
        self.listener._register_probe(self.probe, self.remote, "https")

    def _adapter_reader(self) -> None:
        try:
            while not self._closed:
                chunk = self.adapter_sock.recv(65536)
                if not chunk:
                    break
                with self._condition:
                    if len(self._outbox) + len(chunk) > MAX_HTTP_BODY:
                        self._closed = True
                        self._condition.notify_all()
                        break
                    self._outbox.extend(chunk)
                    self._condition.notify_all()
        except OSError:
            pass
        finally:
            with self._condition:
                self._closed = True
                self._condition.notify_all()

    def poll(self, wait: float) -> bytes:
        if self._closed:
            raise ReverseChannelError("https session is closed", code="disconnected")
        deadline = time.time() + max(0.1, wait)
        with self._condition:
            while not self._outbox and not self._closed:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                self._condition.wait(min(remaining, 1.0))
            data = bytes(self._outbox)
            self._outbox.clear()
        self.last_activity = time.time()
        return data

    def send(self, data: bytes) -> None:
        if self._closed:
            raise ReverseChannelError("https session is closed", code="disconnected")
        self.adapter_sock.sendall(data)
        self.last_activity = time.time()

    def close(self) -> None:
        if self._closed and self.adapter_sock.fileno() < 0:
            return
        self._closed = True
        with self._condition:
            self._condition.notify_all()
        for sock in (self.adapter_sock, self.server_sock):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        try:
            self.probe.close(cleanup=False, timeout=1.0)
        except Exception:
            pass

    def status(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "parent_id": self.parent_id,
            "remote": self.remote,
            "transport": "https",
            "connected_at": self.created_at,
            "last_seen": self.last_activity,
            "online": not self._closed,
            "error": self._error,
        }


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------
class ReverseListener:
    """One encrypted listener accepting probe-initiated sessions."""

    def __init__(
        self,
        token: str,
        *,
        bind: str = "0.0.0.0",
        port: int = 9443,
        timeout: float = 30.0,
        home: str | Path | None = None,
        workspace: str = "local-lab",
        control: bool = True,
        max_probes: int = 0,
        max_pending: int = 64,
        ping_interval: float = 15.0,
        idle_timeout: float = 60.0,
        transport: str = "tls",
        lab_plaintext: bool = False,
        tls_material: dict[str, Any] | None = None,
        tls_dir: str | Path | None = None,
        tls_hosts: Sequence[str] = (),
        wss_path: str = "/ws",
        poll_path: str = "/v1/probe/poll",
        result_path: str = "/v1/probe/result",
        webtransport_path: str = "/inkblade/wt",
        masque_path: str = "/.well-known/masque/udp",
        fallback_transport: str = "",
        user_agent: str = "",
        on_probe: Callable[[dict[str, Any]], None] | None = None,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
    ):
        if not token:
            raise ReverseChannelError("empty probe token")
        if transport not in ENCRYPTED_TRANSPORTS and transport != "tcp":
            raise ReverseChannelError(f"unsupported transport {transport!r}")
        if transport == "tcp" and not lab_plaintext:
            raise ReverseChannelError(
                "plaintext transport is lab-only; omit --transport tcp",
                code="plaintext_forbidden",
            )
        if fallback_transport not in ("", "none") + FALLBACK_TRANSPORTS:
            raise ReverseChannelError(
                f"unsupported fallback transport {fallback_transport!r}",
                code="invalid_fallback",
            )
        if fallback_transport == "none":
            fallback_transport = ""
        if transport in QUIC_TRANSPORTS and not fallback_transport:
            # QUIC family transports require UDP.  Encrypted TCP on the same
            # port is the documented fallback and is on by default.
            fallback_transport = "tls"
        if transport not in QUIC_TRANSPORTS:
            fallback_transport = ""
        self.token = token
        self.bind = bind
        self.port = int(port)
        self.timeout = float(timeout)
        self.home = str(home) if home is not None else ""
        self.workspace = workspace
        self.on_probe = on_probe
        self.on_audit = on_audit
        self.max_probes = int(max_probes or 0)
        self.max_pending = max(1, int(max_pending))
        self.ping_interval = max(0.0, float(ping_interval))
        self.idle_timeout = max(0.0, float(idle_timeout))
        self.transport = transport
        self.wss_path = wss_path or "/ws"
        self.poll_path = poll_path or "/v1/probe/poll"
        self.result_path = result_path or "/v1/probe/result"
        self.webtransport_path = webtransport_path or "/inkblade/wt"
        self.masque_path = masque_path or "/.well-known/masque/udp"
        self.fallback_transport = fallback_transport
        self.user_agent = user_agent
        self._listener: socket.socket | None = None
        self._fallback_listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._fallback_thread: threading.Thread | None = None
        self._quic_server = None
        self._quic_error = ""
        self.fallback_port = 0
        self._maintenance_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._stopped = False
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._records: dict[str, dict[str, Any]] = {}
        self._connections: dict[str, ProbeConnection] = {}
        self._https: dict[str, HttpsSession] = {}
        self._threads: list[threading.Thread] = []
        self._ping_threads: list[threading.Thread] = []
        self.auth_failures = 0
        self.errors: deque[str] = deque(maxlen=200)
        self.started_at = time.time()
        self._last_state_write = 0.0
        self._control: "ReverseControl | None" = None
        self._control_enabled = bool(control)
        self._paths = reverse_paths(self.home, workspace) if self.home else None
        self._tls: dict[str, Any] | None = None
        self._tls_context: ssl.SSLContext | None = None
        if self.transport in ENCRYPTED_TRANSPORTS:
            self._tls_context = self._prepare_tls(tls_material, tls_dir, tls_hosts)

    def _prepare_tls(self, material, tls_dir, hosts) -> ssl.SSLContext:
        if material is None:
            directory = tls_dir or (
                str(self._paths["tls"]) if self._paths else
                str(Path.home() / ".inkblade" / "reverse-tls")
            )
            material = ensure_tls_material(directory, hosts=hosts)
        self._tls = dict(material)
        return tls_context(material)

    # ------------------------------------------------------------ lifecycle
    def start(self) -> "ReverseListener":
        if self.transport in QUIC_TRANSPORTS:
            self._start_quic()
        else:
            listener = self._bind_tcp(self.port)
            self._listener = listener
            self.port = int(listener.getsockname()[1])
            self._accept_thread = threading.Thread(
                target=self._accept_loop, name="reverse-accept", daemon=True
            )
            self._accept_thread.start()
        if self.ping_interval or self.idle_timeout:
            self._maintenance_thread = threading.Thread(
                target=self._maintenance_loop, name="reverse-maintenance", daemon=True
            )
            self._maintenance_thread.start()
        if self._control_enabled:
            self._control = ReverseControl(self)
            self._control.start()
        self._write_state()
        return self

    @property
    def address(self) -> str:
        suffix = "/udp" if self.transport in QUIC_TRANSPORTS else ""
        return f"{self.bind}:{self.port}{suffix}"

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def _bind_tcp(self, port: int) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind, int(port)))
        listener.listen(128)
        listener.settimeout(0.25)
        return listener

    def _start_quic(self) -> None:
        from .quictransport import QuicTransportError, QuicTransportServer

        assert self._tls is not None
        server = QuicTransportServer(
            self,
            mode=self.transport,
            bind=self.bind,
            port=self.port,
            tls_material=self._tls,
            webtransport_path=self.webtransport_path,
            masque_path=self.masque_path,
            idle_timeout=max(30.0, float(self.idle_timeout or 60.0) * 2),
        )
        try:
            server.start()
            self._quic_server = server
            self.port = server.port
            self._audit("reverse.quic.listening", {
                "mode": self.transport, "bind": self.bind, "port": self.port,
            })
        except QuicTransportError as exc:
            self._quic_error = f"{exc.code}: {exc}"
            self.errors.append(f"quic: {exc}")
            if exc.code in ("udp-blocked", "quic_start_failed", "quic_start_timeout"):
                server.udp_blocked = True
            self._audit("reverse.quic.blocked", {
                "mode": self.transport, "bind": self.bind,
                "port": self.port, "error": str(exc),
            })
            if not self.fallback_transport:
                raise
        if self.fallback_transport:
            try:
                listener = self._bind_tcp(self.port)
            except OSError as exc:
                self.errors.append(f"fallback bind {self.bind}:{self.port}: {exc}")
                self._audit("reverse.fallback.failed", {
                    "transport": self.fallback_transport,
                    "bind": self.bind, "port": self.port, "error": str(exc),
                })
                return
            self._fallback_listener = listener
            self.fallback_port = int(listener.getsockname()[1])
            if not self._quic_server:
                # UDP was blocked at the controller: the TCP listener is the
                # only usable path, so keep the advertised port consistent.
                self.port = self.fallback_port
            self._fallback_thread = threading.Thread(
                target=self._accept_loop_for,
                args=(listener, self._handle_fallback_connection, "reverse-fallback"),
                name="reverse-fallback", daemon=True,
            )
            self._fallback_thread.start()
            self._audit("reverse.fallback.listening", {
                "transport": self.fallback_transport,
                "bind": self.bind, "port": self.fallback_port,
            })

    def _accept_loop(self) -> None:
        target = self._handle_tls if self.transport in TRANSPORTS else self._handle_plain
        self._accept_loop_for(self._listener, target, f"reverse-{self.transport}")

    def _accept_loop_for(self, listener, handler, name: str) -> None:
        while not self._stop.is_set():
            if listener is None:
                break
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(None)
            thread = threading.Thread(
                target=handler, args=(client, address), name=name, daemon=True
            )
            with self._lock:
                self._threads.append(thread)
            thread.start()

    def _handle_fallback_connection(self, client, address) -> None:
        try:
            assert self._tls_context is not None
            stream = self._tls_context.wrap_socket(client, server_side=True)
        except Exception as exc:
            self.auth_failures += 1
            self.errors.append(f"fallback tls handshake {address}: {exc}")
            self._audit("reverse.fallback.tls_failed", {
                "remote": str(address), "error": str(exc),
            })
            try:
                client.close()
            except OSError:
                pass
            return
        transport = self.fallback_transport or "tls"
        if transport == "wss":
            try:
                stream = _websocket_upgrade(stream, self.wss_path)
            except Exception as exc:
                self.auth_failures += 1
                self.errors.append(f"fallback wss upgrade {address}: {exc}")
                self._audit("reverse.fallback.wss_failed", {
                    "remote": str(address), "error": str(exc),
                })
                try:
                    stream.close()
                except OSError:
                    pass
                return
        self._handle_connection(stream, address, transport)

    def _handle_plain(self, client, address) -> None:
        self._handle_connection(client, address, "tcp")

    def _handle_tls(self, client, address) -> None:
        try:
            assert self._tls_context is not None
            stream = self._tls_context.wrap_socket(client, server_side=True)
        except Exception as exc:
            self.auth_failures += 1
            self.errors.append(f"tls handshake {address}: {exc}")
            self._audit("reverse.tls_failed", {"remote": str(address), "error": str(exc)})
            try:
                client.close()
            except OSError:
                pass
            return
        if self.transport == "tls":
            self._handle_connection(stream, address, "tls")
            return
        if self.transport == "wss":
            try:
                ws = _websocket_upgrade(stream, self.wss_path)
            except Exception as exc:
                self.auth_failures += 1
                self.errors.append(f"wss upgrade {address}: {exc}")
                self._audit("reverse.wss_failed", {"remote": str(address), "error": str(exc)})
                try:
                    stream.close()
                except OSError:
                    pass
                return
            self._handle_connection(ws, address, "wss")
            return
        if self.transport == "https":
            self._handle_https_connection(stream, address)
            return
        try:
            stream.close()
        except OSError:
            pass

    def _handle_connection(self, client, address, transport: str) -> None:
        remote = f"{address[0]}:{address[1]}"
        probe = ProbeConnection.from_socket(
            client, self.token, timeout=self.timeout,
            on_audit=self._forward_audit, remote=remote,
            max_pending=self.max_pending,
        )
        try:
            probe.start()
        except Exception as exc:
            with self._condition:
                self.auth_failures += 1
                self.errors.append(f"{remote}: {exc}")
                self._condition.notify_all()
            self._audit("reverse.auth_failed",
                        {"remote": remote, "transport": transport, "error": str(exc)})
            try:
                probe.close(cleanup=False, timeout=1.0)
            except Exception:
                pass
            return
        self._register_probe(probe, remote, transport)

    def _register_probe(self, probe: ProbeConnection, remote: str, transport: str) -> None:
        probe_id = probe.probe_id or f"reverse-{secrets.token_hex(4)}"
        probe.probe_id = probe_id
        with self._condition:
            online = sum(1 for row in self._records.values()
                         if row.get("status") == "online")
            if self.max_probes and online >= self.max_probes \
                    and probe_id not in self._records:
                self._condition.notify_all()
                self._audit("reverse.limit", {"probe_id": probe_id,
                                              "max_probes": self.max_probes})
                try:
                    probe.close(cleanup=False, timeout=1.0)
                except Exception:
                    pass
                return
            previous = self._connections.get(probe_id)
            replaced = previous is not None and previous is not probe
            record = {
                "probe_id": probe_id,
                "parent_id": probe.parent_id,
                "remote": remote,
                "transport": transport,
                "fallback": bool(getattr(probe, "fallback_from", "")),
                "fallback_from": getattr(probe, "fallback_from", ""),
                "read_only": bool(probe.read_only),
                "caps": list(probe.caps),
                "version": probe.version,
                "connected_at": time.time(),
                "last_seen": time.time(),
                "status": "online",
                "workspace": self.workspace,
                "replaced": replaced,
            }
            self._records[probe_id] = record
            self._connections[probe_id] = probe
            self._condition.notify_all()
        self._write_state()
        if previous is not None and previous is not probe:
            try:
                previous.close()
            except Exception:
                pass
        self._register_store(record)
        self._write_state()
        self._audit("reverse.registered", {
            "probe_id": probe_id, "parent_id": probe.parent_id,
            "remote": remote, "transport": transport,
            "read_only": probe.read_only, "replaced": replaced,
            "fallback_from": getattr(probe, "fallback_from", ""),
        })
        if getattr(probe, "fallback_from", ""):
            self._audit("reverse.fallback", {
                "probe_id": probe_id, "from": probe.fallback_from,
                "to": transport,
            })
        if self.on_probe:
            try:
                self.on_probe(dict(record))
            except Exception as exc:
                self.errors.append(f"on_probe: {exc}")

    def _https_session(self, probe_id: str, parent_id: str | None, remote: str) -> HttpsSession:
        if not _SAFE_ID.match(probe_id or ""):
            raise ReverseChannelError("invalid probe id", code="invalid_probe_id")
        with self._condition:
            session = self._https.get(probe_id)
            if session is not None and not session._closed:
                return session
            if session is not None:
                self._https.pop(probe_id, None)
            online = sum(1 for row in self._records.values()
                         if row.get("status") == "online")
            if self.max_probes and online >= self.max_probes:
                raise ReverseChannelError("probe limit reached", code="max_probes")
            session = HttpsSession(self, probe_id, parent_id, remote)
            self._https[probe_id] = session
        session.start()
        self._audit("https.session", {"probe_id": probe_id, "remote": remote})
        return session

    def _handle_https_connection(self, stream, address) -> None:
        remote = f"{address[0]}:{address[1]}"
        try:
            stream.settimeout(90)
            reader = stream.makefile("rb")
            while not self._stop.is_set():
                try:
                    request = _read_http_request(reader)
                except (ConnectionError, OSError, ValueError):
                    break
                if request is None:
                    break
                method, path, headers, body = request
                if path == self.poll_path:
                    if method != "POST":
                        _http_response(stream, 405, b'{"error":"method"}')
                        continue
                    try:
                        payload = json.loads(body.decode("utf-8") or "{}")
                        probe_id = str(payload.get("probe_id") or "")
                        parent_id = payload.get("parent_id")
                        session = self._https_session(probe_id, parent_id, remote)
                        data = session.poll(wait=27.0)
                        self._touch(probe_id)
                        response = {"frames": [base64.b64encode(data).decode()] if data else []}
                        _http_response(stream, 200, json.dumps(response).encode("utf-8"))
                    except ReverseChannelError as exc:
                        code = 409 if exc.code == "max_probes" else 400
                        _http_response(stream, code, json.dumps(
                            {"error": str(exc), "code": exc.code}).encode("utf-8"))
                    except Exception as exc:
                        _http_response(stream, 400, json.dumps(
                            {"error": str(exc)}).encode("utf-8"))
                elif path == self.result_path:
                    if method != "POST":
                        _http_response(stream, 405, b'{"error":"method"}')
                        continue
                    try:
                        payload = json.loads(body.decode("utf-8") or "{}")
                        probe_id = str(payload.get("probe_id") or "")
                        session = self._https.get(probe_id)
                        if session is None or session._closed:
                            # The probe may send its `hello` before its first
                            # poll.  Create the session on result too, so the
                            # controller-side ProbeConnection can authenticate.
                            session = self._https_session(
                                probe_id, payload.get("parent_id"), remote
                            )
                        for encoded in payload.get("frames") or []:
                            session.send(base64.b64decode(encoded))
                        self._touch(probe_id)
                        _http_response(stream, 200, b'{"ok":true}')
                    except Exception as exc:
                        _http_response(stream, 400, json.dumps(
                            {"error": str(exc)}).encode("utf-8"))
                else:
                    _http_response(stream, 404, b'{"error":"not found"}')
                if headers.get("connection", "").lower() == "close":
                    break
            try:
                reader.close()
            except OSError:
                pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def wait_for_probe(
        self, timeout: float | None = None, probe_id: str | None = None
    ) -> dict[str, Any]:
        deadline = None if timeout is None else time.time() + float(timeout)
        found: dict[str, Any] | None = None
        with self._condition:
            while found is None:
                for record in self._records.values():
                    if probe_id is not None and record["probe_id"] != probe_id:
                        continue
                    if record.get("status") == "online":
                        found = dict(record)
                        break
                if found is not None:
                    break
                remaining = None if deadline is None else deadline - time.time()
                if remaining is not None and remaining <= 0:
                    raise ProbeTimeout(f"no reverse probe registered within {timeout}s")
                if not self._condition.wait(remaining if remaining is not None else 0.5):
                    if deadline is None:
                        continue
                    if time.time() >= deadline:
                        raise ProbeTimeout(
                            f"no reverse probe registered within {timeout}s"
                        )
        assert found is not None
        self._write_state()
        return found

    def connection(self, probe_id: str) -> ProbeConnection:
        with self._lock:
            probe = self._connections.get(probe_id)
        if probe is None:
            raise ReverseChannelError(
                f"reverse probe {probe_id!r} is not connected", code="probe_not_found"
            )
        return probe

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(record) for record in self._records.values()]
        rows.sort(key=lambda row: (row.get("parent_id") or "", row.get("connected_at") or 0))
        return rows

    def online_count(self) -> int:
        with self._lock:
            return sum(1 for record in self._records.values()
                       if record.get("status") == "online")

    def request(
        self, probe_id: str, op: str, args: dict[str, Any] | None = None,
        *, timeout: float | None = None,
    ) -> dict[str, Any]:
        probe = self.connection(probe_id)
        result = probe.request(op, args or {}, timeout=timeout)
        self._touch(probe_id)
        return result

    def collect(self, probe_id: str, *, timeout: float | None = None) -> dict[str, Any]:
        return self.request(probe_id, "collect", {}, timeout=timeout)

    def perform_exec(
        self, probe_id: str, argv: Sequence[str], *, timeout_ms: int | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        probe = self.connection(probe_id)
        result = probe.exec(argv, timeout_ms=timeout_ms, timeout=timeout)
        self._touch(probe_id)
        return result

    def exec(self, probe_id: str, argv: Sequence[str], **kwargs) -> dict[str, Any]:
        return self.perform_exec(probe_id, argv, **kwargs)

    def close_probe(self, probe_id: str) -> dict[str, Any]:
        with self._condition:
            probe = self._connections.pop(probe_id, None)
            session = self._https.pop(probe_id, None)
            record = self._records.get(probe_id)
            if record is not None:
                record["status"] = "closed"
                record["last_seen"] = time.time()
                self._condition.notify_all()
        if session is not None:
            session.close()
        if probe is not None:
            try:
                probe.close(timeout=0.5)
            except Exception:
                pass
        self._mark_offline(probe_id)
        self._write_state()
        return {"probe_id": probe_id, "closed": probe is not None or session is not None}

    def _drop_probe(self, probe_id: str, reason: str) -> None:
        with self._condition:
            probe = self._connections.pop(probe_id, None)
            session = self._https.pop(probe_id, None)
            record = self._records.get(probe_id)
            if record is not None:
                record["status"] = "offline"
                record["last_seen"] = time.time()
                record["closed_reason"] = reason
            self._condition.notify_all()
        if session is not None:
            session.close()
        if probe is not None:
            try:
                probe.close(cleanup=False, timeout=1.0)
            except Exception:
                pass
        self._mark_offline(probe_id)
        self._audit("reverse.dropped", {"probe_id": probe_id, "reason": reason})

    def _maintenance_loop(self) -> None:
        last_state = 0.0
        while not self._stop.is_set():
            now = time.time()
            rows = self.records()
            for record in rows:
                probe_id = record["probe_id"]
                if record.get("status") != "online":
                    continue
                last = float(record.get("last_seen") or 0)
                if self.idle_timeout and now - last > self.idle_timeout:
                    self._drop_probe(probe_id, f"idle_timeout>{self.idle_timeout}s")
                    continue
                if self.ping_interval and now - last >= self.ping_interval:
                    thread = threading.Thread(
                        target=self._heartbeat, args=(probe_id,),
                        name="reverse-ping", daemon=True,
                    )
                    with self._lock:
                        self._ping_threads.append(thread)
                    thread.start()
            if now - last_state >= 5.0:
                self._write_state()
                last_state = now
            time.sleep(0.5)

    def _heartbeat(self, probe_id: str) -> None:
        try:
            self.request(probe_id, "ping", {}, timeout=5.0)
        except Exception as exc:
            self._drop_probe(probe_id, f"heartbeat: {exc}")

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._stop.set()
        if self._control is not None:
            self._control.stop()
        if self._quic_server is not None:
            try:
                self._quic_server.stop()
            except Exception:
                pass
        for extra in (self._fallback_listener,):
            if extra is not None:
                try:
                    extra.close()
                except OSError:
                    pass
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.0)
        if self._fallback_thread is not None:
            self._fallback_thread.join(timeout=1.0)
        if self._maintenance_thread is not None:
            self._maintenance_thread.join(timeout=1.5)
        with self._condition:
            probes = list(self._connections.values())
            sessions = list(self._https.values())
            self._connections.clear()
            self._https.clear()
            for record in self._records.values():
                record["status"] = "offline"
                record["last_seen"] = time.time()
            self._condition.notify_all()
        for session in sessions:
            try:
                session.close()
            except Exception:
                pass
        for probe in probes:
            try:
                probe.close(timeout=0.5)
            except Exception:
                pass
        for thread in list(self._threads) + list(self._ping_threads):
            if thread is not threading.current_thread():
                thread.join(timeout=0.2)
        with self._lock:
            probe_ids = list(self._records)
        for probe_id in probe_ids:
            self._mark_offline(probe_id)
        self._write_state()
        self._audit("reverse.stopped", {"probes": len(probes)})

    # ------------------------------------------------------------ state
    def status(self) -> dict[str, Any]:
        control = self._control.describe() if self._control else None
        tls_info = None
        if self._tls:
            tls_info = {
                "ca_file": self._tls.get("ca_file"),
                "cert_file": self._tls.get("cert_file"),
                "pin": self._tls.get("pin"),
                "hosts": self._tls.get("hosts"),
            }
        return {
            "schema": STATE_SCHEMA,
            "pid": os.getpid(),
            "bind": self.bind,
            "port": self.port,
            "address": self.address,
            "transport": self.transport,
            "tls": tls_info,
            "fallback_transport": self.fallback_transport or None,
            "fallback_port": self.fallback_port or None,
            "quic": self._quic_server.status() if self._quic_server else None,
            "quic_error": self._quic_error or None,
            "workspace": self.workspace,
            "started_at": self.started_at,
            "running": not self._stop.is_set(),
            "control": control,
            "probes": self.records(),
            "auth_failures": self.auth_failures,
            "errors": list(self.errors)[-20:],
        }

    def _write_state(self) -> None:
        if not self._paths:
            return
        try:
            document = self.status()
            _secure_write(
                self._paths["probes"],
                json.dumps(document, ensure_ascii=False, indent=2, default=str) + "\n",
            )
        except Exception as exc:
            self.errors.append(f"state: {exc}")

    def _register_store(self, record: dict[str, Any]) -> None:
        if not self.home:
            return
        try:
            from .core.evidence import EvidenceStore
            from .core.probes import ProbeRegistry

            store = EvidenceStore(Path(self.home), workspace=self.workspace)
            ProbeRegistry(store).register(
                record["probe_id"],
                parent_id=record.get("parent_id"),
                caps=record.get("caps") or [],
                status="online",
                read_only=bool(record.get("read_only", True)),
                meta={
                    "transport": record.get("transport", ""),
                    "remote": record.get("remote", ""),
                    "version": record.get("version", ""),
                },
            )
        except Exception as exc:
            self.errors.append(f"registry: {exc}")

    def _mark_offline(self, probe_id: str) -> None:
        if not self.home:
            return
        try:
            from .core.evidence import EvidenceStore
            from .core.probes import ProbeRegistry

            store = EvidenceStore(Path(self.home), workspace=self.workspace)
            ProbeRegistry(store).mark_offline(probe_id)
        except Exception as exc:
            self.errors.append(f"registry offline: {exc}")

    def _touch(self, probe_id: str) -> None:
        with self._lock:
            record = self._records.get(probe_id)
            if record is not None:
                record["last_seen"] = time.time()

    def _forward_audit(self, event: dict[str, Any]) -> None:
        if self.on_audit:
            try:
                self.on_audit(event)
            except Exception:
                pass

    def _audit(self, event: str, detail: dict[str, Any]) -> None:
        self._forward_audit({"ts": time.time(), "event": event, **detail})


# ---------------------------------------------------------------------------
# Control port
# ---------------------------------------------------------------------------
class ReverseControl:
    def __init__(self, listener: ReverseListener):
        self.listener = listener
        self.host = "127.0.0.1"
        self.port = 0
        self.token = secrets.token_urlsafe(24)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._handlers: list[threading.Thread] = []
        self._stop = threading.Event()
        self.started_at = time.time()

    def start(self) -> "ReverseControl":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, 0))
        sock.listen(16)
        sock.settimeout(0.25)
        self._sock = sock
        self.port = int(sock.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop,
                                        name="reverse-control", daemon=True)
        self._thread.start()
        self._write_file()
        return self

    def describe(self, *, include_token: bool = False) -> dict[str, Any]:
        document = {"host": self.host, "port": self.port, "pid": os.getpid()}
        if include_token:
            document["token"] = self.token
        return document

    def _write_file(self) -> None:
        paths = self.listener._paths
        if not paths:
            return
        document = {
            "schema": CONTROL_SCHEMA,
            "workspace": self.listener.workspace,
            "started_at": self.started_at,
            **self.describe(include_token=True),
        }
        _secure_write(paths["control"],
                      json.dumps(document, ensure_ascii=False, indent=2) + "\n")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                break
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(client,),
                                      name="reverse-control-client", daemon=True)
            self._handlers.append(thread)
            thread.start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(30)
            reader = client.makefile("rb")
            frame = read_frame(reader)
            if not frame:
                return
            if not hmac.compare_digest(str(frame.get("token") or ""), self.token):
                client.sendall(encode_frame({
                    "ok": False,
                    "error": {"code": "auth_failed", "message": "invalid control token"},
                }))
                return
            try:
                data = self._dispatch(frame)
                client.sendall(encode_frame({"ok": True, "data": data}))
            except Exception as exc:
                client.sendall(encode_frame({
                    "ok": False,
                    "error": {"code": getattr(exc, "code", "control_error"),
                              "message": str(exc)},
                }))
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _dispatch(self, frame: dict[str, Any]) -> Any:
        op = str(frame.get("op") or "")
        probe_id = frame.get("probe_id")
        if not probe_id:
            rows = self.listener.records()
            if len(rows) == 1:
                probe_id = rows[0]["probe_id"]
            elif not rows:
                raise ReverseChannelError("no reverse probe connected",
                                          code="probe_not_found")
            else:
                raise ReverseChannelError("multiple probes connected; pass probe_id",
                                          code="probe_required")
        probe_id = str(probe_id)
        if op == "list":
            return {"probes": self.listener.records()}
        if op == "status":
            return self.listener.status()
        if op == "request":
            op_name = str(frame.get("op_name") or "")
            if not op_name:
                raise ReverseChannelError("request requires op_name")
            args = frame.get("args") if isinstance(frame.get("args"), dict) else {}
            timeout = frame.get("timeout")
            return self.listener.request(
                probe_id, op_name, args,
                timeout=float(timeout) if timeout is not None else None,
            )
        if op == "collect":
            return self.listener.collect(probe_id)
        if op == "exec":
            argv = [str(item) for item in frame.get("argv") or []]
            timeout_ms = frame.get("timeout_ms")
            return self.listener.perform_exec(
                probe_id, argv,
                timeout_ms=int(timeout_ms) if timeout_ms is not None else None,
            )
        if op == "close":
            return self.listener.close_probe(probe_id)
        if op == "shutdown":
            threading.Thread(target=self.listener.stop, daemon=True).start()
            return {"stopping": True}
        raise ReverseChannelError(f"unknown control op {op}", code="unknown_op")

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)
        for thread in list(self._handlers):
            if thread is not threading.current_thread():
                thread.join(timeout=0.2)


def control_request(
    home: str | Path,
    workspace: str = "local-lab",
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 30.0,
) -> Any:
    paths = reverse_paths(home, workspace)
    try:
        document = json.loads(paths["control"].read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReverseChannelError(
            f"reverse control is not available ({paths['control']}): {exc}",
            code="control_unavailable",
        ) from exc
    sock = socket.create_connection(
        (document.get("host", "127.0.0.1"), int(document["port"])), timeout=timeout
    )
    try:
        sock.settimeout(timeout)
        sock.sendall(encode_frame({**(payload or {}), "token": document.get("token", "")}))
        response = read_frame(sock.makefile("rb"))
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not response:
        raise ReverseChannelError("control port closed without a response")
    if not response.get("ok"):
        error = response.get("error") or {}
        raise ReverseChannelError(
            str(error.get("message") or "control request failed"),
            code=str(error.get("code") or "control_error"),
        )
    return response.get("data")


# ---------------------------------------------------------------------------
# Child deployment
# ---------------------------------------------------------------------------
def deploy_reverse_child(
    parent: ProbeConnection,
    binary: bytes,
    *,
    child_id: str,
    host: str,
    port: int,
    transport: str = "tls",
    sni: str = "",
    ca_file: str = "",
    pin: str = "",
    connect_timeout_ms: int = 10_000,
    remote_dirs: Sequence[str] = DEFAULT_REMOTE_DIRS,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Upload a child probe to the pod and ask the parent to start it reverse.

    ``/tmp`` is preferred; ``/dev/shm`` is the fallback.  If both writes fail
    with EROFS the error is ``read_only_rootfs``.  The controller writes
    nothing to the host; the upload lands in the target container.
    """
    if transport not in ENCRYPTED_TRANSPORTS:
        raise ReverseChannelError("child transport must be tls/wss/https/quic/"
                                  "webtransport/masque",
                                  code="invalid_transport")
    if not _SAFE_ID.match(child_id or ""):
        raise ReverseChannelError(
            "child_id must be a short alphanumeric id (., _, - allowed)",
            code="invalid_child_id",
        )
    if not host:
        raise ReverseChannelError("reverse host is required", code="invalid_reverse_target")
    if not (0 < int(port) <= 65535):
        raise ReverseChannelError("reverse port must be 1..65535",
                                  code="invalid_reverse_target")
    if not pin:
        raise ReverseChannelError("certificate pin is required for encrypted transports",
                                  code="missing_pin")
    digest = hashlib.sha256(binary).hexdigest()
    failures: list[dict[str, str]] = []
    uploaded: str | None = None
    for raw in remote_dirs or DEFAULT_REMOTE_DIRS:
        directory = str(raw).rstrip("/") or "/"
        path = f"{directory}/.inkblade-probe-child-{child_id}"
        try:
            parent.upload(path, binary, mode=0o700, timeout=timeout)
            uploaded = path
            break
        except Exception as exc:
            message = str(exc)
            failures.append({"path": path, "error": message})
            if _is_write_disabled(message):
                raise ReverseChannelError(
                    "parent probe is read-only; restart it with --allow-write "
                    "before deploying a child",
                    code="write_disabled", data={"attempts": failures},
                ) from exc
    if uploaded is None:
        read_only = bool(failures) and all(
            _is_read_only_error(item["error"]) for item in failures
        )
        raise ReverseChannelError(
            "could not write the child probe: "
            + ("the container root filesystem (and /dev/shm) is read-only; "
               "mount a writable emptyDir at /tmp or use an existing writable path"
               if read_only else "no writable upload directory"),
            code="read_only_rootfs" if read_only else "upload_failed",
            data={"attempts": failures},
        )
    reverse_args = {
        "host": host,
        "port": int(port),
        "transport": transport,
        "sni": sni or host,
        "ca_file": ca_file,
        "pin": pin,
        "connect_timeout_ms": int(connect_timeout_ms),
    }
    result = parent.spawn(
        None, binary_path=uploaded, remote_path=uploaded, probe_id=child_id,
        sha256=digest, reverse=reverse_args, timeout=timeout,
    )
    return {
        "probe_id": str(result.get("probe_id") or child_id),
        "parent_id": str(result.get("parent_id") or parent.probe_id),
        "child_id": child_id,
        "uploaded_path": uploaded,
        "remote_path": uploaded,
        "sha256": digest,
        "reverse": reverse_args,
        "transport": transport,
        "registered": bool(result.get("registered", True)),
        "spawn": result,
    }


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def _read_token(path: str | None) -> str:
    if not path:
        raise ReverseChannelError("--token-file is required", code="missing_token")
    file_path = Path(path)
    try:
        token = file_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ReverseChannelError(f"cannot read token file: {exc}",
                                  code="missing_token") from exc
    if not token:
        raise ReverseChannelError("token file is empty", code="missing_token")
    if os.name != "nt":
        try:
            mode = file_path.stat().st_mode & 0o777
            if mode & 0o077:
                raise ReverseChannelError(
                    f"token file {file_path} must be 0600 (mode {oct(mode)})",
                    code="token_permissions",
                )
        except OSError as exc:
            raise ReverseChannelError(f"cannot stat token file: {exc}",
                                      code="missing_token") from exc
    return token


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _run_action(listener: ReverseListener, probe_id: str, args) -> dict[str, Any] | None:
    op = getattr(args, "op", None)
    action = getattr(args, "exec_action", None)
    if op:
        try:
            payload = json.loads(getattr(args, "args_json", "{}") or "{}")
        except ValueError as exc:
            raise ReverseChannelError(f"--args is not JSON: {exc}",
                                      code="invalid_args") from exc
        if not isinstance(payload, dict):
            raise ReverseChannelError("--args must be a JSON object", code="invalid_args")
        return listener.request(probe_id, str(op), payload)
    if not action:
        return None
    if action == "collect":
        return listener.collect(probe_id)
    if action == "ping":
        return listener.request(probe_id, "ping", {})
    if action == "beacon":
        return listener.request(probe_id, "beacon", {})
    if action == "exec":
        argv = [str(item) for item in getattr(args, "argv", []) or []]
        if argv and argv[0] == "--":
            argv = argv[1:]
        if not argv:
            raise ReverseChannelError("--exec exec requires --argv", code="invalid_args")
        return listener.perform_exec(probe_id, argv)
    try:
        payload = json.loads(getattr(args, "args_json", "{}") or "{}")
    except ValueError as exc:
        raise ReverseChannelError(f"--args is not JSON: {exc}", code="invalid_args") from exc
    return listener.request(probe_id, str(action), payload if isinstance(payload, dict) else {})


def cli_listen(args, home: Path) -> int:
    try:
        token = _read_token(args.token_file)
        transport = str(getattr(args, "transport", "tls") or "tls")
        lab = bool(getattr(args, "lab_plaintext", False))
        if lab:
            if os.environ.get("INKBLADE_ALLOW_PLAINTEXT_LAB") != "1":
                raise ReverseChannelError(
                    "plaintext lab transport requires INKBLADE_ALLOW_PLAINTEXT_LAB=1",
                    code="plaintext_forbidden",
                )
            transport = "tcp"
        material = None
        tls_hosts = list(getattr(args, "tls_host", []) or [])
        if transport in ENCRYPTED_TRANSPORTS:
            if getattr(args, "tls_cert", None) or getattr(args, "tls_key", None):
                if not (args.tls_cert and args.tls_key and args.tls_ca):
                    raise ReverseChannelError(
                        "--tls-cert/--tls-key/--tls-ca must be provided together",
                        code="tls_material",
                    )
                material = {
                    "ca_file": args.tls_ca, "cert_file": args.tls_cert,
                    "key_file": args.tls_key,
                    "pin": _certificate_pin(Path(args.tls_cert)),
                    "hosts": tls_hosts, "generated": False,
                }
            else:
                directory = args.tls_dir or (
                    str(reverse_paths(home, args.workspace)["tls"])
                )
                hosts = list(tls_hosts) + ([args.sni] if getattr(args, "sni", None) else [])
                if args.bind not in ("0.0.0.0", "::"):
                    hosts.append(args.bind)
                material = ensure_tls_material(
                    directory, hosts=hosts, days=int(args.tls_days)
                )
        fallback = str(getattr(args, "fallback", "") or "")
        if not fallback and transport in QUIC_TRANSPORTS:
            fallback = "tls"
        listener = ReverseListener(
            token,
            bind=args.bind,
            port=int(args.port),
            timeout=float(args.timeout),
            home=home,
            workspace=args.workspace,
            control=not bool(getattr(args, "no_control", False)),
            max_probes=int(getattr(args, "max_probes", 0) or 0),
            max_pending=int(getattr(args, "max_pending", 64) or 64),
            ping_interval=float(getattr(args, "ping_interval", 15.0) or 0),
            idle_timeout=float(getattr(args, "idle_timeout", 60.0) or 0),
            transport=transport,
            lab_plaintext=lab,
            tls_material=material,
            tls_hosts=tls_hosts,
            wss_path=getattr(args, "wss_path", "/ws") or "/ws",
            poll_path=getattr(args, "poll_path", "/v1/probe/poll"),
            result_path=getattr(args, "result_path", "/v1/probe/result"),
            webtransport_path=getattr(args, "webtransport_path", "/inkblade/wt"),
            masque_path=getattr(args, "masque_path", "/.well-known/masque/udp"),
            fallback_transport=fallback,
            user_agent=getattr(args, "user_agent", "") or "",
        )
        listener.start()
    except (ChannelError, OSError, ValueError) as exc:
        print(f"inkblade channel listen: {exc}", file=__import__("sys").stderr)
        return 2
    startup = {
        "status": "listening",
        "address": listener.address,
        "transport": listener.transport,
        "plaintext_lab": listener.transport == "tcp",
        "workspace": args.workspace,
        "control": listener._control.describe() if listener._control else None,
        "probes_state": str(listener._paths["probes"]) if listener._paths else None,
        "tls": listener.status().get("tls"),
        "wss_path": listener.wss_path if listener.transport == "wss" else None,
        "poll_path": listener.poll_path if listener.transport == "https" else None,
        "result_path": listener.result_path if listener.transport == "https" else None,
        "fallback_transport": listener.fallback_transport or None,
        "fallback_port": listener.fallback_port or None,
        "quic": listener.status().get("quic"),
        "quic_error": listener.status().get("quic_error"),
        "webtransport_path": (
            listener.webtransport_path
            if listener.transport == "webtransport" else None
        ),
        "masque_path": (
            listener.masque_path if listener.transport == "masque" else None
        ),
        "udp_blocked": str(listener.status().get("quic_error") or "").startswith("udp-blocked"),
    }
    if args.json and not args.once:
        _print_json(startup)
    elif not args.once:
        print(f"reverse listener on {listener.address} "
              f"[{listener.transport.upper()}] (workspace {args.workspace})")
        if listener.transport == "tcp":
            print("WARNING: PLAINTEXT LAB TRANSPORT - not for product use")
        if startup.get("tls"):
            print(f"CA: {startup['tls']['ca_file']}")
            print(f"PIN: {startup['tls']['pin']}")
        if listener.fallback_transport:
            print(f"fallback: {listener.fallback_transport.upper()} on "
                  f"{listener.bind}:{listener.fallback_port} (same port as UDP)")
        if startup.get("quic_error"):
            print(f"QUIC WARNING: {startup['quic_error']}")
        if listener._control:
            print(f"control 127.0.0.1:{listener._control.port} (token in "
                  f"{listener._paths['control'] if listener._paths else 'control.json'})")
        print("waiting for probes: inkblade-probe reverse --transport "
              f"{listener.transport} --host <this-host> --port {listener.port} ...")
    code = 0
    try:
        if args.once:
            record = listener.wait_for_probe(timeout=float(args.timeout))
            result = _run_action(listener, record["probe_id"], args)
            output = {"probe": record}
            if result is not None:
                output["result"] = result
            _print_json(output)
        else:
            deadline = (time.time() + float(args.duration)
                        if getattr(args, "duration", 0) else None)
            while not listener.stopped:
                if deadline is not None and time.time() >= deadline:
                    break
                if args.max_probes and listener.online_count() >= int(args.max_probes):
                    time.sleep(0.3)
                    break
                time.sleep(0.2)
    except ProbeTimeout as exc:
        print(f"inkblade channel listen: {exc}", file=__import__("sys").stderr)
        code = 2
    except ChannelError as exc:
        print(f"inkblade channel listen: {exc}", file=__import__("sys").stderr)
        code = 1
    except KeyboardInterrupt:
        code = 0
    finally:
        listener.stop()
    return code


def cli_control_exec(args, home: Path) -> int:
    try:
        payload: dict[str, Any] = {
            "probe_id": getattr(args, "probe_id", None),
            "timeout": getattr(args, "timeout", 30),
        }
        op = str(getattr(args, "op", None) or "collect")
        if op == "exec":
            argv = list(getattr(args, "argv", []) or [])
            if argv and argv[0] == "--":
                argv = argv[1:]
            payload.update({"op": "exec", "argv": argv})
        else:
            try:
                values = json.loads(getattr(args, "args_json", "{}") or "{}")
            except ValueError as exc:
                raise ReverseChannelError(f"--args is not JSON: {exc}",
                                          code="invalid_args") from exc
            payload.update({"op": "request", "op_name": op,
                            "args": values if isinstance(values, dict) else {}})
        data = control_request(home, args.workspace, payload,
                               timeout=float(args.timeout))
    except (ChannelError, OSError, ValueError) as exc:
        print(f"inkblade channel exec: {exc}", file=__import__("sys").stderr)
        return 2
    _print_json(data)
    return 0
