#!/usr/bin/env python3
"""Stdlib fake probe for the probe-initiated reverse channel tests.

It connects out to a controller port, performs the real challenge-HMAC
handshake, and answers the framed JSON ops used by the reverse tests.  It is
test-only code and never ships in a release.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import random
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

MAX_FRAME = 8 * 1024 * 1024
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def encode(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def read_exact(stream, count: int) -> bytes | None:
    chunks = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            return None if not chunks else b"".join(chunks)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream) -> dict[str, Any] | None:
    header = read_exact(stream, 4)
    if not header or len(header) < 4:
        return None
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > MAX_FRAME:
        raise ValueError(f"bad frame length {length}")
    payload = read_exact(stream, length)
    if payload is None or len(payload) < length:
        return None
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("frame is not an object")
    return value


class _ClientFile:
    def __init__(self, stream, mode):
        self.stream = stream
        self.mode = mode

    def read(self, size=-1):
        return self.stream.read(size)

    def write(self, data):
        return self.stream.write(data)

    def flush(self):
        self.stream.flush()

    def close(self):
        return None


class _WSClientStream:
    """Client-side WebSocket byte stream (masked outbound frames)."""

    def __init__(self, sock, *, leftover=b""):
        self.sock = sock
        self._incoming = bytearray(leftover)
        self._read_buffer = bytearray()
        self._outgoing = bytearray()
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = False

    def settimeout(self, value):
        self.sock.settimeout(value)

    def makefile(self, mode="rb"):
        return _ClientFile(self, mode)

    def read(self, size=-1):
        if size < 0:
            size = 65536
        with self._read_lock:
            while len(self._read_buffer) < size:
                if not self._next():
                    break
            data = bytes(self._read_buffer[:size])
            del self._read_buffer[:size]
            return data

    def write(self, data):
        with self._write_lock:
            self._outgoing.extend(data)
        return len(data)

    def flush(self):
        with self._write_lock:
            if not self._outgoing:
                return
            payload = bytes(self._outgoing)
            self._outgoing.clear()
            self._send(0x2, payload)

    def shutdown(self, how):
        try:
            self.sock.shutdown(how)
        except OSError:
            pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._send(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _read(self, count):
        while len(self._incoming) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self._incoming.extend(chunk)
        data = bytes(self._incoming[:count])
        del self._incoming[:count]
        return data

    def _send(self, opcode, payload):
        mask = os.urandom(4)
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", length))
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(bytes(header) + mask + masked)

    def _next(self):
        header = self._read(2)
        fin = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        mask = self._read(4) if masked else b""
        payload = self._read(length) if length else b""
        if masked:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        if opcode == 0x8:
            return False
        if opcode == 0x9:
            self._send(0xA, payload)
            return True
        if opcode == 0xA:
            return True
        if opcode in (0x0, 0x2):
            self._read_buffer.extend(payload)
            return True if fin else True
        if opcode == 0x1:
            self._read_buffer.extend(payload.decode("utf-8", "replace").encode("utf-8"))
            return True
        return True


class _HttpsConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, *, context, server_hostname, timeout=35.0):
        super().__init__(host, port, context=context, timeout=timeout)
        self._server_hostname = server_hostname

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self._server_hostname
        )


class _HttpsClientStream:
    """Client-side HTTPS long-poll byte stream."""

    def __init__(self, host, port, context, *, probe_id, parent_id=None,
                 poll_path="/v1/probe/poll", result_path="/v1/probe/result",
                 user_agent="", pin="", sni=None, timeout=35.0):
        self.host = host
        self.port = int(port)
        self.context = context
        self.probe_id = probe_id
        self.parent_id = parent_id
        self.poll_path = poll_path
        self.result_path = result_path
        self.user_agent = user_agent
        self.pin = pin
        self.sni = sni or host
        self.timeout = timeout
        self._buffer = bytearray()
        self._outgoing = bytearray()
        self._lock = threading.Lock()
        self._closed = False
        self._request_count = 0

    def settimeout(self, value):
        self.timeout = float(value) if value else 35.0

    def makefile(self, mode="rb"):
        return _ClientFile(self, mode)

    def _check_pin(self, connection):
        if not self.pin:
            return
        der = connection.sock.getpeercert(binary_form=True)
        got = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(got, self.pin.lower().replace("sha256:", "")):
            raise ValueError(f"certificate pin mismatch: got {got}")

    def _post(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        connection = _HttpsConnection(
            self.host, self.port, context=self.context,
            server_hostname=self.sni, timeout=self.timeout + 10,
        )
        try:
            connection.request(
                "POST", path, body=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": self.user_agent or "Mozilla/5.0",
                    "Connection": "close",
                    "X-Request-Id": secrets.token_hex(8),
                },
            )
            response = connection.getresponse()
            self._check_pin(connection)
            raw = response.read(MAX_FRAME)
            if response.status != 200:
                raise ConnectionError(f"https {path}: {response.status} {raw[:200]!r}")
            return json.loads(raw.decode("utf-8") or "{}")
        finally:
            connection.close()

    def _poll(self):
        data = self._post(self.poll_path, {
            "probe_id": self.probe_id,
            "parent_id": self.parent_id,
            "transport": "https",
        })
        frames = data.get("frames") or []
        out = b"".join(base64.b64decode(item) for item in frames)
        return out

    def read(self, size=-1):
        if size < 0:
            size = 65536
        if self._closed:
            return b""
        with self._lock:
            while len(self._buffer) < size:
                try:
                    chunk = self._poll()
                except Exception:
                    self._closed = True
                    break
                if not chunk:
                    time.sleep(random.uniform(0.05, 0.4))
                    continue
                self._buffer.extend(chunk)
                if len(self._buffer) >= size:
                    break
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
            return data

    def write(self, data):
        with self._lock:
            self._outgoing.extend(data)
        return len(data)

    def flush(self):
        with self._lock:
            if not self._outgoing:
                return
            payload = bytes(self._outgoing)
            self._outgoing.clear()
        self._post(self.result_path, {
            "probe_id": self.probe_id,
            "parent_id": self.parent_id,
            "frames": [base64.b64encode(payload).decode("ascii")],
        })

    def shutdown(self, how):
        self._closed = True

    def close(self):
        self._closed = True


def _ws_client_upgrade(sock, host, path, user_agent=""):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: {user_agent or 'Mozilla/5.0'}\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("websocket upgrade closed")
        raw.extend(chunk)
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    if "101" not in lines[0]:
        raise ConnectionError(f"websocket upgrade failed: {lines[0]}")
    accept = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    ).decode("ascii")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    if headers.get("sec-websocket-accept") != accept:
        raise ConnectionError("websocket accept mismatch")
    return _WSClientStream(sock, leftover=rest)


class FakeReverseProbe(threading.Thread):
    """A fake probe that dials the controller instead of waiting for stdio."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        probe_id: str,
        *,
        parent_id: str | None = None,
        read_only: bool = True,
        caps: list[str] | None = None,
        connect_timeout: float = 10.0,
        read_only_rootfs: bool = False,
        spawn_handler: Callable[[dict[str, Any], "FakeReverseProbe"], dict[str, Any]] | None = None,
        verbose: bool = False,
        transport: str = "tcp",
        ca_file: str | None = None,
        pin: str = "",
        sni: str | None = None,
        context: ssl.SSLContext | None = None,
        path: str = "/ws",
        poll_path: str = "/v1/probe/poll",
        result_path: str = "/v1/probe/result",
        user_agent: str = "",
        fallback_from: str = "",
    ):
        super().__init__(daemon=True)
        self.host = host
        self.port = int(port)
        self.token = token
        self.probe_id = probe_id
        self.parent_id = parent_id
        self.read_only = read_only
        self.transport = transport
        self.ca_file = ca_file
        self.pin = pin
        self.sni = sni or host
        self.fallback_from = fallback_from
        self.context = context
        self.path = path
        self.poll_path = poll_path
        self.result_path = result_path
        self.user_agent = user_agent
        self.caps = list(caps or [
            "collect", "exec", "dial", "beacon", "cleanup", "upload",
            "download", "spawn", "reverse", "task", "socks", "k8s",
            "audit-exec", "read-file", "list-files", "udp",
        ])
        self.connect_timeout = float(connect_timeout)
        self.read_only_rootfs = read_only_rootfs
        self.spawn_handler = spawn_handler
        self.verbose = verbose
        self.error: BaseException | None = None
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.uploads: dict[str, bytes] = {}
        self.spawns: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.streams: dict[int, socket.socket] = {}
        self.udp_sockets: dict[int, socket.socket] = {}
        self._next_stream = 1
        self._next_udp = 1
        self._stream_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self._reader = None
        self._writer = None

    # ------------------------------------------------------------ lifecycle
    def run(self) -> None:
        deadline = time.time() + self.connect_timeout
        sock = None
        last_error: BaseException | None = None
        while time.time() < deadline and not self._stop_event.is_set():
            try:
                sock = socket.create_connection((self.host, self.port), timeout=2)
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        if sock is None:
            self.error = last_error or ConnectionError("could not connect")
            self.ready.set()
            self.finished.set()
            return
        try:
            stream = self._open_stream(sock)
        except BaseException as exc:
            self.error = exc
            try:
                sock.close()
            except OSError:
                pass
            self.ready.set()
            self.finished.set()
            return
        self._sock = stream
        self._serve_stream(stream)

    def _serve_stream(self, stream) -> None:
        self._sock = stream
        stream.settimeout(None)
        self._reader = stream.makefile("rb")
        self._writer = stream.makefile("wb")
        try:
            self._authenticate()
            self.ready.set()
            while not self._stop_event.is_set():
                frame = read_frame(self._reader)
                if frame is None:
                    break
                self._handle_frame(frame)
        except BaseException as exc:  # noqa: BLE001 - surface to the test
            self.error = exc
        finally:
            self.ready.set()
            self._close_streams()
            try:
                if self._writer:
                    self._writer.close()
                if self._reader:
                    self._reader.close()
                stream.close()
            except OSError:
                pass
            self.finished.set()

    def _open_stream(self, sock):
        if self.transport in ("tcp", "lab-plaintext"):
            return sock
        context = self.context
        if context is None:
            context = ssl.create_default_context(cafile=self.ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if self.transport == "https":
            try:
                sock.close()
            except OSError:
                pass
            return _HttpsClientStream(
                self.host, self.port, context, probe_id=self.probe_id,
                parent_id=self.parent_id, poll_path=self.poll_path,
                result_path=self.result_path, user_agent=self.user_agent,
                pin=self.pin, sni=self.sni,
            )
        tls = context.wrap_socket(sock, server_hostname=self.sni)
        if self.pin:
            der = tls.getpeercert(binary_form=True)
            got = hashlib.sha256(der).hexdigest()
            expected = self.pin.lower().replace("sha256:", "")
            if not hmac.compare_digest(got, expected):
                try:
                    tls.close()
                except OSError:
                    pass
                raise ValueError(f"certificate pin mismatch: got {got}")
        if self.transport == "tls":
            return tls
        if self.transport == "wss":
            return _ws_client_upgrade(tls, self.host, self.path, self.user_agent)
        raise ValueError(f"unsupported fake transport {self.transport}")

    def stop(self) -> None:
        self._stop_event.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self.join(timeout=1.0)
        self._close_streams()

    def _close_streams(self) -> None:
        with self._stream_lock:
            streams = list(self.streams.values())
            self.streams.clear()
            udp_sockets = list(self.udp_sockets.values())
            self.udp_sockets.clear()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        for sock in udp_sockets:
            try:
                sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------ handshake
    def _send(self, value: dict[str, Any]) -> None:
        if self._writer is None:
            raise ConnectionError("probe socket is closed")
        data = encode(value)
        with self._write_lock:
            self._writer.write(data)
            self._writer.flush()

    def _authenticate(self) -> None:
        challenge = secrets.token_hex(16)
        self._send({
            "v": 1, "type": "hello", "server": "fake-reverse-probe", "version": "0.1.1",
            "probe_id": self.probe_id, "parent_id": self.parent_id,
            "challenge": challenge, "nonce": secrets.token_hex(16),
            "auth": "hmac-sha256", "read_only": self.read_only,
            "transport": "reverse", "window": 4,
            "fallback_from": self.fallback_from or None,
        })
        frame = read_frame(self._reader)
        if not frame or frame.get("type") != "auth":
            raise ValueError(f"expected auth frame, got {frame}")
        message = f"inkblade-probe/v1|{frame.get('nonce')}|{challenge}".encode("utf-8")
        expected = hmac.new(self.token.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(frame.get("mac") or ""), expected):
            self._send({"v": 1, "type": "error", "ok": False,
                        "error": {"code": "auth_failed", "message": "bad hmac"}})
            raise ValueError("controller sent a bad HMAC")
        self._send({
            "v": 1, "type": "ready", "probe_id": self.probe_id,
            "parent_id": self.parent_id, "version": "0.1.1",
            "read_only": self.read_only, "caps": self.caps,
            "transport": "reverse", "window": 4, "max_output": 1024 * 1024,
        })

    # ------------------------------------------------------------ requests
    def _handle_frame(self, frame: dict[str, Any]) -> None:
        kind = frame.get("type")
        if kind == "req":
            self._handle_request(frame)
        elif kind == "data":
            sid = int(frame.get("stream") or 0)
            with self._stream_lock:
                stream = self.streams.get(sid)
            if stream is not None:
                try:
                    stream.sendall(base64.b64decode(frame.get("data") or ""))
                except OSError:
                    pass
        elif kind == "stream-eof":
            sid = int(frame.get("stream") or 0)
            with self._stream_lock:
                stream = self.streams.get(sid)
            if stream is not None:
                try:
                    stream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        elif kind == "stream-close":
            sid = int(frame.get("stream") or 0)
            with self._stream_lock:
                stream = self.streams.pop(sid, None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _handle_request(self, frame: dict[str, Any]) -> None:
        request_id = str(frame.get("id") or "")
        op = str(frame.get("op") or "")
        args = frame.get("args") if isinstance(frame.get("args"), dict) else {}
        self.requests.append({"op": op, "args": args})
        try:
            data = self._dispatch(op, args, request_id)
            self._send({"v": 1, "type": "resp", "id": request_id,
                        "ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001
            error: dict[str, Any] = {"code": "fake_error", "message": str(exc)}
            if isinstance(exc, OSError) and exc.errno is not None:
                error["errno"] = exc.errno
            self._send({"v": 1, "type": "resp", "id": request_id,
                        "ok": False, "error": error})

    def _dispatch(self, op: str, args: dict[str, Any], request_id: str) -> dict[str, Any]:
        if op == "ping":
            return {"pong": True, "probe_id": self.probe_id}
        if op == "beacon":
            return {"probe_id": self.probe_id, "parent_id": self.parent_id,
                    "read_only": self.read_only, "transport": "reverse",
                    "children": len(self.spawns)}
        if op == "collect":
            return {
                "probe_id": self.probe_id, "parent_id": self.parent_id,
                "read_only": self.read_only, "transport": "reverse",
                "ts": time.time(), "host": {"hostname": "fake-reverse",
                                            "pid": os.getpid()},
                "env": [], "mounts": [], "devices": [],
                "service_account": {"token_present": False},
            }
        if op == "exec":
            return self._exec(args)
        if op == "audit-exec":
            payload = self._exec(args)
            return {"exec": payload, "audit": {
                "pid": os.getpid(), "argv": payload.get("argv") or [],
                "cwd": "", "exit_code": payload.get("exit_code"),
                "opened_files": [], "sampler": "fake-reverse",
            }}
        if op == "read-file":
            path = Path(str(args.get("path") or ""))
            raw = path.read_bytes()
            limit = int(args.get("max_bytes") or 1024 * 1024)
            chunk = raw[:limit]
            return {"path": str(path), "exists": True, "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "data_b64": base64.b64encode(chunk).decode("ascii"),
                    "bytes": len(chunk), "eof": len(chunk) >= len(raw)}
        if op == "list-files":
            root = Path(str(args.get("path") or ""))
            entries = [{"name": item.name, "path": str(item), "dir": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else 0}
                       for item in sorted(root.iterdir(), key=lambda p: p.name)]
            return {"path": str(root), "exists": True, "count": len(entries),
                    "entries": entries}
        if op == "upload":
            return self._upload(args)
        if op == "download":
            raw = Path(str(args.get("path") or "")).read_bytes()
            offset = int(args.get("offset") or 0)
            limit = int(args.get("max_bytes") or 1024 * 1024)
            chunk = raw[offset:offset + limit]
            return {"path": args.get("path"), "offset": offset,
                    "next_offset": offset + len(chunk),
                    "eof": offset + len(chunk) >= len(raw),
                    "data_b64": base64.b64encode(chunk).decode("ascii")}
        if op == "spawn":
            return self._spawn(args)
        if op == "cleanup":
            removed = []
            for raw in args.get("paths") or []:
                try:
                    Path(str(raw)).unlink()
                    removed.append(str(raw))
                except OSError:
                    pass
            return {"removed": removed, "children": len(self.spawns)}
        if op == "dial":
            return self._dial(args)
        if op == "udp":
            return self._udp(args)
        if op == "socks":
            return {"address": "127.0.0.1:0", "bind": "127.0.0.1"}
        if op == "k8s":
            return {"ok": True, "items": [], "kind": "List"}
        if op == "task":
            return {"ok": True, "task_id": request_id, "probe_id": self.probe_id,
                    "steps": [], "vars": {}}
        raise ValueError(f"unknown op {op}")

    def _udp(self, args: dict[str, Any]) -> dict[str, Any]:
        action = str(args.get("action") or "")
        if action == "bind":
            host = str(args.get("host") or "0.0.0.0")
            port = int(args.get("port") or 0)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host, port))
            sock.settimeout(1.0)
            with self._stream_lock:
                socket_id = self._next_udp
                self._next_udp += 1
                self.udp_sockets[socket_id] = sock
            return {"socket": socket_id, "port": sock.getsockname()[1],
                    "address": f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"}
        socket_id = int(args.get("socket") or 0)
        with self._stream_lock:
            sock = self.udp_sockets.get(socket_id)
        if sock is None:
            raise ValueError(f"unknown udp socket {socket_id}")
        if action == "send":
            host = str(args.get("host") or "")
            port = int(args.get("port") or 0)
            data = base64.b64decode(args.get("data_b64") or "")
            sent = sock.sendto(data, (host, port))
            return {"sent": sent, "socket": socket_id}
        if action == "recv":
            timeout = int(args.get("timeout_ms") or 1000) / 1000
            sock.settimeout(timeout)
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                return {"timeout": True, "socket": socket_id}
            return {
                "socket": socket_id,
                "data_b64": base64.b64encode(data).decode("ascii"),
                "host": address[0], "port": address[1], "bytes": len(data),
            }
        if action == "close":
            with self._stream_lock:
                self.udp_sockets.pop(socket_id, None)
            try:
                sock.close()
            except OSError:
                pass
            return {"socket": socket_id, "closed": True}
        raise ValueError(f"unknown udp action {action}")

    def _exec(self, args: dict[str, Any]) -> dict[str, Any]:
        argv = [str(item) for item in args.get("argv") or []]
        if not argv:
            raise ValueError("exec requires argv")
        timeout = min(max(int(args.get("timeout_ms") or 5000), 50), 120000) / 1000
        started = time.time()
        env = {key: value for key, value in os.environ.items()
               if key not in ("INKBLADE_PROBE_TOKEN", "INKBLADE_PROBE_TOKEN_FILE")}
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
            return {
                "exit_code": proc.returncode, "rc": proc.returncode,
                "stdout": proc.stdout.decode("utf-8", "replace"),
                "stderr": proc.stderr.decode("utf-8", "replace"),
                "timed_out": False, "argv": argv,
                "duration_ms": int((time.time() - started) * 1000),
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "rc": -1, "stdout": "", "stderr": "timeout",
                    "timed_out": True, "argv": argv, "duration_ms": int((time.time() - started) * 1000)}

    def _upload(self, args: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(args.get("path") or ""))
        if self.read_only_rootfs:
            raise OSError(30, "Read-only file system")
        data = base64.b64decode(args.get("data_b64") or "")
        offset = int(args.get("offset") or 0)
        mode = "r+b" if path.exists() else "wb"
        with path.open(mode) as handle:
            handle.seek(offset)
            handle.write(data)
        self.uploads[str(path)] = path.read_bytes()
        if args.get("final") and args.get("sha256"):
            got = hashlib.sha256(path.read_bytes()).hexdigest()
            if got != args["sha256"]:
                raise ValueError(f"upload sha mismatch: {got}")
        return {"path": str(path), "offset": offset, "written": len(data),
                "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _spawn(self, args: dict[str, Any]) -> dict[str, Any]:
        self.spawns.append(dict(args))
        child = str(args.get("probe_id") or "fake-child")
        if self.spawn_handler is not None:
            return self.spawn_handler(args, self)
        return {"probe_id": child, "parent_id": self.probe_id,
                "registered": True, "path": args.get("path") or "/tmp/fake-child"}

    def _dial(self, args: dict[str, Any]) -> dict[str, Any]:
        host = str(args.get("host") or "")
        port = int(args.get("port") or 0)
        stream = socket.create_connection((host, port), timeout=5)
        stream.settimeout(None)
        with self._stream_lock:
            stream_id = self._next_stream
            self._next_stream += 1
            self.streams[stream_id] = stream
        threading.Thread(
            target=self._stream_reader, args=(stream_id, stream), daemon=True
        ).start()
        return {"stream": stream_id, "host": host, "port": port, "connected": True}

    def _stream_reader(self, stream_id: int, stream: socket.socket) -> None:
        try:
            while True:
                chunk = stream.recv(32768)
                if not chunk:
                    break
                self._send({
                    "v": 1, "type": "data", "stream": stream_id,
                    "probe_id": self.probe_id,
                    "data": base64.b64encode(chunk).decode("ascii"),
                    "eof": False,
                })
        except OSError:
            pass
        finally:
            try:
                self._send({"v": 1, "type": "data", "stream": stream_id,
                            "probe_id": self.probe_id, "data": "", "eof": True})
            except (OSError, ValueError):
                pass
            with self._stream_lock:
                self.streams.pop(stream_id, None)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fake reverse probe (tests only)")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--token-file", default=None)
    parser.add_argument("--probe-id", default="fake-reverse")
    parser.add_argument("--parent-id", default=None)
    parser.add_argument("--transport", choices=["tcp", "tls", "wss", "https"],
                        default="tls")
    parser.add_argument("--ca-file", default=None)
    parser.add_argument("--pin", default="")
    parser.add_argument("--sni", default=None)
    parser.add_argument("--path", default="/ws")
    parser.add_argument("--read-only", action="store_true", default=True)
    parser.add_argument("--allow-write", action="store_true")
    parser.add_argument("--spawn-child", action="store_true",
                        help="on spawn, start a real second reverse connection")
    parser.add_argument("--spawn-log", default=None)
    args = parser.parse_args(argv)
    token = args.token or ""
    if args.token_file:
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
    if not token:
        print("fake reverse probe: missing token", file=sys.stderr)
        return 2
    children: list[FakeReverseProbe] = []
    spawn_log = Path(args.spawn_log) if args.spawn_log else None

    def spawn_handler(payload, parent):
        if spawn_log is not None:
            try:
                spawn_log.write_text(json.dumps(payload, default=str), encoding="utf-8")
            except OSError:
                pass
        if not args.spawn_child:
            return {"probe_id": str(payload.get("probe_id")),
                    "parent_id": parent.probe_id, "registered": True}
        reverse = payload.get("reverse") or {}
        child = FakeReverseProbe(
            str(reverse.get("host") or parent.host),
            int(reverse.get("port") or parent.port),
            token,
            str(payload.get("probe_id") or "child"),
            parent_id=parent.probe_id,
            transport=str(reverse.get("transport") or "tls"),
            ca_file=reverse.get("ca_file") or args.ca_file,
            pin=str(reverse.get("pin") or ""),
            sni=reverse.get("sni") or None,
            path=str(reverse.get("ws_path") or "/ws"),
        )
        children.append(child)
        child.start()
        return {"probe_id": child.probe_id, "parent_id": parent.probe_id,
                "registered": True}

    probe = FakeReverseProbe(
        args.host, args.port, token, args.probe_id,
        parent_id=args.parent_id, read_only=not args.allow_write, verbose=True,
        transport=args.transport, ca_file=args.ca_file, pin=args.pin,
        sni=args.sni, path=args.path, spawn_handler=spawn_handler,
    )
    probe.start()
    probe.ready.wait(timeout=10)
    if probe.error is not None:
        print(f"fake reverse probe: {probe.error}", file=sys.stderr)
        return 3
    while probe.is_alive():
        probe.join(timeout=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
