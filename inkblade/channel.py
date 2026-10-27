# -*- coding: utf-8 -*-
"""Probe transport and local SOCKS5 / port-forward channel.

The data plane is always the Rust probe's framed JSON protocol carried over
``kubectl exec -i`` (or another explicit stdio command).  The channel listens
only on loopback, dials cluster targets through the probe, and never opens a
second port in the target pod.

Wire format: 4-byte big-endian length + UTF-8 JSON.  Authentication is
challenge-HMAC-SHA256 over a shared token (see docs/PROBE-PROTOCOL.md).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import queue
from collections import deque
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

MAX_FRAME = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
CHUNK_SIZE = 48 * 1024


class ChannelError(Exception):
    """Base error; ``code`` is stable for CLI/API consumers."""

    code = "channel_error"

    def __init__(self, message: str, *, code: str | None = None, data: Any = None):
        super().__init__(message)
        if code:
            self.code = code
        self.data = data


class ProbeError(ChannelError):
    code = "probe_error"


class ProbeTimeout(ChannelError):
    code = "timeout"


class AuthError(ChannelError):
    code = "auth_failed"


def encode_frame(payload: dict[str, Any]) -> bytes:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not data or len(data) > MAX_FRAME:
        raise ChannelError(f"frame size out of range: {len(data)}")
    return struct.pack(">I", len(data)) + data


def read_frame(stream) -> dict[str, Any] | None:
    header = _read_exact(stream, 4, allow_eof=True)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    if length == 0 or length > MAX_FRAME:
        raise ChannelError(f"invalid frame length {length}")
    payload = _read_exact(stream, length)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ChannelError(f"invalid JSON frame: {exc}") from exc
    if not isinstance(value, dict):
        raise ChannelError("frame must be a JSON object")
    return value


def _read_exact(stream, count: int, *, allow_eof: bool = False) -> bytes | None:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if allow_eof and remaining == count:
                return None
            raise ChannelError("probe closed the stream mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def auth_mac(token: str, nonce: str, challenge: str) -> str:
    message = f"inkblade-probe/v1|{nonce}|{challenge}".encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()


@dataclass
class DialStream:
    """One multiplexed byte stream obtained from ``dial``."""

    parent: "ProbeConnection"
    stream_id: int
    incoming: "queue.Queue[bytes | None]" = field(default_factory=queue.Queue)
    closed: bool = False

    def send(self, data: bytes) -> None:
        if self.closed:
            raise ChannelError("stream is closed")
        encoded = base64.b64encode(data).decode("ascii")
        self.parent._send_frame({
            "v": 1, "type": "data", "stream": self.stream_id,
            "probe_id": self.parent.probe_id, "data": encoded, "eof": False,
        })

    def close_write(self) -> None:
        if self.closed:
            return
        self.parent._send_frame({
            "v": 1, "type": "stream-eof", "stream": self.stream_id,
            "probe_id": self.parent.probe_id,
        })

    def recv(self, timeout: float | None = None) -> bytes | None:
        try:
            data = self.incoming.get(timeout=timeout)
        except queue.Empty as exc:
            raise ProbeTimeout("stream read timed out") from exc
        if data is None:
            self.closed = True
        return data

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.parent._send_frame({
                "v": 1, "type": "stream-close", "stream": self.stream_id,
                "probe_id": self.parent.probe_id,
            })
        except ChannelError:
            pass
        self.parent._streams.pop(self.stream_id, None)


class ProbeConnection:
    """Authenticated framed connection to one Rust probe.

    The default transport launches the probe over stdio (``kubectl exec -i``).
    ``from_socket`` wraps an already-accepted TCP socket instead; the handshake
    and every RPC are shared, so a probe-initiated reverse session is not a
    second protocol implementation.
    """

    def __init__(
        self,
        command: Sequence[str] | None,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        probe_id: str | None = None,
        audit_prefix: str = "probe",
        sock: Any | None = None,
        max_pending: int = 64,
        remote: str = "",
    ):
        if sock is None and not command:
            raise ChannelError("probe command is empty")
        self.command = list(command or [])
        self.token = token
        self.timeout = float(timeout)
        self.env = {**os.environ, **(env or {})}
        self.cwd = str(cwd) if cwd else None
        self.on_audit = on_audit
        self.on_event = on_event
        self.probe_id = probe_id or ""
        self.parent_id: str | None = None
        self.version = ""
        self.read_only = True
        self.caps: list[str] = []
        self.fallback_from = ""
        self.audit_prefix = audit_prefix
        self.max_pending = max(1, int(max_pending))
        self.transport = "tcp" if sock is not None else "stdio"
        self.remote = remote
        self._sock = sock
        self._sock_reader = None
        self._sock_writer = None
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._pending: dict[str, "queue.Queue[dict[str, Any]]"] = {}
        self._control: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._streams: dict[int, DialStream] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=200)
        self._stderr_tail: deque[str] = deque(maxlen=200)
        self._closed = False
        self._close_done = False
        self._ready = threading.Event()
        self._fatal: BaseException | None = None

    @classmethod
    def from_socket(
        cls,
        sock: Any,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        on_audit: Callable[[dict[str, Any]], None] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        probe_id: str | None = None,
        audit_prefix: str = "probe",
        remote: str = "",
        max_pending: int = 64,
    ) -> "ProbeConnection":
        """Wrap an accepted TCP/TLS/WebSocket connection."""
        return cls(
            None, token, timeout=timeout, on_audit=on_audit, on_event=on_event,
            probe_id=probe_id, audit_prefix=audit_prefix, sock=sock, remote=remote,
            max_pending=max_pending,
        )

    # ------------------------------------------------------------ lifecycle
    def start(self) -> "ProbeConnection":
        if self._sock is not None:
            self._sock.settimeout(None)
            self._sock_reader = self._sock.makefile("rb")
            self._sock_writer = self._sock.makefile("wb")
            self._reader = threading.Thread(
                target=self._read_loop, name="probe-reader", daemon=True
            )
            self._reader.start()
        else:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=self.env,
                cwd=self.cwd,
            )
            self._reader = threading.Thread(target=self._read_loop, name="probe-reader", daemon=True)
            self._stderr_reader = threading.Thread(
                target=self._stderr_loop, name="probe-audit", daemon=True
            )
            self._reader.start()
            self._stderr_reader.start()
        return self._handshake()

    def _handshake(self) -> "ProbeConnection":
        challenge = self._wait_control(self.timeout)
        if challenge.get("type") not in ("challenge", "hello"):
            self.close(cleanup=False)
            raise AuthError(
                f"probe did not send a challenge: {challenge.get('type') or challenge}"
            )
        self.probe_id = str(challenge.get("probe_id") or self.probe_id)
        self.parent_id = challenge.get("parent_id") or None
        self.read_only = bool(challenge.get("read_only", True))
        nonce = secrets.token_hex(8)
        challenge_value = str(challenge.get("challenge") or challenge.get("nonce") or "")
        self._send_frame({
            "v": 1,
            "type": "auth",
            "nonce": nonce,
            "mac": auth_mac(self.token, nonce, challenge_value),
        })
        ready = self._wait_control(self.timeout)
        if ready.get("type") != "ready":
            self.close(cleanup=False)
            raise AuthError(
                "probe authentication failed"
                if ready.get("type") == "error"
                else f"unexpected handshake frame: {ready.get('type')}"
            )
        self.version = str(ready.get("version") or "")
        self.read_only = bool(ready.get("read_only", self.read_only))
        self.caps = [str(item) for item in ready.get("caps") or []]
        self.parent_id = ready.get("parent_id") or self.parent_id
        self.transport = str(ready.get("transport") or self.transport)
        # A probe that reached the controller over TLS/WSS after a QUIC UDP
        # failure includes this marker in its hello frame.  It is telemetry,
        # never an authentication input.
        self.fallback_from = str(
            challenge.get("fallback_from") or ready.get("fallback_from") or ""
        )
        self._ready.set()
        return self

    def close(self, *, cleanup: bool = True, timeout: float = 2.0) -> None:
        if self._close_done:
            return
        self._close_done = True
        if cleanup and self._ready.is_set():
            try:
                self.request("cleanup", {"paths": []}, timeout=timeout)
            except Exception:
                pass
        self._closed = True
        if self._sock is not None:
            # Shut the socket down first: on Windows, closing a buffered
            # makefile while its reader thread is blocked in read() can wait
            # forever.  shutdown() wakes that thread.
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            for stream in (self._sock_writer, self._sock_reader):
                _close_quietly(stream)
            if self._reader and self._reader is not threading.current_thread():
                self._reader.join(timeout=timeout)
        else:
            try:
                if self._proc and self._proc.stdin:
                    self._proc.stdin.close()
            except OSError:
                pass
            if self._proc:
                try:
                    self._proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._proc.terminate()
                    try:
                        self._proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()
                for stream in (self._proc.stdout, self._proc.stderr):
                    try:
                        if stream:
                            stream.close()
                    except OSError:
                        pass
        for stream in list(self._streams.values()):
            stream.incoming.put(None)
        self._streams.clear()

    def wait(self, timeout: float | None = None) -> int:
        if self._sock is not None:
            if self._reader and self._reader is not threading.current_thread():
                self._reader.join(timeout=timeout)
            return 0
        if not self._proc:
            raise ChannelError("probe has not started")
        return self._proc.wait(timeout=timeout)

    @property
    def alive(self) -> bool:
        if self._sock is not None:
            return not self._closed and not self._close_done and self._fatal is None
        return bool(self._proc and self._proc.poll() is None and not self._closed)

    @property
    def stderr_tail(self) -> list[str]:
        return list(self._stderr_tail)[-50:]

    # ------------------------------------------------------------ framing
    def _send_frame(self, payload: dict[str, Any]) -> None:
        if self._sock is not None:
            writer = self._sock_writer
            if writer is None:
                raise ChannelError("probe socket is closed")
        else:
            proc = self._proc
            if not proc or not proc.stdin:
                raise ChannelError("probe stdin is closed")
            writer = proc.stdin
        data = encode_frame(payload)
        with self._write_lock:
            try:
                writer.write(data)
                writer.flush()
            except (BrokenPipeError, OSError) as exc:
                raise ChannelError(f"probe write failed: {exc}") from exc

    def _read_loop(self) -> None:
        stream = self._sock_reader
        if stream is None and self._proc:
            stream = self._proc.stdout
        if stream is None:
            return
        try:
            while True:
                frame = read_frame(stream)
                if frame is None:
                    break
                self._dispatch(frame)
        except BaseException as exc:  # stream EOF is normal; record real errors
            self._fatal = exc
        finally:
            self._closed = True
            for pending in list(self._pending.values()):
                pending.put({
                    "type": "error", "id": "", "ok": False,
                    "error": {"code": "disconnected", "message": "probe disconnected"},
                })
            for stream in list(self._streams.values()):
                stream.incoming.put(None)
            self._control.put({
                "type": "error", "ok": False,
                "error": {"code": "disconnected", "message": "probe disconnected"},
            })

    def _stderr_loop(self) -> None:
        assert self._proc and self._proc.stderr
        for raw in iter(self._proc.stderr.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            self._stderr_tail.append(line)
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and self.on_audit:
                try:
                    self.on_audit(event)
                except Exception:
                    pass

    def _dispatch(self, frame: dict[str, Any]) -> None:
        kind = str(frame.get("type") or "")
        if kind in ("challenge", "hello", "ready", "error"):
            self._control.put(frame)
            return
        if kind == "resp":
            key = str(frame.get("id") or "")
            pending = self._pending.pop(key, None)
            if pending is not None:
                pending.put(frame)
            return
        if kind == "data":
            stream_id = int(frame.get("stream") or 0)
            stream = self._streams.get(stream_id)
            if stream is not None:
                if frame.get("eof"):
                    stream.incoming.put(None)
                else:
                    data = base64.b64decode(frame.get("data") or "")
                    stream.incoming.put(data)
            return
        if kind in ("probe-exit",):
            self._events.append(frame)
            if self.on_event:
                try:
                    self.on_event(frame)
                except Exception:
                    pass
            return
        self._events.append(frame)
        if self.on_event:
            try:
                self.on_event(frame)
            except Exception:
                pass

    def _wait_control(self, timeout: float) -> dict[str, Any]:
        try:
            frame = self._control.get(timeout=timeout)
        except queue.Empty as exc:
            raise ProbeTimeout("probe handshake timed out") from exc
        if frame.get("type") == "error":
            error = frame.get("error") or {}
            raise AuthError(str(error.get("message") or "probe handshake failed"),
                            code=str(error.get("code") or "handshake_failed"))
        return frame

    # ------------------------------------------------------------ RPC
    def request(
        self,
        op: str,
        args: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        probe_id: str | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        if not self._ready.is_set():
            raise ChannelError("probe is not ready")
        request_id = secrets.token_hex(8)
        frame: dict[str, Any] = {
            "v": 1, "type": "req", "id": request_id, "op": op, "args": args or {},
            "probe_id": probe_id or self.probe_id,
            "parent_id": self.parent_id,
        }
        if task_id:
            frame["task_id"] = task_id
        if probe_id:
            frame["probe"] = probe_id
        if len(self._pending) >= self.max_pending:
            raise ChannelError("probe pending request limit reached", code="too_many_pending")
        pending: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._pending[request_id] = pending
        self._send_frame(frame)
        try:
            response = pending.get(timeout=self.timeout if timeout is None else timeout)
        except queue.Empty as exc:
            self._pending.pop(request_id, None)
            raise ProbeTimeout(f"probe request {op!r} timed out") from exc
        if response.get("type") == "error" and not response.get("id"):
            error = response.get("error") or {}
            raise ProbeError(str(error.get("message") or "probe disconnected"),
                             code=str(error.get("code") or "disconnected"))
        if not response.get("ok", True):
            error = response.get("error") or {}
            raise ProbeError(str(error.get("message") or f"{op} failed"),
                             code=str(error.get("code") or "probe_error"),
                             data=response.get("data"))
        data = response.get("data")
        return data if isinstance(data, dict) else {"value": data}

    def ping(self, timeout: float | None = None) -> dict[str, Any]:
        return self.request("ping", {}, timeout=timeout)

    def beacon(self, timeout: float | None = None) -> dict[str, Any]:
        return self.request("beacon", {}, timeout=timeout)

    def collect(self, timeout: float | None = None) -> dict[str, Any]:
        return self.request("collect", {}, timeout=timeout)

    def exec(
        self,
        argv: Sequence[str],
        *,
        timeout_ms: int | None = None,
        max_output: int | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"argv": list(argv)}
        if timeout_ms is not None:
            args["timeout_ms"] = int(timeout_ms)
        if max_output is not None:
            args["max_output"] = int(max_output)
        return self.request("exec", args, timeout=timeout)

    def audit_exec(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        timeout_ms: int | None = None,
        technique: str = "",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Audited exec: the probe records argv/cwd/env digest and samples fds.

        Returns ``{"exec": {...}, "audit": {pid, cwd, opened_files, ...}}``.
        """
        args: dict[str, Any] = {"argv": list(argv), "technique": str(technique or "")}
        if cwd:
            args["cwd"] = str(cwd)
        if timeout_ms is not None:
            args["timeout_ms"] = int(timeout_ms)
        result = self.request("audit-exec", args, timeout=timeout)
        if "exec" in result or "audit" in result:
            return result
        return {"exec": result, "audit": result}

    def read_file(self, path: str, *, max_bytes: int = 1024 * 1024,
                  timeout: float | None = None) -> dict[str, Any]:
        return self.request("read-file", {"path": str(path), "max_bytes": int(max_bytes)},
                            timeout=timeout)

    def list_files(self, path: str, *, pattern: str = "",
                   timeout: float | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {"path": str(path)}
        if pattern:
            args["pattern"] = str(pattern)
        return self.request("list-files", args, timeout=timeout)

    def run_task(
        self,
        template: dict[str, Any] | str,
        params: dict[str, Any] | None = None,
        *,
        task_id: str | None = None,
        timeout: float | None = None,
        probe_id: str | None = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"params": params or {}}
        if isinstance(template, str) and not template.lstrip().startswith("{"):
            args["template_path"] = template
        else:
            args["template"] = template
        if task_id:
            args["task_id"] = task_id
        return self.request("task", args, timeout=timeout, task_id=task_id, probe_id=probe_id)

    def task(self, template: dict[str, Any] | str, params: dict[str, Any] | None = None,
             task_id: str | None = None) -> dict[str, Any]:
        """Contract used by ``inkblade.tpl.probe.RustProbe``."""
        return self.run_task(template, params or {}, task_id=task_id)


    def upload(
        self,
        remote_path: str,
        data: bytes,
        *,
        mode: int = 0o600,
        chunk_size: int = CHUNK_SIZE,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        offset = 0
        result: dict[str, Any] = {}
        while offset < len(data) or (not data and offset == 0):
            chunk = data[offset:offset + chunk_size]
            result = self.request("upload", {
                "path": remote_path,
                "data_b64": base64.b64encode(chunk).decode("ascii"),
                "offset": offset,
                "mode": mode,
                "sha256": digest,
                "final": offset + len(chunk) >= len(data),
            }, timeout=timeout)
            offset += len(chunk)
            if not data:
                break
        return result

    def download(
        self,
        remote_path: str,
        *,
        max_bytes: int = 16 * 1024 * 1024,
        chunk_size: int = CHUNK_SIZE,
        timeout: float | None = None,
    ) -> bytes:
        out = bytearray()
        offset = 0
        while True:
            result = self.request("download", {
                "path": remote_path,
                "offset": offset,
                "max_bytes": min(chunk_size, max_bytes - len(out)),
            }, timeout=timeout)
            chunk = base64.b64decode(result.get("data_b64") or "")
            out.extend(chunk)
            offset = int(result.get("next_offset") or (offset + len(chunk)))
            if result.get("eof") or not chunk or len(out) >= max_bytes:
                break
        return bytes(out)

    def spawn(
        self,
        binary: bytes | None = None,
        *,
        binary_path: str | None = None,
        remote_path: str | None = None,
        probe_id: str | None = None,
        sha256: str | None = None,
        reverse: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if binary is None and not binary_path:
            raise ChannelError("spawn requires binary bytes or binary_path")
        args: dict[str, Any] = {}
        if binary_path:
            args["binary_path"] = str(binary_path)
        if binary is not None:
            args["binary_b64"] = base64.b64encode(binary).decode("ascii")
            args["sha256"] = sha256 or hashlib.sha256(binary).hexdigest()
        elif sha256:
            args["sha256"] = sha256
        if remote_path:
            args["path"] = remote_path
        if probe_id:
            args["probe_id"] = probe_id
        if reverse:
            args["reverse"] = dict(reverse)
        return self.request("spawn", args, timeout=timeout)

    def cleanup(self, paths: Iterable[str] = (), *, timeout: float | None = None) -> dict[str, Any]:
        return self.request("cleanup", {"paths": list(paths)}, timeout=timeout)

    def dial(self, host: str, port: int, *, timeout_ms: int | None = None) -> DialStream:
        args: dict[str, Any] = {"host": host, "port": int(port)}
        if timeout_ms is not None:
            args["timeout_ms"] = int(timeout_ms)
        result = self.request("dial", args)
        stream_id = int(result.get("stream") or 0)
        if not stream_id:
            raise ProbeError("probe did not return a stream id")
        stream = DialStream(self, stream_id)
        self._streams[stream_id] = stream
        return stream

    # ------------------------------------------------------------ UDP relay
    def udp_bind(
        self, host: str = "0.0.0.0", port: int = 0, *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Bind an ephemeral UDP socket inside the target pod.

        This is a low-privilege operation (ports > 1024), used by the MASQUE
        CONNECT-UDP relay.  It does not provide RDMA verbs.
        """
        result = self.request(
            "udp", {"action": "bind", "host": host, "port": int(port)}, timeout=timeout
        )
        socket_id = int(result.get("socket") or 0)
        if not socket_id:
            raise ProbeError("probe did not return a udp socket id")
        return result

    def udp_send(
        self, socket_id: int, host: str, port: int, data: bytes, *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "udp",
            {
                "action": "send", "socket": int(socket_id),
                "host": str(host), "port": int(port),
                "data_b64": base64.b64encode(data).decode("ascii"),
            },
            timeout=timeout,
        )

    def udp_recv(
        self, socket_id: int, *, timeout_ms: int = 1000,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "udp",
            {"action": "recv", "socket": int(socket_id),
             "timeout_ms": int(timeout_ms)},
            timeout=timeout,
        )

    def udp_close(self, socket_id: int, *, timeout: float | None = None) -> dict[str, Any]:
        return self.request(
            "udp", {"action": "close", "socket": int(socket_id)}, timeout=timeout
        )


def kubectl_probe_command(
    kubectl: str = "kubectl",
    *,
    namespace: str,
    pod: str,
    probe_path: str = "/tmp/.inkblade-probe",
    token_file: str = "/tmp/.inkblade-probe-token",
    container: str | None = None,
    kubeconfig: str | None = None,
    context: str | None = None,
    read_only: bool = True,
    allow_cmds: Sequence[str] = (),
    probe_id: str | None = None,
    parent_id: str | None = None,
    request_timeout: str | None = None,
) -> list[str]:
    command = [kubectl]
    if kubeconfig:
        command += ["--kubeconfig", kubeconfig]
    if context:
        command += ["--context", context]
    if request_timeout:
        command += ["--request-timeout", str(request_timeout)]
    command += ["-n", namespace, "exec", "-i", pod]
    if container:
        command += ["-c", container]
    command += ["--", probe_path, "run", "--stdio", "--token-file", token_file]
    if probe_id:
        command += ["--probe-id", probe_id]
    if parent_id:
        command += ["--parent-id", parent_id]
    command += ["--read-only"] if read_only else ["--allow-write"]
    for name in allow_cmds:
        command += ["--allow-cmd", str(name)]
    return command


@dataclass
class Forward:
    local_port: int
    host: str
    port: int


class ChannelServer:
    """Loopback SOCKS5 and port-forward listeners backed by one probe."""

    def __init__(
        self,
        probe: ProbeConnection,
        *,
        socks_port: int = 0,
        forwards: Sequence[Forward] = (),
        bind_host: str = "127.0.0.1",
        on_audit: Callable[[dict[str, Any]], None] | None = None,
    ):
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise ChannelError("channel listeners must be loopback")
        self.probe = probe
        self.bind_host = bind_host
        self.on_audit = on_audit
        self.socks_port = int(socks_port)
        self.forwards = list(forwards)
        self._listeners: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._clients: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.started_at = time.time()
        self.bytes_up = 0
        self.bytes_down = 0
        self.connections = 0
        self.errors = 0
        self.forward_ports: list[dict[str, Any]] = []

    def start(self) -> "ChannelServer":
        if self.socks_port is not None and self.socks_port >= 0:
            listener = self._listen(self.socks_port)
            self.socks_port = int(listener.getsockname()[1])
            self._threads.append(self._spawn_accept(listener, ("socks", None)))
        for forward in self.forwards:
            if forward.local_port == 0:
                listener = self._listen(0)
                actual = int(listener.getsockname()[1])
            else:
                listener = self._listen(forward.local_port)
                actual = forward.local_port
            self.forward_ports.append({
                "local": actual, "host": forward.host, "port": forward.port,
            })
            self._threads.append(
                self._spawn_accept(listener, ("forward", (forward.host, forward.port)))
            )
        return self

    def _listen(self, port: int) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, int(port)))
        listener.listen(64)
        listener.settimeout(0.3)
        self._listeners.append(listener)
        return listener

    def _spawn_accept(self, listener: socket.socket, mode) -> threading.Thread:
        thread = threading.Thread(
            target=self._accept_loop, args=(listener, mode), name="channel-accept", daemon=True
        )
        thread.start()
        return thread

    def _accept_loop(self, listener: socket.socket, mode) -> None:
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(15)
            with self._lock:
                self._clients.add(client)
                self.connections += 1
            thread = threading.Thread(
                target=self._handle_client, args=(client, mode), daemon=True
            )
            thread.start()

    def _handle_client(self, client: socket.socket, mode) -> None:
        try:
            if mode[0] == "socks":
                self._handle_socks(client)
            else:
                host, port = mode[1]
                self._relay(client, host, port)
        except Exception as exc:
            self.errors += 1
            self._audit("channel.error", {"error": str(exc)})
        finally:
            with self._lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _handle_socks(self, client: socket.socket) -> None:
        header = _read_socket(client, 2)
        if header[0] != 5:
            raise ChannelError("not SOCKS5")
        methods = _read_socket(client, header[1])
        if 0 not in methods:
            client.sendall(b"\x05\xff")
            raise ChannelError("SOCKS5 no-auth method rejected")
        client.sendall(b"\x05\x00")
        request = _read_socket(client, 4)
        if request[0] != 5 or request[1] != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            raise ChannelError("only SOCKS5 CONNECT is supported")
        host = self._read_socks_host(client, request[3])
        port = struct.unpack(">H", _read_socket(client, 2))[0]
        try:
            stream = self.probe.dial(host, port, timeout_ms=10_000)
        except Exception:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        self._audit("channel.socks", {"host": host, "port": port})
        self._relay_stream(client, stream)

    @staticmethod
    def _read_socks_host(client: socket.socket, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntoa(_read_socket(client, 4))
        if atyp == 3:
            length = _read_socket(client, 1)[0]
            return _read_socket(client, length).decode("utf-8", "replace")
        if atyp == 4:
            raw = _read_socket(client, 16)
            return socket.inet_ntop(socket.AF_INET6, raw)
        raise ChannelError(f"unsupported SOCKS address type {atyp}")

    def _relay(self, client: socket.socket, host: str, port: int) -> None:
        stream = self.probe.dial(host, port, timeout_ms=10_000)
        self._audit("channel.forward", {"host": host, "port": port})
        self._relay_stream(client, stream)

    def _relay_stream(self, client: socket.socket, stream: DialStream) -> None:
        client.settimeout(None)
        done = threading.Event()

        def upstream() -> None:
            try:
                while not self._stop.is_set():
                    chunk = client.recv(64 * 1024)
                    if not chunk:
                        break
                    stream.send(chunk)
                    self.bytes_up += len(chunk)
                stream.close_write()
            except (OSError, ChannelError):
                pass
            finally:
                done.set()

        thread = threading.Thread(target=upstream, name="channel-up", daemon=True)
        thread.start()
        try:
            while not self._stop.is_set():
                chunk = stream.recv(timeout=1.0)
                if chunk is None:
                    break
                client.sendall(chunk)
                self.bytes_down += len(chunk)
        except ProbeTimeout:
            pass
        except (OSError, ChannelError):
            pass
        finally:
            done.wait(timeout=2)
            stream.close()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _audit(self, action: str, detail: dict[str, Any]) -> None:
        if self.on_audit:
            try:
                self.on_audit({"ts": time.time(), "event": action, **detail})
            except Exception:
                pass

    def status(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe.probe_id,
            "socks": f"{self.bind_host}:{self.socks_port}" if self.socks_port else None,
            "forwards": list(self.forward_ports),
            "listeners": len(self._listeners),
            "connections": self.connections,
            "active": len(self._clients),
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "errors": self.errors,
            "uptime_s": round(time.time() - self.started_at, 1),
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
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=1)
        try:
            self.probe.close(cleanup=True)
        except Exception:
            pass


def _close_quietly(stream, timeout: float = 0.5) -> None:
    """Close a buffered file without letting a Windows socketpair block.

    ``socket.shutdown`` wakes a reader blocked in ``read`` but closing the
    corresponding ``BufferedReader`` can still wait on its internal lock on
    Windows.  The socket is already closed by the caller; run the file close
    on a helper thread and move on if the kernel is slow.
    """
    if stream is None:
        return

    def _close() -> None:
        try:
            stream.close()
        except OSError:
            pass

    thread = threading.Thread(target=_close, name="probe-close", daemon=True)
    thread.start()
    thread.join(timeout=timeout)


def _read_socket(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ChannelError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def require_loopback(host: str) -> str:
    """Validate a listener address; the public channel never binds wide."""
    if host in ("127.0.0.1", "localhost", "::1"):
        return host
    raise ChannelError(f"refusing non-loopback listener {host!r}")


def mask_token(token: str) -> str:
    if len(token) <= 8:
        return "***"
    return f"***{token[-4:]}"
