#!/usr/bin/env python3
"""Test double for the Rust probe protocol (stdlib only).

It is intentionally small: auth, collect, exec, dial multiplexing, upload,
download, spawn registration, cleanup, and a native-template subset used by
the integration tests.  It never ships in a release.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MAX_FRAME = 8 * 1024 * 1024
STREAMS: dict[int, socket.socket] = {}
STREAM_LOCK = threading.Lock()
WRITE_LOCK = threading.Lock()
NEXT_STREAM = 1
PROBE_ID = os.environ.get("FAKE_PROBE_ID", "fake-probe")
PARENT_ID = os.environ.get("FAKE_PARENT_ID")


def write_frame(value: dict[str, Any]) -> None:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with WRITE_LOCK:
        sys.stdout.buffer.write(struct.pack(">I", len(raw)))
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()


def read_frame(stream) -> dict[str, Any] | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise EOFError("truncated header")
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > MAX_FRAME:
        raise ValueError(f"bad frame length {length}")
    payload = b""
    while len(payload) < length:
        chunk = stream.read(length - len(payload))
        if not chunk:
            raise EOFError("truncated payload")
        payload += chunk
    return json.loads(payload.decode("utf-8"))


def auth(token: str) -> None:
    challenge = os.urandom(16).hex()
    write_frame({
        "v": 1, "type": "hello", "server": "fake-probe", "version": "0.1.0",
        "probe_id": PROBE_ID, "parent_id": PARENT_ID, "challenge": challenge,
        "nonce": os.urandom(16).hex(),
        "auth": "hmac-sha256", "read_only": os.environ.get("FAKE_READ_ONLY", "1") == "1",
        "window": 4,
    })
    frame = read_frame(sys.stdin.buffer)
    if not frame or frame.get("type") != "auth":
        raise SystemExit(3)
    message = f"inkblade-probe/v1|{frame.get('nonce')}|{challenge}".encode("utf-8")
    expected = hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(frame.get("mac")), expected):
        write_frame({"v": 1, "type": "error", "ok": False,
                     "error": {"code": "auth_failed", "message": "bad hmac"}})
        raise SystemExit(3)
    write_frame({
        "v": 1, "type": "ready", "probe_id": PROBE_ID, "parent_id": PARENT_ID,
        "version": "0.1.0", "read_only": os.environ.get("FAKE_READ_ONLY", "1") == "1",
        "caps": ["collect", "exec", "dial", "beacon", "cleanup", "upload",
                 "download", "spawn", "task", "socks", "k8s",
                 "audit-exec", "read-file", "list-files"],
        "window": 4, "max_output": 1024 * 1024,
    })


def _send_stream_data(stream_id: int, data: bytes, eof: bool = False) -> None:
    write_frame({"v": 1, "type": "data", "stream": stream_id,
                 "probe_id": PROBE_ID, "data": base64.b64encode(data).decode("ascii"),
                 "eof": eof})


def _stream_reader(stream_id: int, sock: socket.socket) -> None:
    try:
        while True:
            chunk = sock.recv(32768)
            if not chunk:
                break
            _send_stream_data(stream_id, chunk)
    except OSError:
        pass
    finally:
        _send_stream_data(stream_id, b"", eof=True)
        with STREAM_LOCK:
            STREAMS.pop(stream_id, None)


def _dial(args: dict[str, Any]) -> dict[str, Any]:
    global NEXT_STREAM
    host = str(args.get("host") or "")
    port = int(args.get("port") or 0)
    timeout = min(max(int(args.get("timeout_ms") or 5000), 50), 120000) / 1000
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(None)
    with STREAM_LOCK:
        stream_id = NEXT_STREAM
        NEXT_STREAM += 1
        STREAMS[stream_id] = sock
    threading.Thread(target=_stream_reader, args=(stream_id, sock), daemon=True).start()
    return {"stream": stream_id, "host": host, "port": port, "connected": True}


def _exec(args: dict[str, Any]) -> dict[str, Any]:
    argv = [str(item) for item in args.get("argv") or []]
    timeout = min(max(int(args.get("timeout_ms") or 5000), 50), 120000) / 1000
    started = time.time()
    env = {k: v for k, v in os.environ.items()
           if k not in ("INKBLADE_PROBE_TOKEN", "INKBLADE_PROBE_TOKEN_FILE")}
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        return {
            "exit_code": proc.returncode, "rc": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace"),
            "timed_out": False,
            "duration_ms": int((time.time() - started) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": -1, "rc": -1,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else "",
            "stderr": "timeout", "timed_out": True,
            "duration_ms": int((time.time() - started) * 1000),
        }


def _collect() -> dict[str, Any]:
    return {
        "probe_id": PROBE_ID, "parent_id": PARENT_ID, "read_only": True,
        "ts": time.time(), "host": {"hostname": "fake", "pid": os.getpid()},
        "env": [], "mounts": [], "service_account": {"token_present": False},
        "network": {}, "devices": [], "files_read": [],
    }


def _http_step(step: dict[str, Any]) -> dict[str, Any]:
    url = str(step.get("url") or "")
    method = str(step.get("method") or "GET").upper()
    headers = {str(k): str(v) for k, v in (step.get("headers") or {}).items()}
    body = step.get("body")
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=min(30, max(1, int(step.get("timeout_ms") or 8000) / 1000))) as resp:
            raw = resp.read(8 * 1024 * 1024)
            status = resp.status
            hdrs = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(8 * 1024 * 1024)
        status = exc.code
        hdrs = dict(exc.headers.items()) if exc.headers else {}
    except Exception as exc:  # noqa: BLE001
        return {"status": 0, "error": f"{type(exc).__name__}: {exc}", "body": ""}
    text = raw.decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    result = {
        "status": status, "ok": 200 <= status < 300, "headers": hdrs,
        "body": text, "text": text, "json": parsed, "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    expect = step.get("expect") or {}
    if expect.get("status") is not None:
        wanted = expect["status"] if isinstance(expect["status"], list) else [expect["status"]]
        if status not in wanted:
            result["ok"] = False
            result["error"] = f"HTTP status {status} not in {wanted}"
    return result


def _tcp_step(step: dict[str, Any]) -> dict[str, Any]:
    host = str(step.get("host") or "")
    port = int(step.get("port") or 0)
    sock = socket.create_connection((host, port), timeout=5)
    if step.get("send_b64"):
        sock.sendall(base64.b64decode(step["send_b64"]))
    raw = b""
    try:
        sock.settimeout(0.5)
        while len(raw) < int(step.get("read_bytes") or 4096):
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    except OSError:
        pass
    sock.close()
    return {"connected": True, "data_b64": base64.b64encode(raw).decode("ascii"),
            "bytes": len(raw), "text": raw.decode("utf-8", "replace")}


def _fs_step(step: dict[str, Any]) -> dict[str, Any]:
    action = str(step.get("action") or "read")
    path = Path(str(step.get("path") or ""))
    if action == "read":
        raw = path.read_bytes()
        text = raw.decode("utf-8", "replace")
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        return {"path": str(path), "exists": True, "size": len(raw),
                "data_b64": base64.b64encode(raw).decode("ascii"), "text": text,
                "json": parsed, "sha256": hashlib.sha256(raw).hexdigest()}
    if action == "list":
        entries = [{"name": p.name, "path": str(p), "dir": p.is_dir(),
                    "size": p.stat().st_size} for p in path.iterdir()]
        return {"path": str(path), "exists": True, "entries": entries, "count": len(entries)}
    if action == "stat":
        exists = path.exists()
        return {"path": str(path), "exists": exists,
                "size": path.stat().st_size if exists else 0,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""}
    if action == "write":
        data = step.get("data")
        if isinstance(data, str):
            data = data.encode("utf-8")
        path.write_bytes(data or b"")
        return {"path": str(path), "written": len(data or b""),
                "sha256": hashlib.sha256(data or b"").hexdigest()}
    if action in ("mkdir", "remove", "chmod"):
        return {"path": str(path), "ok": True}
    return {"error": f"unsupported fs action {action}"}


# --------------------------------------------------------------------------
# file/operation audit doubles (op: audit-exec / read-file / list-files)
# --------------------------------------------------------------------------
HOST_ESCAPE_PREFIXES = (
    "/host", "/hostfs", "/mnt/host", "/var/lib/kubelet", "/var/lib/docker",
    "/var/run/docker.sock", "/run/docker.sock", "/run/containerd",
    "/var/run/containerd", "/sys/kernel/debug", "/dev/mem", "/dev/kmem",
    "/dev/kmsg", "/proc/sysrq-trigger", "/proc/kcore",
)
_PROC_ROOT_RE = re.compile(r"^/proc/(?:\d+|self|thread-self)/root(?:/|$)")


def _unsafe_path(path: str) -> str:
    raw = str(path or "").strip().replace("\\", "/")
    if not raw:
        return "empty path"
    if _PROC_ROOT_RE.match(raw):
        return "host escape via /proc/<pid>/root"
    for prefix in HOST_ESCAPE_PREFIXES:
        if raw == prefix or raw.startswith(prefix + "/"):
            return f"host path is out of scope: {prefix}"
    if ".." in [p for p in raw.split("/") if p]:
        return "path traversal is not allowed"
    return ""


def _env_digest(env: dict[str, str]) -> str:
    payload = json.dumps({str(k): str(v) for k, v in sorted(env.items())},
                         sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_file(args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("path") or "")
    reason = _unsafe_path(path)
    if reason:
        raise ValueError(f"refusing {path}: {reason}")
    max_bytes = min(max(int(args.get("max_bytes") or 1024 * 1024), 1), 16 * 1024 * 1024)
    raw = Path(path).read_bytes()
    chunk = raw[:max_bytes]
    return {
        "path": path, "exists": True, "size": len(raw), "bytes": len(chunk),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "data_b64": base64.b64encode(chunk).decode("ascii"),
        "text": chunk.decode("utf-8", "replace"),
        "eof": len(chunk) >= len(raw),
    }


def _list_files(args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("path") or "")
    reason = _unsafe_path(path)
    if reason:
        raise ValueError(f"refusing {path}: {reason}")
    pattern = str(args.get("pattern") or "")
    entries = []
    root = Path(path)
    for item in sorted(root.iterdir(), key=lambda p: p.name):
        if pattern and pattern.strip("*") not in item.name:
            continue
        entry = {"name": item.name, "path": str(item), "dir": item.is_dir(),
                 "size": item.stat().st_size if item.is_file() else 0}
        entries.append(entry)
        if len(entries) >= 4096:
            break
    return {"path": path, "exists": True, "count": len(entries), "entries": entries}


def _builtin_audit_exec(argv: list[str], cwd: str) -> dict[str, Any] | None:
    """便携仿真 cat/echo（Windows CI 没有 cat），保证断言跨平台一致。"""
    program = argv[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    base = Path(cwd) if cwd else None
    if program == "cat":
        stdout = b""
        opened = []
        for target in argv[1:]:
            if target.startswith("-"):
                continue
            reason = _unsafe_path(target)
            if reason:
                raise ValueError(f"refusing {target}: {reason}")
            path = Path(target)
            if base is not None and not path.is_absolute():
                path = base / path
            raw = path.read_bytes()
            stdout += raw
            opened.append({"path": str(path), "mode": "read", "fd": 3 + len(opened),
                           "size_bytes": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()})
        return {"exit_code": 0, "stdout": stdout, "stderr": b"", "opened_files": opened,
                "sampler": "fake-probe-argv"}
    if program == "echo":
        text = " ".join(argv[1:])
        return {"exit_code": 0, "stdout": (text + "\n").encode("utf-8"), "stderr": b"",
                "opened_files": [], "sampler": "fake-probe-argv"}
    return None


def _audit_exec(args: dict[str, Any]) -> dict[str, Any]:
    argv = [str(item) for item in args.get("argv") or []]
    if not argv:
        raise ValueError("audit-exec requires argv")
    cwd = str(args.get("cwd") or "")
    technique = str(args.get("technique") or "")
    timeout = min(max(int(args.get("timeout_ms") or 8000), 50), 120000) / 1000
    for item in argv:
        if item.startswith("/") or item.startswith("./") or item.startswith("../"):
            reason = _unsafe_path(item)
            if reason:
                raise ValueError(f"refusing {item}: {reason}")
    started = time.time()
    pid = os.getpid()
    env = {k: v for k, v in os.environ.items()
           if k not in ("INKBLADE_PROBE_TOKEN", "INKBLADE_PROBE_TOKEN_FILE")}
    builtin = _builtin_audit_exec(argv, cwd)
    if builtin is not None:
        stdout = builtin["stdout"]
        stderr = builtin["stderr"]
        exit_code = builtin["exit_code"]
        opened = builtin["opened_files"]
        sampler = builtin["sampler"]
        timed_out = False
    else:
        timed_out = False
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=env,
                                  cwd=cwd or None)
            stdout, stderr = proc.stdout, proc.stderr
            exit_code, pid = proc.returncode, proc.pid
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
            stderr = b"timeout"
            exit_code = -1
            timed_out = True
        opened, sampler = [], "fake-probe-argv"
    duration_ms = int((time.time() - started) * 1000)
    stdout_text = stdout.decode("utf-8", "replace")
    payload = {
        "exit_code": exit_code, "rc": exit_code,
        "stdout": stdout_text,
        "stderr": stderr.decode("utf-8", "replace"),
        "timed_out": timed_out, "duration_ms": duration_ms,
        "argv": argv, "cwd": cwd, "pid": pid,
        "clean_env": False,
    }
    audit = {
        "pid": pid, "argv": argv, "cwd": cwd, "technique": technique,
        "env_digest": _env_digest(env),
        "opened_files": opened,
        "stdout_hash": hashlib.sha256(stdout).hexdigest(),
        "duration_ms": duration_ms, "exit_code": exit_code,
        "sampler": sampler,
    }
    return {"exec": payload, "audit": audit}


def execute_template(template: dict[str, Any], params: dict[str, Any], task_id: str) -> dict[str, Any]:
    results = []
    variables: dict[str, Any] = dict(params)
    steps: dict[str, Any] = {}
    for step in template.get("steps") or []:
        sid = str(step.get("id") or f"step-{len(results)+1}")
        op = str(step.get("op") or "")
        if step.get("when") is False:
            continue
        try:
            if op == "http":
                value = _http_step(step)
            elif op == "tcp":
                value = _tcp_step(step)
            elif op == "exec":
                payload = _audit_exec({"argv": step.get("argv") or [],
                                       "timeout_ms": step.get("timeout_ms") or 8000})
                value = dict(payload["exec"])
                value["audit"] = payload["audit"]
            elif op == "fs":
                value = _fs_step(step)
            elif op == "assert":
                value = {"asserted": True}
            elif op == "sleep":
                time.sleep(min(10, int(step.get("ms") or 100) / 1000))
                value = {"slept": True}
            elif op == "spawn":
                proc = subprocess.Popen([str(x) for x in step.get("argv") or []],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                value = {"pid": proc.pid, "detached": bool(step.get("detach"))}
            else:
                raise ValueError(f"unsupported op {op}")
        except Exception as exc:  # noqa: BLE001
            results.append({"step": sid, "op": op, "ok": False, "error": str(exc)})
            return {"ok": False, "task_id": task_id, "probe_id": PROBE_ID,
                    "steps": results, "vars": variables, "error": str(exc)}
        steps[sid] = value
        variables[f"steps.{sid}"] = value
        variables["last"] = value
        results.append({"step": sid, "op": op, "ok": bool(value.get("ok", True)),
                        "result": value})
    return {"ok": True, "task_id": task_id, "probe_id": PROBE_ID,
            "parent_id": PARENT_ID, "steps": results, "vars": variables,
            "duration_ms": 1}


def handle_request(frame: dict[str, Any]) -> None:
    request_id = str(frame.get("id") or "")
    op = str(frame.get("op") or "")
    args = frame.get("args") or {}
    try:
        if op == "ping":
            data = {"pong": True, "probe_id": PROBE_ID}
        elif op == "beacon":
            data = {"probe_id": PROBE_ID, "parent_id": PARENT_ID, "read_only": True}
        elif op == "collect":
            data = _collect()
        elif op == "exec":
            data = _exec(args)
        elif op == "audit-exec":
            data = _audit_exec(args)
        elif op == "read-file":
            data = _read_file(args)
        elif op == "list-files":
            data = _list_files(args)
        elif op == "dial":
            data = _dial(args)
        elif op == "task":
            template = args.get("template")
            if not isinstance(template, dict):
                raise ValueError("task needs template")
            data = execute_template(template, args.get("params") or {},
                                    str(args.get("task_id") or request_id))
        elif op == "upload":
            path = str(args.get("path") or "")
            raw = base64.b64decode(args.get("data_b64") or "")
            offset = int(args.get("offset") or 0)
            target = Path(path)
            mode = "r+b" if target.exists() else "wb"
            with target.open(mode) as handle:
                handle.seek(offset)
                handle.write(raw)
            data = {"path": path, "offset": offset, "written": len(raw)}
            if args.get("final") and args.get("sha256"):
                got = hashlib.sha256(target.read_bytes()).hexdigest()
                if got != args["sha256"]:
                    raise ValueError(f"upload sha mismatch: {got}")
        elif op == "download":
            data = _fs_step({"action": "read", "path": str(args.get("path") or "")})
            offset = int(args.get("offset") or 0)
            raw = base64.b64decode(data.get("data_b64") or "")
            chunk = raw[offset:offset + int(args.get("max_bytes") or 1024 * 1024)]
            data = {"path": args.get("path"), "offset": offset,
                    "next_offset": offset + len(chunk), "eof": offset + len(chunk) >= len(raw),
                    "data_b64": base64.b64encode(chunk).decode("ascii")}
        elif op == "spawn":
            child = str(args.get("probe_id") or "fake-child")
            data = {"probe_id": child, "parent_id": PROBE_ID, "registered": True,
                    "path": args.get("path") or "/tmp/fake-child"}
        elif op == "cleanup":
            removed = []
            for path in args.get("paths") or []:
                try:
                    Path(path).unlink()
                    removed.append(path)
                except OSError:
                    pass
            data = {"removed": removed, "children": 0}
        elif op == "socks":
            data = {"address": "127.0.0.1:0", "bind": "127.0.0.1"}
        elif op == "k8s":
            data = {"ok": True, "stdout": "", "kind": "List", "items": []}
        else:
            raise ValueError(f"unknown op {op}")
        write_frame({"v": 1, "type": "resp", "id": request_id, "ok": True, "data": data})
    except Exception as exc:  # noqa: BLE001
        write_frame({"v": 1, "type": "resp", "id": request_id, "ok": False,
                     "error": {"code": "fake_error", "message": str(exc)}})


def main() -> int:
    args = sys.argv[1:]
    token = os.environ.get("INKBLADE_PROBE_TOKEN", "")
    index = 0
    read_only = True
    while index < len(args):
        if args[index] == "--token":
            token = args[index + 1]
            index += 2
        elif args[index] == "--token-file":
            token = Path(args[index + 1]).read_text(encoding="utf-8").strip()
            index += 2
        elif args[index] == "--read-only":
            read_only = True
            index += 1
        elif args[index] == "--allow-write":
            read_only = False
            index += 1
        else:
            index += 1
    os.environ["FAKE_READ_ONLY"] = "1" if read_only else "0"
    if not token:
        print("fake probe: missing token", file=sys.stderr)
        return 2
    try:
        auth(token)
    except (EOFError, ValueError, SystemExit) as exc:
        print(f"fake probe auth: {exc}", file=sys.stderr)
        return 3
    while True:
        try:
            frame = read_frame(sys.stdin.buffer)
        except (EOFError, ValueError):
            break
        if frame is None:
            break
        kind = frame.get("type")
        if kind == "req":
            handle_request(frame)
        elif kind == "data":
            sid = int(frame.get("stream") or 0)
            with STREAM_LOCK:
                sock = STREAMS.get(sid)
            if sock:
                try:
                    sock.sendall(base64.b64decode(frame.get("data") or ""))
                except OSError:
                    pass
        elif kind == "stream-eof":
            sid = int(frame.get("stream") or 0)
            with STREAM_LOCK:
                sock = STREAMS.get(sid)
            if sock:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        elif kind == "stream-close":
            sid = int(frame.get("stream") or 0)
            with STREAM_LOCK:
                sock = STREAMS.pop(sid, None)
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
    with STREAM_LOCK:
        for sock in STREAMS.values():
            try:
                sock.close()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
