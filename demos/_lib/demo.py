"""Local-only demo harness for the InkBlade vulnerability-layer document.

Every runnable demo:
  * binds or connects only to 127.0.0.1 / ::1;
  * writes only ``INKBLADE-BENIGN-*`` markers under ``demos/.work/<id>/``;
  * removes its work directory in ``finally`` (or with ``--cleanup``);
  * accepts ``--help``, ``--target``, ``--marker`` and ``--cleanup``.

The module deliberately uses the Python standard library only.  It is a mock
primitive demonstrator, not an exploit framework and not a scanner.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib
import json
import os
import pickle
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
DEFAULT_TARGET = "127.0.0.1:0"
DEFAULT_KEY = "INKBLADE-BENIGN-DEFAULT-KEY"
WORK_ROOT = Path(__file__).resolve().parent.parent / ".work"


def parse_target(value: str) -> tuple[str, int]:
    """Return (host, port); reject anything that is not a loopback address."""
    text = (value or DEFAULT_TARGET).strip()
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        host, port = parsed.hostname or "", parsed.port or 0
    elif text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = int(rest.lstrip(":") or 0)
    else:
        host, _, raw_port = text.rpartition(":")
        if not host:
            host, raw_port = text, "0"
        port = int(raw_port or 0)
    if host not in LOOPBACK:
        raise SystemExit(f"refusing non-loopback target: {host!r}; use 127.0.0.1")
    if not 0 <= port <= 65535:
        raise SystemExit(f"invalid port: {port}")
    return host, port


def safe_id(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in text)[:120]


def work_dir(spec: dict) -> Path:
    path = WORK_ROOT / safe_id(str(spec.get("id") or "demo"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_work(spec: dict) -> int:
    path = WORK_ROOT / safe_id(str(spec.get("id") or "demo"))
    shutil.rmtree(path, ignore_errors=True)
    print(f"cleanup: removed {path.as_posix()}")
    return 0


def parse_args(default_marker: str, argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local-only benign demo (127.0.0.1); writes a marker and cleans up.",
        epilog="Example: ./run.sh --marker INKBLADE-BENIGN-DEMO --cleanup",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help="loopback host:port, default 127.0.0.1:0 (ephemeral)")
    parser.add_argument("--marker", default=default_marker,
                        help="benign marker written by the demo")
    parser.add_argument("--cleanup", action="store_true",
                        help="remove the demo work directory and exit")
    parser.add_argument("--keep", action="store_true",
                        help="keep the work directory for inspection")
    args = parser.parse_args(argv)
    parse_target(args.target)
    if not args.marker.startswith("INKBLADE-BENIGN-"):
        raise SystemExit("marker must start with INKBLADE-BENIGN-")
    return args


class _Handler(BaseHTTPRequestHandler):
    spec: dict = {}
    marker: str = ""

    def log_message(self, *_args):  # silence per-request logging
        return

    def _send(self, status: int, body: str, ctype: str = "application/json"):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        path = urllib.parse.urlsplit(self.path).path
        route = str(self.spec.get("route") or "/")
        if route.endswith("*"):
            ok = path.startswith(route[:-1])
        else:
            ok = path == route
        if not ok:
            self._send(404, json.dumps({"error": "not_found", "path": path}))
            return
        require = self.spec.get("require_key")
        if require:
            expected = str(self.spec.get("key") or DEFAULT_KEY)
            got = self.headers.get("Authorization", "")
            if got != f"Bearer {expected}":
                self._send(401, json.dumps({"error": "unauthorized"}))
                return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if self.spec.get("kind") == "pprof":
            self._send(200, f"{self.marker}\n{path}\nbenign profile bytes\n", "text/plain")
            return
        payload = {
            "ok": True,
            "marker": self.marker,
            "effect": self.spec.get("effect") or "mock effect reached",
            "path": path,
            "request_body": body[:256],
        }
        self._send(int(self.spec.get("expect_status") or 200),
                   json.dumps(payload, ensure_ascii=False))

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle


def start_http(spec: dict, marker: str) -> tuple[ThreadingHTTPServer, threading.Thread]:
    _Handler.spec = spec
    _Handler.marker = marker
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def http_request(port: int, method: str, path: str, payload: dict | None = None,
                 headers: dict | None = None) -> dict:
    data = None
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers=hdrs, method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "replace")
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8", "replace"),
                "headers": dict(exc.headers)}


def write_marker(path: str, marker: str) -> None:
    Path(path).write_text(marker + "\n", encoding="utf-8")


def make_pickle(path: Path, marker: str) -> bytes:
    class _Benign:
        def __reduce__(self):
            return (write_marker, (str(path), marker))

    return pickle.dumps(_Benign(), protocol=4)


def _http_demo(spec: dict, marker: str, target: str) -> dict:
    _host, port = parse_target(target)
    server, _thread = start_http(spec, marker)
    try:
        if port:
            server.server_close()
            _Handler.spec = spec
            _Handler.marker = marker
            server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        actual = server.server_address[1]
        result = http_request(actual, str(spec.get("method") or "GET"),
                              str(spec.get("route") or "/"),
                              spec.get("payload"), spec.get("headers"))
        result["port"] = actual
        return result
    finally:
        server.shutdown()
        server.server_close()


def _pprof_demo(spec: dict, marker: str, target: str) -> dict:
    spec = {**spec, "kind": "pprof"}
    return _http_demo(spec, marker, target)


def _ssrf_demo(spec: dict, marker: str, target: str) -> dict:
    inner = {"id": str(spec.get("id")) + "-inner", "route": "/secret",
             "effect": "internal service marker"}
    server, _thread = start_http(inner, marker)
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/secret"
        outer = {"route": str(spec.get("route") or "/media"),
                 "effect": "server-side fetch of loopback URL"}
        outer_server, _t = start_http(outer, marker)
        try:
            outer_port = outer_server.server_address[1]
            result = http_request(outer_port, "GET",
                                  f"{outer['route']}?url={urllib.parse.quote(url, safe='')}")
            result["fetched"] = url
            return result
        finally:
            outer_server.shutdown()
            outer_server.server_close()
    finally:
        server.shutdown()
        server.server_close()


def _pickle_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    folder = work_dir(spec)
    marker_path = folder / "marker.txt"
    payload = make_pickle(marker_path, marker)
    loaded = pickle.loads(payload)
    text = marker_path.read_text(encoding="utf-8").strip()
    return {"status": 200, "marker": marker, "body": text,
            "effect": "benign pickle __reduce__ executed", "loaded": str(loaded)}


def _import_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    folder = work_dir(spec)
    name = "demo_pkg_" + uuid.uuid4().hex[:8]
    pkg = folder / name
    pkg.mkdir(parents=True, exist_ok=True)
    marker_path = folder / "marker.txt"
    (pkg / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker_path)!r}).write_text({marker!r} + '\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    sys.path.insert(0, str(folder))
    try:
        importlib.invalidate_caches()
        importlib.import_module(name)
    finally:
        sys.path.remove(str(folder))
    return {"status": 200, "marker": marker,
            "body": marker_path.read_text(encoding="utf-8").strip(),
            "effect": "import-time code executed"}


def _exec_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    folder = work_dir(spec)
    marker_path = folder / "marker.txt"
    code = f"open({str(marker_path)!r}, 'w', encoding='utf-8').write({marker!r} + '\\n')"
    exec(compile(code, "<benign-demo>", "exec"), {})
    return {"status": 200, "marker": marker,
            "body": marker_path.read_text(encoding="utf-8").strip(),
            "effect": "eval/exec primitive executed"}


def _path_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    folder = work_dir(spec)
    victim = folder / "victim.txt"
    victim.write_text(marker + "\n", encoding="utf-8")
    uploads = folder / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    requested = str(spec.get("payload") or "../victim.txt")
    joined = os.path.join(str(uploads), requested)
    text = Path(joined).read_text(encoding="utf-8").strip()
    return {"status": 200, "marker": marker, "body": text,
            "effect": "path traversal read outside uploads/", "resolved": joined}


def _command_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    folder = work_dir(spec)
    marker_path = folder / "marker.txt"
    code = f"open({str(marker_path)!r}, 'w', encoding='utf-8').write({marker!r} + '\\n')"
    subprocess.run([sys.executable, "-c", code], check=True, timeout=20)
    return {"status": 200, "marker": marker,
            "body": marker_path.read_text(encoding="utf-8").strip(),
            "effect": "command execution primitive reached"}


def _jwt_demo(spec: dict, marker: str, target: str) -> dict:
    _host, _port = parse_target(target)
    key = str(spec.get("key") or DEFAULT_KEY).encode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "demo", "tenant": "tenant-a"}).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(hmac.new(key, payload, hashlib.sha256).digest()).rstrip(b"=")
    token = (payload + b"." + sig).decode()
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    got = base64.urlsafe_b64decode(sig + b"=" * (-len(sig) % 4))
    if not hmac.compare_digest(expected, got):
        raise SystemExit("token verification failed")
    return {"status": 200, "marker": marker, "body": token,
            "effect": "token forged with shipped default key"}


def _tcp_demo(spec: dict, marker: str, target: str) -> dict:
    host, _port = parse_target(target)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    result: dict = {}

    def serve():
        conn, _addr = listener.accept()
        with conn:
            data = conn.recv(4096).decode("utf-8", "replace")
            folder = work_dir(spec)
            path = folder / "marker.txt"
            path.write_text(marker + "\n", encoding="utf-8")
            result.update({"received": data, "body": marker, "status": 200})
            conn.sendall(b"ACK " + marker.encode())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall((str(spec.get("payload") or marker)).encode())
        ack = client.recv(4096).decode("utf-8", "replace")
    thread.join(timeout=5)
    listener.close()
    return {"status": result.get("status", 200), "marker": marker,
            "body": result.get("body", marker), "effect": "collective channel join",
            "ack": ack, "port": port}


DISPATCH = {
    "http": _http_demo,
    "pprof": _pprof_demo,
    "ssrf": _ssrf_demo,
    "pickle": _pickle_demo,
    "import": _import_demo,
    "exec": _exec_demo,
    "path": _path_demo,
    "command": _command_demo,
    "jwt": _jwt_demo,
    "tcp": _tcp_demo,
}


def run_demo(spec: dict, target: str = DEFAULT_TARGET,
             marker: str | None = None) -> dict:
    host, _port = parse_target(target)
    marker = marker or str(spec.get("marker") or "INKBLADE-BENIGN-DEMO")
    kind = str(spec.get("kind") or "http")
    if kind not in DISPATCH:
        raise SystemExit(f"unknown demo kind: {kind}")
    result = DISPATCH[kind]({**spec, "id": spec.get("id") or "demo"}, marker, target)
    result.setdefault("id", spec.get("id"))
    result.setdefault("target", f"{host}:{_port}")
    return result


def cli(spec: dict, default_marker: str, demo_fn=None, argv: list[str] | None = None) -> int:
    args = parse_args(default_marker, argv)
    if args.cleanup:
        return cleanup_work(spec)
    spec = {**spec, "marker": args.marker}
    try:
        if demo_fn is not None:
            return int(demo_fn(args) or 0)
        result = run_demo(spec, target=args.target, marker=args.marker)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if not args.keep:
            cleanup_work(spec)
