# -*- coding: utf-8 -*-
"""Mock probe range: real HTTP, TCP, Unix-socket and Kubernetes API surfaces.

Every dynamic template test runs against this range.  Two-state scenarios
(``vulnerable`` / ``fixed`` or ``deployed`` / ``degraded``) are switched through
``/__profile__/<name>`` or the ``X-Range-Profile`` header, so one template can be
verified for both a finding and its negative control.

No third-party dependencies; the range is a test/lab component only.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_ROUTES: dict[str, dict] = {
    "/healthz": {"status": 200, "json": {"ok": True}},
    "/v1/models": {"status": 200, "json": {"object": "list",
                                           "data": [{"id": "lab-model", "object": "model"}]}},
    "/version": {"status": 200, "json": {"version": "0.0.0-lab"}},
    "/__cleanup__": {"status": 200, "json": {"deleted": 0}},
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: N802 - stdlib hook
        pass

    def _profile(self) -> str:
        header = str(self.headers.get("X-Range-Profile") or "").strip()
        if header:
            return header
        return self.server.range.profile

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/__profile__/"):
            name = path.rsplit("/", 1)[-1]
            self.server.range.profile = name
            return {"status": 200, "json": {"profile": name}}, path, {}
        if path == "/__requests__":
            return {"status": 200, "json": {"requests": self.server.range.requests}}, path, {}
        if path == "/__echo__":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            return {"status": 200, "json": {
                "method": self.command, "path": path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace")}}, path, {}
        routes = self.server.range.routes_for(self._profile())
        route = routes.get(path)
        if route is None:
            for key, value in routes.items():
                if key.endswith("*") and path.startswith(key[:-1]):
                    route = value
                    break
        return route or {"status": 404, "json": {"error": "not found", "path": path}}, path, \
            dict(urllib.parse.parse_qsl(parsed.query))

    def _serve(self):
        route, path, query = self._route()
        if callable(route):
            route = route(self, path, query) or {"status": 200}
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""
        if self.server.range.record:
            self.server.range.requests.append({
                "method": self.command, "path": path, "query": query,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": raw_body.decode("utf-8", "replace"),
                "profile": self._profile(), "ts": time.time()})
        status = int(route.get("status") or 200)
        if route.get("delay_ms"):
            time.sleep(float(route["delay_ms"]) / 1000.0)
        if "json" in route:
            payload = json.dumps(route["json"], ensure_ascii=False).encode("utf-8")
            content_type = "application/json"
        elif "text" in route:
            payload = str(route["text"]).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            payload = b""
            content_type = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (route.get("headers") or {}).items():
            self.send_header(str(key), str(value))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _serve
    do_POST = _serve
    do_PUT = _serve
    do_PATCH = _serve
    do_DELETE = _serve
    do_HEAD = _serve


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class Range:
    """A running mock range.  Use as a context manager."""

    def __init__(self, scenarios: dict[str, dict[str, dict]] | None = None,
                 *, workdir: str | Path | None = None, record: bool = True,
                 k8s_objects: dict | None = None):
        self.scenarios = {"vulnerable": {**DEFAULT_ROUTES, **(scenarios or {}).get("vulnerable", {})},
                          "fixed": {**DEFAULT_ROUTES, **(scenarios or {}).get("fixed", {})}}
        self.profile = "vulnerable"
        self.requests: list[dict] = []
        self.record = record
        self.workdir = Path(workdir or tempfile.mkdtemp(prefix="inkblade-range-"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._http: _Server | None = None
        self._k8s: FakeK8s | None = None
        self._tcp: socketserver.TCPServer | None = None
        self._unix: socketserver.ThreadingUnixStreamServer | None = None
        self._threads: list[threading.Thread] = []
        self.k8s_objects = k8s_objects or {}

    # -- lifecycle ------------------------------------------------------
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def start(self):
        self._http = _Server(("127.0.0.1", 0), _Handler)
        self._http.range = self
        self._spawn(self._http.serve_forever)
        self._tcp = _TcpServer(("127.0.0.1", 0), _TcpHandler)
        self._tcp.range = self
        self._spawn(self._tcp.serve_forever)
        if hasattr(socketserver, "ThreadingUnixStreamServer") and os.name == "posix":
            path = str(self.workdir / "range.sock")
            self._unix = socketserver.ThreadingUnixStreamServer(path, _UnixHandler)
            self._unix.range = self
            self._spawn(self._unix.serve_forever)
            self.sock_path = path
        else:
            # Windows: provide a file-backed socket-like surface for fs/socks tests
            self.sock_path = str(self.workdir / "fake.sock")
        self._k8s = FakeK8s(self.k8s_objects)
        self._k8s.start()
        return self

    def _spawn(self, target):
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        self._threads.append(thread)

    def stop(self):
        for server in (self._http, self._tcp, self._unix):
            if server is not None:
                try:
                    server.shutdown()
                    server.server_close()
                except Exception:  # noqa: BLE001
                    pass
        if self._k8s is not None:
            self._k8s.stop()

    # -- accessors ------------------------------------------------------
    def routes_for(self, profile: str) -> dict:
        return self.scenarios.get(profile) or self.scenarios.get("vulnerable") or {}

    def url(self, path: str = "") -> str:
        host, port = self._http.server_address[:2]
        return f"http://{host}:{port}{path}"

    @property
    def tcp_port(self) -> int:
        return int(self._tcp.server_address[1])

    @property
    def k8s_url(self) -> str:
        return self._k8s.url if self._k8s else ""

    def fixture(self, name: str, data: Any, *, as_json: bool = True) -> str:
        path = self.workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if as_json:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        else:
            path.write_text(str(data), encoding="utf-8")
        return str(path)

    def set_profile(self, name: str):
        self.profile = name

    def write_rule_file(self, product: str, rules: list[str]) -> str:
        return self.fixture(f"rules/{product}.json", {"product": product, "rules": rules})

    def reset_requests(self):
        self.requests.clear()


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(4096)
            profile = self.server.range.profile
            if b"PING" in data:
                self.request.sendall(b"+PONG\r\n")
            elif profile == "fixed":
                self.request.sendall(b"-ERR closed\r\n")
            else:
                self.request.sendall(b"+OK\r\n")
        except OSError:
            pass


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UnixHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(4096)
            text = data.decode("utf-8", "replace")
            if "docker" in text.lower() or text.startswith("GET"):
                self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"
                                     b'{"ApiVersion":"1.45","Server":{"Name":"lab"}}')
            else:
                self.request.sendall(b"OK\n")
        except OSError:
            pass


class FakeK8s:
    """Read/write Kubernetes API with service-account token semantics."""

    def __init__(self, objects: dict | None, token: str = "lab-sa-token"):
        self.objects = objects or {}
        self.token = token
        self.writes: list[dict] = []
        self._server: _Server | None = None
        self.url = ""

    def start(self):
        k8s = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _send(self, status: int, payload):
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                auth = str(self.headers.get("Authorization") or "")
                if k8s.token and auth != f"Bearer {k8s.token}":
                    return self._send(401, {"kind": "Status", "code": 401,
                                            "message": "Unauthorized"})
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                doc = None
                if body:
                    try:
                        doc = json.loads(body)
                    except ValueError:
                        doc = {"raw": body.decode("utf-8", "replace")}
                parts = [p for p in path.split("/") if p]
                resource, name = "", ""
                if "namespaces" in parts:
                    idx = parts.index("namespaces")
                    if len(parts) > idx + 2:
                        resource = parts[idx + 2]
                    if len(parts) > idx + 3:
                        name = parts[idx + 3]
                elif len(parts) >= 2:
                    resource = parts[-1]
                    if len(parts) >= 3 and parts[-2] not in ("v1", "api", "apis"):
                        # /apis/group/version/resource/name
                        if len(parts) >= 4:
                            resource, name = parts[-2], parts[-1]
                items = k8s.objects.get(resource) or k8s.objects.get(resource.rstrip("s")) or []
                if name and isinstance(items, list):
                    items = [i for i in items if (i.get("metadata") or {}).get("name") == name]
                if self.command == "GET":
                    if name:
                        if not items:
                            return self._send(404, {"kind": "Status", "code": 404})
                        return self._send(200, items[0])
                    return self._send(200, {"kind": "List", "apiVersion": "v1", "items": items})
                k8s.writes.append({"method": self.command, "path": path, "body": doc})
                if self.command == "POST":
                    return self._send(201, doc or {})
                return self._send(200, doc or {"status": "ok"})

            do_GET = _handle
            do_POST = _handle
            do_PATCH = _handle
            do_DELETE = _handle

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._server.range = self
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}"
        return self

    def stop(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:  # noqa: BLE001
                pass


def simple_range(*, vulnerable: dict | None = None, fixed: dict | None = None,
                 **kwargs) -> Range:
    return Range({"vulnerable": vulnerable or {}, "fixed": fixed or {}}, **kwargs)
