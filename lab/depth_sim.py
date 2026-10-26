# -*- coding: utf-8 -*-
"""lab.depth_sim — two-state vLLM/SGLang operator surface for depth fuzzing.

Only 127.0.0.1, standard library.  ``vulnerable`` models a deployment whose
edge proxy and application disagree about path canonicalization and proxy
headers; ``fixed`` canonicalizes and enforces auth on every operator surface.
No real model, GPU, pickle or file write is involved.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
ADMIN_TOKEN = "admin-token"
SURFACES = {
    "/admin/config": "admin",
    "/plugins/list": "plugin",
    "/dev/exec": "dev-mode",
    "/update_weights_from_tensor": "serialization",
    "/pull_weights": "weights",
}
CONTROL = "/v1/models"


def _canonical(raw_path: str) -> str:
    path = unquote(urlsplit(raw_path).path or "/").lower()
    path = re.sub(r";.*$", "", path)
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _parse_body(raw: bytes):
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {"raw_len": len(raw)}


class _State:
    def __init__(self, mode: str):
        self.mode = mode
        self.lock = threading.Lock()
        self.requests = 0
        self.by_path: dict[str, int] = {}
        self.by_surface: dict[str, int] = {}

    def record(self, path: str, surface: str):
        with self.lock:
            self.requests += 1
            self.by_path[path] = self.by_path.get(path, 0) + 1
            self.by_surface[surface] = self.by_surface.get(surface, 0) + 1


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_admin(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {ADMIN_TOKEN}":
            return True
        if self.server.state.mode == "vulnerable":
            return self.headers.get("X-Forwarded-User", "").lower() == "admin"
        return False

    def _effective_method(self) -> str:
        method = self.command.upper()
        if self.server.state.mode == "vulnerable":
            override = self.headers.get("X-HTTP-Method-Override", "").upper()
            if override:
                return override
        return method

    def _route(self) -> tuple[str | None, str]:
        raw = self.path
        strict = urlsplit(raw).path
        if self.server.state.mode == "vulnerable":
            canon = _canonical(raw)
            for path, surface in SURFACES.items():
                if canon == path:
                    return surface, path
            if canon == CONTROL:
                return "control", CONTROL
            if canon == "/health":
                return "health", "/health"
            return None, canon
        if strict in SURFACES:
            return SURFACES[strict], strict
        if strict == CONTROL:
            return "control", CONTROL
        if strict == "/health":
            return "health", "/health"
        return None, strict

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = _parse_body(self.rfile.read(length) if length else b"")
        surface, path = self._route()
        self.server.state.record(self.path, surface or "unknown")
        if surface == "health":
            return self._send(200, {"status": "ok", "mode": self.server.state.mode})
        if surface is None:
            return self._send(404, {"error": "not found", "path": path})
        method = self._effective_method()
        expected = "POST" if surface in ("dev-mode", "serialization") else "GET"
        if surface == "control":
            expected = "GET"
        if method != expected:
            return self._send(405, {"error": "method not allowed", "method": method,
                                    "surface": surface})
        admin = self._auth_admin()
        mode = self.server.state.mode
        if surface == "control":
            if admin:
                return self._send(200, {"object": "list", "data": [{"id": "mock-model"}]})
            return self._send(401, {"error": "api key required", "surface": surface})
        if mode == "fixed":
            if surface in ("dev-mode", "serialization"):
                return self._send(403, {"error": "operator surface disabled",
                                        "surface": surface})
            if not admin:
                return self._send(401, {"error": "auth required", "surface": surface})
            return self._send(200, {"applied": True, "surface": surface,
                                    "mode": mode, "api_key_tail4": "MOCK"})
        # vulnerable: every operator surface is reachable without auth; the
        # proxy header and path aliases are accepted by design of this state.
        return self._send(200, {
            "applied": True,
            "surface": surface,
            "mode": mode,
            "plugin": "mock-plugin" if surface == "plugin" else None,
            "weights": ["mock-shard-0"] if surface == "weights" else None,
            "dev_enabled": surface == "dev-mode",
            "pickle_accepts": surface == "serialization",
            "api_key_tail4": "MOCK",
            "body_keys": sorted(body) if isinstance(body, dict) else [],
        })

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle


class Server:
    def __init__(self, mode: str, httpd: ThreadingHTTPServer):
        self.mode = mode
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.state = httpd.state

    def url(self, path: str = "") -> str:
        if path and not path.startswith("/"):
            path = "/" + path
        return f"http://{HOST}:{self.port}{path}"

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def start_all(mode: str = "vulnerable", port: int = 0) -> Server:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode}")
    httpd = ThreadingHTTPServer((HOST, port), _Handler)
    httpd.state = _State(mode)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return Server(mode, httpd)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="vulnerable", choices=MODES)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = start_all(args.mode, args.port)
    print(server.url("/health"))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
