"""Minimal deterministic LLM endpoint for the promptfoo bench.

The server echoes the prompt with an ``OK`` prefix so a contains assertion can
verify that every case reached the provider.  It never calls an external model.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class LLMHandler(BaseHTTPRequestHandler):
    server_version = "inkblade-oss-bench-mock-llm/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}
        prompt = body.get("prompt") or ""
        if not prompt and isinstance(body.get("messages"), list):
            prompt = " ".join(str(m.get("content", "")) for m in body["messages"] if isinstance(m, dict))
        # Echo a bounded prefix; deterministic and no secret material.
        self._send(200, {"output": ("OK " + prompt)[:2000], "model": "mock-llm"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockLLM:
    def __init__(self, host: str = "127.0.0.1", port: int = 18082):
        self.host = host
        self.port = port
        self.server: _Server | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "MockLLM":
        self.server = _Server((self.host, self.port), LLMHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)


if __name__ == "__main__":
    with MockLLM():
        print("mock LLM on http://127.0.0.1:18082 (POST any JSON, returns {'output': 'OK ...'})")
        threading.Event().wait()
