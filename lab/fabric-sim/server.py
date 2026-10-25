# -*- coding: utf-8 -*-
"""把仿真 telemetry 暴露为产品 fabric 模块可消费的 HTTP 端点。

仅用于 lab：`roce-pfc-storm` / `nccl-straggler-injection` 的 probe-only 或
backup-write 会在本端点读写计数；不会触碰真实交换机。
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from .sim import Telemetry
except ImportError:
    from sim import Telemetry


class FabricState:
    def __init__(self, telemetry: Telemetry):
        self.pfc = int(telemetry.pfc_pause_frames)
        self.ecn = int(telemetry.ecn_marks)
        self.storm = telemetry.scenario == "pfc-storm"
        self.base_step_ms = max(1.0, round(telemetry.median_completion_ms or 100.0, 3))
        self.straggler_ms = 0
        self.lock = threading.Lock()

    def step_ms(self) -> float:
        return round(self.base_step_ms + self.straggler_ms, 3)


class _Handler(BaseHTTPRequestHandler):
    state: FabricState = None  # type: ignore[assignment]

    def log_message(self, *args):
        pass

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(length) or b"{}") if length else {}
        except ValueError:
            return {}

    def do_GET(self):
        st = self.state
        if self.path == "/roce/pfc":
            return self._json(200, {"service": "roce-pfc", "pfc": {
                "enabled": True, "storm": st.storm,
                "interfaces": ["rail-0", "rail-1"]},
                "pfc_pause_frames": st.pfc, "ecn_marks": st.ecn})
        if self.path == "/metrics":
            return self._json(200, {"roce": {"pfc_pause_frames": st.pfc,
                                             "ecn_marks": st.ecn,
                                             "storm_active": st.storm},
                                    "nccl": {"worst_straggler_ms": st.straggler_ms}})
        if self.path == "/train/step":
            return self._json(200, {"step_ms": st.step_ms()})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        st = self.state
        body = self._body()
        if self.path == "/roce/pfc":
            if body.get("mode") == "storm":
                with st.lock:
                    st.storm = True
                    st.pfc += 25000
                    st.ecn += 2500
                return self._json(200, {"service": "roce-pfc", "op": "storm",
                                        "pfc_pause_frames": st.pfc,
                                        "storm_active": True})
            return self._json(200, {"service": "roce-pfc", "op": "configure"})
        if self.path == "/nccl/rank":
            with st.lock:
                st.straggler_ms = max(st.straggler_ms, int(body.get("straggler_ms") or 0))
            return self._json(200, {"service": "nccl-rank", "op": "straggler",
                                    "worst_straggler_ms": st.straggler_ms})
        if self.path == "/train/step":
            return self._json(200, {"step_ms": st.step_ms()})
        return self._json(404, {"error": "not found"})


class TelemetryServer:
    def __init__(self, telemetry: Telemetry, host: str = "127.0.0.1", port: int = 0):
        self.state = FabricState(telemetry)
        handler = type("BoundHandler", (_Handler,), {"state": self.state})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self): self.thread.start(); return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def __enter__(self): return self.start()
    def __exit__(self, *exc): self.stop()
