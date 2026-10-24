"""本地 Web API（标准库 http.server）：登录/工作区隔离/执行闸门（授权锁 423）。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..core.evidence import EvidenceStore
from ..core.roe import roe_status
from ..core.users import UserStore

_STATIC = Path(__file__).parent / "static"


class _Handler(BaseHTTPRequestHandler):
    users: UserStore = None  # type: ignore[assignment]
    root: Path = None  # type: ignore[assignment]
    abort_flag = False

    def log_message(self, *a):  # 静默
        pass

    # ---------- helpers ----------
    def _json(self, code: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _session(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return self.users.session(auth[7:])

    def _ws_store(self, session, ws: str):
        return session.open_store(self.root, ws)

    # ---------- routes ----------
    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/login":
            b = self._body()
            s = self.users.verify(b.get("name", ""), b.get("password", ""))
            if s is None:
                return self._json(401, {"error": "invalid credentials"})
            return self._json(200, {"token": s.token, "role": s.role})
        if u.path == "/api/execute":
            s = self._session()
            if s is None:
                return self._json(401, {"error": "login required"})
            b = self._body()
            ws = b.get("workspace", "local-lab")
            try:
                store = self._ws_store(s, ws)
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            if roe_status(store) != "complete":
                return self._json(423, {"error": "工作区授权未完成（consent 未签署）"})
            from ..core.runner import run_module  # 延迟导入（模块目录可能不存在）

            try:
                result = run_module(store, s, b.get("module", ""), b.get("params", {}),
                                    modules_dir=self.root / "modules")
            except KeyError as e:
                return self._json(404, {"error": str(e)})
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            except Exception as e:  # BackupGateRefused 等
                return self._json(409, {"error": str(e), "class": type(e).__name__})
            return self._json(200, result)
        if u.path == "/api/abort":
            _Handler.abort_flag = True
            return self._json(200, {"abort": True})
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            html = (_STATIC / "index.html").read_text(encoding="utf-8") if (_STATIC / "index.html").exists() else "<html><body>Trident</body></html>"
            payload = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            return self.wfile.write(payload)
        if u.path == "/api/runs":
            s = self._session()
            if s is None:
                return self._json(401, {"error": "login required"})
            q = parse_qs(u.query)
            ws = (q.get("workspace") or ["local-lab"])[0]
            try:
                store = self._ws_store(s, ws)
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            runs = []
            if store.ws_dir.exists():
                runs = sorted(p.name for p in store.ws_dir.iterdir() if p.is_dir() and not p.name.startswith("_"))
            return self._json(200, {"runs": runs})
        return self._json(404, {"error": "not found"})


def make_server(root: Path | str, users: UserStore, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (_Handler,), {"users": users, "root": Path(root)})
    httpd = ThreadingHTTPServer((host, port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd
