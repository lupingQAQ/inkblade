"""本地 Web API（标准库 http.server）：登录/工作区隔离/执行闸门（授权锁 423）。

XBow 对标 ⑥（API-first）：在既有 /api/login、/api/execute、/api/runs 之上补全
REST 端点（/api/v1/*）：assets / explorer / scheduler / traffic+replay / consent /
zeroday / rules / poc。权限与授权语义：
- 登录必须；工作区越权一律 403（Session.open_store）；
- 执行类路径（explorer.execute、scheduler.run-due、traffic.replay live、poc.reverify）
  在 ROE 未签署时 423，与 CLI/runner 同一把锁；
- 审批类路径（explorer.approve/reject、consent.sign、scheduler.add、zeroday.enable）
  要求 lead/admin 能力位；MCP 侧只暴露同数据源的只读工具。
"""

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

    def _auth(self, body: dict | None = None):
        """登录 + 工作区解析（POST 用已解析 body，GET 用 query）；返回 (session, store, ws)。"""
        session = self._session()
        if session is None:
            self._json(401, {"error": "login required"})
            return None, None, None
        if body is None:
            body = {}
        q = parse_qs(urlparse(self.path).query)
        ws = body.get("workspace") or (q.get("workspace") or ["local-lab"])[0]
        try:
            return session, self._ws_store(session, ws), ws
        except PermissionError as e:
            self._json(403, {"error": str(e)})
            return None, None, None

    @staticmethod
    def _roe_guard(store) -> dict | None:
        if roe_status(store) != "complete":
            return {"code": 423, "error": "工作区授权未完成（consent 未签署）"}
        return None

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
        return self._api_v1_post(u.path)

    # ---------- /api/v1 POST ----------
    def _api_v1_post(self, path: str):
        from ..core import discovery, explorer as explorer_mod, poc as poc_mod, traffic as traffic_mod
        from ..core.roe import ExecutionLocked, init_roe
        from ..core.scheduler import ScheduleError, Scheduler
        from ..core.zeroday import enable as zd_enable

        b = self._body()

        if path == "/api/v1/assets/discover":
            session, store, ws = self._auth(b)
            if session is None:
                return
            try:
                diff = discovery.AssetInventory(store).ingest(b.get("seeds") or {},
                                                              source=b.get("source", "api"))
            except ValueError as e:
                return self._json(400, {"error": str(e), "class": type(e).__name__})
            return self._json(200, {"workspace": ws, "diff": diff})

        if path == "/api/v1/explorer/propose":
            session, store, ws = self._auth(b)
            if session is None:
                return
            ex = explorer_mod.Explorer(store, modules_dir=self.root / "modules")
            try:
                proposal = ex.propose(session, use_llm=b.get("use_llm"),
                                      max_actions=int(b.get("max_actions", 5)))
            except Exception as e:
                return self._json(400, {"error": str(e), "class": type(e).__name__})
            return self._json(200, {"workspace": ws, "proposal": proposal})

        if path in ("/api/v1/explorer/approve", "/api/v1/explorer/reject",
                    "/api/v1/explorer/execute"):
            session, store, ws = self._auth(b)
            if session is None:
                return
            ex = explorer_mod.Explorer(store, modules_dir=self.root / "modules")
            pid = b.get("id", "")
            try:
                if path.endswith("/approve"):
                    if not session.can("approve"):
                        return self._json(403, {"error": f"{session.role} 无 approve 权限"})
                    return self._json(200, {"proposal": ex.approve(session, pid)})
                if path.endswith("/reject"):
                    if not session.can("approve"):
                        return self._json(403, {"error": f"{session.role} 无 approve 权限"})
                    return self._json(200, {"proposal": ex.reject(session, pid, b.get("reason", ""))})
                locked = self._roe_guard(store)
                if locked:
                    return self._json(locked["code"], {"error": locked["error"]})
                return self._json(200, ex.execute(session, pid))
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            except ExecutionLocked as e:
                return self._json(423, {"error": str(e)})
            except ValueError as e:
                return self._json(409, {"error": str(e), "class": type(e).__name__})

        if path == "/api/v1/scheduler/add":
            session, store, ws = self._auth(b)
            if session is None:
                return
            if not session.can("approve"):
                return self._json(403, {"error": f"{session.role} 不可创建计划（须 lead/admin）"})
            sched = Scheduler(store, modules_dir=self.root / "modules")
            try:
                item = sched.add(session, cron=b.get("cron"),
                                 interval_seconds=b.get("interval_seconds"),
                                 chains=b.get("chains") or [], schedule_id=b.get("id", ""))
            except ValueError as e:
                return self._json(400, {"error": str(e), "class": type(e).__name__})
            return self._json(200, {"workspace": ws, "schedule": item})

        if path == "/api/v1/scheduler/remove":
            session, store, ws = self._auth(b)
            if session is None:
                return
            sched = Scheduler(store, modules_dir=self.root / "modules")
            try:
                return self._json(200, sched.remove(b.get("id", "")))
            except ScheduleError as e:
                return self._json(404, {"error": str(e)})

        if path == "/api/v1/scheduler/run-due":
            session, store, ws = self._auth(b)
            if session is None:
                return
            locked = self._roe_guard(store)
            if locked:
                return self._json(locked["code"], {"error": locked["error"]})
            sched = Scheduler(store, modules_dir=self.root / "modules")
            try:
                return self._json(200, sched.run_due(session))
            except PermissionError as e:
                return self._json(403, {"error": str(e)})

        if path == "/api/v1/traffic/replay":
            session, store, ws = self._auth(b)
            if session is None:
                return
            if not b.get("run"):
                return self._json(400, {"error": "run 参数必填"})
            live = bool(b.get("live"))
            if live:
                locked = self._roe_guard(store)
                if locked:
                    return self._json(locked["code"], {"error": locked["error"]})
            try:
                return self._json(200, traffic_mod.replay(
                    store, session, b.get("run", ""), module=b.get("module", ""), live=live))
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            except ValueError as e:
                return self._json(404, {"error": str(e), "class": type(e).__name__})

        if path == "/api/v1/consent/sign":
            session, store, ws = self._auth(b)
            if session is None:
                return
            if not session.can("approve"):
                return self._json(403, {"error": f"{session.role} 不可签署授权（须 lead/admin）"})
            fields = b.get("fields") or {}
            if not fields.get("level"):
                return self._json(400, {"error": "fields.level 必填（只读侦察/主动探测/利用验证/全影响演示）"})
            init_roe(store, fields)
            return self._json(200, {"workspace": ws, "status": roe_status(store)})

        if path == "/api/v1/zeroday/enable":
            session, store, ws = self._auth(b)
            if session is None:
                return
            try:
                zd_enable(store, session)
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            return self._json(200, {"workspace": ws, "enabled": True})

        if path == "/api/v1/poc/reverify":
            session, store, ws = self._auth(b)
            if session is None:
                return
            locked = self._roe_guard(store)
            if locked:
                return self._json(locked["code"], {"error": locked["error"]})
            try:
                verdict = poc_mod.reverify(store, session, self.root / "modules",
                                           b.get("module", ""), b.get("params") or {})
            except KeyError as e:
                return self._json(404, {"error": str(e)})
            except PermissionError as e:
                return self._json(403, {"error": str(e)})
            return self._json(200, verdict)

        if path == "/api/v1/poc/auto-reverify":
            session, store, ws = self._auth(b)
            if session is None:
                return
            if not session.can("approve"):
                return self._json(403, {"error": f"{session.role} 不可改自动重验开关"})
            cfg = poc_mod.set_auto_reverify(store, bool(b.get("enabled")))
            return self._json(200, {"workspace": ws, "poc": cfg.get("poc", {})})

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
        return self._api_v1_get(u.path, u.query)

    # ---------- /api/v1 GET ----------
    def _api_v1_get(self, path: str, query: str):
        from ..core import discovery, explorer as explorer_mod, traffic as traffic_mod
        from ..core.scheduler import Scheduler
        from ..core.zeroday import zeroday_enabled

        q = parse_qs(query)
        session = self._session()
        if session is None:
            return self._json(401, {"error": "login required"})
        ws = (q.get("workspace") or ["local-lab"])[0]
        try:
            store = self._ws_store(session, ws)
        except PermissionError as e:
            return self._json(403, {"error": str(e)})

        if path == "/api/v1/assets":
            inv = discovery.AssetInventory(store)
            assets = inv.list(kind=(q.get("kind") or [""])[0],
                              product=(q.get("product") or [""])[0],
                              include_missing=(q.get("include_missing") or [""])[0] == "1")
            return self._json(200, {"workspace": ws, "assets": assets,
                                    "graph": inv.graph(), "count": len(assets)})
        if path == "/api/v1/explorer":
            ex = explorer_mod.Explorer(store, modules_dir=self.root / "modules")
            return self._json(200, {"workspace": ws,
                                    "proposals": ex.list_proposals(),
                                    "llm_available": explorer_mod.llm_available()})
        if path == "/api/v1/scheduler":
            sched = Scheduler(store, modules_dir=self.root / "modules")
            return self._json(200, {"workspace": ws, "schedules": sched.list(),
                                    "due": [s["id"] for s in sched.due()]})
        if path == "/api/v1/traffic":
            run = (q.get("run") or [""])[0]
            if not run:
                return self._json(400, {"error": "run 参数必填"})
            try:
                entries = traffic_mod.list_traffic(store, run, module=(q.get("module") or [""])[0])
            except KeyError as e:
                return self._json(404, {"error": str(e)})
            return self._json(200, {"workspace": ws, "run": run, "entries": entries,
                                    "count": len(entries)})
        if path == "/api/v1/consent":
            consent = store.consent()
            return self._json(200, {"workspace": ws, "status": roe_status(store),
                                    "fields": (consent or {}).get("fields", {})})
        if path == "/api/v1/zeroday":
            cand_dir = Path(self.root) / "zeroday" / "registry" / "candidates"
            candidates = sorted(p.name for p in cand_dir.glob("*.json")) if cand_dir.exists() else []
            return self._json(200, {"workspace": ws, "enabled": zeroday_enabled(store),
                                    "registry_candidates": candidates,
                                    "candidate_status": "pending-manual-review（不自动入库）"})
        if path == "/api/v1/rules":
            pack = Path(self.root) / "reports" / "rules-pack"
            mapping = pack / "mapping.json"
            if not mapping.is_file():
                return self._json(200, {"workspace": ws, "pack": str(pack), "ok": False,
                                        "error": "规则包未生成（reports/rules-pack 缺 mapping.json）"})
            doc = json.loads(mapping.read_text(encoding="utf-8"))
            return self._json(200, {"workspace": ws, "pack": str(pack), "ok": True,
                                    "rules": len(doc.get("rules") or []),
                                    "chains": len(doc.get("chains") or {})})
        return self._json(404, {"error": "not found"})


def make_server(root: Path | str, users: UserStore, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (_Handler,), {"users": users, "root": Path(root)})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd
