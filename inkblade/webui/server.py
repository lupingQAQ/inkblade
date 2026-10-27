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
from . import api_ext, api_section3

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

    def do_PATCH(self):
        u = urlparse(self.path)
        b = self._body()
        if api_ext.route(self, "PATCH", u.path, u.query, b):
            return
        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        u = urlparse(self.path)
        b = self._body()
        if api_ext.route(self, "DELETE", u.path, u.query, b):
            return
        self._json(404, {"error": "not found"})

    # ---------- /api/v1 POST ----------
    def _api_v1_post(self, path: str):
        from ..core import discovery, explorer as explorer_mod, poc as poc_mod, traffic as traffic_mod
        from ..core.roe import ExecutionLocked, init_roe
        from ..core.scheduler import ScheduleError, Scheduler
        from ..core.zeroday import enable as zd_enable

        b = self._body()

        if api_ext.route(self, "POST", path, "", b):
            return

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
                return self._json(200, ex.execute(session, pid,
                                                  workers=int(b.get("workers", 1) or 1)))
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
        if u.path in ("/openapi.json", "/api/v1/openapi.json"):
            from .openapi import build_openapi

            return self._json(200, build_openapi())
        if u.path == "/":
            html = (_STATIC / "index.html").read_text(encoding="utf-8") if (_STATIC / "index.html").exists() else "<html><body>InkBlade</body></html>"
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
    def _api_readonly(self, path: str, q: dict, session, store, ws: str) -> bool:
        """终审 Minor#8 只读端点：workspaces / steps / evidence / graph / report。"""
        if path == "/api/v1/workspaces":
            self._json(200, {"workspaces": session.visible_workspaces(root=Path(self.root)),
                             "current": ws})
            return True
        if path == "/api/v1/drift":
            run = (q.get("run") or [""])[0]
            ws_dir = Path(store.ws_dir)
            if run:
                run_dir = ws_dir / run
                if not run_dir.is_dir():
                    self._json(404, {"error": f"run not found: {run}"})
                    return True
                drift_path = run_dir / "drift.json"
                if not drift_path.is_file():
                    self._json(404, {"error": f"run 无漂移数据（drift: {run}）"})
                    return True
            else:
                candidates = sorted(
                    (p for p in ws_dir.iterdir()
                     if p.is_dir() and (p / "drift.json").is_file()),
                    key=lambda p: (p / "drift.json").stat().st_mtime, reverse=True)
                if not candidates:
                    self._json(404, {"error": "工作区暂无漂移数据（先 schedule run-due）"})
                    return True
                run_dir = candidates[0]
                run = run_dir.name
                drift_path = run_dir / "drift.json"
            try:
                doc = json.loads(drift_path.read_text(encoding="utf-8"))
            except ValueError as exc:
                self._json(500, {"error": f"drift.json 非法: {exc}"})
                return True
            self._json(200, {"workspace": ws, "run": run,
                             "counts": doc.get("counts") or {},
                             "new": doc.get("new") or [],
                             "fixed": doc.get("fixed") or [],
                             "drift": doc})
            return True
        if path not in ("/api/v1/steps", "/api/v1/evidence", "/api/v1/graph",
                        "/api/v1/report", "/api/v1/timeline", "/api/v1/file-ops"):
            return False
        run = (q.get("run") or [""])[0]
        if not run:
            self._json(400, {"error": "run 参数必填"})
            return True
        run_dir = Path(store.ws_dir) / run
        if not (run_dir / "evidence.db").is_file():
            self._json(404, {"error": f"run not found: {run}"})
            return True
        from .export_static import load_run_data

        try:
            data = load_run_data(run_dir)
        except Exception as exc:  # 库损坏/权限
            self._json(500, {"error": f"run 数据读取失败: {exc}"})
            return True

        if path == "/api/v1/steps":
            steps = data["steps"]
            self._json(200, {"workspace": ws, "run": run, "steps": steps,
                             "count": len(steps)})
            return True
        if path == "/api/v1/evidence":
            step = (q.get("step") or [""])[0]
            rows = []
            for s in data["steps"]:
                if step and s["step_key"] != step:
                    continue
                for ev in s.get("evidence", []):
                    rows.append({"step_key": s["step_key"], "step_id": s["id"], **ev})
            self._json(200, {"workspace": ws, "run": run, "evidence": rows,
                             "count": len(rows),
                             "manifest_verified": store.verify_manifest(run)})
            return True
        if path == "/api/v1/graph":
            nodes, edges = data["nodes"], data["edges"]
            by_layer: dict[str, int] = {}
            for n in nodes:
                layer = n.get("layer") or "未分层"
                by_layer[layer] = by_layer.get(layer, 0) + 1
            self._json(200, {"workspace": ws, "run": run, "nodes": nodes, "edges": edges,
                             "node_count": len(nodes), "edge_count": len(edges),
                             "by_layer": by_layer})
            return True
        if path == "/api/v1/timeline":
            from ..core.timeline import load_timeline

            doc = load_timeline(run_dir, build_if_missing=True) or {}
            events = doc.get("events") or []
            self._json(200, {"workspace": ws, "run": run, "schema": doc.get("schema", ""),
                             "counts": doc.get("counts") or {}, "count": len(events),
                             "events": events})
            return True
        if path == "/api/v1/file-ops":
            step = (q.get("step") or [""])[0]
            rows = [row for row in data.get("file_ops", [])
                    if not step or row.get("step_key") == step]
            self._json(200, {"workspace": ws, "run": run, "file_ops": rows,
                             "count": len(rows)})
            return True
        # report
        kind = (q.get("kind") or ["pentest"])[0]
        lang = (q.get("lang") or ["bi"])[0]
        redact = (q.get("redact") or ["0"])[0] in ("1", "true", "yes")
        if kind not in ("pentest", "remediation") or lang not in ("bi", "zh", "en"):
            self._json(400, {"error": "kind 须 pentest|remediation，lang 须 bi|zh|en"})
            return True
        from ..reports.render import render_pentest, render_remediation

        render = render_remediation if kind == "remediation" else render_pentest
        text = render(store, run, lang=lang, redact_zeroday=redact)
        self._json(200, {"workspace": ws, "run": run, "kind": kind, "lang": lang,
                         "redact_zeroday": redact, "bytes": len(text.encode("utf-8")),
                         "markdown": text})
        return True

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

        if self._api_readonly(path, q, session, store, ws):
            return

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
        if api_section3.route(self, "GET", path, query, None):
            return
        if api_ext.route(self, "GET", path, query, None):
            return
        return self._json(404, {"error": "not found"})


class _Server(ThreadingHTTPServer):
    """并发友好：默认 backlog=5 在 16+ 并发下触发 SYN 重传（吞吐断崖），此处放大。"""

    request_queue_size = 256
    daemon_threads = True
    allow_reuse_address = True


def make_server(root: Path | str, users: UserStore, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (_Handler,), {"users": users, "root": Path(root)})
    httpd = _Server((host, port), handler)
    httpd.port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd
