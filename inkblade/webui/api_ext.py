# -*- coding: utf-8 -*-
"""Web API 扩展路由（新功能）：LLM 池 / 通知 / 模板 / 日历 / 侧问 / 图 / 黑板 / 检索。

由 ``webui/server.py`` 的 GET/POST/PATCH/DELETE 在既有路由未命中时调用；复用同一
Session/工作区隔离/ROE 闸门。返回 True 表示已处理（含 4xx），False 表示不认识的路径。
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, unquote

from ..core import (blackboard, calendar, cigate, credcheck, graphsnap, importers, intel,
                    jsonio, llmpool, notify, search, templates, threads)
from ..core.roe import ExecutionLocked, roe_status


def _q(query: str, key: str, default: str = "") -> str:
    return (parse_qs(query).get(key) or [default])[0]


def _ws_body(body: dict | None) -> dict:
    return body or {}


def route(handler, method: str, path: str, query: str, body: dict | None = None) -> bool:
    if not path.startswith("/api/v1/"):
        return False
    prefixes = ("/api/v1/llm/", "/api/v1/notify/", "/api/v1/templates",
                "/api/v1/calendar", "/api/v1/threads", "/api/v1/side-questions",
                "/api/v1/graph/", "/api/v1/blackboard", "/api/v1/search",
                "/api/v1/logs", "/api/v1/health", "/api/v1/stats", "/api/v1/intel",
                "/api/v1/ci-gate", "/api/v1/credcheck", "/api/v1/import-scan",
                "/api/v1/tokens/")
    if not any(path == p.rstrip("/") or path.startswith(p) for p in prefixes):
        return False
    body = _ws_body(body)
    session, store, ws = handler._auth(body if method in ("POST", "PATCH", "DELETE") else None)
    if session is None:
        return True
    try:
        return _dispatch(handler, method, path.rstrip("/"), query, body, session, store, ws)
    except PermissionError as exc:
        handler._json(403, {"error": str(exc)})
    except ExecutionLocked as exc:
        handler._json(423, {"error": str(exc)})
    except KeyError as exc:
        handler._json(404, {"error": str(exc)})
    except ValueError as exc:
        handler._json(409, {"error": str(exc), "class": type(exc).__name__})
    except Exception as exc:  # 兜底：不泄露 traceback
        handler._json(500, {"error": f"{type(exc).__name__}: {exc}"})
    return True


def _dispatch(handler, method: str, path: str, query: str, body: dict, session, store, ws) -> bool:
    # ---------------------------------------------------------------- GET
    if method == "GET":
        if path == "/api/v1/llm/pool":
            return _ok(handler, {"workspace": ws, "pool": llmpool.LLMPool(store).status()})
        if path == "/api/v1/llm/records":
            pool = llmpool.LLMPool(store)
            return _ok(handler, {"workspace": ws,
                                 "records": pool.records(limit=int(_q(query, "limit", "100") or 100),
                                                        model=_q(query, "model"),
                                                        purpose=_q(query, "purpose"))})
        if path == "/api/v1/llm/records/by-model":
            return _ok(handler, llmpool.LLMPool(store).records_by_model())
        if path.startswith("/api/v1/llm/records/"):
            return _ok(handler, {"workspace": ws,
                                 "record": llmpool.LLMPool(store).record(
                                     path[len("/api/v1/llm/records/"):].strip("/"))})
        if path == "/api/v1/llm/models":
            return _ok(handler, {"workspace": ws, "models": llmpool.LLMPool(store).models()})
        if path == "/api/v1/tokens/daily":
            return _ok(handler, llmpool.LLMPool(store).token_stats(
                days=int(_q(query, "days", "14") or 14)))
        if path == "/api/v1/tokens/usage":
            return _ok(handler, {"workspace": ws,
                                 "usage": llmpool.LLMPool(store).token_stats(),
                                 "by_model": llmpool.LLMPool(store).records_by_model()})
        if path == "/api/v1/notify/meta":
            return _ok(handler, {"workspace": ws, "meta": notify.NotifyManager(store).meta()})
        if path == "/api/v1/notify/channels":
            return _ok(handler, {"workspace": ws,
                                 "channels": notify.NotifyManager(store).list_channels(),
                                 "rules": notify.NotifyManager(store).list_rules()})
        if path == "/api/v1/notify/deliveries":
            nm = notify.NotifyManager(store)
            return _ok(handler, {"workspace": ws,
                                 "deliveries": nm.deliveries(event=_q(query, "event"),
                                                             status=_q(query, "status"),
                                                             limit=int(_q(query, "limit", "100") or 100))})
        if path == "/api/v1/templates":
            return _ok(handler, {"workspace": ws,
                                 "templates": templates.TemplateStore(
                                     store, modules_dir=handler.root / "modules").list()})
        if path.startswith("/api/v1/templates/"):
            rest = path[len("/api/v1/templates/"):].strip("/")
            ts = templates.TemplateStore(store, modules_dir=handler.root / "modules")
            if rest.endswith("/plan"):
                return _ok(handler, {"workspace": ws,
                                     "plan": ts.instantiate(rest[:-5])})
            return _ok(handler, {"workspace": ws, "template": ts.get(rest)})
        if path == "/api/v1/calendar":
            cal = calendar.Calendar(store, modules_dir=handler.root / "modules")
            return _ok(handler, {"workspace": ws, "windows": cal.list(),
                                 "due": [w["id"] for w in cal.due()]})
        if path == "/api/v1/calendar/upcoming":
            cal = calendar.Calendar(store, modules_dir=handler.root / "modules")
            return _ok(handler, {"workspace": ws,
                                 "windows": cal.upcoming(days=int(_q(query, "days", "14") or 14))})
        if path == "/api/v1/calendar/events":
            cal = calendar.Calendar(store, modules_dir=handler.root / "modules")
            return _ok(handler, {"workspace": ws,
                                 "calendar": cal.event_calendar(days=int(_q(query, "days", "42") or 42))})
        if path == "/api/v1/threads":
            th = threads.Threads(store)
            run = _q(query, "run")
            return _ok(handler, {"workspace": ws, "threads": th.list_threads(run or None),
                                 "summary": th.summary(run or None)})
        if path.startswith("/api/v1/threads/") or path.startswith("/api/v1/side-questions/"):
            prefix = "/api/v1/threads/" if path.startswith("/api/v1/threads/") \
                else "/api/v1/side-questions/"
            rest = path[len(prefix):]
            if rest.endswith("/events"):
                tid = rest[:-len("/events")].strip("/")
                return _ok(handler, {"workspace": ws,
                                     "thread": threads.Threads(store).events(_q(query, "run"), tid)})
        if path == "/api/v1/graph/snapshots":
            return _ok(handler, {"workspace": ws,
                                 "snapshots": graphsnap.GraphSnapshots(store).list()})
        if path == "/api/v1/graph/ui":
            gs = graphsnap.GraphSnapshots(store)
            return _ok(handler, {"workspace": ws,
                                 "graph": gs.ui_data(_q(query, "id"))})
        if path == "/api/v1/graph/diff":
            gs = graphsnap.GraphSnapshots(store)
            return _ok(handler, {"workspace": ws,
                                 "diff": gs.diff(_q(query, "base"), _q(query, "head"))})
        if path == "/api/v1/graph/neighbors":
            gs = graphsnap.GraphSnapshots(store)
            return _ok(handler, {"workspace": ws,
                                 "neighbors": gs.neighbors(_q(query, "id"), _q(query, "node"))})
        if path == "/api/v1/blackboard":
            return _ok(handler, {"workspace": ws,
                                 "entries": blackboard.Blackboard(store).list()})
        if path == "/api/v1/blackboard/context":
            return _ok(handler, {"workspace": ws,
                                 "context": blackboard.Blackboard(store).context()})
        if path == "/api/v1/search":
            return _ok(handler, {"workspace": ws,
                                 "result": search.search(store, _q(query, "q"),
                                                         run=_q(query, "run"),
                                                         limit=int(_q(query, "limit", "50") or 50))})
        if path == "/api/v1/logs":
            rows = jsonio.tail_jsonl(store.ws_dir / "audit.jsonl",
                                     limit=int(_q(query, "limit", "100") or 100))
            return _ok(handler, {"workspace": ws, "lines": rows, "count": len(rows),
                                 "source": "audit.jsonl"})
        if path == "/api/v1/health":
            return _ok(handler, {"ok": True, "workspace": ws,
                                 "roe": roe_status(store), "ts": time.time()})
        if path == "/api/v1/stats":
            runs = [p for p in store.ws_dir.iterdir()
                    if p.is_dir() and not p.name.startswith("_") and (p / "evidence.db").is_file()]
            findings = 0
            for p in runs:
                try:
                    findings += len(store.open_run(p.name).findings)
                except Exception:
                    pass
            return _ok(handler, {"workspace": ws, "runs": len(runs), "findings": findings,
                                 "assets": _asset_count(store), "roe": roe_status(store)})
        if path == "/api/v1/intel":
            return _ok(handler, {"workspace": ws,
                                 "intel": intel.IntelRegistry(store).list(
                                     run=_q(query, "run"), kind=_q(query, "kind"))})
        return False

    # ---------------------------------------------------------------- POST
    if method == "POST":
        if path == "/api/v1/llm/pool/add":
            return _ok(handler, {"pool": llmpool.LLMPool(store).add_endpoint(
                session, base_url=body.get("base_url", ""), model=body.get("model", ""),
                api_key=body.get("api_key", ""), api_key_env=body.get("api_key_env", ""),
                weight=int(body.get("weight", 1)),
                quota_requests=int(body.get("quota_requests", 0)),
                quota_tokens=int(body.get("quota_tokens", 0)),
                endpoint_id=body.get("id", ""))})
        if path == "/api/v1/llm/pool/enable":
            return _ok(handler, llmpool.LLMPool(store).set_enabled(
                session, bool(body.get("enabled"))))
        if path == "/api/v1/llm/pool/reset":
            return _ok(handler, llmpool.LLMPool(store).reset(
                session, body.get("id", ""), usage=bool(body.get("usage"))))
        if path == "/api/v1/llm/pool/health":
            return _ok(handler, llmpool.LLMPool(store).health_check(session))
        if path == "/api/v1/notify/channels":
            return _ok(handler, {"channel": notify.NotifyManager(store).add_channel(
                session, body.get("kind", ""), body.get("name", ""),
                body.get("config") or {}, enabled=body.get("enabled", True),
                channel_id=body.get("id", ""))})
        if path == "/api/v1/notify/channels/update":
            return _ok(handler, {"channel": notify.NotifyManager(store).update_channel(
                session, body.get("id", ""),
                **{k: body[k] for k in ("kind", "name", "enabled", "config") if k in body})})
        if path == "/api/v1/notify/channels/delete":
            return _ok(handler, notify.NotifyManager(store).delete_channel(
                session, body.get("id", "")))
        if path.startswith("/api/v1/notify/channels/") and path.endswith("/test"):
            cid = path[len("/api/v1/notify/channels/"):-len("/test")].strip("/")
            return _ok(handler, {"delivery": notify.NotifyManager(store).test_channel(session, cid)})
        if path == "/api/v1/notify/rules/add":
            return _ok(handler, {"rule": notify.NotifyManager(store).add_rule(
                session, body.get("event", ""), body.get("channel_ids") or [],
                min_severity=body.get("min_severity", "info"),
                rule_id=body.get("id", ""))})
        if path == "/api/v1/notify/enable":
            return _ok(handler, notify.NotifyManager(store).set_enabled(
                session, bool(body.get("enabled"))))
        if path == "/api/v1/notify/emit":
            if not session.can("execute"):
                raise PermissionError(f"{session.name}({session.role}) 无 execute 权限")
            return _ok(handler, notify.NotifyManager(store).emit(
                body.get("event", ""), body.get("payload") or {},
                severity=body.get("severity", ""), actor=session.name,
                dispatch=bool(body.get("dispatch", True))))
        if path == "/api/v1/notify/deliveries/retry":
            return _ok(handler, {"delivery": notify.NotifyManager(store).retry(
                session, body.get("id", ""))})
        if path == "/api/v1/templates/add":
            return _ok(handler, {"template": templates.TemplateStore(
                store, modules_dir=handler.root / "modules").add(
                session, name=body.get("name", ""), chains=body.get("chains"),
                params=body.get("params"), modules=body.get("modules"),
                notes=body.get("notes", ""), tags=body.get("tags"),
                template_id=body.get("id", ""))})
        if path == "/api/v1/templates/from-run":
            return _ok(handler, {"template": templates.TemplateStore(
                store, modules_dir=handler.root / "modules").from_run(
                session, body.get("run", ""), name=body.get("name", ""),
                template_id=body.get("id", ""))})
        if path == "/api/v1/templates/update":
            return _ok(handler, {"template": templates.TemplateStore(
                store, modules_dir=handler.root / "modules").update(
                session, body.get("id", ""),
                **{k: body[k] for k in ("name", "chains", "params", "modules", "notes", "tags")
                   if k in body})})
        if path == "/api/v1/templates/delete":
            return _ok(handler, templates.TemplateStore(
                store, modules_dir=handler.root / "modules").delete(session, body.get("id", "")))
        if path == "/api/v1/templates/instantiate":
            return _ok(handler, {"plan": templates.TemplateStore(
                store, modules_dir=handler.root / "modules").instantiate(
                body.get("id", ""), overrides=body.get("overrides"),
                roe_level=body.get("roe_level"))})
        if path == "/api/v1/calendar/add":
            return _ok(handler, {"window": calendar.Calendar(
                store, modules_dir=handler.root / "modules").add_window(
                session, name=body.get("name", ""), start=body.get("start"),
                end=body.get("end"), chains=body.get("chains") or [],
                window_id=body.get("id", ""),
                allow_past=bool(body.get("allow_past", False)))})
        if path in ("/api/v1/calendar/pause", "/api/v1/calendar/resume"):
            cal = calendar.Calendar(store, modules_dir=handler.root / "modules")
            fn = cal.pause if path.endswith("pause") else cal.resume
            return _ok(handler, {"window": fn(session, body.get("id", ""))})
        if path == "/api/v1/calendar/remove":
            return _ok(handler, calendar.Calendar(
                store, modules_dir=handler.root / "modules").remove(session, body.get("id", "")))
        if path == "/api/v1/calendar/run-due":
            return _ok(handler, calendar.Calendar(
                store, modules_dir=handler.root / "modules").run_due(session))
        if path == "/api/v1/threads/ask":
            return _ok(handler, {"thread": threads.Threads(store).ask(
                session, body.get("run", ""), body.get("subject", ""), body.get("body", ""))})
        if path == "/api/v1/threads/reply":
            return _ok(handler, {"thread": threads.Threads(store).reply(
                session, body.get("run", ""), body.get("id", ""), body.get("body", ""))})
        if path == "/api/v1/threads/close":
            return _ok(handler, {"thread": threads.Threads(store).close(
                session, body.get("run", ""), body.get("id", ""),
                resolution=body.get("resolution", ""))})
        if path == "/api/v1/threads/cancel" or path.startswith("/api/v1/side-questions/"):
            if path.startswith("/api/v1/side-questions/"):
                body = {**body, "id": path[len("/api/v1/side-questions/"):].strip("/")}
            return _ok(handler, {"thread": threads.Threads(store).cancel(
                session, body.get("run", ""), body.get("id", ""),
                reason=body.get("reason", ""))})
        if path == "/api/v1/graph/snapshot":
            return _ok(handler, {"snapshot": graphsnap.GraphSnapshots(store).snapshot(
                session, run=body.get("run"), label=body.get("label", ""))})
        if path == "/api/v1/blackboard/pin":
            bb = blackboard.Blackboard(store)
            kind = body.get("kind", "note")
            if kind == "finding":
                entry = bb.pin_finding(session, body.get("run", ""), body.get("title", ""),
                                       note=body.get("note", ""),
                                       include_detail=bool(body.get("include_detail")))
            elif kind == "asset":
                entry = bb.pin_assets(session, kind=body.get("asset_kind", "service"),
                                      product=body.get("product", ""),
                                      limit=int(body.get("limit", 20)),
                                      note=body.get("note", ""))
            else:
                entry = bb.pin_note(session, body.get("text", ""), ref=body.get("ref", ""),
                                    note=body.get("note", ""))
            return _ok(handler, {"entry": entry})
        if path == "/api/v1/blackboard/unpin":
            return _ok(handler, blackboard.Blackboard(store).unpin(session, body.get("ref", "")))
        if path == "/api/v1/intel/add":
            return _ok(handler, {"intel": intel.IntelRegistry(store).add(
                session, kind=body.get("kind", ""), label=body.get("label", ""),
                value=body.get("value", ""), run=body.get("run"), source_step=body.get("step", ""),
                evidence_path=body.get("evidence_path", ""), mode=body.get("mode", "metadata"),
                allow_raw=bool(body.get("allow_raw")), note=body.get("note", ""),
                intel_id=body.get("id", ""))})
        if path == "/api/v1/intel/reveal":
            return _ok(handler, {"intel": intel.IntelRegistry(store).reveal(
                session, body.get("id", ""))})
        if path == "/api/v1/intel/update":
            return _ok(handler, {"intel": intel.IntelRegistry(store).update(
                session, body.get("id", ""), label=body.get("label", ""),
                note=body.get("note", ""))})
        if path == "/api/v1/ci-gate":
            return _ok(handler, cigate.evaluate_run(
                store, body.get("run", ""), {"fail_on": body.get("fail_on", "high"),
                                             "baseline": body.get("baseline"),
                                             "fail_on_new_only": bool(body.get("fail_on_new_only")),
                                             "allow_novel": bool(body.get("allow_novel"))}))
        if path == "/api/v1/credcheck":
            return _ok(handler, {"result": credcheck.validate(body.get("fixture") or {}),
                                 "plan": credcheck.probe_plan(body.get("fixture") or {})})
        if path == "/api/v1/import-scan":
            return _ok(handler, importers.ingest(
                store, body.get("run", ""), body.get("doc") or {},
                source=body.get("source", "api")))
        return False

    # ---------------------------------------------------------------- PATCH/DELETE
    if method == "PATCH":
        if path.startswith("/api/v1/notify/channels/"):
            cid = path[len("/api/v1/notify/channels/"):].strip("/")
            return _ok(handler, {"channel": notify.NotifyManager(store).update_channel(
                session, cid, **{k: body[k] for k in ("kind", "name", "enabled", "config") if k in body})})
        if path.startswith("/api/v1/templates/"):
            tid = path[len("/api/v1/templates/"):].strip("/")
            return _ok(handler, {"template": templates.TemplateStore(
                store, modules_dir=handler.root / "modules").update(
                session, tid, **{k: body[k] for k in ("name", "chains", "params", "modules", "notes", "tags")
                                 if k in body})})
        return False
    if method == "DELETE":
        if path == "/api/v1/llm/records":
            return _ok(handler, llmpool.LLMPool(store).clear_records(session))
        if path.startswith("/api/v1/notify/channels/"):
            cid = path[len("/api/v1/notify/channels/"):].strip("/")
            return _ok(handler, notify.NotifyManager(store).delete_channel(session, cid))
        if path.startswith("/api/v1/templates/"):
            tid = path[len("/api/v1/templates/"):].strip("/")
            return _ok(handler, templates.TemplateStore(
                store, modules_dir=handler.root / "modules").delete(session, tid))
        if path.startswith("/api/v1/calendar/"):
            wid = path[len("/api/v1/calendar/"):].strip("/")
            return _ok(handler, calendar.Calendar(
                store, modules_dir=handler.root / "modules").remove(session, wid))
        if path.startswith("/api/v1/blackboard/"):
            ref = unquote(path[len("/api/v1/blackboard/"):].strip("/"))
            return _ok(handler, blackboard.Blackboard(store).unpin(session, ref))
        return False
    return False


def _ok(handler, body: dict) -> bool:
    handler._json(200, body)
    return True


def _asset_count(store) -> int:
    try:
        from ..core.discovery import AssetInventory

        return AssetInventory(store).count()
    except Exception:
        return 0
