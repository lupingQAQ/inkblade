# -*- coding: utf-8 -*-
"""流量录制与回放（XBow 对标 ④）：模块 HTTP 全量录制入库 + replay 断言重放。

- ``ingest_run(run)``：扫描 run 目录 ``traces/*.json``（各模块 Trace 已落盘的
  请求/响应全量记录），写入 evidence.db 的 ``traffic`` 表（幂等）；
- ``list_traffic(store, run)``：按 run/module 查询已录制流量；
- ``replay(...)``：
  - dry 模式（默认，``live=False``）：不发包，产出重放断言计划
    （每条录制流量的期望 status / sha256 复核点）；
  - live 模式（``live=True``）：须 ROE complete + execute 权限，按录制重发请求，
    逐条断言 status 一致并记录差异；全部动作落 actions 审计。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .roe import roe_status

TIMEOUT = 5


class TrafficError(ValueError):
    """无录制流量/参数非法。"""


class ReplayLocked(PermissionError):
    """live 回放的授权/权限闸门未过。"""


def ingest_run(run) -> dict[str, int]:
    """traces/*.json → traffic 表。返回 {模块: 条数}。"""
    traces_dir = Path(run.dir) / "traces"
    if not traces_dir.exists():
        return {}
    counts: dict[str, int] = {}
    for p in sorted(traces_dir.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            continue
        module = str(doc.get("module") or p.stem)
        entries = doc.get("entries") or []
        if not isinstance(entries, list):
            continue
        counts[module] = run.record_traffic(module, entries)
    return counts


def ingest_store(store) -> dict[str, dict[str, int]]:
    """全工作区 run 的流量入库（API/scheduler 可批量调用）。"""
    out: dict[str, dict[str, int]] = {}
    if not store.ws_dir.exists():
        return out
    for p in sorted(store.ws_dir.iterdir()):
        if not p.is_dir() or p.name.startswith("_"):
            continue
        counts = ingest_run(store.open_run(p.name))
        if counts:
            out[p.name] = counts
    return out


def list_traffic(store, run: str, *, module: str = "") -> list[dict]:
    if not run:
        raise TrafficError("run 参数必填")
    try:
        r = store.open_run(run)
    except KeyError as exc:
        raise TrafficError(str(exc)) from exc
    if not (Path(r.dir) / "evidence.db").is_file():
        raise TrafficError(f"run {run} 无 evidence.db（旧版 run：先经 runner/ingest 重建）")
    try:
        rows = r.traffic
    except Exception as exc:  # 旧库无 traffic 表等
        raise TrafficError(f"run {run} 流量表不可读: {exc}") from exc
    if module:
        rows = [t for t in rows if t["module"] == module]
    return rows


def _assertion_for(entry: dict) -> dict:
    return {"method": entry.get("method"), "url": entry.get("url"),
            "expect_status": int(entry.get("status") or 0),
            "recorded_sha256": entry.get("sha256", "")}


def replay_plan(store, run: str, *, module: str = "") -> dict[str, Any]:
    """dry 回放：断言计划（不发包）。"""
    entries = list_traffic(store, run, module=module)
    if not entries:
        raise TrafficError(f"run {run} 无已录制流量（先 ingest_run）")
    return {"run": run, "mode": "dry", "count": len(entries),
            "assertions": [_assertion_for(e) for e in entries]}


def _replay_one(entry: dict) -> dict:
    method = str(entry.get("method") or "GET")
    url = str(entry.get("url") or "")
    body = entry.get("req_body")
    data = None
    if body is not None and body != "null":
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data if data else None, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    except Exception as exc:
        return {"url": url, "method": method, "expect_status": int(entry.get("status") or 0),
                "actual_status": 0, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    text = raw.decode("utf-8", "replace")
    return {"url": url, "method": method, "expect_status": int(entry.get("status") or 0),
            "actual_status": status, "ok": status == int(entry.get("status") or 0),
            "resp_bytes": len(raw), "resp_head": text[:120]}


def replay(store, session, run: str, *, module: str = "", live: bool = False,
           log_action=True) -> dict[str, Any]:
    """回放入口：dry 出断言计划；live 须授权并真实重放 + 审计。"""
    if not live:
        return replay_plan(store, run, module=module)
    if roe_status(store) != "complete":
        raise ReplayLocked("工作区授权未完成（consent 未签署）")
    if not session.can("execute"):
        raise ReplayLocked(f"{session.name}({session.role}) 无 execute 权限")
    entries = list_traffic(store, run, module=module)
    if not entries:
        raise TrafficError(f"run {run} 无已录制流量（先 ingest_run）")
    results = [_replay_one(e) for e in entries]
    ok = all(r["ok"] for r in results)
    if log_action:
        target_run = store.open_run(run)
        target_run.log_action(session.name, "replay", run,
                              {"module": module, "live": True, "count": len(results)},
                              "ok" if ok else "diff")
    return {"run": run, "mode": "live", "count": len(results), "ok": ok,
            "results": results, "ts": time.time()}
