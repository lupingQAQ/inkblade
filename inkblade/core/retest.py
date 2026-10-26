# -*- coding: utf-8 -*-
"""finding 级确定性复测闭环（CM-14）：修复后重放 + retest 结论留档。

- ``plan``：从 run 的 traffic 表取该 finding 所属模块的请求/响应断言（只读，不发包）；
- ``run_retest(live=False)``：默认只出计划（不执行）；``live=True`` 才要求 ROE + execute，
  逐条按录制顺序重放并比较期望 status：
  - 与录制一致 → ``open``（仍可利用）；
  - 变为 4xx（含 401/403）→ ``fixed``；
  - 其它变化 → ``changed``；
  - 无录制断言 → ``no-checks``；
- 结论落 ``retests/<module>-<ts>.json``、evidence.db ``retests`` 表与 actions；
  同时经 ``run.add_step`` 归档，形成可回链证据；
- 单测可注入 ``probe`` 回调，完全离线确定性。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from . import jsonio
from .roe import roe_status

_TABLE = (
    "CREATE TABLE IF NOT EXISTS retests(id INTEGER PRIMARY KEY, run TEXT, finding TEXT, module TEXT,"
    " conclusion TEXT, detail TEXT, evidence_path TEXT, actor TEXT, created_at REAL)"
)


class RetestError(ValueError):
    """finding/traffic 参数非法。"""


def _find_finding(run, title_or_index: Any) -> dict:
    findings = run.findings
    if isinstance(title_or_index, int):
        if not (0 <= title_or_index < len(findings)):
            raise RetestError(f"finding 下标越界：{title_or_index}")
        return findings[title_or_index]
    for f in findings:
        if f.get("title") == title_or_index:
            return f
    raise RetestError(f"未找到 finding：{title_or_index!r}")


def _checks_for(run, module: str) -> list[dict]:
    checks = []
    for t in run.traffic:
        if t.get("module") != module:
            continue
        checks.append({"seq": t.get("seq"), "method": t.get("method"), "url": t.get("url"),
                       "expect_status": int(t.get("status") or 0),
                       "recorded_sha256": t.get("sha256", ""),
                       "req_body": t.get("req_body"), "ts": t.get("ts")})
    return sorted(checks, key=lambda c: (c.get("seq") or 0))


def plan(store, run_name: str, title_or_index: Any) -> dict:
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise RetestError(f"run 不存在：{run_name}") from exc
    finding = _find_finding(run, title_or_index)
    module = finding.get("step_key", "")
    checks = _checks_for(run, module)
    return {"run": run_name, "finding": finding.get("title"), "module": module,
            "mode": "dry", "execution": False, "checks": checks,
            "count": len(checks), "conclusion": "not-run",
            "gate": "live=True 时须 ROE 已签署 + execute 权限"}


def _probe_default(entry: dict) -> dict:
    from .traffic import _replay_one

    return _replay_one(entry)


def _conclusion(checks: list[dict], results: list[dict]) -> str:
    if not checks:
        return "no-checks"
    if any(r.get("error") for r in results):
        return "error"
    verdicts = []
    for c, r in zip(checks, results):
        actual = int(r.get("actual_status") or 0)
        expect = int(c.get("expect_status") or 0)
        if actual == expect:
            verdicts.append("open")
        elif 400 <= actual < 500:
            verdicts.append("fixed")
        else:
            verdicts.append("changed")
    if all(v == "fixed" for v in verdicts):
        return "fixed"
    if any(v == "open" for v in verdicts):
        return "open"
    return "changed"


def run_retest(store, session, run_name: str, title_or_index: Any, *,
               live: bool = False, probe: Callable[[dict], dict] | None = None) -> dict:
    base = plan(store, run_name, title_or_index)
    if not live:
        jsonio.append_audit(store, getattr(session, "name", "system"), "retest.plan",
                            base["finding"], {"run": run_name, "checks": base["count"]}, "ok")
        return base
    if roe_status(store) != "complete":
        from .roe import ExecutionLocked

        raise ExecutionLocked("工作区授权未完成（consent 未签署）")
    if not session.can("execute"):
        raise PermissionError(f"{session.name}({session.role}) 无 execute 权限")
    run = store.open_run(run_name)
    checks = base["checks"]
    probe = probe or _probe_default
    results = []
    for c in checks:
        try:
            r = probe(c)
        except Exception as exc:
            r = {"actual_status": 0, "error": f"{type(exc).__name__}: {exc}"}
        results.append({"seq": c["seq"], "url": c["url"], "expect_status": c["expect_status"],
                        "actual_status": r.get("actual_status", 0),
                        "ok": bool(r.get("ok")), "error": r.get("error", "")})
    conclusion = _conclusion(checks, results)
    now = time.time()
    out_dir = Path(run.dir) / "retests"
    out_dir.mkdir(exist_ok=True)
    art = out_dir / f"{(base['module'] or 'unknown')}-{int(now)}.json"
    doc = {"run": run_name, "finding": base["finding"], "module": base["module"],
           "conclusion": conclusion, "checks": checks, "results": results,
           "actor": session.name, "ts": now,
           "deterministic": True,
           "criteria": {"open": "status unchanged", "fixed": "4xx after fix",
                        "changed": "other status change", "no-checks": "no traffic"}}
    art.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    step = run.add_step(f"retest-{base['module']}", "retest", {"finding": base["finding"]},
                        f"复测结论 {conclusion}（{len(checks)} checks）", artifacts=[art])
    with run._tx() as conn:
        conn.execute(_TABLE)
        conn.execute(
            "INSERT INTO retests(run, finding, module, conclusion, detail, evidence_path, actor, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (run_name, base["finding"], base["module"], conclusion,
             json.dumps(results, ensure_ascii=False), step["archive"], session.name, now))
    run.log_action(session.name, "retest", base["module"],
                   {"finding": base["finding"], "conclusion": conclusion,
                    "checks": len(checks)}, conclusion)
    jsonio.append_audit(store, session.name, "retest.run", base["finding"],
                        {"run": run_name, "conclusion": conclusion,
                         "checks": len(checks)}, conclusion)
    return {**base, "mode": "live", "execution": True, "conclusion": conclusion,
            "results": results, "evidence_path": step["archive"], "checked_at": now}


def list_retests(store, run_name: str) -> list[dict]:
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise RetestError(f"run 不存在：{run_name}") from exc
    with run._tx() as conn:
        conn.execute(_TABLE)
    rows = run.query(
        "SELECT id, finding, module, conclusion, detail, evidence_path, actor, created_at"
        " FROM retests WHERE run=? ORDER BY id", (run_name,))
    keys = ["id", "finding", "module", "conclusion", "detail", "evidence_path",
            "actor", "created_at"]
    return [dict(zip(keys, r)) for r in rows]
