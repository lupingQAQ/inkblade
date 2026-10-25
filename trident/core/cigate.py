# -*- coding: utf-8 -*-
"""CI/CD 退出码契约（CM-11）：阈值判定 + 机器可读摘要。

退出码（稳定契约）：
- ``0`` 通过（无达到阈值的 finding）；
- ``1`` 配置/输入非法（由调用方把 :class:`CiGateError` 映射为 1）；
- ``2`` 策略违规（存在达到阈值的 finding，且含基线内既有问题）；
- ``3`` 回归（仅相对基线新增的 finding 达到阈值；或 ``fail_on_new_only`` 下的新增）。

策略字段：``fail_on``（默认 high）、``baseline``（key 列表或含 findings 的对象）、
``fail_on_new_only``（默认 false）、``allow_zeroday``（默认 false，即零日 finding 同样
参与阈值判定）。摘要 JSON 含 severity 计数、failing 列表、基线差异与证据锚。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
EXIT_OK, EXIT_CONFIG, EXIT_POLICY, EXIT_REGRESSION = 0, 1, 2, 3


class CiGateError(ValueError):
    """策略/输入非法（退出码 1）。"""


def finding_key(f: dict) -> str:
    if f.get("key"):
        return str(f["key"])
    return f"{f.get('step_key', '')}|{f.get('title', '')}"


def _rank(sev: str) -> int:
    try:
        return SEVERITIES.index(str(sev).lower())
    except ValueError:
        return 0


def _baseline_keys(policy: dict) -> set[str]:
    raw = policy.get("baseline")
    if raw is None:
        return set()
    if isinstance(raw, dict):
        raw = raw.get("findings") or raw.get("keys") or []
    if not isinstance(raw, list):
        raise CiGateError("baseline 必须是列表或含 findings/keys 的对象")
    keys = set()
    for item in raw:
        if isinstance(item, dict):
            keys.add(finding_key(item))
        else:
            keys.add(str(item))
    return keys


def evaluate(findings: list[dict], policy: dict | None = None) -> dict:
    policy = dict(policy or {})
    threshold = str(policy.get("fail_on") or "high").lower()
    if threshold not in SEVERITIES:
        raise CiGateError(f"未知 fail_on 阈值 {threshold!r}")
    if not isinstance(findings, list):
        raise CiGateError("findings 必须是列表")
    allow_zeroday = bool(policy.get("allow_zeroday", False))
    baseline = _baseline_keys(policy)
    baseline_present = "baseline" in policy and policy.get("baseline") is not None
    failing, passing = [], []
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = str(f.get("severity") or f.get("sev") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
        hit = _rank(sev) >= _rank(threshold)
        if hit and bool(f.get("is_zeroday")) and allow_zeroday:
            hit = False
        row = {"key": finding_key(f), "severity": sev,
               "title": f.get("title", ""), "step_key": f.get("step_key", ""),
               "evidence_path": f.get("evidence_path", ""),
               "is_zeroday": bool(f.get("is_zeroday"))}
        (failing if hit else passing).append(row)
    new_failing = [r for r in failing if r["key"] not in baseline]
    existing_failing = [r for r in failing if r["key"] in baseline]
    if not failing:
        code = EXIT_OK
    elif bool(policy.get("fail_on_new_only")):
        code = EXIT_REGRESSION if new_failing else EXIT_OK
    elif baseline_present and new_failing and not existing_failing:
        code = EXIT_REGRESSION
    else:
        code = EXIT_POLICY
    return {
        "ok": code == EXIT_OK, "exit_code": code, "threshold": threshold,
        "policy": {"fail_on": threshold, "fail_on_new_only": bool(policy.get("fail_on_new_only")),
                   "allow_zeroday": allow_zeroday, "baseline_present": baseline_present,
                   "baseline_size": len(baseline)},
        "counts": {"total": len(findings), "failing": len(failing),
                   "new_failing": len(new_failing),
                   "by_severity": counts},
        "failing": failing, "new_failing": new_failing,
        "baseline_existing": existing_failing,
        "summary": {"gate": "fail" if code else "pass",
                    "headline": f"{len(failing)} finding(s) >= {threshold}",
                    "contract": {"0": "pass", "1": "config-error",
                                 "2": "policy-violation", "3": "regression"}},
    }


def evaluate_run(store, run_name: str, policy: dict | None = None) -> dict:
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise CiGateError(f"run 不存在：{run_name}") from exc
    result = evaluate(run.findings, policy)
    result["run"] = run_name
    return result


def baseline_from_runs(store, run_names: list[str], *, severity: str = "") -> list[str]:
    keys = []
    for name in run_names:
        try:
            run = store.open_run(name)
        except KeyError as exc:
            raise CiGateError(f"run 不存在：{name}") from exc
        for f in run.findings:
            if severity and _rank(f.get("severity", "info")) < _rank(severity):
                continue
            keys.append(finding_key(f))
    return keys


def write_summary(result: dict, path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def render_md(result: dict) -> str:
    s = result.get("summary", {})
    lines = [f"# CI Gate：{s.get('gate', '?')}", "",
             f"- 退出码：**{result.get('exit_code')}**（{s.get('headline', '')}）",
             f"- 阈值：{result.get('threshold')}；总数 {result.get('counts', {}).get('total', 0)}；"
             f"failing {result.get('counts', {}).get('failing', 0)}；"
             f"new {result.get('counts', {}).get('new_failing', 0)}", "",
             "| 严重度 | Key | 标题 |", "|---|---|---|"]
    for f in result.get("failing", []):
        lines.append(f"| {f['severity']} | {f['key']} | {f['title']} |")
    return "\n".join(lines) + "\n"
