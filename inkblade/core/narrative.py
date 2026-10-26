# -*- coding: utf-8 -*-
"""CTEM 五阶段报告叙事（CM-20）：暴露验证 → 侦查 → 攻击 → 报告 → 修复验证。

- 从 run 的 steps/findings、资产库、retests 表重建五阶段章节；每章含计数、要点与证据锚；
- ``narrative`` 默认确定性模板（零 token）；工作区启用 LLM 池时可用其生成摘要，
  失败自动降级（``core/llmpool.narrate``）；
- 只读：不执行模块、不修改 findings；报告可导出 Markdown。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import kb, llmpool
from .discovery import AssetInventory
from .registry import load_modules
from .retest import list_retests

PHASES = [
    ("exposure", "暴露验证", "Exposure validation"),
    ("recon", "侦查", "Reconnaissance"),
    ("attack", "攻击", "Attack"),
    ("report", "报告", "Reporting"),
    ("remediation", "修复验证", "Remediation verification"),
]

SERIES_KEYWORDS = {
    "侦察": ("exposure", "discovery", "dns", "fingerprint", "observability", "kube-audit",
             "port", "metadata", "recon"),
    "权限链": ("rbac", "privilege", "escape", "token", "serviceaccount", "sa-", "permission"),
    "横向利用": ("lateral", "nccl", "collective", "fabric", "multus", "sharp", "rdma", "roce"),
    "窃取与数据泄露": ("theft", "leak", "exfil", "bucket", "weight", "checkpoint", "model",
                       "residue", "cache"),
    "核心代码": ("code", "sink", "pickle", "rce", "plugin", "webui", "dify", "skyrl", "trl"),
    "混合云": ("cloud", "imds", "irsa", "instance", "snapshot", "role"),
    "网络架构": ("network", "route", "gateway", "inference", "scheduler", "cni", "policy"),
    "AI 网关": ("aigateway", "litellm", "higress", "gateway"),
    "情报": ("intel", "audit"),
}


class NarrativeError(ValueError):
    """run/报告参数非法。"""


def _series_of(store, step_keys: list[str]) -> dict[str, str]:
    mods = load_modules(Path(store.root) / "modules") \
        if (Path(store.root) / "modules").exists() else {}
    out = {}
    for key in step_keys:
        meta = mods.get(key)
        if meta is not None:
            out[key] = meta.series
            continue
        low = key.lower()
        for series, words in SERIES_KEYWORDS.items():
            if any(w in low for w in words):
                out[key] = series
                break
        else:
            out[key] = "核心代码"
    return out


def build(store, run_name: str) -> dict:
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise NarrativeError(f"run 不存在：{run_name}") from exc
    findings = run.findings
    steps = run.query("SELECT step_key, result_summary, archive FROM steps ORDER BY id")
    step_keys = sorted({r[0] for r in steps})
    series = _series_of(store, step_keys)
    sev = {}
    for f in findings:
        sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
    assets = AssetInventory(store).list(kind="service")
    try:
        retests = list_retests(store, run_name)
    except Exception:
        retests = []
    recon_steps = [k for k in step_keys if series.get(k) == "侦察"]
    attack_steps = [k for k in step_keys if series.get(k) != "侦察"]
    recon_findings = [f for f in findings if series.get(f.get("step_key")) == "侦察"]
    attack_findings = [f for f in findings if series.get(f.get("step_key")) != "侦察"]
    anchors = [r[2] for r in steps if r[2]]

    sections = {
        "exposure": {
            "title": dict(zip(("zh", "en"), PHASES[0][1:])),
            "counts": {"services": len(assets), "exposed_findings": len(recon_findings),
                       "namespaces": len({a.get("namespace") for a in assets if a.get("namespace")})},
            "items": [f"[{a.get('product') or 'unknown'}] {a['asset_key']}"
                      for a in assets[:20]],
            "evidence": anchors[:10],
        },
        "recon": {
            "title": dict(zip(("zh", "en"), PHASES[1][1:])),
            "counts": {"steps": len(recon_steps), "findings": len(recon_findings)},
            "items": [f"{f.get('severity')}: {f.get('title')}" for f in recon_findings[:20]],
            "evidence": anchors[:10],
        },
        "attack": {
            "title": dict(zip(("zh", "en"), PHASES[2][1:])),
            "counts": {"steps": len(attack_steps), "findings": len(attack_findings),
                       "series": sorted({series[k] for k in attack_steps})},
            "items": [f"{f.get('severity')}: {f.get('title')}" for f in attack_findings[:20]],
            "evidence": anchors[:10],
        },
        "report": {
            "title": dict(zip(("zh", "en"), PHASES[3][1:])),
            "counts": {"findings": len(findings), "by_severity": sev,
                       "zeroday": sum(1 for f in findings if f.get("is_zeroday")),
                       "kb_entries": len({kb.cite(f)["key"] for f in findings})},
            "items": [f"[{kb.cite(f)['key']}] {f.get('title')}" for f in findings[:20]],
            "evidence": anchors[:10],
        },
        "remediation": {
            "title": dict(zip(("zh", "en"), PHASES[4][1:])),
            "counts": {"retests": len(retests),
                       "fixed": sum(1 for r in retests if r.get("conclusion") == "fixed"),
                       "open": sum(1 for r in retests if r.get("conclusion") == "open")},
            "items": [f"{r.get('module')}: {r.get('conclusion')}" for r in retests[:20]],
            "evidence": [r.get("evidence_path", "") for r in retests if r.get("evidence_path")][:10],
        },
    }
    runs = [p.name for p in Path(store.ws_dir).iterdir()
            if p.is_dir() and not p.name.startswith("_") and (p / "evidence.db").is_file()]
    facts = {"runs": len(runs), "run": run_name, "findings": len(findings),
             "critical": sev.get("critical", 0), "steps": len(steps),
             "series": sorted(set(series.values())), "assets": len(assets),
             "retests": len(retests)}
    narrative = llmpool.narrate(store, facts)
    return {"run": run_name, "generated_at": time.time(), "sections": sections,
            "facts": facts, "narrative": narrative,
            "read_only": True, "writes": {"actions": 0, "runs": 0}}


def render_md(report: dict) -> str:
    lines = [f"# CTEM 报告叙事：{report.get('run')}", "",
             f"> 生成时间 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(report.get('generated_at', time.time())))}"
             f" · 只读重建 · 叙述模式 {report.get('narrative', {}).get('mode')}", ""]
    if report.get("narrative", {}).get("text"):
        lines += [f"> {report['narrative']['text']}", ""]
    for key, zh, en in PHASES:
        s = report.get("sections", {}).get(key, {})
        lines += [f"## {zh} / {en}", ""]
        counts = s.get("counts", {})
        lines.append("- 计数：" + ", ".join(f"{k}={v}" for k, v in counts.items()))
        for item in s.get("items", [])[:10]:
            lines.append(f"- {item}")
        if s.get("evidence"):
            lines.append("- 证据锚：" + ", ".join(f"`{e}`" for e in s["evidence"][:5]))
        lines.append("")
    return "\n".join(lines) + "\n"


def export(store, run_name: str, path: Path | str) -> Path:
    report = build(store, run_name)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_md(report), encoding="utf-8")
    return p
