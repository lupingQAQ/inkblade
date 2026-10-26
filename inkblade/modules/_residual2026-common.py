# -*- coding: utf-8 -*-
"""_residual2026-common — R01–R07 残余缺口模块族共享库（只读快照分析）。

统一输入：一份 JSON 快照（dict 或路径），由客户/实验室采集器导出；模块不发起
网络请求、不写控制面、不执行外部命令。每条 finding 携带来源议题与必要性说明。
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SEVS = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVS)}


def load_snapshot(params: dict) -> dict:
    raw = params.get("snapshot")
    if raw is None:
        return dict(params)
    if isinstance(raw, dict):
        return raw
    path = Path(str(raw))
    if not path.is_file():
        raise ValueError(f"snapshot 不存在：{path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc if isinstance(doc, dict) else {"items": doc}


def section(doc: dict, *keys, default=None):
    for key in keys:
        value = doc.get(key)
        if value is not None:
            return value
    return default if default is not None else {}


def items(doc: dict, *keys) -> list[dict]:
    value = section(doc, *keys, default=[])
    if isinstance(value, dict):
        for k in ("items", "servers", "skills", "agents", "services", "operators"):
            if isinstance(value.get(k), list):
                return [x for x in value[k] if isinstance(x, dict)]
        return [value] if value else []
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if value is not None else ""
    if text in ("1", "true", "yes", "on", "enabled"):
        return True
    if text in ("0", "false", "no", "off", "disabled", ""):
        return False
    return default


def as_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def wildcard(value) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(wildcard(v) for v in value)
    return str(value or "").strip() in ("*", "all", "any", "0.0.0.0/0", "::/0", "**")


def finding(sev: str, title: str, detail: dict | str, *, evidence: str = "",
            mapping: str = "", source: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {
        "sev": sev,
        "title": title,
        "detail": json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail),
    }
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if source:
        item["source"] = source
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def summary_json(family: str, findings: list[dict], *, extra: dict | None = None,
                 source: str = "") -> str:
    counts = Counter(f.get("sev", "info") for f in findings)
    top = min((f.get("sev", "info") for f in findings),
              key=lambda s: _RANK.get(s, len(_RANK)), default="none")
    payload = {"family": family, "findings": len(findings),
               "severity": {s: counts[s] for s in SEVS if counts.get(s)},
               "top": top, "source": source}
    payload.update(extra or {})
    return json.dumps(payload, ensure_ascii=False)


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run") if isinstance(ctx, dict) else None
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def result(ctx: dict, key: str, family: str, findings: list[dict], *,
           extra: dict | None = None, source: str = "") -> dict:
    summary = summary_json(family, findings, extra=extra, source=source)
    artifact = write_artifact(ctx, f"{key}.json", {
        "summary": json.loads(summary),
        "findings": findings,
        "note": "只读快照分析；未连接控制面，未执行写操作。",
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
