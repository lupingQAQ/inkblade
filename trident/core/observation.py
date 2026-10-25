# -*- coding: utf-8 -*-
"""结构化观察：动作 / 结果 / 证据指针 / 下一步候选。

产品动机（第三节差距）：参赛项目的复盘反复出现同一组问题——上下文腐败、
结论无法追溯、失败路径被重复尝试、下一步全靠模型即兴。这里把「观察到什么」
固化成可审计结构，而不是继续堆聊天记录。

边界：
- 只读/写文件均在**工作区**内（``evidence/<ws>/agent/observations.jsonl``）；
- 「确认」必须带证据指针（run/step/finding/file/audit/plan/artifact）；
  没有证据的失败观察降级为 hypothesis，不允许冒充结论。
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

SCHEMA = "trident-observation-v1"
MAX_SUMMARY = 400
EVIDENCE_KINDS = ("run", "step", "finding", "file", "audit", "plan", "artifact")
STATUSES = ("ok", "failed", "skipped", "proposed")


class ObservationError(ValueError):
    """观察结构非法（缺证据/候选越界/状态未知）。"""


def _short(text: Any, limit: int = MAX_SUMMARY) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[:limit] + "…"


def _tokens(text: str) -> int:
    # 与 cost.estimate_tokens 同口径，避免循环依赖
    return max(1, math.ceil(len(text) / 4))


def action_key(action: dict) -> str:
    """同一动作（模块 + 参数）的稳定去重键。"""
    payload = json.dumps({"module": action.get("module"),
                          "params": action.get("params") or {}},
                         ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _normalize_evidence(evidence: list[dict] | None) -> list[dict]:
    out: list[dict] = []
    for item in evidence or []:
        if not isinstance(item, dict):
            raise ObservationError(f"证据指针必须是对象: {item!r}")
        kind, ref = item.get("kind"), item.get("ref")
        if kind not in EVIDENCE_KINDS:
            raise ObservationError(f"未知证据类型 {kind!r}（可选 {EVIDENCE_KINDS}）")
        if not ref:
            raise ObservationError("证据指针缺少 ref")
        out.append({"kind": kind, "ref": str(ref),
                    **({"detail": _short(item["detail"])} if item.get("detail") else {})})
    return out


def _normalize_candidates(candidates: list[dict] | None) -> list[dict]:
    out: list[dict] = []
    for item in candidates or []:
        if not isinstance(item, dict) or not item.get("module"):
            raise ObservationError(f"候选缺少 module: {item!r}")
        try:
            conf = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        out.append({
            "module": str(item["module"]),
            "reason": _short(item.get("reason", "")),
            "confidence": round(min(1.0, max(0.0, conf)), 2),
            "requires_approval": bool(item.get("requires_approval", True)),
            "source": item.get("source", "policy"),
        })
    return out


def build(step: int, action: dict, *, status: str = "ok", result_summary: str = "",
          evidence: list[dict] | None = None, candidates: list[dict] | None = None,
          tokens: int = 0, latency_ms: int = 0) -> dict:
    """构造一条观察；``ok`` 且无证据指针 → 拒绝（不允许无证据结论）。"""
    if status not in STATUSES:
        raise ObservationError(f"未知状态 {status!r}（可选 {STATUSES}）")
    if not isinstance(action, dict) or not action.get("module"):
        raise ObservationError("动作缺少 module")
    ev = _normalize_evidence(evidence)
    if status == "ok" and not ev:
        raise ObservationError("确认结论缺证据指针：请先落 run/step/finding 再观察")
    claim = "confirmed" if status == "ok" else ("planned" if status == "proposed"
                                                else "hypothesis")
    summary = _short(result_summary)
    return {
        "schema": SCHEMA,
        "step": int(step),
        "key": action_key(action),
        "action": {"module": str(action["module"]),
                   "writes": bool(action.get("writes")),
                   "params": _short(json.dumps(action.get("params") or {},
                                                ensure_ascii=False, sort_keys=True), 200)},
        "result": {"status": status, "summary": summary},
        "evidence": ev,
        "next": _normalize_candidates(candidates),
        "claim": claim,
        "tokens": int(tokens),
        "latency_ms": int(latency_ms),
    }


def dedupe(observations: list[dict]) -> list[dict]:
    """同键观察只保留一条：优先最新成功，其次最新一条。"""
    latest: dict[str, dict] = {}
    order: list[str] = []
    for obs in observations:
        key = obs.get("key") or action_key(obs.get("action") or {})
        if key not in latest:
            order.append(key)
            latest[key] = obs
            continue
        old, new = latest[key], obs
        if new.get("result", {}).get("status") == "ok" or \
                old.get("result", {}).get("status") != "ok":
            latest[key] = new
    return [latest[k] for k in order]


def is_dead_end(observations: list[dict], module: str) -> bool:
    """同一模块连续/累计两次失败 → 视为死胡同，不再自动提议。"""
    fails = [o for o in observations
             if o.get("action", {}).get("module") == module
             and o.get("result", {}).get("status") == "failed"]
    return len(fails) >= 2


def next_candidates(catalog: list[dict], observations: list[dict],
                    *, limit: int = 3) -> list[dict]:
    """从候选目录生成下一步：排除已成功动作与死胡同，只读优先。"""
    done = {o["action"]["module"] for o in observations
            if o.get("result", {}).get("status") == "ok"}
    picked: list[dict] = []
    seen: set[str] = set()
    ordered = sorted(catalog, key=lambda c: (bool(c.get("writes")), str(c.get("module"))))
    for item in ordered:
        module = item.get("module")
        if not module or module in done or module in seen:
            continue
        if is_dead_end(observations, module):
            continue
        seen.add(module)
        picked.append({"module": module,
                       "reason": _short(item.get("reason", "候选目录")),
                       "confidence": float(item.get("confidence", 0.5)),
                       "requires_approval": bool(item.get("writes", True)),
                       "source": "catalog"})
        if len(picked) >= limit:
            break
    return picked


def compress(observations: list[dict], *, max_items: int = 20) -> dict:
    """上下文压缩：confirmed 优先、按步号倒序，并估算省下的 token。"""
    if max_items < 1:
        raise ObservationError("max_items 必须 >= 1")
    ranked = sorted(observations,
                    key=lambda o: (o.get("claim") != "confirmed", -int(o.get("step", 0))))
    kept = ranked[:max_items]
    dropped = ranked[max_items:]
    items = [{
        "step": o.get("step"), "module": o.get("action", {}).get("module"),
        "status": o.get("result", {}).get("status"),
        "summary": o.get("result", {}).get("summary"),
        "evidence": [e.get("ref") for e in o.get("evidence") or []],
        "claim": o.get("claim"), "key": o.get("key"),
    } for o in kept]
    saved = sum(_tokens(str(o.get("result", {}).get("summary", ""))) +
                _tokens(json.dumps(o.get("evidence") or [], ensure_ascii=False))
                for o in dropped)
    return {"schema": SCHEMA, "items": items, "dropped": len(dropped),
            "tokens_saved": saved, "total": len(observations)}


def coverage(observations: list[dict]) -> dict:
    total = len(observations)
    confirmed = sum(1 for o in observations
                    if o.get("result", {}).get("status") == "ok" and o.get("evidence"))
    return {"total": total, "confirmed": confirmed,
            "ratio": round(confirmed / total, 3) if total else 0.0}


def observation_path(store) -> Path:
    return Path(store.ws_dir) / "agent" / "observations.jsonl"


def append(store, observation: dict) -> Path:
    """追加写入工作区 JSONL（只追加，不改历史）。"""
    path = observation_path(store)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(observation, ensure_ascii=False) + "\n")
    return path


def read(path: Path | str, *, limit: int | None = None) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    rows: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    if limit:
        rows = rows[-int(limit):]
    return rows
