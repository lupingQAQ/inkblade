# -*- coding: utf-8 -*-
"""InkBlade 0day reserve: state machine, registry and human report.

The reserve is deliberately strict:

* ``candidate`` is the only entry state for unverified claims.
* ``verified-exploitable`` requires a dynamic reproduction (``verification.status
  == "verified"`` and ``verification.dynamic is True``).
* ``novelty-checked`` requires a novelty verdict from ``tools/novelty-check.py``.
* ``disclosed`` is only reachable for ``confirmed-unpublished`` findings.
* ``public`` is terminal.

Only an entry that is simultaneously **verified** and
**confirmed-unpublished** contributes to ``0day-reserve``.  A public CVE,
GHSA, security commit, vendor advisory or an inconclusive network check is
never counted.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parents[1]
DEFAULT_INVENTORY = ROOT / "corpus" / "zeroday" / "inventory.json"
DEFAULT_NOVELTY = ROOT / "corpus" / "novelty" / "results.json"
DEFAULT_REGISTRY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
DEFAULT_DOC = ROOT / "docs" / "0DAY-RESERVE.md"

STATES = ("candidate", "verified-exploitable", "novelty-checked", "disclosed", "public")
TRANSITIONS = {
    "candidate": {"verified-exploitable"},
    "verified-exploitable": {"novelty-checked"},
    "novelty-checked": {"disclosed", "public"},
    "disclosed": {"public"},
    "public": set(),
}
VERIFICATION_STATUSES = {"verified", "static-only", "unsupported", "failed"}
NOVELTY_VERDICTS = {"confirmed-unpublished", "already-public", "inconclusive"}
SOURCE_LABELS = {
    "audit-history": "审计历史-核心框架",
    "omni-jev": "审计历史-OMNI/JEV",
    "agent-platform": "审计历史-Agent 平台",
    "mining": "挖掘候选",
    "new-discovery": "新增发现",
    "legacy-candidate": "遗留候选",
}


class ReserveError(ValueError):
    """Invalid inventory/registry data or an illegal state transition."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: Path | str, default: Any = None) -> Any:
    p = Path(path)
    if not p.is_file():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(path: Path | str, obj: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
    return p


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_path(path: str | Path, *, root: Path = ROOT) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    if (root / p).exists():
        return root / p
    return WORKSPACE / p


def evidence_digest(entry: dict) -> str | None:
    ev = entry.get("evidence") or {}
    path = ev.get("path")
    if not path:
        return None
    resolved = resolve_path(path)
    if resolved.is_file():
        return sha256_file(resolved)
    if resolved.is_dir():
        h = hashlib.sha256()
        for file in sorted(p for p in resolved.rglob("*") if p.is_file()):
            h.update(str(file.relative_to(resolved)).replace("\\", "/").encode())
            h.update(sha256_file(file).encode())
        return h.hexdigest()
    return None


def transition(current: str, target: str, entry: dict | None = None) -> str:
    """Validate one explicit state transition and return the new state.

    Same-state calls are idempotent.  Backward, skipped and guarded
    transitions raise :class:`ReserveError`.
    """
    if current not in STATES:
        raise ReserveError(f"unknown state {current!r}")
    if target not in STATES:
        raise ReserveError(f"unknown target state {target!r}")
    if current == target:
        return target
    if target not in TRANSITIONS[current]:
        raise ReserveError(f"illegal transition {current} -> {target}")
    if entry is not None:
        verification = entry.get("verification") or {}
        novelty = entry.get("novelty_result") or {}
        if target == "verified-exploitable":
            if verification.get("status") != "verified" or not verification.get("dynamic"):
                raise ReserveError("verified-exploitable requires a dynamic verified reproduction")
        if target == "novelty-checked":
            if verification.get("status") != "verified" or not verification.get("dynamic"):
                raise ReserveError("novelty-checked requires verified-exploitable first")
            if novelty.get("verdict") not in NOVELTY_VERDICTS:
                raise ReserveError("novelty-checked requires a novelty verdict")
        if target == "disclosed" and novelty.get("verdict") != "confirmed-unpublished":
            raise ReserveError("only confirmed-unpublished findings can be disclosed")
        if target == "public" and current == "novelty-checked" and novelty.get("verdict") != "already-public":
            raise ReserveError("novelty-checked -> public requires already-public")
    return target


def derive_state(entry: dict) -> str:
    """Compute the furthest justified state from evidence and novelty data."""
    verification = entry.get("verification") or {}
    novelty = entry.get("novelty_result") or {}
    disclosure = entry.get("disclosure") or {}
    verified = verification.get("status") == "verified" and bool(verification.get("dynamic"))
    verdict = novelty.get("verdict")
    if disclosure.get("status") == "public":
        return "public"
    if disclosure.get("status") == "disclosed" and verified and verdict == "confirmed-unpublished":
        return "disclosed"
    if not verified:
        return "candidate"
    if verdict == "confirmed-unpublished":
        return "novelty-checked"
    if verdict == "already-public":
        return "public"
    return "verified-exploitable"


def is_reserve(entry: dict) -> bool:
    if entry.get("reserve_eligible") is False:
        return False
    verification = entry.get("verification") or {}
    novelty = entry.get("novelty_result") or {}
    return (
        verification.get("status") == "verified"
        and bool(verification.get("dynamic"))
        and novelty.get("verdict") == "confirmed-unpublished"
        and entry.get("state") in ("novelty-checked", "disclosed")
    )


def dedupe_key(entry: dict) -> str:
    if entry.get("dedupe_key"):
        return str(entry["dedupe_key"])
    if entry.get("source") == "mining":
        rc = entry.get("root_cause") or {}
        return f"{entry.get('component')}:{rc.get('file')}:{rc.get('line')}"
    return str(entry.get("id"))


def _require(entry: dict, field: str) -> Any:
    value = entry.get(field)
    if value in (None, "", [], {}):
        raise ReserveError(f"{entry.get('id', '?')}: missing {field}")
    return value


def validate_entry(entry: dict) -> None:
    eid = _require(entry, "id")
    if entry.get("source") not in SOURCE_LABELS:
        raise ReserveError(f"{eid}: invalid source {entry.get('source')!r}")
    _require(entry, "component")
    _require(entry, "title")
    verification = entry.get("verification") or {}
    status = verification.get("status")
    if status not in VERIFICATION_STATUSES:
        raise ReserveError(f"{eid}: invalid verification status {status!r}")
    root = entry.get("root_cause") or {}
    if status == "verified":
        if not verification.get("dynamic"):
            raise ReserveError(f"{eid}: verified without dynamic=true")
        if not root.get("file"):
            raise ReserveError(f"{eid}: verified without root_cause.file")
        if not entry.get("evidence", {}).get("path"):
            raise ReserveError(f"{eid}: verified without evidence.path")
    novelty = entry.get("novelty_result")
    if novelty is not None and novelty.get("verdict") not in NOVELTY_VERDICTS:
        raise ReserveError(f"{eid}: invalid novelty verdict {novelty.get('verdict')!r}")
    state = entry.get("state")
    if state not in STATES:
        raise ReserveError(f"{eid}: invalid state {state!r}")
    if state in ("novelty-checked", "disclosed") and novelty is None:
        raise ReserveError(f"{eid}: {state} without novelty result")
    if state == "disclosed" and novelty.get("verdict") != "confirmed-unpublished":
        raise ReserveError(f"{eid}: disclosed but not confirmed-unpublished")
    if state == "public" and novelty and novelty.get("verdict") == "confirmed-unpublished":
        raise ReserveError(f"{eid}: public but novelty says confirmed-unpublished")


def _entry_counts(entry: dict) -> dict:
    verification = entry.get("verification") or {}
    novelty = entry.get("novelty_result") or {}
    return {
        "verified": verification.get("status") == "verified" and bool(verification.get("dynamic")),
        "static": verification.get("status") == "static-only",
        "unsupported": verification.get("status") == "unsupported",
        "failed": verification.get("status") == "failed",
        "confirmed": novelty.get("verdict") == "confirmed-unpublished",
        "public": novelty.get("verdict") == "already-public",
        "inconclusive": novelty.get("verdict") == "inconclusive",
        "reserve": is_reserve(entry),
    }


def build_registry(inventory: dict, novelty: dict | None = None, *, root: Path = ROOT) -> dict:
    entries_in = inventory.get("entries") or []
    if not isinstance(entries_in, list) or not entries_in:
        raise ReserveError("inventory has no entries")
    verdicts = (novelty or {}).get("verdicts") or {}
    entries: list[dict] = []
    seen: set[str] = set()
    for raw in entries_in:
        entry = copy.deepcopy(raw)
        eid = entry.get("id")
        if not eid:
            raise ReserveError("inventory entry without id")
        if eid in seen:
            raise ReserveError(f"duplicate entry id {eid}")
        seen.add(eid)
        if eid in verdicts:
            entry["novelty_result"] = copy.deepcopy(verdicts[eid])
        elif entry.get("novelty_result") is None:
            entry["novelty_result"] = None
        entry["state"] = derive_state(entry)
        entry["evidence_sha256"] = evidence_digest(entry)
        validate_entry(entry)
        entries.append(entry)

    by_source: dict[str, dict] = {}
    for source in SOURCE_LABELS:
        rows = [e for e in entries if e.get("source") == source]
        counts = {k: 0 for k in ("verified", "static", "unsupported", "failed", "confirmed", "public", "inconclusive", "reserve")}
        for e in rows:
            for k, v in _entry_counts(e).items():
                counts[k] += int(v)
        by_source[source] = {"label": SOURCE_LABELS[source], "total": len(rows), **counts}

    totals = {k: sum(v[k] for v in by_source.values()) for k in next(iter(by_source.values())) if k not in ("label",)}
    reserve = [e for e in entries if is_reserve(e)]
    unique: dict[str, dict] = {}
    for e in reserve:
        unique.setdefault(dedupe_key(e), e)
    excluded_non_0day = [
        e for e in entries
        if e.get("reserve_eligible") is False
        and (e.get("verification") or {}).get("status") == "verified"
        and (e.get("novelty_result") or {}).get("verdict") == "confirmed-unpublished"
    ]
    already_public = [e for e in entries if (e.get("novelty_result") or {}).get("verdict") == "already-public"]
    inconclusive = [e for e in entries if (e.get("novelty_result") or {}).get("verdict") == "inconclusive"]
    components: dict[str, dict] = {}
    for e in entries:
        comp = str(e.get("component") or "unknown")
        item = components.setdefault(comp, {"component": comp, "entries": 0, "verified": 0, "reserve": 0,
                                            "reachability": []})
        item["entries"] += 1
        item["verified"] += int((e.get("verification") or {}).get("status") == "verified")
        item["reserve"] += int(is_reserve(e))
        text = (e.get("reachability") or "").strip()
        if text:
            item["reachability"].append({"id": e.get("id"), "text": text})
    return {
        "schema": "inkblade-zeroday-registry-v1",
        "generated_at": now(),
        "reserve_rule": "verified (dynamic) + confirmed-unpublished; already-public/inconclusive never count",
        "inventory": inventory.get("schema"),
        "summary": {
            "total": len(entries),
            "by_source": by_source,
            **totals,
            "reserve": len(reserve),
            "reserve_ids": [e["id"] for e in reserve],
            "reserve_unique": len(unique),
            "reserve_unique_ids": [e["id"] for e in unique.values()],
            "excluded_non_0day": [e["id"] for e in excluded_non_0day],
            "already_public_ids": [e["id"] for e in already_public],
            "inconclusive_ids": [e["id"] for e in inconclusive],
        },
        "components": components,
        "entries": entries,
    }


def _esc(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _short(value: Any, limit: int = 120) -> str:
    text = _esc(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _root(entry: dict) -> str:
    root = entry.get("root_cause") or {}
    file = root.get("file") or "?"
    line = root.get("line")
    return f"`{file}:{line}`" if line else f"`{file}`"


def _evidence(entry: dict) -> str:
    ev = entry.get("evidence") or {}
    path = ev.get("path") or ""
    mode = ev.get("mode") or ""
    return f"`{path}` ({mode})" if mode else f"`{path}`"


def _novelty(entry: dict) -> str:
    n = entry.get("novelty_result") or {}
    verdict = n.get("verdict") or "unchecked"
    matched = n.get("matched") or []
    if not matched:
        for provider in (n.get("providers") or {}).values():
            matched.extend(provider.get("matches") or [])
    if matched:
        first = matched[0]
        return f"{verdict} ({_short(first.get('id') or first.get('url'), 60)})"
    return verdict


def _disclosure(entry: dict) -> str:
    d = entry.get("disclosure") or {}
    return d.get("status") or "undisclosed"


def _table(entries: list[dict], *, include_reachability: bool = False) -> list[str]:
    lines = [
        "| ID | 组件 | 版本 | 根因 file:line | 前置 | 利用 | 证据 | 查新 | 披露 | 状态 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for e in entries:
        pre = "; ".join(e.get("preconditions") or []) or "-"
        exploit = e.get("exploit") or "-"
        lines.append(
            f"| `{_esc(e['id'])}` | {_esc(e.get('component'))} | {_short(e.get('version'), 48)} | {_root(e)} | "
            f"{_short(pre, 110)} | {_short(exploit, 130)} | {_evidence(e)} | {_novelty(e)} | "
            f"{_esc(_disclosure(e))} | **{_esc(e.get('state'))}** |"
        )
        if include_reachability and e.get("reachability"):
            lines.append(f"| ↳ 可达性 | {_esc(e['reachability'])} | | | | | | | | |")
    return lines


def render_markdown(registry: dict) -> str:
    s = registry["summary"]
    lines: list[str] = []
    lines.append("# InkBlade 0day Reserve")
    lines.append("")
    lines.append(f"Generated: `{registry['generated_at']}` ｜ registry: `inkblade/core/zeroday-registry.json` ｜ "
                 f"inventory: `corpus/zeroday/inventory.json`")
    lines.append("")
    lines.append("> **计数规则（硬门禁）**：只有 **动态复现成功 (`verification=verified, dynamic=true`)** 且 "
                 "**查新为 `confirmed-unpublished`** 的条目才进入 `0day-reserve`。"
                 "`already-public` 一律降级为 `public`；`inconclusive` 单列，绝不按未公开处理；"
                 "static-only / unsupported 不计入任何利用储备。")
    lines.append("")
    lines.append("## 1. 总账")
    lines.append("")
    lines.append("| 库存来源 | 总数 | 动态 verified | static-only | unsupported | failed | confirmed-unpublished | already-public | inconclusive | **0day-reserve** |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for source, data in s["by_source"].items():
        if not data["total"]:
            continue
        lines.append(
            f"| {data['label']} | {data['total']} | {data['verified']} | {data['static']} | "
            f"{data['unsupported']} | {data['failed']} | {data['confirmed']} | {data['public']} | "
            f"{data['inconclusive']} | **{data['reserve']}** |"
        )
    lines.append(
        f"| **合计** | **{s['total']}** | **{s['verified']}** | **{s['static']}** | **{s['unsupported']}** | "
        f"**{s['failed']}** | **{s['confirmed']}** | **{s['public']}** | **{s['inconclusive']}** | "
        f"**{s['reserve']}** |"
    )
    lines.append("")
    lines.append(f"- **0day-reserve = {s['reserve']}**（去重后 **{s.get('reserve_unique', s['reserve'])}**）："
                 f"{', '.join(s['reserve_ids']) or '（空）'}")
    lines.append(f"- **去重口径**：同一 `module`/`dedupe_key` 的 AST/regex 重复 case 只计 1 条；代表条目："
                 f"{', '.join(s.get('reserve_unique_ids') or []) or '（空）'}")
    if s.get("excluded_non_0day"):
        lines.append(f"- **不计入储备（verified+confirmed 但非 0day 性质）**：{', '.join(s['excluded_non_0day'])}")
    lines.append(f"- **already-public 降级 = {s['public']}**：{", ".join(s['already_public_ids']) or '（空）'}")
    if s["inconclusive"]:
        lines.append(f"- **inconclusive = {s['inconclusive']}**：网络/速率/缺少包映射，未计入储备；"
                     f"{', '.join(s.get('inconclusive_ids') or [])}")
    else:
        lines.append("- **inconclusive = 0**：全部闭环（OSV 包级查询 + 仓库改名解析 + 受控 N/A 理由）")
    lines.append("")
    lines.append("## 2. 0day Reserve（仅 verified + confirmed-unpublished）")
    lines.append("")
    reserve = [e for e in registry["entries"] if is_reserve(e)]
    if not reserve:
        lines.append("**当前为 0。** 不把 static-only、已知 CVE/GHSA、已公开 commit 或网络不可达的条目混入储备。")
    else:
        lines.extend(_table(reserve, include_reachability=True))
    lines.append("")
    lines.append("## 3. 已公开降级（already-public，不计入储备）")
    lines.append("")
    public = [e for e in registry["entries"] if (e.get("novelty_result") or {}).get("verdict") == "already-public"]
    if not public:
        lines.append("（无）")
    else:
        lines.extend(_table(public))
    lines.append("")
    lines.append("## 4. Inconclusive（查新未闭环，不计入储备）")
    lines.append("")
    inconclusive = [e for e in registry["entries"] if (e.get("novelty_result") or {}).get("verdict") == "inconclusive"]
    if not inconclusive:
        lines.append("（无）")
    else:
        lines.extend(_table(inconclusive))
    lines.append("")
    lines.append("## 5. 审计历史-OMNI/JEV（逐条状态）")
    lines.append("> `djev-open-proxy` / `vllm-jev-plugin-auth-bypass` / `slime-pull-weights` 同时属于 OMNI/JEV 生态；总账按主来源计数，本栏交叉列出，不重复计入合计。")
    lines.append("")
    lines.append("")
    omni = [e for e in registry["entries"]
            if e.get("source") == "omni-jev" or "omni-jev" in (e.get("source_tags") or [])]
    if not omni:
        lines.append("**空栏。** 这是漏并，不是无误报；OMNI/JEV 条目必须在此逐条列出。")
    else:
        lines.extend(_table(omni, include_reachability=True))
    lines.append("")
    lines.append("## 6. 审计历史-核心框架（§1–§6 动态复现条目）")
    lines.append("")
    core = [e for e in registry["entries"] if e.get("source") == "audit-history"]
    lines.extend(_table(core, include_reachability=True) if core else ["（无）"])
    lines.append("")
    lines.append("## 7. 审计历史-Agent 平台（Dify / Open WebUI）")
    lines.append("")
    agent = [e for e in registry["entries"] if e.get("source") == "agent-platform"]
    lines.extend(_table(agent, include_reachability=True) if agent else ["（无）"])
    lines.append("")
    lines.append("## 8. 挖掘候选（96 条）")
    lines.append("")
    mining = [e for e in registry["entries"] if e.get("source") == "mining"]
    lines.extend(_table(mining))
    lines.append("")
    lines.append("## 9. 新增发现（最近两个 release diff + 动态复现）")
    lines.append("")
    new = [e for e in registry["entries"] if e.get("source") == "new-discovery"]
    lines.extend(_table(new, include_reachability=True) if new else ["（无）"])
    lines.append("")
    lines.append("## 10. 遗留候选（reports/samples/mining/zeroday/registry/candidates）")
    lines.append("")
    legacy = [e for e in registry["entries"] if e.get("source") == "legacy-candidate"]
    lines.extend(_table(legacy) if legacy else ["（无）"])
    lines.append("")
    lines.append("## 11. 每组件端到端可达性论证")
    lines.append("")
    lines.append("> 至少每组件一条：配置→sink、请求→sink、文件/环境→sink 或协议解析面（HTTP/ZMQ/pickle/模板/路由）。"
                 "论证只描述已复现路径；未复现的 static-only 不写成可利用。")
    lines.append("")
    lines.append("| 组件 | 条目 | verified | reserve | 端到端可达性 |")
    lines.append("|---|---:|---:|---:|---|")
    for comp, data in sorted(registry["components"].items()):
        reach = data.get("reachability") or []
        text = "<br>".join(f"`{r['id']}`: {_esc(r['text'])}" for r in reach[:3]) or "（未提供；不得声称可利用）"
        lines.append(f"| {_esc(comp)} | {data['entries']} | {data['verified']} | {data['reserve']} | {text} |")
    lines.append("")
    lines.append("## 12. 方法与限制")
    lines.append("")
    lines.append("- 动态复核：新增发现使用 `lab/zeroday_reserve/` 真实上游源码/路由 + 证据哈希；历史条目复用 "
                 "`projects/repro-2026-10/`、`projects/agent-2026-10/` 与 `lab/upstream_verify/` 的已落盘动态证据，"
                 "并在 registry 中标注 `mode=evidence-reused`；能重跑的条目另有 `mode=rerun`。")
    lines.append("- 查新：`tools/novelty-check.py` 查询 OSV、NVD、GitHub Advisory、GitHub commit/code 搜索与厂商 "
                 "security/advisory 页面；每次请求原始结果缓存于 `corpus/novelty/cache/`。")
    lines.append("- 查新补强（2026-10-27）：GitHub 搜索对仓库改名返回 422，工具先解析 canonical repo 再重试；"
                 "无版本/commit 钉的条目改查 OSV 包级（全版本）并在 PyPI 身份不符/占位包时记录 *受控 N/A*；"
                 "commit 只在含 CVE/GHSA ID 或 subject 同时出现修复动词与 sink 关键词时计为公开，避免把 "
                 "rename/lint/docker `--privileged` 误判为披露。")
    lines.append("- 离线/限流：缓存缺失、401/403、超时、无包映射均标 `inconclusive`，**不默认未公开**。"
                 "GitHub 未认证 code search 返回 401，工具降级到 grep.app + 本地上游树扫描并在结果中记录 `via`。")
    lines.append("- 不自动外发：披露状态仅在本 registry 与 `docs/0DAY-DISCLOSURE.md` 中记录。")
    lines.append("")
    return "\n".join(lines) + "\n"


def build(inventory_path: Path | str = DEFAULT_INVENTORY,
          novelty_path: Path | str = DEFAULT_NOVELTY,
          registry_path: Path | str = DEFAULT_REGISTRY,
          doc_path: Path | str = DEFAULT_DOC) -> dict:
    inventory = load_json(inventory_path)
    if inventory is None:
        raise ReserveError(f"inventory not found: {inventory_path}")
    novelty = load_json(novelty_path, default={"verdicts": {}})
    registry = build_registry(inventory, novelty)
    write_json(registry_path, registry)
    doc = Path(doc_path)
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(render_markdown(registry), encoding="utf-8")
    return registry


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build/validate the InkBlade 0day reserve")
    parser.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    parser.add_argument("--novelty", default=str(DEFAULT_NOVELTY))
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--doc", default=str(DEFAULT_DOC))
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    if args.validate_only:
        registry = build_registry(load_json(args.inventory), load_json(args.novelty, default={"verdicts": {}}))
        print(json.dumps(registry["summary"], ensure_ascii=True, indent=2, sort_keys=True))
        return 0
    registry = build(args.inventory, args.novelty, args.registry, args.doc)
    print(json.dumps(registry["summary"], ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
