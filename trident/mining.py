# -*- coding: utf-8 -*-
"""漏洞挖掘流水线闭环（弹药 B③）：模板验证 → 最新版本差异复核 → 登记册候选。

三环闭环（对 vLLM / SGLang / KubeRay / HAMi / LiteLLM 各一轮）：

1. **模板验证**（validate_templates）：core/data/sink-rules.json 每条规则的
   anchor 必须在实验室样本树（lab/sample-vuln-repo）上命中——规则失准即拒绝产出候选；
2. **最新版本差异复核**（extract_latest + diff_baseline）：对 ``lab/mining-fixture/<t>/``
   下按最新 release tag 抓取的上游源文件跑 codescan 双通道提取，与已提交基线
   （core/data/mining-baseline.json）逐 (target, file, line, rule, channel) 差异；
3. **登记册**（register_candidates）：差异候选写入 ``<out>/zeroday/registry/candidates/``
   ``status=pending-manual-review``，**绝不自动入库**（不进模块注册表、不进零日加密库）。

诚实边界（tests 锁定）：候选 ≠ 漏洞；fixtures 为上游公开源码快照（Apache-2.0），
hit=规则命中而非可利用性结论；人工确认前不得生成模块。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .core.codescan import load_rules, match_combos, scan_file
from .core.version_matrix import products as matrix_products

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE_DIR = REPO_ROOT / "lab" / "mining-fixture"
DEFAULT_SAMPLE_TREE = REPO_ROOT / "lab" / "sample-vuln-repo"
BASELINE_PATH = Path(__file__).resolve().parent / "data" / "mining-baseline.json"

# 挖掘目标（与任务口径一致：五仓库各一轮；latest_tag=2026-10-25 webfetch GitHub raw 快照）
TARGETS = {
    "vllm": {"repo": "vllm-project/vllm", "tag": "v0.32.0"},
    "sglang": {"repo": "sgl-project/sglang", "tag": "v0.5.22"},
    "kuberay": {"repo": "kuberay-project/kuberay", "tag": "v1.7.1"},
    "hami": {"repo": "Project-HAMi/HAMi", "tag": "v2.10.0"},
    "litellm": {"repo": "BerriAI/litellm", "tag": "v1.106.4"},
}

CANDIDATE_SCHEMA = "trident-mining-candidate-v1"


class MiningError(ValueError):
    """流水线前置/结构非法。"""


def _anchor_hit(rule: dict, sample_hits: list[dict]) -> bool:
    anchor = rule.get("anchor") or ""
    if not anchor:
        return False
    fname, _, lineno = anchor.partition(":")
    return any(h["rule"] == rule["id"] and h["file"].endswith(fname)
               and str(h["line"]) == lineno for h in sample_hits)


def validate_templates(sample_tree: Path | str | None = None) -> dict[str, Any]:
    """环 1：全部 sink 规则在实验室样本树上可命中（模板失准即拒绝产出）。"""
    tree = Path(sample_tree) if sample_tree else DEFAULT_SAMPLE_TREE
    if not tree.exists():
        raise MiningError(f"样本树不存在: {tree}")
    rules = load_rules()["rules"]
    hits: list[dict] = []
    for p in sorted(tree.rglob("*")):
        if p.is_file():
            hits += scan_file(p, root=tree)
    invalid = [r["id"] for r in rules if not _anchor_hit(r, hits)]
    return {"ok": not invalid, "rules": len(rules), "sample_hits": len(hits),
            "invalid_rules": invalid}


def extract_latest(target: str, fixture_dir: Path | str | None = None) -> dict[str, Any]:
    """环 2a：对目标最新 tag 的源文件快照跑双通道提取。"""
    if target not in TARGETS:
        raise MiningError(f"未知挖掘目标 {target}（可用: {sorted(TARGETS)}）")
    fdir = Path(fixture_dir) / target if fixture_dir else DEFAULT_FIXTURE_DIR / target
    if not fdir.exists() or not any(fdir.iterdir()):
        raise MiningError(f"目标 {target} 缺源码快照: {fdir}（lab/mining-fixture/README）")
    hits: list[dict] = []
    for p in sorted(fdir.iterdir()):
        if p.is_file():
            hits += scan_file(p, root=fdir)
    combos = match_combos(hits, load_rules().get("combos", []))
    return {"target": target, **TARGETS[target], "fixture_dir": str(fdir),
            "files": [p.name for p in sorted(fdir.iterdir()) if p.is_file()],
            "hits": hits, "combos": combos}


def _hit_keys(extraction: dict) -> set[str]:
    return {f"{h['file']}:{h['line']}:{h['rule']}:{h['channel']}" for h in extraction["hits"]}


def load_baseline(path: Path | str | None = None) -> dict[str, list[str]]:
    p = Path(path) if path else BASELINE_PATH
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def diff_baseline(extraction: dict, baseline: dict | None = None) -> list[dict]:
    """环 2b：与基线逐键差异 → 候选（新增命中；基线缺失时全部视为候选并要求先固化基线）。"""
    base = load_baseline() if baseline is None else baseline
    keys = _hit_keys(extraction)
    base_keys = set((base or {}).get(extraction["target"], []))
    fresh = keys - base_keys if base_keys else keys
    return [h for h in extraction["hits"]
            if f"{h['file']}:{h['line']}:{h['rule']}:{h['channel']}" in fresh]


def _candidate_id(target: str, hit: dict) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", f"{target}-{hit['file']}-{hit['rule']}").strip("-")
    return f"{slug}-l{hit['line']}-{hit['channel']}"


def register_candidates(target: str, hits: list[dict], out_dir: Path | str) -> list[dict]:
    """环 3：候选入登记册（pending-manual-review；不自动入库）。幂等：同 id 覆盖。"""
    if not hits:
        return []
    cand_dir = Path(out_dir) / "zeroday" / "registry" / "candidates"
    cand_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict] = []
    for h in hits:
        cid = _candidate_id(target, h)
        doc = {
            "schema": CANDIDATE_SCHEMA, "id": cid, "target": target,
            "repo": TARGETS[target]["repo"], "tag": TARGETS[target]["tag"],
            "status": "pending-manual-review",
            "rule": h["rule"], "channel": h["channel"],
            "file": h["file"], "line": h["line"], "snippet": h.get("snippet", ""),
            "note": "规则命中≠漏洞：须人工复核可达性与可利用性后方可建模块；不自动入库",
            "registered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        (cand_dir / f"{cid}.json").write_text(
            json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        written.append(doc)
    return written


def run_pipeline(out_dir: Path | str, *, targets: list[str] | None = None,
                 fixture_dir: Path | str | None = None,
                 sample_tree: Path | str | None = None,
                 baseline_path: Path | str | None = None) -> dict[str, Any]:
    """三环闭环入口：返回报告并落 ``<out_dir>/mining-report.json``。

    基线语义：本轮命中集在产出候选后写回基线（core/data/mining-baseline.json），
    下一轮只对「新增命中」产出候选；首轮（基线无该 target）全部命中入候选
    （报告注明 first-round）。
    """
    validation = validate_templates(sample_tree)
    if not validation["ok"]:
        raise MiningError(f"模板验证失败（规则失准）: {validation['invalid_rules']}")
    names = targets or list(TARGETS)
    baseline_doc: dict[str, list[str]] = dict(load_baseline(baseline_path))
    per_target: dict[str, Any] = {}
    all_candidates: list[dict] = []
    for t in names:
        extraction = extract_latest(t, fixture_dir)
        first_round = t not in baseline_doc or not baseline_doc[t]
        candidates = diff_baseline(extraction, baseline_doc)
        registered = register_candidates(t, candidates, out_dir)
        baseline_doc[t] = sorted(_hit_keys(extraction))
        per_target[t] = {
            "tag": extraction["tag"], "repo": extraction["repo"],
            "files": extraction["files"], "hits": len(extraction["hits"]),
            "combos": [c["id"] for c in extraction["combos"]],
            "first_round": first_round,
            "new_hits": len(candidates), "candidates_registered": len(registered),
        }
        all_candidates += registered
    bpath = Path(baseline_path) if baseline_path else BASELINE_PATH
    bpath.write_text(json.dumps(baseline_doc, ensure_ascii=False, indent=1), encoding="utf-8")
    report = {
        "schema": "trident-mining-report-v1", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "validation": validation, "targets": per_target,
        "candidates_total": len(all_candidates),
        "candidates": all_candidates,
        "registry": "zeroday/registry/candidates（status=pending-manual-review，不自动入库）",
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mining-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    return report
