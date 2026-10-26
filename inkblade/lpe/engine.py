# -*- coding: utf-8 -*-
"""LPE 判定引擎 — 版本区间（stable 分支感知）+ 前置面门控，**只判定不利用**。

版本逻辑：
- ``introduced`` 之下不命中；
- ``fixed["mainline"]`` 及以上不命中（主线已修复）；
- 命中同 ``major.minor`` 的 stable 键时，低于该修复版本才命中；
- 无匹配 stable 键且低于主线修复 → 命中（EOL/发行版回移需人工复核）。

所有命中 ``confidence=detection-only``；不下载/编译/执行任何 PoC。
"""
from __future__ import annotations

import re

from inkblade.lpe.catalog import CATALOG, KERNEL_RULES, USERSPACE_RULES, by_category, by_component

DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN",
                  "DAC_READ_SEARCH", "BPF", "PERFMON", "SYS_RAWIO"}


class LpeError(ValueError):
    """版本/输入非法。"""


def parse_version(value: str) -> tuple[int, ...]:
    text = str(value or "").strip()
    match = re.match(r"^(\d+(?:\.\d+){0,3})", text)
    if not match:
        raise LpeError(f"无法解析版本 {value!r}")
    return tuple(int(x) for x in match.group(1).split("."))


def _pad(value: tuple[int, ...], width: int) -> tuple[int, ...]:
    return tuple(list(value) + [0] * (width - len(value)))


def version_lt(observed: str, limit: str) -> bool:
    a, b = parse_version(observed), parse_version(limit)
    width = max(len(a), len(b))
    return _pad(a, width) < _pad(b, width)


def version_in_range(version: str, rule: dict) -> bool:
    """版本是否落在规则的受影响区间（stable 分支感知）。"""
    obs = parse_version(version)
    intro = rule.get("introduced")
    if intro:
        intro_v = parse_version(intro)
        width = max(len(obs), len(intro_v))
        if _pad(obs, width) < _pad(intro_v, width):
            return False
    fixed = rule.get("fixed") or {}
    mainline = fixed.get("mainline")
    mainline_v = parse_version(mainline) if mainline else None
    stream = f"{obs[0]}.{obs[1]}"
    for key, value in fixed.items():
        if key == "mainline":
            continue
        key_v = parse_version(key)
        if key_v[0] == obs[0] and (len(key_v) < 2 or key_v[1] == obs[1]):
            return version_lt(version, value)
    if mainline_v is not None:
        width = max(len(obs), len(mainline_v))
        return _pad(obs, width) < _pad(mainline_v, width)
    return True


# ---------------------------------------------------------------- 前置面
def _caps(node: dict) -> set[str]:
    raw = node.get("capabilities") or []
    if isinstance(raw, dict):
        raw = raw.get("effective") or []
    return {str(c).upper() for c in raw}


def _userns_on(node: dict) -> bool:
    raw = node.get("userns")
    if isinstance(raw, dict):
        raw = raw.get("mode")
    text = str(raw).lower()
    return bool(raw) and text not in ("host", "disabled", "none", "false", "off")


def _unprivileged_bpf(node: dict) -> bool:
    sysctl = node.get("sysctl") or {}
    raw = sysctl.get("unprivileged_bpf_disabled")
    if raw is None:
        return True  # 默认未禁用（多数发行版）
    try:
        return int(raw) < 2
    except (TypeError, ValueError):
        return str(raw).lower() in ("0", "1", "false", "no", "off")


def _cgroups_v1_writable(node: dict) -> bool:
    cgroups = node.get("cgroups") or {}
    return str(cgroups.get("version")) == "v1" and bool(cgroups.get("writable"))


def _flags(node: dict) -> dict:
    caps = _caps(node)
    userns = _userns_on(node)
    os_text = str(node.get("os") or "").lower()
    return {
        "userns": userns,
        "userns_or_net_admin": userns or "NET_ADMIN" in caps,
        "net_admin": "NET_ADMIN" in caps,
        "sys_admin": "SYS_ADMIN" in caps,
        "sys_ptrace": "SYS_PTRACE" in caps,
        "bpf": "BPF" in caps,
        "unprivileged_bpf": _unprivileged_bpf(node),
        "cgroups_v1_writable": _cgroups_v1_writable(node),
        "ubuntu": "ubuntu" in os_text,
    }


def _fixed_text(rule: dict) -> str:
    fixed = rule.get("fixed") or {}
    parts = [f"{key} {value}" for key, value in fixed.items() if key != "mainline"]
    if fixed.get("mainline"):
        parts.append(f"mainline {fixed['mainline']}")
    return " / ".join(parts) if parts else "无单一修复（缓解见 note）"


# ---------------------------------------------------------------- 组件
def _component_state(value) -> tuple[bool, str]:
    if isinstance(value, bool):
        return value, ""
    if isinstance(value, str):
        return value != "", value
    if isinstance(value, dict):
        present = bool(value.get("present", True))
        return present, str(value.get("version") or "")
    return False, ""


def _component_hits(node: dict) -> list[dict]:
    comps = node.get("components") or {}
    out = []
    for rule in USERSPACE_RULES:
        present, version = _component_state(comps.get(rule["component"]))
        if not present:
            continue
        fixed = (rule.get("fixed") or {}).get("mainline")
        if version and fixed and not version_lt(version, fixed):
            continue
        if not version and rule.get("detect") != "presence":
            continue
        out.append({
            "cve": rule["cve"], "name": rule["name"], "category": rule["category"],
            "sev": rule["sev"], "component": rule["component"],
            "installed": version or "<未知>", "fixed_in": _fixed_text(rule),
            "confidence": "detection-only", "note": rule["note"], "logic": rule["logic"],
            "evidence": f"{rule['component']} version={version or 'unknown'}",
        })
    return out


def _kernel_hits(node: dict) -> list[dict]:
    kernel = str(node.get("kernel") or "")
    if not kernel:
        return []
    try:
        parse_version(kernel)
    except LpeError:
        return []
    flags = _flags(node)
    out = []
    for rule in KERNEL_RULES:
        try:
            if not version_in_range(kernel, rule):
                continue
        except LpeError:
            continue
        missing = [req for req in rule["requires"] if not flags.get(req)]
        if missing:
            continue
        out.append({
            "cve": rule["cve"], "name": rule["name"], "category": rule["category"],
            "sev": rule["sev"], "component": "kernel",
            "introduced": rule["introduced"], "fixed_in": _fixed_text(rule),
            "requires": list(rule["requires"]), "confidence": "detection-only",
            "evidence": (f"kernel={kernel};os={node.get('os', '?')};"
                         f"requires={rule['requires']};missing=[]"),
            "note": rule["note"], "logic": rule["logic"],
        })
    return sorted(out, key=lambda h: h["cve"])


def assess_node(node: dict) -> dict:
    name = str(node.get("name") or "node")
    hits = _kernel_hits(node)
    comp_hits = _component_hits(node)
    return {
        "name": name, "kernel": str(node.get("kernel") or ""),
        "os": str(node.get("os") or ""), "role": str(node.get("role") or ""),
        "userns": _userns_on(node), "capabilities": sorted(_caps(node)),
        "hits": hits, "component_hits": comp_hits,
        "kernel_component_hits": comp_hits,
        "checked": len(CATALOG),
    }


def assess(snapshot: dict) -> dict:
    snapshot = snapshot or {}
    raw = snapshot.get("nodes")
    nodes: list[dict] = []
    if isinstance(raw, list):
        nodes = [n for n in raw if isinstance(n, dict)]
    elif isinstance(raw, dict):
        nodes = [dict(v, name=k) for k, v in raw.items() if isinstance(v, dict)]
    elif raw is None and (snapshot.get("kernel") or snapshot.get("components")):
        nodes = [snapshot]

    report_nodes: dict[str, dict] = {}
    for node in nodes:
        result = assess_node(node)
        name = result["name"]
        if name in report_nodes:
            suffix = 2
            while f"{name}#{suffix}" in report_nodes:
                suffix += 1
            name = f"{name}#{suffix}"
            result["name"] = name
        report_nodes[name] = result

    all_cves: set[str] = set()
    hit_count = 0
    for result in report_nodes.values():
        for hit in result["hits"] + result["component_hits"]:
            all_cves.add(hit["cve"])
            hit_count += 1
    aggregate = {
        "rules": len(CATALOG),
        "kernel_rules": len(KERNEL_RULES),
        "userspace_rules": len(USERSPACE_RULES),
        "nodes": len(report_nodes),
        "hits": hit_count,
        "hit_cves": len(all_cves),
        "cves": sorted(all_cves),
        "by_category": by_category(),
        "by_component": by_component(),
        "detection_only": True,
    }
    return {
        "nodes": report_nodes,
        "aggregate": aggregate,
        "catalog": {"rules": len(CATALOG), "categories": by_category(),
                    "components": by_component()},
    }
