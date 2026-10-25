# -*- coding: utf-8 -*-
"""arch-intel 覆盖矩阵门槛校验（2026-10-25 万卡语料重收批次，权威）。

硬门槛（推倒重收任务口径）：
- corpus 三分类目录：official-cn / official-en / paper
- official-cn（中文官方源）≥ 12；official-en（外文官方源）≥ 12
- 万卡证据源（wanka_evidence=true）≥ 20：核验状态 verified 才计数
- 网络要素 8 项全覆盖（每项 ≥ 1 个 verified 源）：
  rail-optimized / multi-plane / in-network-computing / congestion-control /
  optical-switching / multi-tenancy / isolation / ops-fault-surface
- 本轮新增源（added_this_round=true）≥ 30，且其中 official 占比 ≥ 70%

只有 verification.status=verified 的源计入门槛；verified-partial 等
非 verified 状态显式记录不可达/快照原因（见 verification.summary）。

用法：python trident/arch-intel/check.py [coverage-matrix.json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# 2026-10-25 重收门槛（权威，勿随意调整）
REQUIRED = {
    "official-cn": 12,
    "official-en": 12,
    "wanka-evidence": 20,
    "new-this-round": 30,
    "new-official-ratio": 0.70,
}

CLASSES = ("official-cn", "official-en", "paper")
OFFICIAL_CLASSES = ("official-cn", "official-en")

# 网络要素机器键（8 项全覆盖）
NETWORK_ELEMENTS = (
    "rail-optimized",
    "multi-plane",
    "in-network-computing",
    "congestion-control",
    "optical-switching",
    "multi-tenancy",
    "isolation",
    "ops-fault-surface",
)

VERIFIED = "verified"


def _is_verified(source: dict) -> bool:
    return source.get("verification", {}).get("status") == VERIFIED


def _category_result(count: int, required: int) -> dict:
    return {"count": count, "required": required, "ok": count >= required}


def verify(matrix: dict) -> dict:
    """校验覆盖矩阵：重收门槛达标布尔 + 计数明细。"""
    sources = matrix.get("sources", [])
    verified = [s for s in sources if _is_verified(s)]

    counts: dict[str, int] = {c: 0 for c in CLASSES}
    for s in verified:
        cls = s.get("class", "")
        if cls in counts:
            counts[cls] += 1

    classes = {"counts": counts}
    for cls in CLASSES:
        classes[cls] = _category_result(counts[cls], REQUIRED.get(cls, 0))
    classes["ok"] = all(classes[c]["ok"] for c in CLASSES if c in REQUIRED)

    wanka_sources = [s for s in verified if s.get("wanka_evidence")]
    wanka = _category_result(len(wanka_sources), REQUIRED["wanka-evidence"])

    elements = {}
    for elem in NETWORK_ELEMENTS:
        n = sum(1 for s in verified if elem in s.get("network_elements", []))
        elements[elem] = _category_result(n, 1)
    network = {"elements": elements}
    network["ok"] = all(e["ok"] for e in elements.values())

    new_sources = [s for s in sources if s.get("added_this_round")]
    new_verified = [s for s in new_sources if _is_verified(s)]
    new_count = _category_result(len(new_sources), REQUIRED["new-this-round"])
    new_official = sum(
        1 for s in new_sources if s.get("class") in OFFICIAL_CLASSES
    )
    ratio_value = (new_official / len(new_sources)) if new_sources else 0.0
    new_ratio = {
        "official": new_official,
        "total": len(new_sources),
        "ratio": round(ratio_value, 4),
        "required": REQUIRED["new-official-ratio"],
        "ok": ratio_value >= REQUIRED["new-official-ratio"],
    }
    new_round = {
        "count": new_count,
        "ratio": new_ratio,
        "verified": len(new_verified),
        "ok": new_count["ok"] and new_ratio["ok"],
    }

    result = {
        "schema": "arch-intel-coverage-verification",
        "total_sources": len(sources),
        "verified_sources": len(verified),
        "classes": classes,
        "wanka-evidence": wanka,
        "network-elements": network,
        "new-this-round": new_round,
    }
    result["ok"] = all(
        (
            classes["ok"],
            wanka["ok"],
            network["ok"],
            new_round["ok"],
        )
    )
    return result


def main(argv: list[str]) -> int:
    path = (
        Path(argv[1])
        if len(argv) > 1
        else Path(__file__).resolve().parent / "coverage-matrix.json"
    )
    matrix = json.loads(path.read_text(encoding="utf-8"))
    report = verify(matrix)
    ok = report.pop("ok")
    lines = []
    for cls in CLASSES:
        r = report["classes"][cls]
        gate = "（门槛）" if cls in REQUIRED else ""
        lines.append(
            f"class {cls}: {r['count']}/{r['required']}{gate} ok={r['ok']}"
        )
    lines.append("classes.ok={}".format(report["classes"]["ok"]))
    w = report["wanka-evidence"]
    lines.append(
        f"wanka-evidence: {w['count']}/{w['required']} ok={w['ok']}"
    )
    lines.append("network-elements ok={}".format(report["network-elements"]["ok"]))
    for elem, r in report["network-elements"]["elements"].items():
        lines.append(f"  element {elem}: {r['count']}/{r['required']} ok={r['ok']}")
    n = report["new-this-round"]
    lines.append(
        "new-this-round: {cnt}/{cnt_req} ok={cnt_ok}; official-ratio "
        "{ratio}/{ratio_req} ok={ratio_ok}".format(
            cnt=n["count"]["count"], cnt_req=n["count"]["required"],
            cnt_ok=n["count"]["ok"], ratio=n["ratio"]["ratio"],
            ratio_req=n["ratio"]["required"], ratio_ok=n["ratio"]["ok"],
        )
    )
    lines.append(f"verified {report['verified_sources']}/{report['total_sources']} sources")
    lines.append(f"ALL GATES ok={ok}")
    print("\n".join(lines), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
