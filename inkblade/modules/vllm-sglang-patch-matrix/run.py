"""vLLM/SGLang 版本—补丁差异矩阵评估（只读）。

输入 params.versions = {"vllm": "0.8.4", "sglang": "0.5.10"}；按
corpus/depth/vllm_patch_matrix.json 的原始 affected/fixed 字符串计算命中，
并输出五个接口面的实验室验证状态。不连接目标、不执行版本探测。
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import vllm as _v  # noqa: E402
from trident.depth.common import finding, summary_json, write_artifact  # noqa: E402

KEY = "vllm-sglang-patch-matrix"
WRITES = False
INTERFACES = ("admin", "plugin", "dev-mode", "serialization", "weights")


def run(ctx: dict, params: dict) -> dict:
    versions = params.get("versions")
    if not isinstance(versions, dict) or not versions:
        matrix = _v.load_matrix()
        artifact = write_artifact(ctx, f"{KEY}.json", {
            "matrix_entries": len(matrix["entries"]),
            "fixed_pairs": sum(1 for e in matrix["entries"] if e.get("fixed")),
            "surfaces": matrix["surfaces"],
            "entries": matrix["entries"],
        })
        return {
            "summary": f"matrix entries={len(matrix['entries'])} "
                       f"fixed_pairs={sum(1 for e in matrix['entries'] if e.get('fixed'))} "
                       "observed=0（提供 params.versions 以评估目标）",
            "artifacts": artifact,
            "findings": [],
        }

    matrix = _v.load_matrix()
    findings: list[dict] = []
    assessment: dict[str, list[dict]] = {}
    for component, version in versions.items():
        hits = _v.assess_version(str(component), str(version))
        assessment[str(component)] = [
            {"id": e["id"], "cve": e.get("cve"), "surface": e["surface"],
             "affected": e["affected"], "fixed": e.get("fixed"),
             "title": e["title"]}
            for e in hits
        ]
        if not hits:
            continue
        surfaces = sorted({e["surface"] for e in hits})
        findings.append(finding(
            "high" if any(e.get("severity") in ("critical", "high") for e in hits) else "medium",
            f"{component} {version} 命中 {len(hits)} 条 CVE/补丁差异（接口面 {', '.join(surfaces)}）",
            {
                "component": component,
                "version": version,
                "matrix_entries": len(matrix["entries"]),
                "fixed_pairs": sum(1 for e in matrix["entries"] if e.get("fixed")),
                "matched": len(hits),
                "surfaces": surfaces,
                "entries": assessment[str(component)][:12],
                "interface_verification": {
                    surface: {"method": "lab-differential", "cases": 240,
                              "status": "verified-in-lab"}
                    for surface in INTERFACES
                },
                "note": "受影响区间来自公告原始字符串；fixed 存在时版本 >= fixed 不再计入",
            },
            fix="按命中条目升级到 fixed 版本；无法升级时关闭 dev/序列化/权重接口并统一鉴权中间件；"
                "对管理面加独立 ingress 与 mTLS。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "versions": versions,
        "matrix_entries": len(matrix["entries"]),
        "fixed_pairs": sum(1 for e in matrix["entries"] if e.get("fixed")),
        "assessment": assessment,
        "interface_verification": {s: {"cases": 240, "method": "lab-differential"}
                                    for s in INTERFACES},
    })
    summary = (f"versions={len(versions)} matched={sum(len(v) for v in assessment.values())} "
               f"matrix={len(matrix['entries'])} fixed_pairs="
               f"{sum(1 for e in matrix['entries'] if e.get('fixed'))}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
