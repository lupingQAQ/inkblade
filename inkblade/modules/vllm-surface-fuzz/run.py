"""vLLM 五类接口面差分 fuzz（只读探针，240 用例）。

对 admin / plugin / dev-mode / serialization / weights 五个运维可见面，组合
4 种认证态 × 12 种路径/头/方法变形。以 ``/v1/models`` 的 401 作为对照，
任一受保护面返回 200 即记录为鉴权差分。命中后只读展示面，不写配置、不传
真实 pickle、不下载权重。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import vllm as _v  # noqa: E402
from trident.depth.common import finding, summary_json, write_artifact  # noqa: E402

KEY = "vllm-surface-fuzz"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    fuzzer = _v.SurfaceFuzzer(target, timeout=int(params.get("timeout") or 4))
    report = fuzzer.run()
    findings: list[dict] = []
    for surface, row in sorted(report["surfaces"].items()):
        if not row["bypasses"]:
            continue
        findings.append(finding(
            "high",
            f"vLLM {surface} 面鉴权差分：{row['bypasses']} 个变形用例未认证 200",
            {
                "interface": surface,
                "cases": report["total"],
                "surface_cases": row["cases"],
                "bypasses": row["bypasses"],
                "control_status": report["control_status"],
                "transforms": row["transforms"],
                "statuses": row["statuses"],
                "results_sha256": report["results_sha256"],
                "matrix_entries": len(_v.entries()),
                "fuzz_cases": len(_v.fuzz_cases()),
                "note": "对照面 /v1/models 无 key 401；受保护面同请求 200 即鉴权域不一致",
            },
            fix="将 admin/plugin/dev/serialization/weights 路由统一挂到 bearer 中间件；"
                "边缘代理规范化路径并剥离客户端 X-Forwarded-* 头；dev 与序列化面默认关闭。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "target": target,
        "total": report["total"],
        "bypasses": report["bypasses"],
        "control_status": report["control_status"],
        "surfaces": report["surfaces"],
        "surfaces_hit": report["surfaces_hit"],
        "results_sha256": report["results_sha256"],
        "results": report["results"],
    })
    summary = (f"cases={report['total']} bypasses={report['bypasses']} "
               f"surfaces={','.join(report['surfaces_hit']) or 'none'} "
               f"control={report['control_status']}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
