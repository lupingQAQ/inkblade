"""GPU Operator/NVIDIA 配置面深度审计（driver/MIG/DCGM/device plugin/DRA）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import gpu as _g  # noqa: E402
from trident.depth.common import finding, write_artifact  # noqa: E402

KEY = "gpu-operator-config-depth"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    snapshot = _g.load_snapshot(params.get("snapshot"))
    report = _g.audit(snapshot)
    findings: list[dict] = []
    for item in report["results"]:
        findings.append(finding(
            item["sev"],
            f"GPU Operator 配置风险（{item['domain']}）：{item['title']}",
            {
                "checks": report["checks"],
                "failed": report["failed"],
                "domains": report["domains"],
                "case": item["id"],
                "domain": item["domain"],
                "snapshot_sha256": report["snapshot_sha256"],
            },
            fix="driver/toolkit 去除 privileged 与宿主挂载并启用 CDI；MIG strategy/profile 一致；"
                "DCGM 改 ClusterIP+mTLS+鉴权；device plugin shareCount=1；DRA 关闭 adminAccess 与通配 deviceClass。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "checks": report["checks"], "failed": report["failed"],
        "domains": report["domains"], "severity": report["severity"],
        "snapshot_sha256": report["snapshot_sha256"], "results": report["results"],
    })
    summary = (f"checks={report['checks']} failed={report['failed']} "
               f"domains={','.join(report['domains'])}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
