"""SONiC/IB/SHARP fabric 配置深度审计（28 检查 + fabric_sim 场景映射）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.depth import fabric as _f  # noqa: E402
from inkblade.depth.common import finding, write_artifact  # noqa: E402

KEY = "sonic-fabric-config-audit"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    snapshot = _f.load_snapshot(params.get("snapshot"))
    report = _f.audit(snapshot)
    plan = _f.fabric_sim_plan(snapshot)
    findings: list[dict] = []
    for item in report["results"]:
        findings.append(finding(
            item["sev"],
            f"Fabric 配置风险（{item['domain']}）：{item['title']}",
            {
                "checks": report["checks"],
                "failed": report["failed"],
                "domains": report["domains"],
                "case": item["id"],
                "domain": item["domain"],
                "fabric_sim_scenarios": plan["scenarios"],
                "snapshot_sha256": report["snapshot_sha256"],
            },
            fix="PFC watchdog/ECN 开启并调高 storm 阈值；ACL 去除 any-any；gNMI 启用 TLS+鉴权；"
                "IB SM 主备、默认分区最小成员、按租户 PKey；SHARP 会话鉴权与 reduce ACL。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "checks": report["checks"], "failed": report["failed"],
        "domains": report["domains"], "severity": report["severity"],
        "fabric_sim_plan": plan, "snapshot_sha256": report["snapshot_sha256"],
        "results": report["results"],
    })
    summary = (f"checks={report['checks']} failed={report['failed']} "
               f"domains={','.join(report['domains'])} sim={','.join(plan['scenarios'])}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
