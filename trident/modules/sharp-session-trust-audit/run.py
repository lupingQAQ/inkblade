"""SHARP 会话/聚合树信任审计（会话鉴权、共享、reduce ACL、树成员）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import fabric as _f  # noqa: E402
from trident.depth.common import finding, write_artifact  # noqa: E402

KEY = "sharp-session-trust-audit"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    snapshot = _f.load_snapshot(params.get("snapshot"))
    report = _f.audit(snapshot)
    items = [r for r in report["results"] if r["domain"] == "sharp"]
    plan = _f.fabric_sim_plan(snapshot)
    findings: list[dict] = []
    for item in items:
        findings.append(finding(
            item["sev"], f"SHARP 会话信任风险：{item['title']}",
            {"checks": report["checks"], "failed": report["failed"],
             "domains": report["domains"], "case": item["id"],
             "fabric_sim_scenarios": plan["scenarios"],
             "snapshot_sha256": report["snapshot_sha256"]},
            fix="SHARP 会话强制作业令牌；reduce 校验成员 ACL；聚合树仅含作业 rank；"
                "关闭跨租户会话复用并统一 v3/v4。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "domains": ["sharp"], "cases": len(items), "failed": len(items),
        "fabric_sim_plan": plan, "snapshot_sha256": report["snapshot_sha256"],
        "results": items,
    })
    summary = (f"checks={len(items)} failed={len(items)} "
               f"sim={','.join(plan['scenarios'])}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
