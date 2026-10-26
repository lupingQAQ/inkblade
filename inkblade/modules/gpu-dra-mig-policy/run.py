"""GPU MIG 策略与 DRA 设备声明深度审计。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.depth import gpu as _g  # noqa: E402
from inkblade.depth.common import finding, write_artifact  # noqa: E402

KEY = "gpu-dra-mig-policy"
WRITES = False
DOMAINS = ("mig", "dra")


def run(ctx: dict, params: dict) -> dict:
    snapshot = _g.load_snapshot(params.get("snapshot"))
    report = _g.audit(snapshot)
    items = [r for r in report["results"] if r["domain"] in DOMAINS]
    findings: list[dict] = []
    for item in items:
        findings.append(finding(
            item["sev"],
            f"MIG/DRA 策略风险（{item['domain']}）：{item['title']}",
            {
                "checks": report["checks"],
                "domains": report["domains"],
                "case": item["id"],
                "domain": item["domain"],
                "failed": report["failed"],
                "snapshot_sha256": report["snapshot_sha256"],
            },
            fix="MIG 统一 strategy/profile 并启用 device plugin MIG advertise；"
                "DRA 关闭 adminAccess、使用精确 deviceClass/CEL 与 nodeSelector，claim 仅在消费命名空间创建。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "domains": sorted({i["domain"] for i in items}),
        "checks": len(items), "failed": len(items),
        "snapshot_sha256": report["snapshot_sha256"], "results": items,
    })
    summary = f"checks={len(items)} failed={len(items)} domains={','.join(sorted({i['domain'] for i in items}))}"
    return {"summary": summary, "artifacts": artifact, "findings": findings}
