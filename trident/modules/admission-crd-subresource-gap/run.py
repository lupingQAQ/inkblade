"""准入覆盖面缺口：CRD conversion、子资源、ephemeral、cluster scope（只读）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import admission as _a  # noqa: E402
from trident.depth.common import finding, write_artifact  # noqa: E402

KEY = "admission-crd-subresource-gap"
WRITES = False
MECHANISMS = ("crd-conversion", "subresource", "ephemeral-container", "scope")


def run(ctx: dict, params: dict) -> dict:
    rows = [c for c in _a.cases() if c["mechanism"] in MECHANISMS]
    report = _a.audit(rows)
    mechanisms = sorted({c["mechanism"] for c in rows})
    findings: list[dict] = []
    for row in report["results"]:
        if not (row["vulnerable"]["admitted"] and not row["hardened"]["admitted"]):
            continue
        findings.append(finding(
            "high",
            f"准入覆盖面缺口（{row['mechanism']}）：{row['title']}",
            {
                "cases": len(rows),
                "mechanisms": mechanisms,
                "case": row["id"],
                "vulnerable_trace": row["vulnerable"]["trace"],
                "violations": row["vulnerable"]["violations"],
                "hardened_trace": row["hardened"]["trace"],
                "results_sha256": report["results_sha256"],
            },
            fix="以 storage version 为锚生成策略并对所有 served version 做 conversion 回归；"
                "为 pods/exec、pods/ephemeralcontainers 显式声明 subresources；"
                "init/ephemeral 容器与 containers 同权校验；cluster-scoped CRD 单列策略。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "mechanisms": mechanisms, "cases": len(rows), "report": report,
    })
    summary = (f"cases={len(rows)} mechanisms={','.join(mechanisms)} "
               f"admitted={report['vulnerable_admitted']} findings={len(findings)}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
