"""OIDC issuer/audience/subject 混淆专项审计。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import identity as _i  # noqa: E402
from trident.depth.common import finding, write_artifact  # noqa: E402

KEY = "oidc-issuer-confusion"
WRITES = False
CATEGORIES = ("oidc-confusion", "audience-wildcard", "subject-wildcard")


def run(ctx: dict, params: dict) -> dict:
    rows = [c for c in _i.cases() if c["category"] in CATEGORIES]
    report = _i.audit(rows)
    labels = ["issuer", "audience", "subject"]
    findings: list[dict] = []
    for row in report["results"]:
        if not (row["vulnerable"]["allowed"] and not row["hardened"]["allowed"]
                and row["legit"]["allowed"]):
            continue
        findings.append(finding(
            "critical",
            f"OIDC 混淆（{row['category']}）：{row['title']}",
            {
                "cases": report["total"],
                "allowed": report["allowed"],
                "hardened_allowed": report["hardened_allowed"],
                "categories": labels,
                "case": row["id"],
                "provider": row["vulnerable"]["provider"],
                "reasons": row["vulnerable"]["reasons"],
                "results_sha256": report["results_sha256"],
            },
            fix="issuer/audience/subject 三者同时精确绑定；拒绝 issuer 通配与 audience 缺失；"
                "对不同云厂商的 OIDC provider 使用独立 trust 与 thumbprint。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "cases": report["total"], "allowed": report["allowed"],
        "categories": labels, "results_sha256": report["results_sha256"],
        "results": report["results"],
    })
    summary = f"cases={report['total']} allowed={report['allowed']} categories={','.join(labels)}"
    return {"summary": summary, "artifacts": artifact, "findings": findings}
