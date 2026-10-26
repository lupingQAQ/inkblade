"""IRSA/RRSA/PodIdentity/GCP/Azure 身份联邦 trust 策略绕过矩阵。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.depth import identity as _i  # noqa: E402
from inkblade.depth.common import finding, write_artifact  # noqa: E402

KEY = "identity-federation-trust-matrix"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    rows = _i.cases()
    if params.get("snapshot"):
        rows = _i.load_cases(params["snapshot"])
    report = _i.audit(rows)
    categories = sorted({c["category"] for c in rows})
    findings: list[dict] = []
    for row in report["results"]:
        if not (row["vulnerable"]["allowed"] and not row["hardened"]["allowed"]
                and row["legit"]["allowed"]):
            continue
        findings.append(finding(
            "critical",
            f"身份联邦 trust 绕过（{row['vulnerable']['provider']}/{row['category']}）：{row['title']}",
            {
                "cases": report["total"],
                "allowed": report["allowed"],
                "hardened_allowed": report["hardened_allowed"],
                "categories": categories,
                "case": row["id"],
                "provider": row["vulnerable"]["provider"],
                "category": row["category"],
                "reasons": row["vulnerable"]["reasons"],
                "legit_allowed": row["legit"]["allowed"],
                "results_sha256": report["results_sha256"],
            },
            fix="Principal 精确绑定 role/provider；强制 sub/aud/iss、SourceAccount/SourceArn、ExternalId；"
                "禁用 Principal=*、pool/*、repo:org/*；Pod Identity namespace/serviceAccount 精确。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "cases": report["total"], "allowed": report["allowed"],
        "hardened_allowed": report["hardened_allowed"],
        "categories": categories, "results_sha256": report["results_sha256"],
        "results": report["results"],
    })
    summary = (f"cases={report['total']} allowed={report['allowed']} "
               f"hardened_allowed={report['hardened_allowed']} findings={len(findings)}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
