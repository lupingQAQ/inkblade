"""Kyverno 准入语义深度审计（Audit/豁免/mutation/init/ephemeral/subresource/CRD）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.depth import admission as _a  # noqa: E402
from inkblade.depth.common import finding, write_artifact  # noqa: E402

KEY = "admission-kyverno-semantics"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    rows = [c for c in _a.cases() if c["engine"] == "kyverno"]
    report = _a.audit(rows)
    mechanisms = sorted({c["mechanism"] for c in rows})
    findings: list[dict] = []
    for row in report["results"]:
        if not (row["vulnerable"]["admitted"] and not row["hardened"]["admitted"]):
            continue
        findings.append(finding(
            "high",
            f"Kyverno 语义绕过（{row['mechanism']}）：{row['title']}",
            {
                "cases": len(rows),
                "mechanisms": mechanisms,
                "case": row["id"],
                "mechanism": row["mechanism"],
                "vulnerable_trace": row["vulnerable"]["trace"],
                "hardened_trace": row["hardened"]["trace"],
                "violations": row["vulnerable"]["violations"],
                "results_sha256": report["results_sha256"],
            },
            fix="Audit→Enforce；exclude 仅允许平台签名的 namespace/label；校验覆盖 initContainers、"
                "ephemeralContainers 与 exec/ephemeralcontainers 子资源；"
                "mutation 后重新评估排除标签；CRD 各版本与 cluster-scoped 资源统一策略。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "engine": "kyverno", "cases": len(rows), "mechanisms": mechanisms,
        "report": report,
    })
    summary = (f"cases={len(rows)} admitted={report['vulnerable_admitted']} "
               f"hardened_admitted={report['hardened_admitted']} findings={len(findings)}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
