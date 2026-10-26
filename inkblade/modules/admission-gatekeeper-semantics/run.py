"""Gatekeeper 准入语义深度审计（dryrun/warn/排除/mutation/子资源/CRD/参数）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.depth import admission as _a  # noqa: E402
from inkblade.depth.common import finding, write_artifact  # noqa: E402

KEY = "admission-gatekeeper-semantics"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    rows = [c for c in _a.cases() if c["engine"] == "gatekeeper"]
    report = _a.audit(rows)
    mechanisms = sorted({c["mechanism"] for c in rows})
    findings: list[dict] = []
    for row in report["results"]:
        if not (row["vulnerable"]["admitted"] and not row["hardened"]["admitted"]):
            continue
        findings.append(finding(
            "high",
            f"Gatekeeper 语义绕过（{row['mechanism']}）：{row['title']}",
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
            fix="enforcementAction 从 dryrun/warn 提升为 deny；移除可被工作负载改写的 labelSelector 依赖；"
                "subresources 显式覆盖 exec/ephemeralcontainers；constraint 匹配全部 CRD 版本与 cluster scope；"
                "参数禁止 '*' 豁免。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "engine": "gatekeeper", "cases": len(rows), "mechanisms": mechanisms,
        "report": report,
    })
    summary = (f"cases={len(rows)} admitted={report['vulnerable_admitted']} "
               f"hardened_admitted={report['hardened_admitted']} findings={len(findings)}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
