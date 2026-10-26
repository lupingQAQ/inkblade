"""Falco/Tetragon 运行时覆盖盲区审计（只读事件重放）。"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.depth import ebpf as _e  # noqa: E402
from trident.depth.common import finding, write_artifact  # noqa: E402

KEY = "ebpf-runtime-coverage-gap"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    rows = _e.cases()
    if params.get("snapshot"):
        rows = _e.load_cases(params["snapshot"])
    report = _e.audit(rows)
    findings: list[dict] = []
    for row in report["results"]:
        if not (not row["vulnerable"]["detected"] and row["hardened"]["detected"]):
            continue
        event = row["event"]
        findings.append(finding(
            "high",
            f"运行时盲区（{row['category']}）：{row['title']}",
            {
                "cases": report["total"],
                "missed": report["vulnerable_missed"],
                "hardened_missed": report["hardened_missed"],
                "coverage_gaps": report["coverage_gaps"],
                "case": row["id"],
                "category": row["category"],
                "syscall": event["syscall"],
                "event_type": event["type"],
                "missed_by": row["vulnerable"]["missed_by"],
                "falco_reason": row["vulnerable"]["falco"]["reason"],
                "tetragon_reason": row["vulnerable"]["tetragon"]["reason"],
                "results_sha256": report["results_sha256"],
            },
            fix="把 execveat/fexecve/memfd/io_uring/ptrace/mount/clone3/bpf 纳入规则；"
                "以 hostPID+namespace 归属替代 container_id 过滤；hostNetwork/Multus 与短进程单独采集。",
        ))
    artifact = write_artifact(ctx, f"{KEY}.json", {
        "total": report["total"],
        "vulnerable_missed": report["vulnerable_missed"],
        "hardened_missed": report["hardened_missed"],
        "categories": report["categories"],
        "results_sha256": report["results_sha256"],
        "results": report["results"],
    })
    summary = (f"cases={report['total']} missed={report['vulnerable_missed']} "
               f"hardened_missed={report['hardened_missed']} gaps={report['coverage_gaps']}")
    return {"summary": summary, "artifacts": artifact, "findings": findings}
