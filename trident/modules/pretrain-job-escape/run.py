# -*- coding: utf-8 -*-
"""预训练作业提交面 — K8s Job / Ray / Slurm 特权与共享 SA 接受面。

probe-only：GET /jobs/cluster（调度器、共享 trainer-admin SA、hostNetwork/特权允许）。
backup-write：POST /jobs/submit 提交带 benign marker 的作业（hostPath=/ + privileged +
共享 SA），再 GET /jobs/submitted/<id> 读回；提交 200 且读回三项原语齐全 → high。
fixed：集群读面 401、提交 403 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "pretrain-job-escape"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    headers = _COMMON.headers_for(params)
    detail = {"route": "/jobs/cluster,/jobs/submit,/jobs/submitted/{job}",
              "mode": mode, "marker": marker}

    cluster_entry = t.call("GET", f"{target}/jobs/cluster", headers=headers)
    cluster = _COMMON.resp(cluster_entry)
    detail.update({
        "cluster_status": cluster_entry.get("status"),
        "scheduler": cluster.get("scheduler", ""),
        "shared_service_account": cluster.get("shared_service_account", ""),
        "host_network": bool(cluster.get("host_network")),
        "privileged_allowed": bool(cluster.get("privileged_allowed")),
        "submitters": cluster.get("submitters") or [],
    })

    if mode == "backup-write":
        job_spec = {
            "name": f"{marker}-job",
            "service_account": "trainer-admin",
            "host_path": "/",
            "privileged": True,
            "image": "pytorch/pytorch:2.9-cuda12.8",
        }
        submit = t.call("POST", f"{target}/jobs/submit", {"job_spec": job_spec}, headers)
        submitted = _COMMON.resp(submit)
        job_id = str(submitted.get("job_id") or "")
        readback = t.call("GET", f"{target}/jobs/submitted/{quote(job_id, safe='')}",
                          headers=headers) if job_id else {"status": 0, "response": {}}
        job = _COMMON.resp(readback).get("job") or {}
        detail.update({
            "submit_status": submit.get("status"),
            "accepted": bool(submitted.get("accepted")),
            "job_id": job_id,
            "readback_status": readback.get("status"),
            "readback_service_account": job.get("service_account", ""),
            "readback_host_path": job.get("host_path", ""),
            "readback_privileged": bool(job.get("privileged")),
            "readback_name": job.get("name", ""),
            "escape_primitives": sum([
                job.get("service_account") == "trainer-admin",
                job.get("host_path") == "/",
                bool(job.get("privileged")),
            ]),
        })
        exploited = (_COMMON.is_ok(submit) and detail["accepted"]
                     and _COMMON.is_ok(readback) and detail["escape_primitives"] == 3
                     and detail["host_network"])
        if exploited:
            findings.append(_COMMON.finding(
                "high",
                "预训练作业提交面接受特权 Pod：共享 trainer-admin SA + hostPath=/ + privileged",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "作业提交面被拒绝或未接受全套逃逸原语", detail))
    else:
        detail.update({"submit_status": "skipped", "accepted": None,
                       "readback_status": "skipped"})
        findings.append(_COMMON.finding(
            "info", "作业提交面与调度器指纹（probe-only，不提交作业）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} cluster={detail['cluster_status']} sa="
               f"{detail['shared_service_account']} submit={detail['submit_status']}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
