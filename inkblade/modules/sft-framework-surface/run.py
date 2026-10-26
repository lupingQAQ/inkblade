# -*- coding: utf-8 -*-
"""SFT 框架面 — LLaMA-Factory / ms-swift / TRL 无鉴权、远程代码与数据路径。

读面：GET /sft/llamafactory/api/status、/options、/sft/ms-swift/datasets、/sft/trl/status。
写面（backup-write）：POST /sft/llamafactory/api/train 提交带 benign marker 的任务
（file:// 数据路径 + trust_remote_code=true），并统计跨租户数据集可见性。
判定：读面无鉴权且 0.0.0.0 绑定 + 远程代码/文件路径开启 + 提交被接受 + 跨租户数据集可见
→ high；fixed 读面 401/写面 401 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "sft-framework-surface"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    headers = _COMMON.headers_for(params)
    detail = {"route": ("/sft/llamafactory/api/status,/sft/llamafactory/api/options,"
                        "/sft/llamafactory/api/train,/sft/ms-swift/datasets,/sft/trl/status"),
              "mode": mode, "marker": marker}

    status_entry = t.call("GET", f"{target}/sft/llamafactory/api/status", headers=headers)
    options_entry = t.call("GET", f"{target}/sft/llamafactory/api/options", headers=headers)
    datasets_entry = t.call("GET", f"{target}/sft/ms-swift/datasets", headers=headers)
    trl_entry = t.call("GET", f"{target}/sft/trl/status", headers=headers)

    status_payload = _COMMON.resp(status_entry)
    options = _COMMON.resp(options_entry)
    datasets = [d for d in (_COMMON.resp(datasets_entry).get("datasets") or [])
                if isinstance(d, dict)]
    other = [d for d in datasets if str(d.get("tenant")) != tenant]
    trl = _COMMON.resp(trl_entry)
    detail.update({
        "status_status": status_entry.get("status"),
        "bind": status_payload.get("bind", ""),
        "auth": status_payload.get("auth"),
        "version": status_payload.get("version", ""),
        "trust_remote_code": bool(status_payload.get("trust_remote_code")),
        "options_status": options_entry.get("status"),
        "allow_file_scheme": bool(options.get("allow_file_scheme")),
        "accepted_schemes": options.get("accepted_schemes") or [],
        "datasets_status": datasets_entry.get("status"),
        "datasets_total": len(datasets),
        "other_tenant_datasets": [str(d.get("name")) for d in other],
        "trl_status": trl_entry.get("status"),
        "trl_dev_mode": bool(trl.get("dev_mode")),
        "trl_host": trl.get("host", ""),
    })

    if mode == "backup-write":
        run_name = f"{marker}-sft-job"
        submit = t.call("POST", f"{target}/sft/llamafactory/api/train", {
            "config": {
                "dataset_dir": "file:///shared/tenant-b/sft",
                "trust_remote_code": True,
                "run_name": run_name,
            },
        }, headers)
        submit_payload = _COMMON.resp(submit)
        detail.update({
            "submit_status": submit.get("status"),
            "accepted": bool(submit_payload.get("accepted")),
            "job_id": submit_payload.get("job_id", ""),
            "run_name": submit_payload.get("run_name", ""),
            "data_path_scheme": submit_payload.get("data_path_scheme", ""),
            "submitted_trust_remote_code": bool(submit_payload.get("trust_remote_code")),
        })
        open_surface = (_COMMON.is_ok(status_entry) and status_payload.get("auth") is False
                        and str(status_payload.get("bind", "")).startswith("0.0.0.0")
                        and (detail["trust_remote_code"] or detail["allow_file_scheme"]))
        exploited = (open_surface and detail["accepted"]
                     and detail["data_path_scheme"] == "file"
                     and bool(detail["other_tenant_datasets"]))
        if exploited:
            findings.append(_COMMON.finding(
                "high",
                "SFT 框架提交面未鉴权：file:// 数据路径 + trust_remote_code + 跨租户数据集可提交",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "SFT 提交面被拒绝或未满足组合判据（安装/权限/数据路径）", detail))
    else:
        detail.update({"submit_status": "skipped", "accepted": None})
        findings.append(_COMMON.finding(
            "info", "SFT 框架读面指纹（probe-only，不提交任务）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} llamafactory={detail['status_status']} bind={detail['bind']} "
               f"datasets={detail['datasets_total']} submit={detail['submit_status']}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
