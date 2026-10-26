# -*- coding: utf-8 -*-
"""实验追踪器暴露 — MLflow / W&B / TensorBoard 未授权读与凭据。

只读：GET /tracker/mlflow/api/2.0/mlflow/runs、/tracker/mlflow/config、
/tracker/wandb/keys、/tracker/tensorboard/runs。
判定（非单点）：run 列表可读且含他租户 run + MLflow 鉴权 none/artifact root 可见 +
W&B key 可读（finding 仅 MOCK****尾4位）→ high；fixed 全部 401 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "experiment-tracker-exposure"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    t = _COMMON.Trace(ctx, KEY)
    headers = _COMMON.headers_for(params)
    runs_entry = t.call("GET", f"{target}/tracker/mlflow/api/2.0/mlflow/runs", headers=headers)
    config_entry = t.call("GET", f"{target}/tracker/mlflow/config", headers=headers)
    wandb_entry = t.call("GET", f"{target}/tracker/wandb/keys", headers=headers)
    tb_entry = t.call("GET", f"{target}/tracker/tensorboard/runs", headers=headers)

    runs = [r for r in (_COMMON.resp(runs_entry).get("runs") or []) if isinstance(r, dict)]
    other_runs = [r for r in runs if str(r.get("tenant")) != tenant]
    cfg = _COMMON.resp(config_entry)
    keys = [k for k in (_COMMON.resp(wandb_entry).get("keys") or []) if isinstance(k, dict)]
    tb_runs = [r for r in (_COMMON.resp(tb_entry).get("runs") or []) if isinstance(r, dict)]
    tb_other = [r for r in tb_runs if str(r.get("tenant")) != tenant]
    masked_keys = [{"name": str(k.get("name")), "tenant": str(k.get("tenant")),
                    "value": _COMMON.mask_value(k.get("value"))} for k in keys]
    detail = {
        "route": ("/tracker/mlflow/api/2.0/mlflow/runs,/tracker/mlflow/config,"
                  "/tracker/wandb/keys,/tracker/tensorboard/runs"),
        "runs_status": runs_entry.get("status"),
        "runs_total": len(runs),
        "tenants": sorted({str(r.get("tenant")) for r in runs}),
        "other_tenant_runs": len(other_runs),
        "config_status": config_entry.get("status"),
        "tracking_uri": cfg.get("tracking_uri", ""),
        "artifact_root": cfg.get("artifact_root", ""),
        "auth": cfg.get("auth", ""),
        "wandb_status": wandb_entry.get("status"),
        "wandb_entity": _COMMON.resp(wandb_entry).get("entity", ""),
        "key_count": len(keys),
        "keys_masked": masked_keys,
        "tensorboard_status": tb_entry.get("status"),
        "tensorboard_runs": len(tb_runs),
        "tensorboard_other_tenant": len(tb_other),
        "credential_exposure": any(not k["value"] == "MOCK****" for k in masked_keys),
    }
    exposed = (_COMMON.is_ok(runs_entry) and detail["other_tenant_runs"] >= 1
               and detail["auth"].lower() == "none"
               and (_COMMON.is_ok(wandb_entry) and detail["key_count"] >= 1
                    or detail["tensorboard_other_tenant"] >= 1))
    findings: list[dict] = []
    if exposed:
        findings.append(_COMMON.finding(
            "high",
            "实验追踪器未授权：跨租户 run/指标可读 + MLflow 无鉴权 + W&B 凭据可见（尾4位）",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info", "实验追踪器被拒绝或已加固（401 / 鉴权开启 / 无跨租户数据）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"runs={runs_entry.get('status')}({detail['runs_total']},其他租户 "
               f"{detail['other_tenant_runs']}) wandb={wandb_entry.get('status')} "
               f"tb={tb_entry.get('status')} auth={detail['auth']}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
