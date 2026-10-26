# -*- coding: utf-8 -*-
"""Megatron/DeepSpeed 训练配置面 — 并行度、checkpoint 路径与环境变量暴露。

只读：GET /train/config（world_size / TP-PP-EP-CP-SP / checkpoint 目录 / 远程代码开关 /
rendezvous）+ GET /train/env（环境变量名与值）。
判定（非单点）：配置可读 + world_size ≥ 64 + 五维并行度齐全 +（trust_remote_code 或
存在令牌类环境变量）→ high；fixed 姿态下两条读面 401 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "megatron-deepspeed-config-surface"
WRITES = False
MIN_WORLD_SIZE = 64
TOPOLOGY_KEYS = ("tp", "pp", "ep", "cp", "sp")


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    t = _COMMON.Trace(ctx, KEY)
    cfg_entry = t.call("GET", f"{target}/train/config", headers=_COMMON.headers_for(params))
    env_entry = t.call("GET", f"{target}/train/env", headers=_COMMON.headers_for(params))
    cfg = _COMMON.resp(cfg_entry)
    env = _COMMON.resp(env_entry)
    parallelism = cfg.get("parallelism") if isinstance(cfg.get("parallelism"), dict) else {}
    degrees = {key: _COMMON.int_of(parallelism.get(key)) for key in TOPOLOGY_KEYS}
    env_items = [item for item in (env.get("env") or []) if isinstance(item, dict)]
    env_names = [str(item.get("name")) for item in env_items]
    secret_items = [item for item in env_items
                    if _COMMON.is_secret_name(item.get("name"))]
    rendezvous = cfg.get("rendezvous") if isinstance(cfg.get("rendezvous"), dict) else {}
    detail = {
        "route": "/train/config,/train/env",
        "config_status": cfg_entry.get("status"),
        "env_status": env_entry.get("status"),
        "framework": cfg.get("framework", ""),
        "version": cfg.get("version", ""),
        "world_size": _COMMON.int_of(cfg.get("world_size")),
        "parallelism": degrees,
        "checkpoint_dir": cfg.get("checkpoint_dir", ""),
        "optimizer_state_dir": cfg.get("optimizer_state_dir", ""),
        "data_dir": cfg.get("data_dir", ""),
        "trust_remote_code": bool(cfg.get("trust_remote_code")),
        "rendezvous_backend": rendezvous.get("backend", ""),
        "rendezvous_tls": bool(rendezvous.get("tls")),
        "env_count": len(env_items),
        "env_names": env_names,
        "secret_names": [str(item.get("name")) for item in secret_items],
        "secret_values_masked": all(str(item.get("value")).startswith("MOCK")
                                    for item in secret_items),
        "checkpoint_shared_path": str(cfg.get("checkpoint_dir", "")).startswith("/shared/"),
    }
    exposed = (_COMMON.is_ok(cfg_entry) and detail["world_size"] >= MIN_WORLD_SIZE
               and all(v > 0 for v in degrees.values())
               and (detail["trust_remote_code"] or bool(secret_items)))
    findings: list[dict] = []
    if exposed:
        findings.append(_COMMON.finding(
            "high",
            "Megatron/DeepSpeed 训练配置面暴露：并行度/共享 checkpoint 路径/令牌类环境变量可读",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info", "训练配置面被拒绝或未满足暴露判据（配置 401 / 并行度不全 / 无敏感环境变量）",
            detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"config={cfg_entry.get('status')} env={env_entry.get('status')} "
               f"world_size={detail['world_size']} secrets={len(secret_items)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
