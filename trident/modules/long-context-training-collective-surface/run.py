# -*- coding: utf-8 -*-
"""大规模训练集合通信面 — 长上下文训练的并行拓扑与集合通信端口暴露。

检测口径（真实 HTTP）：GET /metrics 中 training 字段暴露
world_size / tp / pp / ep / cp / sp / ring_attention / hierarchical_all_reduce /
collective_ports / nccl_bootstrap_port / kv_transfer_port。
暴露到未鉴权指标面 → 攻击者可据此枚举 ring attention 通信环与层级 all-reduce 边界（medium）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "long-context-training-collective-surface"
WRITES = False
MIN_WORLD_SIZE = 64
TOPOLOGY_KEYS = ("tp", "pp", "ep", "cp", "sp")


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    t = _COMMON.Trace(ctx, KEY)
    metrics = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))
    training = _COMMON.resp(metrics).get("training")
    training = training if isinstance(training, dict) else {}
    world_size = _COMMON.int_of(training.get("world_size"))
    degrees = {key: _COMMON.int_of(training.get(key)) for key in TOPOLOGY_KEYS}
    ports = [p for p in (training.get("collective_ports") or []) if isinstance(p, int)]
    detail = {
        "route": "/metrics",
        "metrics_status": metrics.get("status"),
        "world_size": world_size,
        "parallelism": degrees,
        "ring_attention": bool(training.get("ring_attention")),
        "hierarchical_all_reduce": bool(training.get("hierarchical_all_reduce")),
        "collective_ports": ports,
        "nccl_bootstrap_port": training.get("nccl_bootstrap_port"),
        "kv_transfer_port": training.get("kv_transfer_port"),
        "assumptions": "A1-A8：万卡 fat-tree/rail 拓扑、作业内 rank 互信、"
                       "rendezvous/KV 通道默认无 mTLS、checkpoint 桶即权重面、"
                       "ring attention/层级 all-reduce 边界可枚举",
    }
    exposed = (world_size >= MIN_WORLD_SIZE and all(v > 0 for v in degrees.values())
               and detail["ring_attention"] and detail["hierarchical_all_reduce"] and ports)
    findings: list[dict] = []
    if _COMMON.is_ok(metrics) and exposed:
        findings.append(_COMMON.finding(
            "medium", "大规模训练并行拓扑与集合通信端口暴露（ring attention / 层级 all-reduce）",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info", "训练拓扑未暴露或指标面需鉴权（集合通信面收敛）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "long-context-training-collective-surface.json", detail)
    summary = (f"metrics={metrics.get('status')} world_size={world_size} "
               f"ports={len(ports)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
