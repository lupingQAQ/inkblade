# -*- coding: utf-8 -*-
"""R06 多租户推理统一隔离基线（只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "inference-tenant-isolation-baseline"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    policy = _C.section(doc, "inference_tenancy", "inference_tenant_policy", default={})
    tenants = [str(t) for t in (policy.get("tenants") or [])]
    findings: list[dict] = []

    checks = [
        ("cache_salt", True, "high", "缓存未启用 per-tenant salt（跨租户缓存命中）",
         "cache salt / 前缀缓存隔离", "为每个租户生成 cache_salt 并进入缓存键"),
        ("prefix_cache_shared", False, "high", "prefix cache 跨租户共享",
         "prefix cache 隔离", "按租户/模型命名空间隔离 prefix cache"),
        ("weight_namespace", "per-tenant", "high", "权重命名空间共享",
         "权重/适配器隔离", "权重与 LoRA adapter 使用租户命名空间"),
        ("kv_namespace", "per-tenant", "high", "KV cache 命名空间全局共享",
         "KV cache 隔离", "KV/远程池按租户命名空间隔离"),
        ("timing_oracle", False, "medium", "暴露可区分租户的计时旁路",
         "计时侧信道", "移除按租户可观测的 token/队列计时或加噪"),
        ("gpu_residue_after_release", False, "high", "GPU 释放后残留他租户数据",
         "GPU 显存残留", "释放时清零显存/上下文；启用 MIG 或独占"),
        ("quota_per_tenant", True, "medium", "未设置每租户配额",
         "多租户配额", "按租户设置 token/并发/GPU 配额"),
        ("log_tenant_id", True, "medium", "日志缺少租户标识（无法审计归属）",
         "日志租户归属", "所有请求/响应日志带 tenant_id 并做访问控制"),
        ("tokenizer_shared", False, "low", "tokenizer/模板跨租户共享",
         "tokenizer 隔离", "租户自定义 tokenizer 时使用独立目录并校验哈希"),
    ]
    for key, good, sev, title, mapping, fix in checks:
        value = policy.get(key)
        if isinstance(good, bool):
            ok = _C.as_bool(value, default=not good) == good
        else:
            ok = str(value or "").lower() == good
        if not ok:
            findings.append(_C.finding(
                sev, title, {"field": key, "value": value, "expected": good},
                evidence=f"{key}={value!r} expected={good!r}",
                mapping=mapping,
                source="KCon 2026 I58",
                fix=fix,
            ))
    if len(tenants) < 2:
        findings.append(_C.finding(
            "info", "租户清单少于 2 个（隔离基线样本不足）",
            {"tenants": tenants},
            evidence=f"tenants={len(tenants)}",
            mapping="多租户基线",
            source="KCon 2026 I58",
            fix="提供至少两个租户的配置/请求样本",
        ))
    if not policy:
        findings.append(_C.finding(
            "high", "未提供多租户推理策略导出",
            {"snapshot": params.get("snapshot")},
            evidence="inference_tenancy missing",
            mapping="基线完整性",
            source="KCon 2026 I58",
            fix="导出 cache/权重/KV/配额/日志租户策略",
        ))

    extra = {
        "tenants": len(tenants),
        "cache_salt": _C.as_bool(policy.get("cache_salt")),
        "prefix_cache_shared": _C.as_bool(policy.get("prefix_cache_shared")),
        "weight_namespace": policy.get("weight_namespace"),
        "kv_namespace": policy.get("kv_namespace"),
        "quota_per_tenant": _C.as_bool(policy.get("quota_per_tenant")),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "多租户推理统一隔离基线", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
