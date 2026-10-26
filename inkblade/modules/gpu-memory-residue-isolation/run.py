# -*- coding: utf-8 -*-
"""GPU 显存残留隔离（MIG/MPS 释放后残留对抗，benign marker）。

只读导出（params.snapshot）：
- allocations[]：tenant/device/mig_instance/mps_client/released/zeroized/
  readable_after_release/marker_sha256/residue_sha256/process/mps_shared_context；
- policy：mig_enabled/mps_enabled/zeroize_on_release/mps_shared_context/
  tenant_isolation/multi_tenant。

主动模式（params.target + mode=backup-write，需 backup_targets）：
- POST /gpu/allocate 写入 benign marker；
- POST /gpu/release 释放；
- GET /gpu/residue?allocation=… 读回并比对 marker sha256；
- 释放后仍可读且哈希一致 → high；fixed 清理后 404 → 无 finding。

边界：只写 benign marker，不读取/覆盖真实租户数据；写类模块必须由 runner 的
备份闸门先取得回执。不调用真实 nvidia-smi/NVML，不直接读 /dev/nvidia*。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, benign_marker, ok, read_headers, resolve_mode, resp,
    sha256_text, write_headers,
)

KEY = "gpu-memory-residue-isolation"
WRITES = True


def _entry(payload: dict) -> dict:
    rows = payload.get("residue") or []
    return rows[0] if rows else {}


def _export_findings(doc: dict, requester: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    allocations = [a for a in doc.get("allocations") or [] if isinstance(a, dict)]
    policy = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
    readable = cross = mps_shared = 0
    for item in allocations:
        tenant = str(item.get("tenant") or "")
        released = bool(item.get("released"))
        zeroized = bool(item.get("zeroized"))
        can_read = bool(item.get("readable_after_release"))
        if released and can_read and not zeroized:
            readable += 1
            findings.append(_C.finding(
                "high", "MIG/MPS 释放后显存残留可读",
                {"detected": True, "allocation_id": item.get("allocation_id"),
                 "tenant": tenant, "device": item.get("device"),
                 "mig_instance": item.get("mig_instance"),
                 "mps_client": item.get("mps_client"),
                 "process": item.get("process"),
                 "marker_sha256": item.get("marker_sha256"),
                 "residue_sha256": item.get("residue_sha256"),
                 "readable_after_release": can_read, "zeroized": zeroized,
                 "note": "释放生命周期未清零：残留含进程名/显存快照"},
                evidence=f"allocation={item.get('allocation_id')} readable_after_release=true",
                mapping="MIG/MPS release lifecycle / VRAM zeroization",
                fix="释放即清零 VRAM/MIG 实例；MIG 重配前做全量清零并校验",
            ))
        if tenant and tenant != requester and can_read:
            cross += 1
            findings.append(_C.finding(
                "high", "跨租户显存残留可读",
                {"detected": True, "requester_tenant": requester, "victim_tenant": tenant,
                 "allocation_id": item.get("allocation_id"), "device": item.get("device"),
                 "process": item.get("process"),
                 "marker_sha256": item.get("marker_sha256")},
                evidence=f"requester={requester} victim={tenant} readable=true",
                mapping="GPU multi-tenant isolation / MIG/MPS",
                fix="按租户隔离 MIG/MPS 实例；拒绝跨租户 residue 查询",
            ))
        if item.get("mps_shared_context") and tenant and tenant != requester:
            mps_shared += 1
            findings.append(_C.finding(
                "high", "MPS 共享上下文跨租户",
                {"detected": True, "requester_tenant": requester, "victim_tenant": tenant,
                 "mps_client": item.get("mps_client"), "process": item.get("process")},
                mapping="CUDA MPS shared context",
                fix="MPS 仅用于可信租户；多租户使用 MIG 硬件分区",
            ))
        if released and not zeroized and not can_read:
            findings.append(_C.finding(
                "medium", "释放未清零显存",
                {"detected": True, "allocation_id": item.get("allocation_id"),
                 "tenant": tenant, "zeroized": zeroized},
                fix="释放钩子执行 cudaMemset/驱动清零并记录哈希",
            ))

    if policy.get("zeroize_on_release") is False:
        findings.append(_C.finding(
            "medium", "未配置释放即清零",
            {"detected": True, "policy": policy},
            mapping="GPU memory lifecycle policy",
            fix="把 zeroize_on_release 设为 true，并把清零失败视为调度失败",
        ))
    if policy.get("mps_enabled") and policy.get("tenant_isolation") is False:
        findings.append(_C.finding(
            "high", "MPS 无租户内存隔离",
            {"detected": True, "policy": policy},
            mapping="CUDA MPS / multi-tenant isolation",
            fix="不可信多租户改用 MIG；MPS 仅限同一信任域",
        ))
    if policy.get("mig_enabled") is False and policy.get("multi_tenant"):
        findings.append(_C.finding(
            "medium", "多租户未使用 MIG 硬件分区",
            {"detected": True, "policy": policy},
            mapping="NVIDIA MIG hardware partitioning",
            fix="为不可信租户启用 MIG；核对实例 profile 与显存边界",
        ))
    extra = {
        "allocations": len(allocations),
        "residue_readable": readable,
        "cross_tenant": cross,
        "mps_shared": mps_shared,
        "zeroize_on_release": policy.get("zeroize_on_release"),
        "mig_enabled": policy.get("mig_enabled"),
        "mps_enabled": policy.get("mps_enabled"),
    }
    return findings, extra


def _active(ctx: dict, params: dict, note: str) -> tuple[list[dict], dict]:
    base = base_url(params)
    if not base:
        raise ValueError("backup-write 需要 params.target")
    tenant = str(params.get("tenant") or "tenant-a")
    device = str(params.get("own_device") or "gpu-a-1")
    marker = benign_marker(ctx, "GPU")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    allocation = t.call("POST", f"{base}/gpu/allocate", {
        "tenant": tenant, "device": device,
        "namespace": str(params.get("namespace") or f"ns-{tenant}-infer"),
        "marker": marker, "process": f"trident-residue-{tenant}",
    }, headers=write_headers(params))
    alloc_payload = resp(allocation)
    allocation_id = str(alloc_payload.get("allocation_id") or "")
    release = {}
    readback = {}
    entry: dict = {}
    if ok(allocation) and allocation_id:
        release = t.call("POST", f"{base}/gpu/release", {
            "tenant": tenant, "allocation_id": allocation_id,
        }, headers=write_headers(params))
        readback = t.call(
            "GET", f"{base}/gpu/residue?device={device}&allocation={allocation_id}",
            headers=read_headers(params))
        entry = _entry(resp(readback))
        expected = sha256_text(marker)
        if ok(readback) and entry:
            after_release = bool(entry.get("readable_after_release"))
            sha_ok = entry.get("marker_sha256") == expected
            findings.append(_C.finding(
                "high" if after_release and sha_ok else "medium",
                "MIG/MPS 释放后显存残留可读",
                {"detected": True, "route": "/gpu/allocate → /gpu/release → /gpu/residue",
                 "allocate_status": allocation.get("status"),
                 "release_status": release.get("status"),
                 "readback_status": readback.get("status"),
                 "allocation_id": allocation_id, "tenant": tenant, "device": device,
                 "marker": marker, "marker_sha256": expected,
                 "server_marker_sha256": entry.get("marker_sha256"),
                 "marker_sha256_match": sha_ok,
                 "readable_after_release": after_release,
                 "zeroized": bool(entry.get("zeroized")),
                 "residue_file": entry.get("residue_file"),
                 "residue_file_sha256": entry.get("file_sha256"),
                 "note": "释放后 benign marker 写读回 + sha256 一致即残留可读"},
                evidence=f"readback={readback.get('status')} marker_sha256_match={sha_ok}",
                mapping="MIG/MPS release lifecycle / VRAM residue",
                fix="释放即清零；fixed 行为应返回 404/zeroized",
            ))
        elif readback.get("status") == 404:
            note = (note + "；" if note else "") + "residue_cleanup（fixed 释放即清理，读回 404）"

    active = {
        "allocate_status": allocation.get("status"),
        "release_status": release.get("status"),
        "readback_status": readback.get("status"),
        "allocation_id": allocation_id,
        "marker": marker,
        "marker_sha256": sha256_text(marker),
        "server_marker_sha256": entry.get("marker_sha256"),
        "marker_sha256_match": entry.get("marker_sha256") == sha256_text(marker),
        "readable_after_release": bool(entry.get("readable_after_release")),
        "zeroized": bool(entry.get("zeroized")),
    }
    return findings, active


def run(ctx: dict, params: dict) -> dict:
    mode, note = resolve_mode(params, WRITES)
    findings: list[dict] = []
    extra: dict = {"mode": mode}
    source = "<no-export>"
    active: dict = {}

    if mode == "backup-write":
        findings, active = _active(ctx, params, note)
        extra["active"] = active
        source = base_url(params)
    else:
        doc, source = _C.load_snapshot(params)
        findings, extra2 = _export_findings(
            doc, str(params.get("tenant") or doc.get("requester_tenant") or "tenant-a"))
        extra.update(extra2)

    if note:
        extra["note"] = note
    summary = _C.summary_json("GPU 显存残留隔离", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "active": active, "findings": findings,
    })
    trace = None
    if mode == "backup-write":
        # Trace 由模块内部创建；再次落盘同一路径的成本很低，且保证无 run 时也有返回值。
        trace = None
    return {"summary": summary, "artifacts": artifact, "findings": findings}
