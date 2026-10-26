"""lab/gpu_cloud_sim.py — GPU 组卡/池化平台 + 云平台跨租户仿真靶场（真 HTTP，单文件多路由）。

仅监听 127.0.0.1，仅标准库（http.server + threading）。两种姿态：
- vulnerable：HAMi/OrionX/cGPU 风格池化调度的 fail-open 姿态（无鉴权、跨租户分配/迁移、
  MIG/MPS 释放后残留、DCGM 指标泄露他租户进程）+ 云租户面通配信任/公共桶/任意共享/宽 grants/IMDS 开放；
- fixed：鉴权 + 租户隔离 + 释放清理 + 最小策略（401/403/404/409，按真实修复语义）。

路由清单（GET /__routes__ 返回同表 JSON，供测试与利用模块发现）：
GPU 池化：
- GET  /gpu/pools                  池/设备清单（tenant 标签、MIG 档位、MPS、pod namespace）
- POST /gpu/allocate               分配/迁移（vulnerable：任意租户覆盖他租户分配；fixed：admin+租户校验/409）
- POST /gpu/release                释放（vulnerable：残留显存快照可读；fixed：清理后 404）
- GET/POST /gpu/mig/profiles       MIG 档位清单/重配（vulnerable：请求与生效不一致且可任意重配）
- GET  /gpu/metrics                DCGM 风格指标（进程名/租户标签；fixed 按租户过滤）
- GET  /gpu/mps/status             MPS context（vulnerable：跨租户共享 pipe；fixed 隔离）
- GET  /gpu/residue                释放后残留 benign marker 读回（含 sha256）
云租户面：
- GET  /cloud/identity             IRSA/RRSA/WorkloadIdentity 注解 + trust policy
- POST /cloud/identity/assume-role 模拟 STS AssumeRole（vulnerable：通配信任跨账户成功）
- GET  /cloud/bucket/policy        S3/OSS/COS/Blob 桶策略
- GET  /cloud/bucket/list          列目录（vulnerable：public/跨租户；fixed：仅 owner）
- GET/POST /cloud/snapshot/share   快照共享（vulnerable：任意账户；fixed：仅同账户）
- GET  /cloud/kms/grants           KMS grants（vulnerable：Principal "*"；fixed：最小权限）
- GET  /cloud/security-group       安全组 + IMDS 选项（vulnerable：0.0.0.0/0 + IMDSv1）

写盘边界：一切落盘仅限 Server.root（默认临时目录并在 shutdown 清理；start_all(root=...) 可注入）。
残留/共享对象一律 benign marker（INKBLADE-BENIGN 前缀），不含真实模型数据。

命令行：python lab/gpu_cloud_sim.py [--port N] [--mode vulnerable|fixed] [--root DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
ADMIN_TOKEN = "mock-gpu-platform-admin-key"
TENANT_TOKENS = {
    "tenant-a": "mock-tenant-a-token",
    "tenant-b": "mock-tenant-b-token",
}
TENANT_ACCOUNTS = {"tenant-a": "111111111111", "tenant-b": "222222222222"}
TENANTS = tuple(sorted(TENANT_TOKENS))
MIG_PROFILES = ("1g.10gb", "2g.20gb", "3g.40gb", "7g.80gb")
BENIGN = "INKBLADE-BENIGN"
DEFAULT_MARKER = f"{BENIGN}-VRAM-SNAPSHOT"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _safe_name(value: str, fallback: str = "unnamed") -> str:
    """把请求可控字符串压成安全文件/目录名（防路径穿越，写盘仅限 root 内）。"""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return cleaned or fallback


def _bearer(headers) -> str:
    raw = (headers.get("Authorization") or "").strip()
    return raw[7:].strip() if raw.lower().startswith("bearer ") else ""


class _RequestContext:
    """单次请求上下文：模式、根目录、进程内状态、请求要素。"""

    def __init__(self, mode, root, state, lock, headers, body, path, query, entry):
        self.mode = mode
        self.root = root
        self.state = state
        self.lock = lock
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.entry = entry

    @property
    def token(self) -> str:
        return _bearer(self.headers)

    @property
    def tenant(self) -> str:
        return (self.headers.get("X-Tenant") or "").strip()

    def principal(self) -> tuple[str | None, str]:
        """返回 (身份, X-Tenant)；身份 = admin / tenant / invalid / None。"""
        tenant = self.tenant
        token = self.token
        if not token:
            return None, tenant
        if token == ADMIN_TOKEN:
            return "admin", tenant
        if tenant in TENANT_TOKENS and token == TENANT_TOKENS[tenant]:
            return "tenant", tenant
        return "invalid", tenant

    def sandbox(self, *parts: str) -> Path:
        target = self.root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target


def _gate_read(ctx: _RequestContext):
    """fixed 读闸门：有效 token + 明确租户；返回错误三元组或 None。"""
    kind, tenant = ctx.principal()
    if kind is None:
        return 401, {"error": "unauthorized", "service": ctx.entry["service"],
                     "hint": "fixed 模式需要 Authorization: Bearer <tenant-token> 与 X-Tenant 头"}
    if kind == "invalid":
        return 403, {"error": "forbidden", "service": ctx.entry["service"],
                     "hint": "token 与 X-Tenant 不匹配"}
    if tenant not in TENANTS:
        return 400, {"error": "bad request", "service": ctx.entry["service"],
                     "hint": "缺少或非法 X-Tenant"}
    return None


def _gate_write(ctx: _RequestContext):
    """fixed 写闸门：平台 admin token + 明确租户（租户 token 不得改池状态）。"""
    err = _gate_read(ctx)
    if err:
        return err
    kind, _ = ctx.principal()
    if kind != "admin":
        return 403, {"error": "forbidden", "service": ctx.entry["service"],
                     "hint": "池/共享面写操作需要平台 admin token"}
    return None


def _gate_owner(ctx: _RequestContext, owner_tenant: str):
    """fixed 资源归属闸门：X-Tenant 必须等于资源 owner（admin 同样受租户作用域约束）。"""
    err = _gate_read(ctx)
    if err:
        return err
    if ctx.tenant != owner_tenant:
        return 403, {"error": "forbidden", "service": ctx.entry["service"],
                     "hint": f"跨租户访问被拒（owner={owner_tenant}）"}
    return None


def _device(ctx: _RequestContext, name: str) -> dict | None:
    return ctx.state["devices"].get(name)


def _allocation(ctx: _RequestContext, alloc_id: str) -> dict | None:
    return ctx.state["allocations"].get(alloc_id)


def _persist_state(ctx: _RequestContext) -> str:
    """把池状态真实写入 server 侧文件，返回 sha256（写类证据锚）。"""
    state = ctx.state
    state["revision"] += 1
    payload = {
        "revision": state["revision"],
        "updated_at": _utcnow_iso(),
        "mode": ctx.mode,
        "devices": state["devices"],
        "allocations": state["allocations"],
    }
    path = ctx.sandbox("gpu", "pools-state.json")
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return _sha256_bytes(path.read_bytes())


def _residue_path(ctx: _RequestContext, device: str, alloc_id: str) -> Path:
    return ctx.sandbox("gpu", "residue", _safe_name(device), f"{_safe_name(alloc_id)}.json")


def _write_residue(ctx: _RequestContext, allocation: dict, *, released: bool = False,
                   marker: str = "", model_marker: str = "") -> tuple[Path, str]:
    """写 benign marker 残留文件（真实字节），返回 (路径, 文件 sha256)。"""
    marker = marker or allocation.get("marker") or DEFAULT_MARKER
    model_marker = model_marker or allocation.get("model_marker") or f"{BENIGN}-MODEL-{allocation['tenant']}"
    payload = {
        "benign_marker": marker,
        "marker_sha256": _sha256_text(marker),
        "model_marker": model_marker,
        "device": allocation["device"],
        "tenant": allocation["tenant"],
        "namespace": allocation.get("namespace", ""),
        "allocation_id": allocation["allocation_id"],
        "process": allocation.get("process", "mock-process"),
        "released": released,
        "retained": released,
        "created_at": allocation.get("created_at", _utcnow_iso()),
        "updated_at": _utcnow_iso(),
    }
    path = _residue_path(ctx, allocation["device"], allocation["allocation_id"])
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return path, _sha256_bytes(path.read_bytes())


def _read_residue(ctx: _RequestContext, path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    raw = path.read_bytes()
    return {
        "allocation_id": doc.get("allocation_id", ""),
        "device": doc.get("device", ""),
        "tenant": doc.get("tenant", ""),
        "namespace": doc.get("namespace", ""),
        "marker": doc.get("benign_marker", ""),
        "marker_sha256": doc.get("marker_sha256", ""),
        "model_marker": doc.get("model_marker", ""),
        "process": doc.get("process", ""),
        "released": bool(doc.get("released")),
        "readable_after_release": bool(doc.get("released")),
        "residue_file": path.relative_to(ctx.root).as_posix(),
        "file_sha256": _sha256_bytes(raw),
        "updated_at": doc.get("updated_at", ""),
    }


# ---------------------------------------------------------------------------
# GPU 池化面
# ---------------------------------------------------------------------------


def _gpu_pools(ctx: _RequestContext):
    if ctx.mode == "fixed":
        err = _gate_read(ctx)
        if err:
            return err
        visible = ctx.tenant
        devices = [d for d in ctx.state["devices"].values() if d["tenant"] == visible]
    else:
        devices = list(ctx.state["devices"].values())
    tenants = sorted({d["tenant"] for d in devices})
    return 200, {
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "revision": ctx.state["revision"],
        "tenant_filter": ctx.tenant if ctx.mode == "fixed" else "*",
        "cross_tenant_visible": len(tenants) > 1,
        "devices": devices,
        "pools": [
            {
                "pool": "pool-a", "scheduler": "hami", "tenant": "tenant-a",
                "device_count": 2, "sharing": "mig+mps",
            },
            {
                "pool": "pool-b", "scheduler": "orionx", "tenant": "tenant-b",
                "device_count": 2, "sharing": "vcuda",
            },
        ],
    }


def _gpu_allocate(ctx: _RequestContext):
    tenant = str(ctx.body.get("tenant") or "tenant-a")
    device_name = str(ctx.body.get("device") or "")
    if tenant not in TENANTS:
        return 400, {"error": "bad request", "service": "gpu-pooling", "hint": f"未知租户 {tenant}"}
    device = _device(ctx, device_name)
    if device is None:
        return 404, {"error": "not found", "service": "gpu-pooling", "hint": f"未知设备 {device_name}"}
    if ctx.mode == "fixed":
        err = _gate_write(ctx)
        if err:
            return err
        if ctx.tenant != tenant or device["tenant"] != tenant:
            return 403, {"error": "forbidden", "service": "gpu-pooling",
                         "hint": "跨租户分配/迁移被拒（X-Tenant 与设备归属不一致）"}
        if device.get("allocation"):
            return 409, {"error": "conflict", "service": "gpu-pooling",
                         "hint": "设备已被分配，需先释放"}

    previous_id = device.get("allocation") or ""
    previous = _allocation(ctx, previous_id) if previous_id else None
    cross_tenant = bool(previous and previous["tenant"] != tenant)
    if previous and cross_tenant:
        previous["status"] = "migrated"
        previous["released_at"] = _utcnow_iso()
        if ctx.mode == "vulnerable":
            _write_residue(ctx, previous, released=True)

    alloc_id = "alloc-" + uuid.uuid4().hex[:10]
    allocation = {
        "allocation_id": alloc_id,
        "device": device_name,
        "tenant": tenant,
        "namespace": str(ctx.body.get("namespace") or "default"),
        "mig_profile": str(ctx.body.get("mig_profile") or device["mig"]["active"]),
        "mps": bool(ctx.body.get("mps", True)),
        "marker": str(ctx.body.get("marker") or DEFAULT_MARKER),
        "process": str(ctx.body.get("process") or f"probe-{tenant}"),
        "status": "active",
        "created_at": _utcnow_iso(),
    }
    ctx.state["allocations"][alloc_id] = allocation
    device["allocation"] = alloc_id
    device["tenant"] = tenant
    device["mig"]["active"] = allocation["mig_profile"]
    device["mps_shared"] = True
    device["pods"].append({
        "name": f"{allocation['process']}-{alloc_id[-4:]}",
        "namespace": allocation["namespace"],
        "tenant": tenant,
        "allocation_id": alloc_id,
    })
    residue_path, residue_sha = _write_residue(ctx, allocation)
    state_sha = _persist_state(ctx)
    response = {
        "ok": True,
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "allocation_id": alloc_id,
        "device": device_name,
        "tenant": tenant,
        "namespace": allocation["namespace"],
        "cross_tenant": cross_tenant,
        "migrated": cross_tenant,
        "previous_allocation": previous_id,
        "previous_tenant": previous["tenant"] if previous else "",
        "previous_process": previous.get("process", "") if previous else "",
        "previous_residue": True if cross_tenant else False,
        "residue_file": residue_path.relative_to(ctx.root).as_posix(),
        "residue_sha256": residue_sha,
        "marker_sha256": _sha256_text(allocation["marker"]),
        "mps_shared": True,
        "pods": device["pods"],
        "state_sha256": state_sha,
    }
    return 200, response


def _gpu_release(ctx: _RequestContext):
    if ctx.mode == "fixed":
        err = _gate_write(ctx)
        if err:
            return err
    alloc_id = str(ctx.body.get("allocation_id") or "")
    if not alloc_id:
        by_device = _device(ctx, str(ctx.body.get("device") or ""))
        alloc_id = (by_device or {}).get("allocation") or ""
    allocation = _allocation(ctx, alloc_id)
    if allocation is None:
        return 404, {"error": "not found", "service": "gpu-pooling", "hint": f"未知 allocation {alloc_id}"}
    tenant = str(ctx.body.get("tenant") or allocation["tenant"])
    if ctx.mode == "fixed":
        if tenant != allocation["tenant"] or ctx.tenant != tenant:
            return 403, {"error": "forbidden", "service": "gpu-pooling",
                         "hint": "跨租户释放被拒"}
    device = _device(ctx, allocation["device"])
    allocation["status"] = "released"
    allocation["released_at"] = _utcnow_iso()
    if device is not None and device.get("allocation") == alloc_id:
        device["allocation"] = None
        if ctx.mode == "fixed":
            device["pods"] = [p for p in device["pods"] if p.get("allocation_id") != alloc_id]
            device["mps_shared"] = False
    if ctx.mode == "fixed":
        path = _residue_path(ctx, allocation["device"], alloc_id)
        if path.is_file():
            path.unlink()
        retained = False
        residue_file = ""
        residue_sha = ""
    else:
        path, residue_sha = _write_residue(ctx, allocation, released=True)
        retained = True
        residue_file = path.relative_to(ctx.root).as_posix()
    state_sha = _persist_state(ctx)
    return 200, {
        "ok": True,
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "allocation_id": alloc_id,
        "tenant": allocation["tenant"],
        "released": True,
        "residue_retained": retained,
        "residue_removed": not retained,
        "residue_file": residue_file,
        "residue_sha256": residue_sha,
        "state_sha256": state_sha,
    }


def _mig_profiles(ctx: _RequestContext):
    requested_device = (ctx.query.get("device") or [""])[0]
    if ctx.mode == "fixed":
        err = _gate_read(ctx)
        if err:
            return err
        devices = [d for d in ctx.state["devices"].values() if d["tenant"] == ctx.tenant]
    else:
        devices = list(ctx.state["devices"].values())
    if requested_device:
        devices = [d for d in devices if d["device"] == requested_device]
        if not devices:
            return 404, {"error": "not found", "service": "gpu-pooling", "hint": f"未知设备 {requested_device}"}
    rows = [
        {
            "device": d["device"],
            "tenant": d["tenant"],
            "active": d["mig"]["active"],
            "requested": d["mig"]["requested"],
            "mismatch": d["mig"]["active"] != d["mig"]["requested"],
            "allocation": d.get("allocation"),
            "isolation": "shared-slices" if d.get("mps_shared") else "dedicated-slice",
        }
        for d in devices
    ]
    return 200, {
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "profiles": list(MIG_PROFILES),
        "devices": rows,
        "mismatch_count": sum(1 for r in rows if r["mismatch"]),
    }


def _mig_reconfigure(ctx: _RequestContext):
    tenant = str(ctx.body.get("tenant") or "tenant-a")
    device_name = str(ctx.body.get("device") or "")
    profile = str(ctx.body.get("profile") or "")
    device = _device(ctx, device_name)
    if device is None:
        return 404, {"error": "not found", "service": "gpu-pooling", "hint": f"未知设备 {device_name}"}
    if profile not in MIG_PROFILES:
        return 400, {"error": "bad request", "service": "gpu-pooling",
                     "hint": f"非法 MIG profile {profile}", "profiles": list(MIG_PROFILES)}
    if ctx.mode == "fixed":
        err = _gate_write(ctx)
        if err:
            return err
        if ctx.tenant != tenant or device["tenant"] != tenant:
            return 403, {"error": "forbidden", "service": "gpu-pooling",
                         "hint": "跨租户 MIG 重配被拒"}
        if device.get("allocation"):
            return 409, {"error": "conflict", "service": "gpu-pooling",
                         "hint": "已分配设备禁止在线重配 MIG"}
    previous = device["mig"]["active"]
    device["mig"]["active"] = profile
    device["mig"]["requested"] = profile
    state_sha = _persist_state(ctx)
    return 200, {
        "ok": True,
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "device": device_name,
        "tenant": tenant,
        "previous_profile": previous,
        "active": profile,
        "requested": profile,
        "applied": True,
        "isolation_downgraded": previous != profile,
        "state_sha256": state_sha,
    }


def _gpu_metrics(ctx: _RequestContext):
    if ctx.mode == "fixed":
        err = _gate_read(ctx)
        if err:
            return err
        visible = ctx.tenant
        devices = [d for d in ctx.state["devices"].values() if d["tenant"] == visible]
    else:
        visible = "*"
        devices = list(ctx.state["devices"].values())
    gpus = []
    for d in devices:
        processes = []
        for p in d["pods"]:
            processes.append({
                "pid": 1000 + abs(hash(p["name"])) % 9000,
                "name": p["name"],
                "tenant": p["tenant"],
                "namespace": p["namespace"],
                "model_marker": f"{BENIGN}-MODEL-{p['tenant']}",
            })
        gpus.append({
            "device": d["device"],
            "tenant": d["tenant"],
            "uuid": f"GPU-MOCK-{d['device'].upper()}",
            "utilization_gpu": 71 if d.get("allocation") else 0,
            "memory_used_mib": 40960 if d.get("allocation") else 512,
            "mig_profile": d["mig"]["active"],
            "processes": processes,
        })
    leaked = sorted({p["tenant"] for g in gpus for p in g["processes"]} - ({visible} if visible != "*" else set()))
    return 200, {
        "service": "dcgm-exporter",
        "mode": ctx.mode,
        "tenant_filter": visible,
        "gpus": gpus,
        "leaked_tenants": leaked if ctx.mode == "vulnerable" else [],
    }


def _mps_status(ctx: _RequestContext):
    if ctx.mode == "fixed":
        err = _gate_read(ctx)
        if err:
            return err
        contexts = [c for c in ctx.state["mps"]["contexts"] if c["tenant"] == ctx.tenant]
        shared = False
        cross = False
    else:
        contexts = list(ctx.state["mps"]["contexts"])
        shared = bool(ctx.state["mps"]["shared_pipe"])
        cross = len({c["tenant"] for c in contexts}) > 1
    return 200, {
        "service": "nvidia-mps",
        "mode": ctx.mode,
        "server": ctx.state["mps"]["server"],
        "shared_context": shared,
        "cross_tenant_clients": cross,
        "contexts": contexts,
    }


def _gpu_residue(ctx: _RequestContext):
    device_name = (ctx.query.get("device") or [""])[0]
    wanted_tenant = (ctx.query.get("tenant") or [""])[0]
    wanted_alloc = (ctx.query.get("allocation") or [""])[0]
    device = _device(ctx, device_name)
    if device is None:
        return 404, {"error": "not found", "service": "gpu-pooling", "hint": f"未知设备 {device_name}"}
    if ctx.mode == "fixed":
        err = _gate_read(ctx)
        if err:
            return err
        if device["tenant"] != ctx.tenant:
            return 403, {"error": "forbidden", "service": "gpu-pooling",
                         "hint": "跨租户残留读取被拒"}
    entries = []
    for path in sorted((ctx.root / "gpu" / "residue" / _safe_name(device_name)).glob("*.json")):
        try:
            entry = _read_residue(ctx, path)
        except (OSError, ValueError):
            continue
        if wanted_tenant and entry["tenant"] != wanted_tenant:
            continue
        if wanted_alloc and entry["allocation_id"] != wanted_alloc:
            continue
        entries.append(entry)
    if not entries:
        return 404, {"error": "not found", "service": "gpu-pooling",
                     "hint": "无残留（fixed 释放即清理 / 指定 allocation 不存在）"}
    return 200, {
        "service": "gpu-pooling",
        "mode": ctx.mode,
        "device": device_name,
        "count": len(entries),
        "residue": entries,
    }


# ---------------------------------------------------------------------------
# 云租户面
# ---------------------------------------------------------------------------


def _role(ctx: _RequestContext, name: str) -> dict | None:
    return ctx.state["roles"].get(name)


def _cloud_identity(ctx: _RequestContext):
    name = (ctx.query.get("role") or ["weight-reader"])[0]
    role = _role(ctx, name)
    if role is None:
        return 404, {"error": "not found", "service": "cloud-identity", "hint": f"未知角色 {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, role["tenant"])
        if err:
            return err
    statement = role["trust"]["Statement"][0]
    principal = statement.get("Principal")
    wildcard = principal == "*"
    trusted_accounts = role["trusted_accounts"] if ctx.mode == "fixed" else ["*"]
    return 200, {
        "service": "cloud-identity",
        "mode": ctx.mode,
        "provider": role["provider"],
        "role": role["role"],
        "role_arn": role["arn"],
        "account": role["account"],
        "tenant": role["tenant"],
        "annotations": {
            "eks.amazonaws.com/role-arn": role["arn"],
            "azure.workload.identity/client-id": f"mock-client-{role['tenant']}",
            "iam.gke.io/gcp-service-account": f"weights-{role['tenant']}@mock-project.iam.gserviceaccount.com",
            "rrssa.alibabacloud.com/role-arn": f"acs:ram::{role['account']}:role/weights-{role['tenant']}",
        },
        "trust_policy": role["trust"],
        "wildcard_principal": wildcard,
        "trusted_accounts": trusted_accounts,
        "external_id_required": bool(statement.get("Condition")),
        "cross_account_allowed": wildcard,
        "assume_role_endpoint": "/cloud/identity/assume-role",
        "oidc_subject": f"system:serviceaccount:{role['tenant']}:weights-reader",
    }


def _cloud_assume_role(ctx: _RequestContext):
    name = str(ctx.body.get("role") or ctx.body.get("role_arn") or "weight-reader")
    role = _role(ctx, name)
    if role is None:
        for candidate in ctx.state["roles"].values():
            if candidate["arn"] == name:
                role = candidate
                break
    if role is None:
        return 404, {"error": "not found", "service": "cloud-identity", "hint": f"未知角色 {name}"}
    source = str(ctx.body.get("source_account") or "999999999999")
    external_id = str(ctx.body.get("external_id") or "")
    cross_account = source != role["account"]
    if ctx.mode == "fixed":
        if cross_account:
            return 403, {"error": "forbidden", "service": "cloud-identity",
                         "hint": "trust policy 仅允许同账户主体 AssumeRole"}
        if role["trust"].get("Statement", [{}])[0].get("Condition") and external_id != "inkblade-lab":
            return 403, {"error": "forbidden", "service": "cloud-identity",
                         "hint": "缺少或错误 sts:ExternalId"}
    return 200, {
        "ok": True,
        "assumed": True,
        "service": "cloud-identity",
        "mode": ctx.mode,
        "role_arn": role["arn"],
        "role": role["role"],
        "source_account": source,
        "cross_account": cross_account,
        "session_name": str(ctx.body.get("session_name") or "inkblade-probe"),
        "duration_seconds": 3600,
        "credentials": {
            "AccessKeyId": "MOCKAKIACROSSTENANT0001",
            "SecretAccessKey": "MOCKSECRETCROSSTENANT0001",
            "SessionToken": "MOCKSESSIONCROSSTENANT0001",
            "Expiration": "2030-01-01T00:00:00Z",
        },
    }


def _bucket(ctx: _RequestContext, name: str) -> dict | None:
    return ctx.state["buckets"].get(name)


def _cloud_bucket_policy(ctx: _RequestContext):
    name = (ctx.query.get("bucket") or ["weights-b"])[0]
    bucket = _bucket(ctx, name)
    if bucket is None:
        return 404, {"error": "not found", "service": "cloud-storage", "hint": f"未知桶 {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, bucket["tenant"])
        if err:
            return err
    public = ctx.mode == "vulnerable"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InkBladeMock",
                "Effect": "Allow",
                "Principal": "*" if public else {"AWS": f"arn:aws:iam::{bucket['account']}:root"},
                "Action": ["s3:GetObject", "s3:ListBucket"] if public else ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
            }
        ],
    }
    return 200, {
        "service": "cloud-storage",
        "mode": ctx.mode,
        "provider": bucket["provider"],
        "bucket": name,
        "owner": bucket["tenant"],
        "account": bucket["account"],
        "policy": policy,
        "public": public,
        "cross_tenant_read": public,
        "list_requires_auth": not public,
        "block_public_acls": not public,
        "provider_variants": {
            "s3": "Block Public Access + bucket policy Principal 收敛到账户",
            "oss": "OSS bucket ACL private + RAM policy 仅本账号",
            "cos": "COS 存储桶 ACL 私有 + 跨账号授权需 CAM 角色",
            "blob": "Blob container public access level=None + SAS 最小权限",
        },
    }


def _cloud_bucket_list(ctx: _RequestContext):
    name = (ctx.query.get("bucket") or ["weights-b"])[0]
    prefix = (ctx.query.get("prefix") or [""])[0]
    bucket = _bucket(ctx, name)
    if bucket is None:
        return 404, {"error": "not found", "service": "cloud-storage", "hint": f"未知桶 {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, bucket["tenant"])
        if err:
            return err
    requester = ctx.tenant or "anonymous"
    objects = [o for o in bucket["objects"] if o["key"].startswith(prefix)]
    return 200, {
        "service": "cloud-storage",
        "mode": ctx.mode,
        "bucket": name,
        "bucket_owner": bucket["tenant"],
        "requester": requester,
        "prefix": prefix,
        "object_count": len(objects),
        "objects": objects,
        "cross_tenant": requester != bucket["tenant"],
        "truncated": False,
    }


def _snapshot(ctx: _RequestContext, name: str) -> dict | None:
    return ctx.state["snapshots"].get(name)


def _cloud_snapshot_get(ctx: _RequestContext):
    name = (ctx.query.get("snapshot") or ["snap-weights-b"])[0]
    snap = _snapshot(ctx, name)
    if snap is None:
        return 404, {"error": "not found", "service": "cloud-storage", "hint": f"未知快照 {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, snap["tenant"])
        if err:
            return err
    return 200, {
        "service": "cloud-storage",
        "mode": ctx.mode,
        "snapshot": name,
        "owner": snap["tenant"],
        "account": snap["account"],
        "public": snap["public"],
        "shared_with": list(snap["shared_with"]),
        "cross_account": any(acc != snap["account"] for acc in snap["shared_with"]),
        "snapshot_uri": f"mock://snapshot/{name}",
    }


def _cloud_snapshot_share(ctx: _RequestContext):
    name = str(ctx.body.get("snapshot") or "snap-weights-b")
    target = str(ctx.body.get("target_account") or "999999999999")
    snap = _snapshot(ctx, name)
    if snap is None:
        return 404, {"error": "not found", "service": "cloud-storage", "hint": f"未知快照 {name}"}
    cross = target != snap["account"]
    if ctx.mode == "fixed":
        err = _gate_write(ctx)
        if err:
            return err
        if ctx.tenant != snap["tenant"]:
            return 403, {"error": "forbidden", "service": "cloud-storage",
                         "hint": "仅快照 owner 可共享"}
        if cross:
            return 403, {"error": "forbidden", "service": "cloud-storage",
                         "hint": "禁止共享给外部账户（同账户 allowlist 为空）"}
    if target not in snap["shared_with"]:
        snap["shared_with"].append(target)
    if cross:
        snap["public"] = True
    state_path = ctx.sandbox("cloud", "snapshot-shares.json")
    state_path.write_text(json.dumps(ctx.state["snapshots"], ensure_ascii=False, indent=2),
                          encoding="utf-8")
    return 200, {
        "ok": True,
        "service": "cloud-storage",
        "mode": ctx.mode,
        "snapshot": name,
        "owner": snap["tenant"],
        "target_account": target,
        "shared_with": list(snap["shared_with"]),
        "public": snap["public"],
        "cross_account": cross,
        "snapshot_uri": f"mock://snapshot/{name}",
        "state_sha256": _sha256_bytes(state_path.read_bytes()),
    }


def _cloud_kms_grants(ctx: _RequestContext):
    name = (ctx.query.get("key") or ["weights-key"])[0]
    key = ctx.state["kms"].get(name)
    if key is None:
        return 404, {"error": "not found", "service": "cloud-kms", "hint": f"未知 KMS key {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, key["tenant"])
        if err:
            return err
    vulnerable = ctx.mode == "vulnerable"
    grants = [
        {
            "grant_id": "grant-mock-1",
            "grantee": "*" if vulnerable else f"arn:aws:iam::{key['account']}:root",
            "account": "*" if vulnerable else key["account"],
            "operations": ["Decrypt", "GenerateDataKey", "DescribeKey"] if vulnerable else ["Decrypt"],
            "constraints": {} if vulnerable else {"encryption_context": {"tenant": key["tenant"]}},
        }
    ]
    return 200, {
        "service": "cloud-kms",
        "mode": ctx.mode,
        "key": name,
        "key_arn": f"arn:aws:kms:mock-region:{key['account']}:key/{name}",
        "owner": key["tenant"],
        "grants": grants,
        "wildcard": vulnerable,
        "cross_account": vulnerable,
        "rotation_enabled": not vulnerable,
    }


def _cloud_security_group(ctx: _RequestContext):
    name = (ctx.query.get("group") or ["sg-gpu-nodes"])[0]
    sg = ctx.state["security_groups"].get(name)
    if sg is None:
        return 404, {"error": "not found", "service": "cloud-network", "hint": f"未知安全组 {name}"}
    if ctx.mode == "fixed":
        err = _gate_owner(ctx, sg["tenant"])
        if err:
            return err
    vulnerable = ctx.mode == "vulnerable"
    ingress = (
        [{"proto": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
         {"proto": "tcp", "from_port": 30000, "to_port": 30000, "cidr": "0.0.0.0/0"}]
        if vulnerable else
        [{"proto": "tcp", "from_port": 30000, "to_port": 30000, "cidr": "10.0.0.0/8"}]
    )
    metadata = (
        {"http_tokens": "optional", "http_put_response_hop_limit": 2,
         "endpoint": "enabled", "allowed_from": "0.0.0.0/0"}
        if vulnerable else
        {"http_tokens": "required", "http_put_response_hop_limit": 1,
         "endpoint": "enabled", "allowed_from": "10.0.0.0/8"}
    )
    return 200, {
        "service": "cloud-network",
        "mode": ctx.mode,
        "group": name,
        "owner": sg["tenant"],
        "ingress": ingress,
        "egress": [{"proto": "all", "cidr": "0.0.0.0/0"}] if vulnerable else
                  [{"proto": "tcp", "to_port": 443, "cidr": "10.0.0.0/8"}],
        "metadata_options": metadata,
        "public_ingress": vulnerable,
        "imds_v1_disabled": not vulnerable,
        "imds_reachable_from_internet": vulnerable and metadata["allowed_from"] == "0.0.0.0/0",
        "note": "GPU 节点安全组同时承载 IMDS 与池化管理端口，0.0.0.0/0 入站 + IMDSv1 可选即跨租户凭据面暴露",
    }


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "inkblade-gpu-cloud-lab",
        "mode": ctx.mode,
        "host": HOST,
        "route_count": len(ROUTE_TABLE),
        "admin_token_hint": "fixed 模式平台写操作 = Authorization: Bearer <admin token> + X-Tenant",
        "tenant_tokens_hint": "fixed 模式租户读操作 = Authorization: Bearer <tenant token> + X-Tenant",
        "tenant_accounts": dict(TENANT_ACCOUNTS),
        "routes": [{k: v for k, v in entry.items() if k != "behavior"} for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 状态初始化（vulnerable / fixed 两套种子）
# ---------------------------------------------------------------------------


def _seed_state(mode: str, root: Path) -> dict:
    vulnerable = mode == "vulnerable"
    pods_a = [{"name": "vllm-a", "namespace": "ns-a-infer", "tenant": "tenant-a",
               "allocation_id": "alloc-seed-a"}]
    if vulnerable:
        pods_a.append({"name": "notebook-a", "namespace": "ns-a-dev", "tenant": "tenant-a",
                       "allocation_id": "alloc-seed-a"})
    devices = {
        "gpu-a-0": {
            "device": "gpu-a-0", "pool": "pool-a", "scheduler": "hami", "tenant": "tenant-a",
            "allocation": "alloc-seed-a",
            "mig": {"active": "1g.10gb", "requested": "1g.10gb"},
            "pods": pods_a, "mps_shared": vulnerable,
        },
        "gpu-a-1": {
            "device": "gpu-a-1", "pool": "pool-a", "scheduler": "hami", "tenant": "tenant-a",
            "allocation": None,
            "mig": {"active": "3g.40gb", "requested": "3g.40gb"},
            "pods": [], "mps_shared": False,
        },
        "gpu-b-0": {
            "device": "gpu-b-0", "pool": "pool-b", "scheduler": "orionx", "tenant": "tenant-b",
            "allocation": "alloc-seed-b",
            "mig": {"active": "1g.10gb", "requested": "1g.10gb"},
            "pods": [{"name": "trainer-b", "namespace": "ns-b-train", "tenant": "tenant-b",
                      "allocation_id": "alloc-seed-b"}],
            "mps_shared": vulnerable,
        },
        "gpu-b-1": {
            "device": "gpu-b-1", "pool": "pool-b", "scheduler": "orionx", "tenant": "tenant-b",
            "allocation": None,
            "mig": {"active": "3g.40gb" if vulnerable else "1g.10gb",
                    "requested": "1g.10gb" if vulnerable else "1g.10gb"},
            "pods": [], "mps_shared": False,
        },
    }
    allocations = {
        "alloc-seed-a": {
            "allocation_id": "alloc-seed-a", "device": "gpu-a-0", "tenant": "tenant-a",
            "namespace": "ns-a-infer", "mig_profile": "1g.10gb", "mps": True,
            "marker": f"{BENIGN}-MODEL-A-SEED", "process": "vllm-a", "status": "active",
            "created_at": _utcnow_iso(),
        },
        "alloc-seed-b": {
            "allocation_id": "alloc-seed-b", "device": "gpu-b-0", "tenant": "tenant-b",
            "namespace": "ns-b-train", "mig_profile": "1g.10gb", "mps": True,
            "marker": f"{BENIGN}-MODEL-B-SEED", "process": "trainer-b", "status": "active",
            "created_at": _utcnow_iso(),
        },
    }
    if vulnerable:
        mps_contexts = [
            {"context_id": "ctx-a1", "client": "vllm-a", "pid": 4101, "tenant": "tenant-a",
             "namespace": "ns-a-infer", "pipe": "/tmp/nvidia-mps/pipe-0", "active": True},
            {"context_id": "ctx-b1", "client": "trainer-b", "pid": 4202, "tenant": "tenant-b",
             "namespace": "ns-b-train", "pipe": "/tmp/nvidia-mps/pipe-0", "active": True},
        ]
    else:
        mps_contexts = [
            {"context_id": "ctx-a1", "client": "vllm-a", "pid": 4101, "tenant": "tenant-a",
             "namespace": "ns-a-infer", "pipe": "/tmp/nvidia-mps/pipe-a", "active": True},
            {"context_id": "ctx-b1", "client": "trainer-b", "pid": 4202, "tenant": "tenant-b",
             "namespace": "ns-b-train", "pipe": "/tmp/nvidia-mps/pipe-b", "active": True},
        ]
    trust_vulnerable = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }],
    }
    trust_fixed = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "inkblade-lab"}},
        }],
    }
    roles = {
        "weight-reader": {
            "role": "weight-reader",
            "arn": "arn:aws:iam::222222222222:role/weight-reader",
            "account": "222222222222",
            "tenant": "tenant-b",
            "provider": "aws",
            "trust": trust_vulnerable if vulnerable else trust_fixed,
            "trusted_accounts": ["*"] if vulnerable else ["222222222222"],
        },
        "trainer-a": {
            "role": "trainer-a",
            "arn": "arn:aws:iam::111111111111:role/trainer-a",
            "account": "111111111111",
            "tenant": "tenant-a",
            "provider": "aws",
            "trust": trust_vulnerable if vulnerable else {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "trusted_accounts": ["*"] if vulnerable else ["111111111111"],
        },
    }
    objects_b = [
        {"key": "tenant-b/model.safetensors", "size": 4096, "tenant": "tenant-b",
         "sha256": _sha256_text(f"{BENIGN}-WEIGHTS-B"), "last_modified": "2026-10-20T00:00:00Z"},
        {"key": "tenant-b/checkpoint-00001.safetensors", "size": 8192, "tenant": "tenant-b",
         "sha256": _sha256_text(f"{BENIGN}-CKPT-B"), "last_modified": "2026-10-21T00:00:00Z"},
        {"key": "tenant-b/tokenizer.json", "size": 512, "tenant": "tenant-b",
         "sha256": _sha256_text(f"{BENIGN}-TOKENIZER-B"), "last_modified": "2026-10-21T00:00:00Z"},
    ]
    buckets = {
        "weights-b": {
            "bucket": "weights-b", "tenant": "tenant-b", "account": "222222222222",
            "provider": "s3", "objects": objects_b,
        },
        "weights-a": {
            "bucket": "weights-a", "tenant": "tenant-a", "account": "111111111111",
            "provider": "oss", "objects": [
                {"key": "tenant-a/model.safetensors", "size": 1024, "tenant": "tenant-a",
                 "sha256": _sha256_text(f"{BENIGN}-WEIGHTS-A"), "last_modified": "2026-10-19T00:00:00Z"},
            ],
        },
    }
    snapshots = {
        "snap-weights-b": {
            "snapshot": "snap-weights-b", "tenant": "tenant-b", "account": "222222222222",
            "public": vulnerable,
            "shared_with": ["999999999999"] if vulnerable else [],
        }
    }
    kms = {
        "weights-key": {"key": "weights-key", "tenant": "tenant-b", "account": "222222222222"},
    }
    security_groups = {
        "sg-gpu-nodes": {"group": "sg-gpu-nodes", "tenant": "tenant-b"},
    }
    state = {
        "devices": devices,
        "allocations": allocations,
        "mps": {"server": "/tmp/nvidia-mps", "shared_pipe": vulnerable, "contexts": mps_contexts},
        "roles": roles,
        "buckets": buckets,
        "snapshots": snapshots,
        "kms": kms,
        "security_groups": security_groups,
        "revision": 0,
    }
    # 种子残留：真实落盘，供释放后/跨租户读回对照。
    for alloc_id in ("alloc-seed-a", "alloc-seed-b"):
        allocation = allocations[alloc_id]
        path = root / "gpu" / "residue" / _safe_name(allocation["device"]) / f"{alloc_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "benign_marker": allocation["marker"],
            "marker_sha256": _sha256_text(allocation["marker"]),
            "model_marker": allocation["marker"],
            "device": allocation["device"],
            "tenant": allocation["tenant"],
            "namespace": allocation["namespace"],
            "allocation_id": alloc_id,
            "process": allocation["process"],
            "released": False,
            "retained": False,
            "created_at": allocation["created_at"],
            "updated_at": _utcnow_iso(),
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return state


# ---------------------------------------------------------------------------
# 路由表
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "gpu-pooling", "title": "GPU 池/设备清单", "method": "GET", "path": "/gpu/pools",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：无鉴权全租户可见；fixed：租户 token + 过滤", "behavior": _gpu_pools},
    {"service": "gpu-pooling", "title": "GPU 分配/迁移", "method": "POST", "path": "/gpu/allocate",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable：无鉴权可覆盖他租户分配并迁移；fixed：admin+租户校验/409", "behavior": _gpu_allocate},
    {"service": "gpu-pooling", "title": "GPU 释放", "method": "POST", "path": "/gpu/release",
     "vulnerable": 404, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable：释放留残留；fixed：admin+租户校验并清理残留", "behavior": _gpu_release},
    {"service": "gpu-pooling", "title": "MIG 档位清单", "method": "GET", "path": "/gpu/mig/profiles",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：请求/生效档位不一致可见；fixed：租户过滤", "behavior": _mig_profiles},
    {"service": "gpu-pooling", "title": "MIG 在线重配", "method": "POST", "path": "/gpu/mig/profiles",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable：无鉴权任意重配（含已分配设备）；fixed：admin+租户+409", "behavior": _mig_reconfigure},
    {"service": "gpu-pooling", "title": "DCGM 风格指标", "method": "GET", "path": "/gpu/metrics",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：进程名/租户标签全量；fixed：租户过滤", "behavior": _gpu_metrics},
    {"service": "gpu-pooling", "title": "MPS context 状态", "method": "GET", "path": "/gpu/mps/status",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：跨租户共享 MPS pipe；fixed：租户隔离", "behavior": _mps_status},
    {"service": "gpu-pooling", "title": "释放后残留读回", "method": "GET", "path": "/gpu/residue",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：MIG/MPS 释放后 benign marker 可读；fixed：清理后 404", "behavior": _gpu_residue},
    {"service": "cloud-identity", "title": "云身份联邦与 trust policy", "method": "GET", "path": "/cloud/identity",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "IRSA/RRSA/WorkloadIdentity 注解 + trust policy 通配差分", "behavior": _cloud_identity},
    {"service": "cloud-identity", "title": "跨账户 AssumeRole", "method": "POST", "path": "/cloud/identity/assume-role",
     "vulnerable": 200, "fixed": 403, "gate": "open", "writes": False,
     "description": "vulnerable：通配 Principal 跨账户假设成功；fixed：仅同账户+ExternalId", "behavior": _cloud_assume_role},
    {"service": "cloud-storage", "title": "桶策略", "method": "GET", "path": "/cloud/bucket/policy",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "S3/OSS/COS/Blob 桶策略：public/跨租户 vs 最小策略", "behavior": _cloud_bucket_policy},
    {"service": "cloud-storage", "title": "桶列目录", "method": "GET", "path": "/cloud/bucket/list",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：匿名/跨租户列目录；fixed：仅 owner", "behavior": _cloud_bucket_list},
    {"service": "cloud-storage", "title": "快照共享清单", "method": "GET", "path": "/cloud/snapshot/share",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：public/跨账户共享可见；fixed：仅 owner", "behavior": _cloud_snapshot_get},
    {"service": "cloud-storage", "title": "快照共享", "method": "POST", "path": "/cloud/snapshot/share",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable：共享给任意账户；fixed：仅同账户 allowlist", "behavior": _cloud_snapshot_share},
    {"service": "cloud-kms", "title": "KMS grants", "method": "GET", "path": "/cloud/kms/grants",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：Principal '*' + 宽操作；fixed：最小权限+encryption context", "behavior": _cloud_kms_grants},
    {"service": "cloud-network", "title": "安全组与 IMDS 选项", "method": "GET", "path": "/cloud/security-group",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable：0.0.0.0/0 入站 + IMDSv1 + hop limit 2；fixed：内网+IMDSv2", "behavior": _cloud_security_group},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "返回本清单 JSON（供测试与利用模块发现）", "behavior": _routes_manifest},
]

_METHODS = ("GET", "POST", "PUT")
_EXACT_ROUTES: dict[tuple[str, str], dict] = {}
for _entry in ROUTE_TABLE:
    _EXACT_ROUTES.setdefault((_entry["method"], _entry["path"].rstrip("/") or "/"), _entry)


def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


class _LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, root: Path):
        super().__init__(address, _LabHandler)
        self.lab_mode = mode
        self.lab_root = root
        self.lab_lock = threading.RLock()
        self.lab_state = _seed_state(mode, root)


class _LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeGpuCloudLab/0.1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, payload):
        body = (payload.encode("utf-8") if isinstance(payload, str)
                else json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        content_type = ("text/plain; charset=utf-8" if isinstance(payload, str)
                        else "application/json; charset=utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"_raw": raw.decode("utf-8", "replace")}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _EXACT_ROUTES.get((method, norm))
        if entry is None:
            if any((other, norm) in _EXACT_ROUTES for other in _METHODS if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _LabHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            root=server.lab_root,
            state=server.lab_state,
            lock=server.lab_lock,
            headers=self.headers,
            body=self._read_body() if method in ("POST", "PUT") else {},
            path=split.path,
            query=parse_qs(split.query),
            entry=entry,
        )
        try:
            with server.lab_lock:
                outcome = entry["behavior"](ctx)
        except Exception as exc:  # 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"], "detail": str(exc)})
            return
        status, payload = outcome[0], outcome[1]
        self._send(status, payload)


# ---------------------------------------------------------------------------
# Server 句柄与启动入口
# ---------------------------------------------------------------------------


class Server:
    """仿真靶场句柄：.port/.mode/.root + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _LabHTTPServer, thread: threading.Thread, mode: str, root: Path, owns_root: bool):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self.root = root
        self._owns_root = owns_root
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{key: value for key, value in entry.items() if key != "behavior"} for entry in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join(timeout=5)
        finally:
            if self._owns_root:
                shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE, root: Path | str | None = None) -> Server:
    """启动全部 GPU 池化/云租户 mock 路由（单服务器，仅 127.0.0.1）。"""
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    if root is None:
        root_path = Path(tempfile.mkdtemp(prefix="inkblade-gpu-cloud-lab-"))
        owns_root = True
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        owns_root = False
    httpd = _LabHTTPServer((HOST, int(port)), mode, root_path)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode, root_path, owns_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade GPU 池化/云租户仿真靶场（仅监听 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    parser.add_argument("--root", default=None, help="sandbox 根目录（缺省临时目录，退出时清理）")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, root=args.root)
    print(f"gpu/cloud lab: {server.url('/')} mode={server.mode} root={server.root}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭 GPU/云仿真靶场…")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
