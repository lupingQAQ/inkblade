"""GPU 租户残留 — 池化/MIG/MPS 释放后显存快照（benign marker）跨租户可读。

检测面：
1) GET /gpu/residue?device=gpu-b-0&tenant=tenant-b 以 tenant-a 身份读取他租户残留；
2) backup-write 下在自有设备分配 → 写入 benign marker → 释放 → 读回，断言 marker sha256
   与残留文件 sha256 一致且 released=true（释放后仍可读）。
fixed：租户过滤 + 释放即删除残留（读回 404）。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, benign_marker, detail, ok, read_headers, resolve_mode, resp, sha256_text,
    write_headers,
)

KEY = "gpu-tenant-residue"
WRITES = True


def _residue_entry(payload: dict) -> dict:
    entries = payload.get("residue") or []
    return entries[0] if entries else {}


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    victim = str(params.get("victim_tenant") or "tenant-b")
    victim_device = str(params.get("device") or "gpu-b-0")
    own_device = str(params.get("own_device") or "gpu-a-1")
    marker = benign_marker(ctx, "RESIDUE")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    victim_read = t.call(
        "GET", f"{base}/gpu/residue?device={victim_device}&tenant={victim}",
        headers=read_headers(params))
    victim_entry = _residue_entry(resp(victim_read))
    if ok(victim_read) and victim_entry:
        findings.append({
            "sev": "high",
            "title": "GPU 显存快照残留跨租户可读（他租户模型数据）",
            "detail": detail({
                "route": "/gpu/residue",
                "http_status": victim_read.get("status"),
                "requester_tenant": tenant,
                "victim_tenant": victim,
                "device": victim_device,
                "residue_allocation": victim_entry.get("allocation_id", ""),
                "marker": victim_entry.get("marker", ""),
                "marker_sha256": victim_entry.get("marker_sha256", ""),
                "model_marker": victim_entry.get("model_marker", ""),
                "process": victim_entry.get("process", ""),
                "residue_file": victim_entry.get("residue_file", ""),
                "residue_file_sha256": victim_entry.get("file_sha256", ""),
                "readable_after_release": bool(victim_entry.get("readable_after_release")),
                "note": "MIG/MPS 释放未清理显存快照：残留含他租户进程名与模型 benign marker",
            }),
        })

    allocation = {}
    release = {}
    readback = {}
    readback_entry = {}
    if mode == "backup-write":
        allocation = t.call("POST", f"{base}/gpu/allocate", {
            "tenant": tenant,
            "device": own_device,
            "namespace": str(params.get("namespace") or f"ns-{tenant}-infer"),
            "marker": marker,
            "process": f"trident-residue-{tenant}",
        }, headers=write_headers(params))
        alloc_payload = resp(allocation)
        if ok(allocation):
            release = t.call("POST", f"{base}/gpu/release", {
                "tenant": tenant,
                "allocation_id": alloc_payload.get("allocation_id", ""),
            }, headers=write_headers(params))
            readback = t.call(
                "GET",
                f"{base}/gpu/residue?device={own_device}&allocation={alloc_payload.get('allocation_id', '')}",
                headers=read_headers(params))
            readback_entry = _residue_entry(resp(readback))
            expected = sha256_text(marker)
            if ok(readback) and readback_entry:
                after_release = bool(readback_entry.get("readable_after_release"))
                sha_ok = readback_entry.get("marker_sha256") == expected
                findings.append({
                    "sev": "high" if after_release and sha_ok else "medium",
                    "title": "GPU 释放后残留 marker 写读回成功（含释放后读取 + sha256 一致）",
                    "detail": detail({
                        "route": "/gpu/allocate → /gpu/release → /gpu/residue",
                        "allocate_status": allocation.get("status"),
                        "release_status": release.get("status"),
                        "readback_status": readback.get("status"),
                        "allocation_id": alloc_payload.get("allocation_id", ""),
                        "tenant": tenant,
                        "device": own_device,
                        "marker": marker,
                        "marker_sha256": expected,
                        "server_marker_sha256": readback_entry.get("marker_sha256", ""),
                        "marker_sha256_match": sha_ok,
                        "readback_after_release": after_release,
                        "readback_file_sha256": readback_entry.get("file_sha256", ""),
                        "residue_file_sha256": resp(release).get("residue_sha256", ""),
                        "residue_file": readback_entry.get("residue_file", ""),
                        "victim_tenant": victim,
                        "note": "释放后显存快照未清零：benign marker 写读回 + 哈希一致即残留可读",
                    }),
                })
            elif readback.get("status") == 404:
                note = (note + "；" if note else "") + "residue_cleanup（fixed 释放即清理，读回 404）"

    artifact = t.dump()
    summary = (f"victim_residue={victim_read.get('status')} "
               f"own_allocate={allocation.get('status', '-')} "
               f"own_release={release.get('status', '-')} "
               f"readback={readback.get('status', '-')} findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
