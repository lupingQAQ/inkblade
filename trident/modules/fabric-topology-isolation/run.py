# -*- coding: utf-8 -*-
"""Fabric 拓扑与隔离测绘（spec 5.2 网络架构模块 / 5.6 物理 Fabric 层）。

IB/RoCE/EFA/NVLink 拓扑识别：rail/plane 对齐、双平面、SM/Partition 线索、
IMEX ComputeDomain 资源；IB 无认证可达面。输入 params.snapshot（fixture dict
或 lab/fixtures/network/ 路径）→ 指纹 → findings（含 combo 线索字段）。
"""

from __future__ import annotations

import json
from pathlib import Path


def _merge_file(merged: dict, stem: str, data) -> None:
    if isinstance(data, dict):
        kind = str(data.get("kind", ""))
        if kind.endswith("List"):  # PodList/NetworkPolicyList/... 项缺 kind → 补单数 kind
            for it in data.get("items", []) or []:
                if isinstance(it, dict) and not it.get("kind"):
                    it["kind"] = kind[:-4]
        merged.setdefault("_sources", {})[stem] = data
        for k, v in data.items():
            if k in merged and isinstance(merged[k], list) and isinstance(v, list):
                merged[k] = merged[k] + v
            elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k].update(v)
            else:
                merged[k] = v
    elif isinstance(data, list):
        merged["items"] = merged.get("items", []) + data


def _load_snapshot(params: dict) -> dict:
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 lab/fixtures/network/ 路径）")
    if isinstance(snap, dict):
        return snap
    paths = snap if isinstance(snap, (list, tuple)) else [snap]
    merged: dict = {}
    for raw in paths:
        p = Path(str(raw))
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            _merge_file(merged, f.stem, json.loads(f.read_text(encoding="utf-8")))
    return merged


def _artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run")
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def _finding(sev: str, title: str, detail: str, fps: dict, combo=()) -> dict:
    f = {"sev": sev, "title": title, "detail": detail,
         "fingerprints": {k: bool(v) for k, v in fps.items()},
         "combo": list(combo)}
    tail = " ||fingerprints=" + json.dumps(f["fingerprints"], sort_keys=True, ensure_ascii=False)
    if combo:
        tail += " ||combo=" + ",".join(combo)
    f["detail"] += tail
    return f


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    items = snap.get("items", [])
    findings: list[dict] = []
    fps: dict = {}

    nodes = snap.get("nodes", [])
    ib_fabric = snap.get("ib_fabric", {}) or {}
    hca_inventory = {
        n.get("name", "?"): (n.get("annotations", {}) or {}).get("fabric.hca.inventory", "")
        for n in nodes if isinstance(n, dict)
    }
    has_ib = "infiniband" in str(ib_fabric.get("type", "")).lower() or any(
        ":ib" in inv for inv in hca_inventory.values()
    )
    roce = bool((snap.get("roce") or {}).get("present"))
    efa = bool((snap.get("efa") or {}).get("present"))
    nvlink = snap.get("nvlink", {}) or {}

    # --- IB 无认证可达面（SM/Partition 是唯一隔离手段） ---
    partitions = ib_fabric.get("partitions") or []
    if has_ib:
        fps["ib-fabric"] = True
        if partitions:
            fps["ib-partition"] = True
            findings.append(_finding(
                "info", "IB Partition 已配置",
                f"IB Fabric 检测到 {len(partitions)} 个 Partition（SM 隔离在位）。Partition 清单："
                + json.dumps(partitions, ensure_ascii=False),
                {"ib-fabric": True, "ib-partition": True},
                combo=("ib-flatnet-no-partition",)))
        else:
            fps["ib-no-partition"] = True
            findings.append(_finding(
                "high", "IB Fabric 无 Partition：无认证可达面",
                "IB/RDMA 无内建认证，SM/Partition 是唯一隔离手段。未配置 Partition 时仅默认 "
                "pkey 0xffff 全网互通：fabric 内任意 HCA 可直接对任意 rank 发起 RDMA 读写。"
                f"SM masters={ib_fabric.get('sm', {}).get('masters', [])}；"
                f"带 IB HCA 的节点：{[n for n, v in hca_inventory.items() if ':ib' in v]}",
                {"ib-fabric": True, "ib-no-partition": True, "ib-partition": False},
                combo=("ib-flatnet-no-partition", "nccl-collective-join")))
    if roce:
        fps["roce-fabric"] = True
    if efa:
        fps["efa-fabric"] = True

    # --- NVLink/NVSwitch 节点内域 ---
    if nvlink.get("present"):
        fps["nvl-host"] = True
        findings.append(_finding(
            "info", "NVLink/NVSwitch 节点内 Fabric 域",
            "节点内 NVLink/NVSwitch 域：同一信任域内 GPU-P2P 无网络层隔离（与跨节点 IB 域边界不同，"
            "报告须分别标注层级）。",
            {"nvl-host": True},
            combo=("nvl-dra-imex-domain",)))

    # --- rail/plane 对齐与双平面 ---
    rails: dict[str, str] = {}
    planes: set[str] = set()
    for n in nodes:
        labels = (n.get("labels", {}) or {})
        rail = next((v for k, v in labels.items() if k.startswith("topology.rail")), "")
        plane = next((v for k, v in labels.items() if k.endswith("plane")), "")
        if rail:
            rails[str(n.get("name", "?"))] = rail
        if plane:
            planes.add(plane)
    if rails:
        fps["rail-topology"] = True
        findings.append(_finding(
            "info", "rail/plane 拓扑映射",
            "rail 对齐映射：" + json.dumps(rails, ensure_ascii=False)
            + "；plane 集合：" + json.dumps(sorted(planes), ensure_ascii=False)
            + "。rail 拓扑决定 fabric 可达对（spec 5.6 物理 Fabric 层）。",
            {"rail-topology": True}))
        if len(planes) >= 2:
            fps["dual-plane"] = True
            findings.append(_finding(
                "medium", "双平面共址：单一信任域",
                "检测到双平面（" + "、".join(sorted(planes)) + "）。双平面通常为带宽冗余而非隔离边界："
                "平面间共享同一 Pod 身份与集合通信组，不能当作隔离域。",
                {"dual-plane": True, "rail-topology": True}))
    misaligned = [n for n, r in rails.items() if not hca_inventory.get(n)]
    if misaligned:
        fps["rail-mismatch"] = True
        findings.append(_finding(
            "medium", "rail 与 HCA 资源错配",
            "以下节点声明了 rail 标签但无 IB HCA 清单（拓扑错配会导致集合通信落在错误 rail、"
            "绕开既定可达对设计）：" + ", ".join(misaligned),
            {"rail-mismatch": True, "rail-topology": True}))

    # --- DRA / IMEX ComputeDomain ---
    compute_domains = [i for i in items if i.get("kind") == "ComputeDomain"]
    dra_objs = [i for i in items if i.get("kind") in ("ResourceSlice", "ResourceClaim")]
    if compute_domains or dra_objs:
        if compute_domains:
            fps["computedomain"] = True
        if dra_objs:
            fps["dra"] = True
        members = [m.get("name") for cd in compute_domains for m in cd.get("spec", {}).get("members", [])]
        findings.append(_finding(
            "medium", "IMEX/ComputeDomain 跨节点 GPU 内存域无网络隔离",
            f"ComputeDomain={len(compute_domains)}（成员 {members}）；DRA ResourceSlice/Claim={len(dra_objs)}。"
            "IMEX/ComputeDomain 把多节点 GPU 内存并为一个域，域内越权访问缺乏网络层隔离"
            "（spec 5.6 + 12.1 ComputeDomain/IMEX 指南）。",
            {"computedomain": bool(compute_domains), "dra": bool(dra_objs),
             "nvl-host": bool(nvlink.get("present"))},
            combo=("nvl-dra-imex-domain",)))

    # --- 基线 finding（无 IB 时也有测绘结论） ---
    findings.append(_finding(
        "info", "Fabric 测绘基线",
        f"节点 {len(nodes)}；fabric 类型：{'IB ' if has_ib else ''}{'RoCE ' if roce else ''}"
        f"{'EFA ' if efa else ''}{'NVLink ' if nvlink.get('present') else ''}"
        f"{'（无）' if not (has_ib or roce or efa or nvlink.get('present')) else ''}；"
        f"Partition {len(partitions)} 个。",
        {"fabric-mapped": True, "ib-fabric": has_ib, "roce-fabric": roce, "efa-fabric": efa}))

    artifacts = _artifact(ctx, "fabric-topology.json", {
        "nodes": nodes, "ib_fabric": ib_fabric,
        "rails": rails, "planes": sorted(planes),
        "compute_domains": compute_domains, "dra": dra_objs, "fingerprints": fps,
    })
    return {
        "summary": f"Fabric 测绘：节点 {len(nodes)}，rail {len(rails)}，plane {len(planes)}，"
                   f"IB={'有' if has_ib else '无'}，Partition={len(partitions)}",
        "artifacts": artifacts,
        "findings": findings,
    }
