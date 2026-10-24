# -*- coding: utf-8 -*-
"""多网卡与 RDMA 旁路（spec 5.2 网络架构模块 / 5.6 CNI 与 Overlay 层）。

Multus 附件、SR-IOV VF / RDMA shared device / IB device plugin、Pod 多网卡绑定 →
「NetworkPolicy 不覆盖路径」清单实证：SR-IOV VF/IB/macvlan/host-device 流量
不经 CNI 策略执行点，即使策略覆盖该 Pod 也构成旁路边。
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


_BYPASS_REASON = {
    "sriov": "SR-IOV VF 流量经硬件直通，不经 CNI/NetworkPolicy 策略执行点",
    "infiniband": "IB VF/RDMA 流量无 NetworkPolicy 执行点（fabric 层仅 SM/Partition 可隔离）",
    "host-device": "host-device 直接把宿主接口移入 Pod netns，策略栈不可见",
    "macvlan": "macvlan 桥接宿主网卡，绕过 overlay 与策略链",
    "ib": "IB/RDMA 流量无 NetworkPolicy 执行点",
}


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    items = snap.get("items", [])
    pods: list[dict] = []
    policies: list[dict] = []
    nads: list[dict] = []
    daemonsets: list[dict] = []
    for item in items:
        kind = item.get("kind", "")
        if kind == "Pod":
            pods.append(item)
        elif kind == "NetworkPolicy":
            policies.append(item)
        elif kind == "NetworkAttachmentDefinition":
            nads.append(item)
        elif kind == "DaemonSet":
            daemonsets.append(item)
    pods += list(snap.get("pods", []))

    findings: list[dict] = []
    fps: dict = {}

    # --- 解析 net-attach-def ---
    defs: dict[str, dict] = {}
    for nad in nads:
        meta = nad.get("metadata", {}) or {}
        name = str(meta.get("name", ""))
        ns = str(meta.get("namespace", "default"))
        try:
            cfg = json.loads((nad.get("spec", {}) or {}).get("config", "{}"))
        except (json.JSONDecodeError, TypeError):
            cfg = {}
        ctype = str(cfg.get("type", ""))
        if cfg.get("deviceType") == "infiniband":
            ctype = "infiniband"
        defs[f"{ns}/{name}"] = {
            "type": ctype,
            "rdma": bool(cfg.get("rdma")) or "rdma" in str(meta.get("annotations", {})).lower()
            or str(cfg.get("deviceName", "")).endswith("hca"),
            "ns": ns, "name": name,
        }

    # --- Pod 多网卡绑定 → 未覆盖路径 ---
    uncovered: list[dict] = []
    for pod in pods:
        meta = pod.get("metadata", {}) or {}
        ann = meta.get("annotations", {}) or {}
        ns = str(meta.get("namespace", "default"))
        raw = ann.get("k8s.v1.cni.cncf.io/networks", "")
        if not raw:
            continue
        for ref in [r.strip() for r in raw.split(",") if r.strip()]:
            key = ref if "/" in ref else f"{ns}/{ref}"
            d = defs.get(key, {"type": "unknown", "rdma": False, "ns": ns, "name": ref})
            covered_here = any(
                str((p.get("metadata", {}) or {}).get("namespace", "")) == ns for p in policies
            )
            uncovered.append({
                "pod": str(meta.get("name", "?")), "namespace": ns,
                "network": ref, "cni_type": d["type"], "rdma": d["rdma"],
                "policy_in_namespace": covered_here,
                "reason": _BYPASS_REASON.get(d["type"], "附加接口流量不经主 CNI 策略执行点"),
            })

    if uncovered:
        types = sorted({u["cni_type"] for u in uncovered})
        fps.update({
            "multus": True, "sriov": any(u["cni_type"] == "sriov" for u in uncovered),
            "rdma": any(u["rdma"] or u["cni_type"] in ("infiniband", "ib") for u in uncovered),
            "sriov-attachment": any(u["cni_type"] == "sriov" for u in uncovered),
            "ib-attachment": any(u["cni_type"] in ("infiniband", "ib") for u in uncovered),
            "network-policy-coverage": any(u["policy_in_namespace"] for u in uncovered),
            "hostdevice-attachment": any(u["cni_type"] == "host-device" for u in uncovered),
            "macvlan-attachment": any(u["cni_type"] == "macvlan" for u in uncovered),
        })
        findings.append(_finding(
            "high", "NetworkPolicy 不覆盖路径清单（Multus/SR-IOV/RDMA 旁路）",
            "以下 Pod↔网络路径不受 NetworkPolicy 约束（spec 5.6：SR-IOV VF/IB/macvlan/host-device "
            "流量不经 CNI 策略执行点；即使策略覆盖该 Pod，附件接口仍构成旁路边）：\n"
            + json.dumps(uncovered, ensure_ascii=False, indent=2),
            fps,
            combo=("multus-sriov-rdma-bypass", "areal-sglang-nccl-rdma-flatnet", "ib-flatnet-no-partition")))

    # --- 设备插件 / 旁路基座在位证据 ---
    plugin_pods = [p for p in pods if any(
        k in str((p.get("metadata", {}) or {}).get("name", "")).lower()
        for k in ("sriov", "rdma", "ib-kubernetes", "multus"))]
    if plugin_pods:
        fps["sriov-operator"] = any("sriov" in str(p.get("metadata", {}).get("name", "")).lower() for p in plugin_pods)
        fps["rdma-device-plugin"] = any("rdma" in str(p.get("metadata", {}).get("name", "")).lower() for p in plugin_pods)
        fps["ib-kubernetes"] = any("ib-kubernetes" in str(p.get("metadata", {}).get("name", "")).lower() for p in plugin_pods)
        findings.append(_finding(
            "info", "旁路基座在位：SR-IOV/RDMA device plugin 与 ib-kubernetes",
            "设备插件/ib-kubernetes 在位：附件能力可达工作负载。Pod："
            + ", ".join(sorted(str(p.get("metadata", {}).get("name", "?")) for p in plugin_pods)),
            {k: fps.get(k, False) for k in ("sriov-operator", "rdma-device-plugin", "ib-kubernetes", "multus")}))

    if not uncovered:
        findings.append(_finding(
            "info", "未发现 Multus 附件路径",
            "快照内未发现带 k8s.v1.cni.cncf.io/networks 注解的 Pod。", {"multus": False}))

    artifacts = _artifact(ctx, "rdma-bypass-paths.json", {
        "net_attach_defs": list(defs.values()), "uncovered_paths": uncovered,
        "fingerprints": fps,
    })
    return {
        "summary": f"Multus/RDMA 旁路：附件定义 {len(defs)}，未覆盖路径 {len(uncovered)}",
        "artifacts": artifacts,
        "findings": findings,
    }
