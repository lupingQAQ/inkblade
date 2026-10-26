# -*- coding: utf-8 -*-
"""CNI 栈与策略能力矩阵（spec 5.2 网络架构模块 / 5.6 CNI 与 Overlay 层）。

CNI 类型与版本识别 → per-CNI 策略能力矩阵（artifact JSON）→
hostNetwork/hostDevice/Multus 旁路清单 + VPC 安全组双控制面错配。
策略语义按 CNI 不同：不得把「有 NetworkPolicy」等同于「隔离有效」。
"""

from __future__ import annotations

import json
import re
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


def _pods(snap: dict) -> list[dict]:
    pods: list[dict] = list(snap.get("pods", [])) + list(snap.get("csi_pods", []))
    for item in snap.get("items", []):
        if isinstance(item, dict) and item.get("kind") == "Pod":
            pods.append(item)
    return pods


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


# per-CNI 策略能力矩阵（静态基线，随 CNI 版本演进维护）
CAPABILITY_BASE = {
    "calico": {
        "network-policy": True, "policy-scope": "L3-L4（GlobalNetworkPolicy 可达 host endpoint）",
        "host-network-policy": "支持（host endpoint 策略，默认未启用）",
        "encryption": "可选 wireguard/ipsec（默认关）",
        "sriov-enforcement": False, "multus-aware": "部分（不约束 VF/secondary 接口流量）",
        "vpc-native": False, "default-deny": "否（默认全通，需显式配置）",
    },
    "cilium": {
        "network-policy": True, "policy-scope": "L3-L7（eBPF）",
        "host-network-policy": "支持（host firewall，默认未启用）",
        "encryption": "可选 ipsec/wireguard（默认关）",
        "sriov-enforcement": False, "multus-aware": "部分（多接口策略语义不完整）",
        "vpc-native": False, "default-deny": "否（默认全通）",
    },
    "terway": {
        "network-policy": "部分（依赖 terway 策略组件）", "policy-scope": "L3-L4（ENI 直通）",
        "host-network-policy": "不支持",
        "encryption": "依赖 VPC/ENI 层",
        "sriov-enforcement": False, "multus-aware": "否",
        "vpc-native": True, "default-deny": "否（安全组默认放行集群内）",
        "dual-control-plane": "VPC 安全组与 NetworkPolicy 双控制面，互不感知",
    },
    "multus": {
        "network-policy": False, "policy-scope": "meta-CNI：仅附加接口，无策略执行点",
        "host-network-policy": "不适用", "encryption": "不适用",
        "sriov-enforcement": False, "multus-aware": "本尊",
        "vpc-native": False, "default-deny": "不适用",
    },
}

_DETECTORS = (
    ("calico", ("calico/node", "calico-node")),
    ("cilium", ("cilium:v", "cilium/cilium", "cilium-operator")),
    ("flannel", ("flannel",)),
    ("multus", ("multus",)),
    ("terway", ("terway",)),
    ("eks-vpc-cni", ("aws-vpc-cni", "aws-node")),
    ("tke-vpc-cni", ("tke-cni", "tke-bridge")),
    ("azure-cni", ("azure-cni",)),
)


def _version_of(image: str) -> str:
    m = re.search(r":v?(\d+\.\d+(?:\.\d+)?)", image)
    return m.group(1) if m else ""


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    pods = _pods(snap)
    findings: list[dict] = []
    fps: dict = {}

    # --- CNI 识别（pod 名/镜像） ---
    evidence: dict[str, list[str]] = {}
    for pod in pods:
        meta = pod.get("metadata", {}) or {}
        names = [str(meta.get("name", ""))]
        for c in (pod.get("spec", {}) or {}).get("containers", []) or []:
            img = str(c.get("image", ""))
            names.append(img)
        blob = " ".join(names).lower()
        for key, needles in _DETECTORS:
            if any(n in blob for n in needles):
                evidence.setdefault(key, []).append(meta.get("name", "?"))

    rows: list[dict] = []
    for key, hits in sorted(evidence.items()):
        row = {"cni": key, "evidence": hits, "version": _version_of(blob_of(hits, pods))}
        row.update(CAPABILITY_BASE.get(key, {"network-policy": "未知", "sriov-enforcement": False,
                                             "vpc-native": False}))
        rows.append(row)
        fps[key] = True
        if CAPABILITY_BASE.get(key, {}).get("vpc-native"):
            fps["vpc-native-cni"] = True

    # --- hostNetwork / hostPort 旁路清单 ---
    hostnet_pods = [p.get("metadata", {}).get("name", "?") for p in pods if (p.get("spec", {}) or {}).get("hostNetwork")]
    hostports = [
        f"{p.get('metadata', {}).get('name', '?')}:{pt.get('hostPort')}"
        for p in pods for c in (p.get("spec", {}) or {}).get("containers", []) or []
        for pt in c.get("ports", []) or [] if pt.get("hostPort")
    ]
    multus_daemon = "multus" in evidence
    if hostnet_pods:
        fps["hostnetwork-pod"] = True
        findings.append(_finding(
            "medium", "hostNetwork/hostPort 旁路 CNI 与 NetworkPolicy",
            "hostNetwork Pod 直接占用宿主网络栈，绕过 CNI 与 NetworkPolicy（设计基线 5.6 主机网络层）。"
            f"hostNetwork Pod：{hostnet_pods}；hostPort：{hostports or '无'}。"
            "该路径可达节点面（node-plane），可达性图按「配置证据」标注。",
            {"hostnetwork-pod": True, "hostport-exposed": bool(hostports)},
            combo=("multus-sriov-rdma-bypass", "escape-primitives")))
    if multus_daemon or hostnet_pods:
        findings.append(_finding(
            "info", "Multus/hostDevice 旁路清单",
            f"Multus DS 在位={multus_daemon}；hostNetwork Pod {len(hostnet_pods)} 个。"
            "Multus 附件（SR-IOV/host-device/macvlan）不受 NetworkPolicy 约束，"
            "详见 multus-sriov-rdma-bypass 模块的未覆盖路径清单。",
            {"multus": multus_daemon, "hostnetwork-pod": bool(hostnet_pods)},
            combo=("multus-sriov-rdma-bypass",)))

    # --- VPC 安全组双控制面 ---
    cloud = snap.get("vpc_cni", {}) or {}
    sgs = snap.get("security_groups", []) or []
    open_sgs = [sg.get("name", "?") for sg in sgs
                for rule in sg.get("ingress", []) or []
                if rule.get("source") in ("0.0.0.0/0", "::/0")]
    sg_gap = bool(open_sgs)
    if sg_gap:
        fps["security-group-gap"] = True
    if cloud.get("security_group_for_pods"):
        fps["sgp-pods"] = True
    if fps.get("vpc-native-cni"):
        detail = f"VPC-native CNI（{cloud.get('type', 'vpc')}）与 K8s NetworkPolicy 是两套控制面。"
        if sg_gap:
            detail += f"安全组存在 0.0.0.0/0 入站（{open_sgs}）：缺口即绕过策略的云内横向。"
            findings.append(_finding(
                "high", "VPC-native CNI 安全组缺口（双控制面错配）", detail,
                {"vpc-native-cni": True, "security-group-gap": True,
                 str(cloud.get("type", "vpc-cni")): True, "sgp-pods": bool(cloud.get("security_group_for_pods"))},
                combo=("vpc-cni-dual-controlplane-mismatch",)))
        else:
            findings.append(_finding(
                "medium", "VPC-native CNI 双控制面（安全组未见显式缺口）", detail + "建议安全组与策略一致性审计。",
                {"vpc-native-cni": True, str(cloud.get("type", "vpc-cni")): True},
                combo=("vpc-cni-dual-controlplane-mismatch",)))

    # --- 能力矩阵基线 finding ---
    findings.append(_finding(
        "info", "CNI 能力矩阵（per-CNI 策略语义）",
        f"检测到 CNI：{sorted(evidence)}。per-CNI 能力矩阵已落 artifact cni-capability-matrix.json；"
        "关键事实：SR-IOV VF/IB/macvlan 流量不受任何一家 NetworkPolicy 约束（sriov-enforcement=false）。",
        {k: True for k in evidence} or {"cni-detected": False}))

    artifacts = _artifact(ctx, "cni-capability-matrix.json", {
        "cni": rows,
        "bypass": {"hostnetwork_pods": hostnet_pods, "hostports": hostports,
                   "multus_daemon": multus_daemon},
        "cloud": {"vpc_cni": cloud, "security_group_open": sorted(set(open_sgs))},
        "fingerprints": fps,
    })
    return {
        "summary": f"CNI 栈：{sorted(evidence)}；hostNetwork Pod {len(hostnet_pods)}；"
                   f"安全组缺口={'有' if sg_gap else '无'}",
        "artifacts": artifacts,
        "findings": findings,
    }


def blob_of(hits: list[str], pods: list[dict]) -> str:
    for pod in pods:
        if pod.get("metadata", {}).get("name") == hits[-1]:
            for c in (pod.get("spec", {}) or {}).get("containers", []) or []:
                return str(c.get("image", ""))
    return ""
