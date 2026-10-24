# -*- coding: utf-8 -*-
"""GPU 与网络 Operator 权限姿态（spec 5.2 网络架构模块 / 5.6 主机网络层）。

driver container / DCGM / NFD / validator / SR-IOV operator / RDMA device plugin /
ib-kubernetes / DRA kubelet plugin / ComputeDomain controller：
特权 + hostNetwork + 宿主挂载（/ /sys /dev）盘点 → 宿主接管风险矩阵。
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


# 组件 → 指纹键（命名对齐组合矩阵组件）
COMPONENTS = (
    ("ofed-driver", "ofed-driver-privileged", ("ofed-driver", "cloud-native/driver")),
    ("gpu-operator-validator", "gpu-operator-validator", ("gpu-operator-validator",)),
    ("dcgm-exporter", "dcgm", ("dcgm-exporter",)),
    ("node-feature-discovery", "nfd", ("node-feature-discovery", "nfd-")),
    ("sr-iov-operator", "sriov-operator", ("sriov-network-device-plugin", "sriov-device-plugin", "sriov-operator")),
    ("rdma-shared-device-plugin", "rdma-device-plugin", ("rdma-shared", "rdma-shared-device-plugin")),
    ("ib-kubernetes", "ib-kubernetes", ("ib-kubernetes",)),
    ("dra-kubelet-plugin", "dra-kubelet-plugin", ("dra-controller", "k8s-dra", "dra-kubelet")),
    ("computedomain-controller", "computedomain-controller", ("computedomain", "compute-domain")),
    ("network-operator", "network-operator", ("network-operator",)),
    ("imex-daemon", "imex-daemon", ("imex-daemon",)),
)


def _podlike(snap: dict):
    """产出 (来源, pod spec) —— Pod / DaemonSet 模板 / Deployment 模板。"""
    for item in snap.get("items", []):
        kind = item.get("kind", "")
        if kind == "Pod":
            yield f"Pod/{item.get('metadata', {}).get('name', '?')}", item
        elif kind in ("DaemonSet", "Deployment", "StatefulSet", "LeaderWorkerSet"):
            tpl = (item.get("spec", {}) or {}).get("template", {}) or {}
            if tpl.get("spec"):
                yield f"{kind}/{item.get('metadata', {}).get('name', '?')}", tpl


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    findings: list[dict] = []
    fps: dict = {}

    posture: list[dict] = []
    for source, pod in _podlike(snap):
        spec = pod.get("spec", {}) or {}
        meta = pod.get("metadata", {}) or {}
        blob = " ".join([source, str(meta.get("name", ""))] +
                        [str(c.get("image", "")) for c in spec.get("containers", []) or []]).lower()
        for comp_name, fp_key, needles in COMPONENTS:
            if not any(n in blob for n in needles):
                continue
            entry = {
                "component": comp_name, "source": source,
                "privileged": [], "hostNetwork": bool(spec.get("hostNetwork")),
                "hostPaths": [], "serviceAccount": spec.get("serviceAccountName", ""),
            }
            for c in spec.get("containers", []) or []:
                sc = c.get("securityContext", {}) or {}
                if sc.get("privileged"):
                    entry["privileged"].append(str(c.get("name", "?")))
                for vm in c.get("volumeMounts", []) or []:
                    mp = str(vm.get("mountPath", ""))
                    if mp in ("/", "/host", "/sys", "/dev", "/var/lib/kubelet") or mp.startswith("/dev/"):
                        entry["hostPaths"].append(mp)
            posture.append(entry)
            fps[fp_key] = True
            fps[f"{comp_name}-privileged"] = bool(entry["privileged"])
            if entry["privileged"] and entry["hostPaths"]:
                findings.append(_finding(
                    "high", f"Operator 组件特权 + 宿主挂载：{comp_name}",
                    f"{source}：privileged 容器 {entry['privileged']}，宿主挂载 {entry['hostPaths']}，"
                    f"hostNetwork={entry['hostNetwork']}，SA={entry['serviceAccount'] or '默认'}。"
                    "该组件被攻陷即等价宿主接管（逃逸原语见权限链模块）。",
                    {fp_key: True, f"{comp_name}-privileged": True,
                     "operator-privileged": True},
                    combo=("hardware-route-privileged-posture", "privileged-gpu-pod-escape")))
            elif entry["privileged"] or entry["hostPaths"]:
                findings.append(_finding(
                    "medium", f"Operator 组件高危姿态：{comp_name}",
                    f"{source}：privileged={entry['privileged']}，宿主挂载 {entry['hostPaths']}，"
                    f"hostNetwork={entry['hostNetwork']}。",
                    {fp_key: True, "operator-privileged": entry['privileged'] != []},
                    combo=("hardware-route-privileged-posture",)))
            break  # 一个 pod 只归一个组件

    if posture:
        privileged_n = sum(1 for p in posture if p["privileged"])
        findings.append(_finding(
            "medium", "GPU/网络 Operator 权限姿态总览",
            f"组件 {len(posture)} 个（特权 {privileged_n} 个）。宿主网络层事实：驱动容器特权 + "
            "hostNetwork 是常态而非例外 —— 这些组件是横向移动的高价值落点。矩阵见 artifact "
            "gpu-network-operator-posture.json。",
            {k: True for k, v in fps.items() if v and not k.endswith("-privileged")},
            combo=("nvl-dra-imex-domain",)))
    else:
        findings.append(_finding(
            "info", "未检测到 GPU/网络 Operator 组件",
            "快照内未发现 driver/DCGM/NFD/validator/SR-IOV/RDMA/ib-kubernetes/DRA/ComputeDomain 组件。",
            {"operator-privileged": False}))

    artifacts = _artifact(ctx, "gpu-network-operator-posture.json", {
        "posture": posture, "fingerprints": fps,
    })
    return {
        "summary": f"Operator 姿态：组件 {len(posture)}，特权 {privileged_n if posture else 0}",
        "artifacts": artifacts,
        "findings": findings,
    }
