# -*- coding: utf-8 -*-
"""存储协议与 CSI 面（spec 5.2 网络架构模块 / 5.6 存储数据面层）。

NFSv4 AUTH_SYS uid 可伪造、JuiceFS/CephFS/Lustre、CSI node plugin 特权与
宿主挂载、RWX 语义、checkpoint 原子性。存储数据面 = 权重/checkpoint 面。
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
    findings: list[dict] = []
    fps: dict = {}

    storageclasses = snap.get("storageclasses", []) or snap.get("_sources", {}).get(
        "storageclasses", {}).get("storageclasses", [])
    csi_pods = snap.get("csi_pods", [])
    pvcs = snap.get("pvcs", [])

    # --- NFS AUTH_SYS ---
    nfs_scs = []
    for sc in storageclasses:
        meta = sc.get("metadata", {}) or {}
        provisioner = str(sc.get("provisioner", "")).lower()
        mopts = [str(m).lower() for m in sc.get("mountOptions", []) or []]
        name_blob = str(meta.get("name", "")).lower() + provisioner
        if "nfs" in name_blob:
            auth_sys = any("sec=sys" in m for m in mopts) or not any("sec=krb" in m for m in mopts)
            root_squash_off = str((meta.get("annotations", {}) or {}).get(
                "storage.example.io/root-squash", "")).lower() == "false"
            nfs_scs.append({"storageclass": meta.get("name", "?"), "auth_sys": auth_sys,
                            "root_squash_off": root_squash_off,
                            "mountOptions": sc.get("mountOptions", [])})
    if nfs_scs:
        vulnerable = [n for n in nfs_scs if n["auth_sys"]]
        fps["nfs-authsys"] = bool(vulnerable)
        if vulnerable:
            findings.append(_finding(
                "high", "NFSv4 AUTH_SYS：uid 可伪造的跨租户读写面",
                f"NFS 导出使用 AUTH_SYS（sec=sys / 无 krb）：客户端自报 uid，服务端按 uid 授权。"
                f"任何可达 NAS 的 Pod 可伪造任意 uid（含 0）读写他租户文件。"
                f"root_squash 关闭项：{[n for n in vulnerable if n['root_squash_off']]}。"
                f"清单：{json.dumps(nfs_scs, ensure_ascii=False)}（spec 5.6 存储数据面层）。",
                {"nfs-authsys": True, "root-squash-off": any(n["root_squash_off"] for n in vulnerable)},
                combo=("shared-pvc-hf-cache-supply-chain", "shared-volume-weight-copy",
                       "training-data-leak")))

    # --- 其他协议 ---
    protocol_fps = {"juicefs": "juicefs", "cephfs": "cephfs", "lustre": "lustre"}
    for sc in storageclasses:
        provisioner = str(sc.get("provisioner", "")).lower() + str(sc.get("metadata", {}).get("name", "")).lower()
        for proto, fp_key in protocol_fps.items():
            if proto in provisioner:
                fps[fp_key] = True
                notes = ""
                if proto == "juicefs":
                    metaurl = str((sc.get("parameters", {}) or {}).get("metaurl", ""))
                    if metaurl:
                        fps["juicefs-metadata-exposed"] = True
                        notes = f" 元数据端点 {metaurl}（redis 无 TLS/鉴权线索）。"
                findings.append(_finding(
                    "info", f"共享存储协议在位：{proto}",
                    f"StorageClass {sc.get('metadata', {}).get('name', '?')}（provisioner="
                    f"{sc.get('provisioner', '')}）。{notes}共享语义按协议差异单列（CephFS cephx 密钥在 "
                    "Secret；Lustre 依赖网络可达控制）。",
                    {fp_key: True}))

    # --- CSI node plugin 特权 ---
    privileged_plugins = []
    for pod in csi_pods:
        meta = pod.get("metadata", {}) or {}
        for c in (pod.get("spec", {}) or {}).get("containers", []) or []:
            mounts = [str(vm.get("mountPath", "")) for vm in c.get("volumeMounts", []) or []]
            hostish = [m for m in mounts if m in ("/", "/host", "/var/lib/kubelet", "/sys", "/dev")
                       or m.startswith("/dev/")]
            if (c.get("securityContext", {}) or {}).get("privileged") and hostish:
                privileged_plugins.append({"pod": meta.get("name", "?"),
                                           "container": c.get("name", "?"),
                                           "hostMounts": hostish})
    if privileged_plugins:
        fps["csi-node-privileged"] = True
        findings.append(_finding(
            "medium", "CSI node plugin 特权 + 宿主挂载",
            f"{json.dumps(privileged_plugins, ensure_ascii=False)}。CSI node plugin 以特权运行并挂载 "
            "kubelet/设备目录：攻陷即宿主接管（与运行时 socket 逃逸同型）。",
            {"csi-node-privileged": True},
            combo=("runtime-socket-escape", "privileged-gpu-pod-escape")))

    # --- RWX 语义 ---
    rwx = [p.get("metadata", {}).get("name", "?") for p in pvcs
           if "ReadWriteMany" in (p.get("spec", {}) or {}).get("accessModes", [])]
    if rwx:
        fps["rwx-shared-pvc"] = True
        fps["shared-pvc"] = True
        ckpt = [n for n in rwx if "ckpt" in n.lower() or "checkpoint" in n.lower()]
        if ckpt:
            fps["checkpoint-surface"] = True
        findings.append(_finding(
            "medium", "RWX 共享卷：跨租户写面（权重/数据集/checkpoint）",
            f"ReadWriteMany PVC：{rwx}。RWX = 任意挂载者可写：一份恶意模型/权重会被全集群加载者执行"
            f"（供应链投毒）；checkpoint 卷（{ckpt or '无'}）叠加 NFS AUTH_SYS 时可污染训练状态。"
            "原子性建议：checkpoint 采用 临时名+rename 提交，避免读到半写状态。",
            {"rwx-shared-pvc": True, "shared-pvc": True,
             "checkpoint-surface": bool(ckpt)},
            combo=("shared-pvc-hf-cache-supply-chain", "shared-volume-weight-copy",
                   "training-data-leak")))

    if not findings:
        findings.append(_finding(
            "info", "未发现存储协议/CSI 线索", "快照内无 StorageClass/CSI pod/PVC。",
            {"storage-mapped": False}))

    artifacts = _artifact(ctx, "storage-protocol-csi.json", {
        "storageclasses": storageclasses, "privileged_csi_plugins": privileged_plugins,
        "rwx_pvcs": rwx, "fingerprints": fps,
    })
    return {
        "summary": f"存储面：SC {len(storageclasses)}（NFS AUTH_SYS {len(nfs_scs)}），"
                   f"特权 CSI plugin {len(privileged_plugins)}，RWX PVC {len(rwx)}",
        "artifacts": artifacts,
        "findings": findings,
    }
