"""storage-sharing — 存储共享面测绘：RWX/共享文件系统/NFS PV/共享模型缓存目录线索。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

SHARED_PROVISIONER_HINTS = ("nfs", "juicefs", "ceph", "lustre", "gluster")
CACHE_HOSTPATH_HINTS = ("hf-cache", "huggingface", "checkpoint", "model-cache", "/models")


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    for pvc in snapshot.get("pvcs", []):
        if "ReadWriteMany" in pvc.get("accessModes", []):
            findings.append(finding(
                "high", f"RWX 共享 PVC：{pvc.get('namespace', 'default')}/{pvc.get('name', '?')}（{pvc.get('storageClass', '-')}）",
                detail="ReadWriteMany 卷对全部挂载者开放读写：跨租户同卷即权重偷换一体（读+写+哈希替换）前提。",
                evidence=f"pvc={pvc.get('name')} accessModes={pvc.get('accessModes')} storageClass={pvc.get('storageClass')}",
                mapping="链「共享 PVC + 模型加载 → 供应链投毒」；存储协议与 CSI 面",
                fix="按租户拆卷或 RWO；必须 RWX 时叠加只读挂载、文件级权限与写入审计",
            ))
    for sc in snapshot.get("storageclasses", []):
        provisioner = str(sc.get("provisioner", ""))
        if any(h in provisioner.lower() for h in SHARED_PROVISIONER_HINTS):
            findings.append(finding(
                "medium", f"共享文件系统 StorageClass：{sc.get('name', '?')}（{provisioner}）",
                detail="NFS/JuiceFS/CephFS 类共享后端：默认跨命名空间可达且 AUTH_SYS uid 可伪造，需按导出域收敛。",
                evidence=f"storageclass={sc.get('name')} provisioner={provisioner}",
                mapping="存储数据面层；存储协议与 CSI 面（网络架构族）",
                fix="导出目录按租户子目录 + root_squash/no_root_squash 策略审计；kerberos/强认证可选时启用",
            ))
    for pv in snapshot.get("pvs", []):
        nfs = pv.get("nfs")
        if nfs:
            findings.append(finding(
                "medium", f"NFS PV：{pv.get('name', '?')} → {nfs.get('server', '?')}:{nfs.get('path', '?')}",
                detail="NFSv4 AUTH_SYS 客户端 uid 可伪造：任意挂载者可冒充属主读写（含 checkpoint/权重导出）。",
                evidence=f"pv={pv.get('name')} nfs={nfs}",
                mapping="存储数据面层；共享卷权重直读",
                fix="NFS 导出最小化 + 强认证（RPCSEC_GSS）/入口 ACL；权重目录写入审计",
            ))
    for pod in snapshot.get("pods", []):
        pid = f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"
        for volume in pod.get("volumes", []):
            hp = (volume.get("hostPath") or {}).get("path", "")
            if hp and any(h in hp.lower() for h in CACHE_HOSTPATH_HINTS):
                findings.append(finding(
                    "medium", f"共享模型缓存 hostPath：{pid} {hp}",
                    detail="HF 缓存/checkpoint 目录多 Pod 共享：模型文件偷换即供应链投毒（加载即执行）。",
                    evidence=f"pod={pid} hostPath={hp}",
                    mapping="链「共享 PVC + 模型加载 → 供应链投毒」；组合签名「任意框架 + 共享 HF 缓存」",
                    fix="缓存目录按租户隔离 + 只读挂载；模型入库走带哈希校验的制品库",
                ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="存储共享面测绘")
