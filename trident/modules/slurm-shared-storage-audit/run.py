# -*- coding: utf-8 -*-
"""Slurm 共享存储客户端审计（Lustre/GPFS/NFS，只读导出）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-shared-storage-audit"


def _opts(mount: dict) -> set[str]:
    raw = mount.get("options") or mount.get("opts") or []
    if isinstance(raw, str):
        raw = raw.split(",")
    return {str(o).strip().lower() for o in raw}


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    mounts = _C.mount_list(snap, "lustre-mounts.json") + _C.mount_list(snap, "gpfs-mounts.json")
    findings: list[dict] = []

    for mount in mounts:
        path = str(mount.get("path") or "")
        fstype = str(mount.get("fstype") or mount.get("type") or "").lower()
        opts = _opts(mount)
        if not path:
            continue
        if fstype in ("lustre", "gpfs", "nfs", "nfs4", "beegfs"):
            if "nosuid" not in opts:
                findings.append(_C.finding(
                    "high", f"共享存储 {path} 未设置 nosuid",
                    {"mount": mount, "options": sorted(opts)},
                    evidence=f"{path} fstype={fstype} options={sorted(opts)}",
                    mapping="共享存储 setuid 提权",
                    fix="挂载增加 nosuid；权重/数据集目录禁止 setuid 二进制",
                ))
            if "nodev" not in opts:
                findings.append(_C.finding(
                    "high", f"共享存储 {path} 未设置 nodev",
                    {"mount": mount, "options": sorted(opts)},
                    evidence=f"{path} fstype={fstype} options={sorted(opts)}",
                    mapping="共享存储设备节点注入",
                    fix="挂载增加 nodev；禁止用户创建设备节点",
                ))
            if "noexec" not in opts:
                findings.append(_C.finding(
                    "medium", f"共享存储 {path} 未设置 noexec",
                    {"mount": mount, "options": sorted(opts)},
                    evidence=f"{path} fstype={fstype}",
                    mapping="共享存储代码执行",
                    fix="模型/数据挂载增加 noexec；代码目录单独受控",
                ))
        if mount.get("root_squash") is False:
            findings.append(_C.finding(
                "high", f"NFS 导出 {path} 关闭 root_squash",
                {"mount": mount},
                evidence=f"{path} root_squash=false",
                mapping="NFS root 映射",
                fix="启用 root_squash/all_squash；导出网段最小化",
            ))
        exports = [str(e) for e in (mount.get("exports") or [])]
        if any(e in ("*", "0.0.0.0/0", "::/0") for e in exports):
            findings.append(_C.finding(
                "high", f"共享存储 {path} 导出到任意主机",
                {"exports": exports},
                evidence=f"{path} exports={exports}",
                mapping="共享存储网络边界",
                fix="导出限制到计算/登录网段；禁止公网/管理网",
            ))
        if mount.get("client_quota") is False or mount.get("quota") is False:
            findings.append(_C.finding(
                "medium", f"共享存储 {path} 未启用客户端配额",
                {"mount": mount},
                evidence=f"{path} client_quota={mount.get('client_quota')} quota={mount.get('quota')}",
                mapping="存储配额 / 资源耗尽",
                fix="启用 Lustre/GPFS 配额；按项目/租户设硬限",
            ))
        if fstype == "lustre" and mount.get("lnet_encryption") is False:
            findings.append(_C.finding(
                "medium", f"Lustre {path} LNet 未加密",
                {"mount": mount},
                evidence=f"{path} lnet_encryption=false",
                mapping="LNet 传输窃听",
                fix="启用 LNet 加密或使用隔离 RDMA 网段",
            ))
        if str(mount.get("uid_mapping") or "").lower() in ("", "none"):
            findings.append(_C.finding(
                "high", f"共享存储 {path} 未做 UID/GID 映射",
                {"mount": mount},
                evidence=f"{path} uid_mapping={mount.get('uid_mapping')}",
                mapping="跨域身份混淆",
                fix="使用 SSSD/LDAP 统一 UID；GPFS 启用 uid mapping",
            ))
        writable = [str(x) for x in (mount.get("world_writable_dirs") or [])]
        if writable:
            findings.append(_C.finding(
                "high", f"共享存储 {path} 存在全局可写目录",
                {"dirs": writable[:20]},
                evidence=f"{path} world_writable={writable[:20]}",
                mapping="权重/检查点篡改",
                fix="目录按项目组 2770；权重目录 2750 且只读挂载",
            ))
        if str(mount.get("acl") or "").lower() == "allow":
            findings.append(_C.finding(
                "medium", f"GPFS {path} ACL 仅 allow 模式",
                {"mount": mount},
                evidence=f"{path} acl=allow",
                mapping="ACL 执行模式",
                fix="GPFS ACL 使用 enforce；定期导出并比对",
            ))

    extra = {
        "mounts": len(mounts),
        "lustre": sum(1 for m in mounts if str(m.get("fstype")).lower() == "lustre"),
        "gpfs": sum(1 for m in mounts if str(m.get("fstype")).lower() == "gpfs"),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm 共享存储客户端审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
