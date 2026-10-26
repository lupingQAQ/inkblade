# -*- coding: utf-8 -*-
"""slurmctld 控制面配置审计（只读）。

读 slurm.conf + inventory.json：
- AuthType != auth/munge、CryptoType 非 munge/tls → high；
- SlurmUser=root、DisableRootJobs!=YES → high；
- TaskPlugin/ProctrackType 非 cgroup → high/medium；
- PrivateData 缺失、AccountingStorageType=none → medium；
- StateSaveLocation 可写、SlurmctldParameters=enable_configless → medium。

不连接 slurmctld、不执行 scontrol、不改配置。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurmctld-config-audit"


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    conf = _C.conf(snap, "slurm.conf")
    findings: list[dict] = []

    auth = _C.get(conf, "AuthType").lower()
    crypto = _C.get(conf, "CryptoType").lower()
    slurmd_user = _C.get(conf, "SlurmUser")
    root_jobs = _C.get(conf, "DisableRootJobs", "NO").upper()
    task_plugin = _C.get(conf, "TaskPlugin").lower()
    proctrack = _C.get(conf, "ProctrackType").lower()
    private = _C.get(conf, "PrivateData").lower()
    acct = _C.get(conf, "AccountingStorageType").lower()
    select = _C.get(conf, "SelectType").lower()
    state_dir = _C.get(conf, "StateSaveLocation")

    if auth != "auth/munge":
        findings.append(_C.finding(
            "high", "slurmctld 未启用 Munge 认证",
            {"AuthType": auth or "<missing>"},
            evidence=f"AuthType={auth or '<missing>'}",
            mapping="Slurm AuthType / auth/munge",
            fix="设置 AuthType=auth/munge 并确保所有节点共享受保护的 Munge 密钥",
        ))
    if crypto not in ("crypto/munge", "crypto/tls"):
        findings.append(_C.finding(
            "high", "slurmctld 通信未使用 MUNGE/TLS 加密",
            {"CryptoType": crypto or "<missing>"},
            evidence=f"CryptoType={crypto or '<missing>'}",
            mapping="Slurm CryptoType / 节点间凭证保护",
            fix="设置 CryptoType=crypto/munge（同信任域）或 crypto/tls（跨域）",
        ))
    if slurmd_user in ("", "root"):
        findings.append(_C.finding(
            "high", "SlurmUser 为 root 或未设置",
            {"SlurmUser": slurmd_user or "<missing>"},
            evidence=f"SlurmUser={slurmd_user or '<missing>'}",
            mapping="Slurm 最小权限 / 守护进程降权",
            fix="创建专用 slurm 用户并设置 SlurmUser=slurm（UID/GID 全集群一致）",
        ))
    if root_jobs != "YES":
        findings.append(_C.finding(
            "high", "允许 root 提交作业",
            {"DisableRootJobs": root_jobs},
            evidence=f"DisableRootJobs={root_jobs}",
            mapping="Slurm root 作业边界",
            fix="设置 DisableRootJobs=YES；运维作业走专用服务账号",
        ))
    if "task/cgroup" not in task_plugin:
        findings.append(_C.finding(
            "high", "TaskPlugin 未启用 task/cgroup",
            {"TaskPlugin": task_plugin or "<missing>"},
            evidence=f"TaskPlugin={task_plugin or '<missing>'}",
            mapping="Slurm TaskPlugin / cgroup 作业约束",
            fix="设置 TaskPlugin=task/cgroup,task/affinity 并配置 cgroup.conf",
        ))
    if "cgroup" not in proctrack:
        findings.append(_C.finding(
            "medium", "ProctrackType 未使用 cgroup",
            {"ProctrackType": proctrack or "<missing>"},
            evidence=f"ProctrackType={proctrack or '<missing>'}",
            mapping="Slurm ProctrackType / 进程追踪",
            fix="设置 ProctrackType=proctrack/cgroup，避免 pgid 追踪漏掉逃逸子进程",
        ))
    if not private or "none" in private:
        findings.append(_C.finding(
            "medium", "PrivateData 未限制作业/用量可见性",
            {"PrivateData": private or "<missing>"},
            evidence=f"PrivateData={private or '<missing>'}",
            mapping="Slurm PrivateData / 跨租户信息暴露",
            fix="设置 PrivateData=jobs,usage,account（按合规要求裁剪）",
        ))
    if "none" in acct or not acct:
        findings.append(_C.finding(
            "medium", "未启用 SlurmDBD 记账",
            {"AccountingStorageType": acct or "<missing>"},
            evidence=f"AccountingStorageType={acct or '<missing>'}",
            mapping="Slurm accounting / 审计与配额依据",
            fix="设置 AccountingStorageType=accounting_storage/slurmdbd 并保护 slurmdbd",
        ))
    if select and "cons_tres" not in select:
        findings.append(_C.finding(
            "medium", "SelectType 未启用 cons_tres（GPU/TRES 记账缺失）",
            {"SelectType": select},
            evidence=f"SelectType={select}",
            mapping="Slurm SelectType / GRES 调度",
            fix="设置 SelectType=select/cons_tres 并启用 GresTypes",
        ))
    meta = _C.meta(snap, state_dir or "StateSaveLocation")
    if state_dir and (not meta or _C.group_or_world_writable(meta.get("mode"))):
        findings.append(_C.finding(
            "medium", "StateSaveLocation 缺失或可被非 Slurm 用户写入",
            {"StateSaveLocation": state_dir, "meta": meta},
            evidence=f"StateSaveLocation={state_dir} meta={meta or '<missing>'}",
            mapping="Slurm 状态目录完整性",
            fix="StateSaveLocation 归 slurm:slurm 所有，权限 0750 或更严；纳入文件完整性监控",
        ))
    if "enable_configless" in _C.get(conf, "SlurmctldParameters").lower():
        findings.append(_C.finding(
            "medium", "启用 configless 节点配置下发",
            {"SlurmctldParameters": _C.get(conf, "SlurmctldParameters")},
            evidence="SlurmctldParameters contains enable_configless",
            mapping="Slurm configless / 配置注入面",
            fix="仅可信网络启用 configless，并限制 slurmctld 端口到计算网段",
        ))

    extra = {
        "auth_type": auth or "missing",
        "crypto_type": crypto or "missing",
        "slurm_user": slurmd_user or "missing",
        "disable_root_jobs": root_jobs,
        "task_plugin": task_plugin or "missing",
        "proctrack": proctrack or "missing",
        "private_data": private or "missing",
        "accounting": acct or "missing",
        "select_type": select or "missing",
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "slurmctld 控制面配置审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
