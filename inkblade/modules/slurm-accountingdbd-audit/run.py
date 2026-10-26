# -*- coding: utf-8 -*-
"""SlurmDBD 记账库配置审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-accountingdbd-audit"


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    conf = _C.conf(snap, "slurmdbd.conf")
    findings: list[dict] = []

    storage = _C.get(conf, "StorageType").lower()
    dbd_host = _C.get(conf, "DbdHost")
    user = _C.get(conf, "SlurmUser").lower()
    password = _C.get(conf, "StoragePass")
    password_file = _C.get(conf, "StoragePassFile")
    private = _C.get(conf, "PrivateData").lower()
    backup = _C.get(conf, "StorageBackupHost")
    params_text = _C.get(conf, "StorageParameters").lower()
    debug = _C.get(conf, "DebugLevel").lower()
    queue_size = _C.as_int(_C.get(conf, "DbdAgentQueueSize"), 0)

    if "none" in storage or not storage:
        findings.append(_C.finding(
            "high", "slurmdbd 未配置记账存储",
            {"StorageType": storage or "<missing>"},
            evidence=f"StorageType={storage or '<missing>'}",
            mapping="记账完整性",
            fix="StorageType=accounting_storage/slurmdbd 或 mysql",
        ))
    if password:
        findings.append(_C.finding(
            "critical", "slurmdbd.conf 明文保存数据库口令",
            {"StoragePass": "<redacted>", "StoragePassFile": password_file},
            evidence="StoragePass present",
            mapping="数据库凭据泄漏",
            fix="改用 StoragePassFile（0600）或客户密钥托管；轮换已暴露口令",
        ))
    if dbd_host in ("0.0.0.0", "::", "[::]", ""):
        findings.append(_C.finding(
            "high", "slurmdbd 绑定到所有地址",
            {"DbdHost": dbd_host or "<missing>"},
            evidence=f"DbdHost={dbd_host or '<missing>'}",
            mapping="记账库网络暴露",
            fix="DbdHost 绑定管理网/回环；防火墙只放 slurmctld",
        ))
    if user in ("", "root"):
        findings.append(_C.finding(
            "high", "slurmdbd 以 root 运行",
            {"SlurmUser": user or "<missing>"},
            evidence=f"SlurmUser={user or '<missing>'}",
            mapping="记账服务降权",
            fix="SlurmUser=slurm",
        ))
    if not private or "none" in private:
        findings.append(_C.finding(
            "medium", "PrivateData 未限制记账可见性",
            {"PrivateData": private or "<missing>"},
            evidence=f"PrivateData={private or '<missing>'}",
            mapping="跨租户作业历史暴露",
            fix="PrivateData=jobs,usage,account",
        ))
    if not backup:
        findings.append(_C.finding(
            "medium", "未配置 StorageBackupHost",
            {"StorageBackupHost": backup},
            evidence="StorageBackupHost empty",
            mapping="记账可用性/恢复",
            fix="配置备份 DBD；定期演练恢复",
        ))
    if "ssl=off" in params_text or "tls=off" in params_text or "ssl" not in params_text and "tls" not in params_text:
        findings.append(_C.finding(
            "high", "slurmdbd 到数据库未启用 TLS",
            {"StorageParameters": _C.get(conf, "StorageParameters")},
            evidence=f"StorageParameters={_C.get(conf, 'StorageParameters') or '<missing>'}",
            mapping="记账链路加密",
            fix="启用数据库 TLS（SSL=on + CA 校验）",
        ))
    if debug.startswith("debug") or debug in ("verbose", "trace"):
        findings.append(_C.finding(
            "medium", "slurmdbd 调试级别过高",
            {"DebugLevel": debug},
            evidence=f"DebugLevel={debug}",
            mapping="日志泄漏/性能",
            fix="生产使用 info 或更低",
        ))
    if queue_size > 500000:
        findings.append(_C.finding(
            "low", "DbdAgentQueueSize 过大",
            {"DbdAgentQueueSize": queue_size},
            evidence=f"DbdAgentQueueSize={queue_size}",
            mapping="内存/队列耗尽",
            fix="按事件量设置合理上限并监控积压",
        ))
    meta = _C.meta(snap, "slurmdbd.conf")
    if meta and _C.group_or_world_writable(meta.get("mode")):
        findings.append(_C.finding(
            "high", "slurmdbd.conf 可被组/其他用户写入",
            {"meta": meta},
            evidence=f"slurmdbd.conf mode={meta.get('mode')}",
            mapping="记账配置完整性",
            fix="slurmdbd.conf slurm:slurm 0600",
        ))

    extra = {
        "storage_type": storage or "missing",
        "dbd_host": dbd_host or "missing",
        "slurm_user": user or "missing",
        "plaintext_password": bool(password),
        "password_file": password_file or "",
        "private_data": private or "missing",
        "backup_host": backup or "",
        "tls": "on" if ("ssl=on" in params_text or "tls=on" in params_text) else "off",
        "debug": debug or "missing",
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "SlurmDBD 记账库配置审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
