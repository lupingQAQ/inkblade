# -*- coding: utf-8 -*-
"""Munge 认证面审计（只读元数据，不读取密钥内容）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "munge-auth-audit"
_SAFE_DIRS = ("/etc/munge", "/run/munge", "/var/run/munge", "/var/lib/munge", "/var/log/munge")


def _in_safe_dir(path: str) -> bool:
    return any(str(path or "").startswith(d) for d in _SAFE_DIRS)


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    conf = _C.conf(snap, "munge.conf")
    meta = _C.json_file(snap, "munge.key.meta", "munge.key.json", default={})
    findings: list[dict] = []

    mode = _C.parse_mode(meta.get("mode"))
    owner = str(meta.get("owner") or "")
    key_age = _C.age_days(meta.get("mtime"))
    reused = [str(x) for x in (meta.get("reused_clusters") or [])]
    backups = [str(x) for x in (meta.get("key_backup_paths") or [])]
    socket_mode = _C.parse_mode(meta.get("socket_mode"))

    if mode is None or mode & 0o077:
        findings.append(_C.finding(
            "high", "Munge 密钥可被组/其他用户读取",
            {"mode": meta.get("mode"), "owner": owner, "path": meta.get("path")},
            evidence=f"munge.key mode={meta.get('mode')} owner={owner}",
            mapping="Munge 密钥保密性",
            fix="chown munge:munge /etc/munge/munge.key && chmod 0400",
        ))
    if owner and owner not in ("munge", "root"):
        findings.append(_C.finding(
            "high", "Munge 密钥属主非 munge/root",
            {"owner": owner, "group": meta.get("group")},
            evidence=f"owner={owner} group={meta.get('group')}",
            mapping="Munge 密钥属主",
            fix="密钥归 munge:munge；slurm 用户不得直接读取",
        ))
    if key_age is not None and key_age > 365:
        findings.append(_C.finding(
            "medium", "Munge 密钥超过一年未轮换",
            {"key_age_days": key_age, "mtime": meta.get("mtime")},
            evidence=f"key_age_days={key_age}",
            mapping="密钥生命周期",
            fix="建立 90–365 天轮换流程；轮换期间保持集群一致",
        ))
    if len(reused) > 1:
        findings.append(_C.finding(
            "high", "同一 Munge 密钥跨多个集群复用",
            {"reused_clusters": reused},
            evidence=f"reused_clusters={reused}",
            mapping="信任域隔离",
            fix="每个集群生成独立密钥；跨集群提交走 auth/jwt + audience 限制",
        ))
    if bool(meta.get("in_image")):
        findings.append(_C.finding(
            "high", "Munge 密钥被打包进镜像",
            {"path": meta.get("path"), "backup_paths": backups},
            evidence="in_image=true",
            mapping="镜像供应链 / 密钥泄漏",
            fix="密钥运行时挂载/注入，禁止写入镜像层；轮换已泄漏密钥",
        ))
    if backups:
        findings.append(_C.finding(
            "high", "Munge 密钥存在用户可读备份",
            {"key_backup_paths": backups[:10]},
            evidence=f"backup_paths={len(backups)}",
            mapping="密钥副本扩散",
            fix="删除明文备份；改用受控密钥托管/密封存储",
        ))
    if socket_mode is not None and socket_mode & 0o002:
        findings.append(_C.finding(
            "high", "Munge socket 全局可写",
            {"socket_mode": meta.get("socket_mode"), "socket_owner": meta.get("socket_owner")},
            evidence=f"socket_mode={meta.get('socket_mode')}",
            mapping="Munge socket 伪造",
            fix="socket 目录 0755、socket 0660 或更严，属主 munge",
        ))
    opts = _C.get(conf, "MUNGE_OPTIONS").lower()
    if "--verbose" in opts or "--logfile" in opts:
        findings.append(_C.finding(
            "medium", "MUNGE_OPTIONS 开启详细日志或写到可读路径",
            {"MUNGE_OPTIONS": _C.get(conf, "MUNGE_OPTIONS")},
            evidence=f"MUNGE_OPTIONS={_C.get(conf, 'MUNGE_OPTIONS')}",
            mapping="认证日志泄漏",
            fix="生产关闭 --verbose；日志写受保护目录并限权",
        ))
    if str(_C.get(conf, "MUNGE_UID")) in ("0", "") or str(_C.get(conf, "MUNGE_GID")) in ("0", ""):
        findings.append(_C.finding(
            "medium", "Munge 以 root 运行或未降权",
            {"MUNGE_UID": _C.get(conf, "MUNGE_UID"), "MUNGE_GID": _C.get(conf, "MUNGE_GID")},
            evidence=f"MUNGE_UID={_C.get(conf, 'MUNGE_UID')} MUNGE_GID={_C.get(conf, 'MUNGE_GID')}",
            mapping="守护进程降权",
            fix="使用专用 munge 用户/组",
        ))
    socket_path = _C.get(conf, "MUNGE_SOCKET", "/run/munge/munge.socket.2")
    if not _in_safe_dir(socket_path):
        findings.append(_C.finding(
            "medium", "Munge socket 位于非常规可写目录",
            {"MUNGE_SOCKET": socket_path},
            evidence=f"MUNGE_SOCKET={socket_path}",
            mapping="socket 路径劫持",
            fix="使用 /run/munge/munge.socket.2 并确保目录 root/munge 所有",
        ))
    slurm_conf = _C.conf(snap, "slurm.conf")
    auth = _C.get(slurm_conf, "AuthType").lower()
    if slurm_conf and auth != "auth/munge" and not auth.startswith("auth/jwt"):
        findings.append(_C.finding(
            "high", "slurm.conf AuthType 与 Munge 部署不一致",
            {"AuthType": auth},
            evidence=f"AuthType={auth or '<missing>'}",
            mapping="认证路径混淆",
            fix="统一 AuthType=auth/munge；JWT 仅作为 AuthAltTypes 叠加",
        ))

    extra = {
        "key_mode": meta.get("mode"),
        "key_owner": owner,
        "key_age_days": key_age,
        "reused_clusters": len(reused),
        "in_image": bool(meta.get("in_image")),
        "socket_mode": meta.get("socket_mode"),
        "auth_type": auth or "missing",
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Munge 认证面审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
