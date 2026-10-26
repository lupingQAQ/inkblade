# -*- coding: utf-8 -*-
"""Slurm JWT 认证与密钥生命周期审计（只读）。"""
from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-jwt-auth-audit"


def _key_bits(key: dict) -> int:
    if str(key.get("kty") or "").upper() != "OCT":
        return 0
    raw = str(key.get("k") or "")
    try:
        return len(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))) * 8
    except Exception:  # noqa: BLE001
        return 0


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    doc = _C.json_file(snap, "jwt.json", default={})
    conf = _C.conf(snap, "slurm.conf")
    findings: list[dict] = []

    auth_alt = _C.get(conf, "AuthAltTypes").lower()
    auth_params = _C.get(conf, "AuthAltParameters")
    keys = [k for k in (doc.get("keys") or []) if isinstance(k, dict)]
    hs = [k for k in keys if str(k.get("alg") or k.get("kty") or "").upper() in ("HS256", "HS384", "HS512", "OCT")]
    weak = [k for k in hs if _key_bits(k) and _key_bits(k) < 256]

    if conf and "auth/jwt" not in auth_alt:
        findings.append(_C.finding(
            "high", "slurm.conf 未启用 auth/jwt",
            {"AuthAltTypes": auth_alt or "<missing>"},
            evidence=f"AuthAltTypes={auth_alt or '<missing>'}",
            mapping="Slurm JWT 认证路径",
            fix="AuthAltTypes=auth/jwt + AuthAltParameters=jwt_key=<受保护路径>",
        ))
    if not keys:
        findings.append(_C.finding(
            "high", "JWT 公钥/密钥集为空",
            {"jwt.json": doc},
            evidence="keys=0",
            mapping="令牌验签可用性",
            fix="通过 slurmctld --generate-jwt 或外部 IdP 配置 JWKS",
        ))
    if weak:
        findings.append(_C.finding(
            "high", "JWT 使用短于 256 位的 HS256 共享密钥",
            {"keys": [{"kid": k.get("kid"), "bits": _key_bits(k)} for k in weak]},
            evidence=f"weak_hs_keys={[k.get('kid') for k in weak]}",
            mapping="JWT 对称密钥强度",
            fix="改用 RS256/ES256 非对称密钥；HS256 至少 256 位随机密钥",
        ))
    if hs and not weak:
        findings.append(_C.finding(
            "medium", "JWT 使用 HS 共享密钥（无法做发送方公钥隔离）",
            {"kids": [k.get("kid") for k in hs]},
            evidence=f"hs_keys={[k.get('kid') for k in hs]}",
            mapping="JWT 信任模型",
            fix="跨集群/多服务场景改用 RS256/ES256 + JWKS 轮换",
        ))
    mode = _C.parse_mode(doc.get("key_file_mode"))
    if mode is None or mode & 0o077:
        findings.append(_C.finding(
            "high", "JWT 私钥/共享密钥文件可被组或其他用户读取",
            {"key_file": doc.get("key_file"), "mode": doc.get("key_file_mode")},
            evidence=f"key_file_mode={doc.get('key_file_mode')}",
            mapping="JWT 签名密钥保密性",
            fix="chmod 0600，属主 slurm；禁止镜像/家目录副本",
        ))
    age = _C.as_int(doc.get("key_age_days"), 0)
    if age > 180:
        findings.append(_C.finding(
            "medium", "JWT 密钥超过 180 天未轮换",
            {"key_age_days": age},
            evidence=f"key_age_days={age}",
            mapping="密钥生命周期",
            fix="建立 90 天轮换；保留旧 key 的短暂验签窗口",
        ))
    rotation = str(doc.get("rotation") or "none").lower()
    if rotation in ("", "none", "off", "disabled"):
        findings.append(_C.finding(
            "high", "JWT 密钥无轮换策略",
            {"rotation": rotation},
            evidence=f"rotation={rotation}",
            mapping="长期令牌风险",
            fix="配置 rotation=90d；轮换后撤销旧 token",
        ))
    lifetime = _C.as_int(doc.get("max_token_lifetime_seconds"), 0)
    if lifetime <= 0 or lifetime > 86400:
        findings.append(_C.finding(
            "high", "JWT 令牌有效期未限制或超过 24 小时",
            {"max_token_lifetime_seconds": lifetime},
            evidence=f"max_token_lifetime_seconds={lifetime}",
            mapping="令牌重放窗口",
            fix="设置 <=3600 秒；高风险操作使用短时 token",
        ))
    if not bool(doc.get("verify_audience", False)) or not str(doc.get("audience") or ""):
        findings.append(_C.finding(
            "medium", "JWT 未校验 audience",
            {"audience": doc.get("audience"), "verify_audience": doc.get("verify_audience")},
            evidence=f"audience={doc.get('audience')} verify={doc.get('verify_audience')}",
            mapping="跨服务令牌混淆",
            fix="设置 audience=slurmrestd 并强制校验",
        ))
    exposed = [str(x) for x in (doc.get("exposed_paths") or [])]
    if exposed:
        findings.append(_C.finding(
            "high", "JWT 密钥出现在家目录/镜像等可读路径",
            {"paths": exposed[:10]},
            evidence=f"exposed_paths={len(exposed)}",
            mapping="密钥副本扩散",
            fix="删除副本并轮换；密钥仅由 slurmctld/slurmrestd 读取",
        ))
    if auth_params:
        key_path = ""
        for part in auth_params.split(","):
            if part.lower().startswith("jwt_key="):
                key_path = part.split("=", 1)[1]
        if key_path and not key_path.startswith(("/etc/slurm/", "/var/lib/slurm/")):
            findings.append(_C.finding(
                "medium", "AuthAltParameters jwt_key 位于非常规受保护目录",
                {"AuthAltParameters": auth_params},
                evidence=f"jwt_key={key_path}",
                mapping="密钥路径保护",
                fix="密钥放 /etc/slurm 或 /var/lib/slurm，root/slurm 0600",
            ))

    extra = {
        "keys": len(keys),
        "hs_keys": len(hs),
        "weak_hs_keys": len(weak),
        "key_file_mode": doc.get("key_file_mode"),
        "key_age_days": age,
        "rotation": rotation,
        "max_token_lifetime_seconds": lifetime,
        "exposed_paths": len(exposed),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm JWT 认证与密钥生命周期审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
