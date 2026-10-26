# -*- coding: utf-8 -*-
"""slurmrestd REST API 暴露面审计（配置导出；可选 GET 探测）。"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurmrestd-exposure"


def _env(snapshot: dict) -> dict[str, str]:
    _, text = _C.find_file(snapshot, "slurmrestd.env")
    out: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip("'\"")
    return out


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    env = _env(snap)
    findings: list[dict] = []

    bind = env.get("SLURMRESTD_BIND", "")
    host = bind.rsplit(":", 1)[0] if ":" in bind else bind
    if host in ("0.0.0.0", "::", "[::]", ""):
        findings.append(_C.finding(
            "high", "slurmrestd 绑定到所有地址",
            {"SLURMRESTD_BIND": bind or "<missing>"},
            evidence=f"bind={bind or '<missing>'}",
            mapping="REST 管理面暴露",
            fix="绑定 127.0.0.1 或专用管理网段；用反向代理做 TLS/鉴权",
        ))
    auth = env.get("SLURMRESTD_AUTH", "").lower()
    plugin = env.get("SLURMRESTD_PLUGIN", "").lower()
    if auth in ("", "no", "none", "disabled", "false") or "auth/none" in plugin:
        findings.append(_C.finding(
            "critical", "slurmrestd 未启用认证",
            {"SLURMRESTD_AUTH": auth or "<missing>", "SLURMRESTD_PLUGIN": plugin or "<missing>"},
            evidence=f"auth={auth or '<missing>'} plugin={plugin or '<missing>'}",
            mapping="slurmrestd 未授权 API",
            fix="SLURMRESTD_AUTH=required + rest_auth/jwt；禁止 auth/none",
        ))
    tls = env.get("SLURMRESTD_TLS", "").lower()
    if tls in ("", "no", "none", "disabled", "false"):
        findings.append(_C.finding(
            "high", "slurmrestd 未启用 TLS",
            {"SLURMRESTD_TLS": tls or "<missing>"},
            evidence=f"tls={tls or '<missing>'}",
            mapping="管理面明文传输",
            fix="启用 TLS 或仅在 loopback/受保护 unix socket 上监听",
        ))
    user = env.get("SLURMRESTD_USER", "").lower()
    if user in ("", "root"):
        findings.append(_C.finding(
            "high", "slurmrestd 以 root 运行",
            {"SLURMRESTD_USER": user or "<missing>"},
            evidence=f"user={user or '<missing>'}",
            mapping="REST 服务降权",
            fix="使用专用 slurmrestd 用户，仅授予所需 Slurm 权限",
        ))
    debug = env.get("SLURMRESTD_DEBUG", "").lower()
    if debug.startswith("debug") or debug in ("verbose", "trace"):
        findings.append(_C.finding(
            "medium", "slurmrestd 开启调试日志",
            {"SLURMRESTD_DEBUG": debug},
            evidence=f"debug={debug}",
            mapping="请求/凭证日志泄漏",
            fix="生产设置 info 或更低；日志脱敏并限权",
        ))
    max_conn = _C.as_int(env.get("SLURMRESTD_MAX_CONNECTIONS"), 0)
    if max_conn <= 0:
        findings.append(_C.finding(
            "low", "slurmrestd 未限制最大连接数",
            {"SLURMRESTD_MAX_CONNECTIONS": env.get("SLURMRESTD_MAX_CONNECTIONS")},
            evidence=f"max_connections={env.get('SLURMRESTD_MAX_CONNECTIONS')}",
            mapping="管理面 DoS",
            fix="设置 max_connections（如 256）并加前置限流",
        ))
    if env.get("SLURM_JWT", "").lower() in ("disabled", "no", "none", ""):
        findings.append(_C.finding(
            "high", "slurmrestd 未启用 JWT",
            {"SLURM_JWT": env.get("SLURM_JWT", "<missing>")},
            evidence=f"SLURM_JWT={env.get('SLURM_JWT', '<missing>')}",
            mapping="REST 认证",
            fix="SLURM_JWT=required，并配置 auth/jwt 公钥/共享密钥",
        ))
    # 可选：显式 target 时只做一次 GET，验证是否无认证 200。
    target = str(params.get("target") or "").rstrip("/")
    probe = {"attempted": False}
    if target:
        try:
            import urllib.error
            import urllib.request
            req = urllib.request.Request(f"{target}/slurm/v0.0.40/jobs", method="GET")
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(2000).decode("utf-8", "replace")
                    probe = {"attempted": True, "status": resp.status, "body_sha256": _C.sha256_text(body)}
            except urllib.error.HTTPError as exc:
                probe = {"attempted": True, "status": exc.code, "body_sha256": ""}
            except Exception as exc:  # noqa: BLE001
                probe = {"attempted": True, "status": 0, "error": f"{type(exc).__name__}: {exc}"}
            if probe.get("status") == 200:
                findings.append(_C.finding(
                    "critical", "slurmrestd /jobs 未认证可读",
                    {"target": target, "probe": probe},
                    evidence="GET /slurm/v0.0.40/jobs -> 200",
                    mapping="未授权作业枚举",
                    fix="启用 JWT + TLS；仅允许管理网访问",
                ))
        except Exception:  # noqa: BLE001
            probe = {"attempted": False}

    extra = {
        "bind": bind or "missing",
        "auth": auth or "missing",
        "tls": tls or "missing",
        "user": user or "missing",
        "jwt": env.get("SLURM_JWT", "missing"),
        "probe": probe,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "slurmrestd REST API 暴露面审计", findings, extra=extra,
                     source=str(params.get("snapshot") or target or "<inline snapshot>"))
