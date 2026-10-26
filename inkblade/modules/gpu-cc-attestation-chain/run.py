# -*- coding: utf-8 -*-
"""GPU Confidential Computing 证明链核验（NRAS JWKS + nonce + claims）。

输入（params.evidence 或 params.snapshot）：
- token / overall / tokens[]：NRAS 风格 attestation JWT（单 token 或 detached EAT 集合）；
- jwks：JWKS dict / 路径 / "cache" / "live"；缺省读取 trident/tee/online_cache；
- expected_nonce（或 nonce）：32 字节随机数的十六进制/字符串；
- expected_claims：需要精确匹配的 claims（如 x-nvidia-gpu-name）；
- issuer / audience / now / min_version。

校验复用 ``trident.tee`` 的在线校验器：
- JWKS 结构（kid/alg/kty）与 RS256/ES384/ES256 验签；
- exp/nbf/iat/iss/aud/eat_nonce/dbgstat/secboot/x-nvidia-overall-att-result/x-nvidia-ver；
- 可选 expected_claims 精确匹配。

边界：本仓库没有 NVIDIA 签发的真实生产 JWT；fixture 使用公开的自签 RSA 密钥，
只证明解析/验签/claims 逻辑正确。真实环境必须用 NRAS 的 JWKS 与设备证明。
只读：不联网除非显式 jwks="live"；不写设备。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_PARENT = Path(__file__).resolve().parent.parent
import importlib.util  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

from trident.tee import nvidia_cc, online  # noqa: E402

KEY = "gpu-cc-attestation-chain"
NRAS_ISSUER = nvidia_cc.NRAS_ISSUER


def _token_list(doc: dict) -> list[str]:
    raw = doc.get("tokens")
    tokens: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item.strip():
                tokens.append(item.strip())
            elif isinstance(item, dict) and item.get("token"):
                tokens.append(str(item["token"]).strip())
    for name in ("token", "jwt", "overall"):
        value = doc.get(name)
        if isinstance(value, str) and value.strip() and value not in tokens:
            tokens.append(value.strip())
    detached = doc.get("detached")
    if isinstance(detached, list):
        for item in detached:
            value = item.get("token") if isinstance(item, dict) else item
            if isinstance(value, str) and value.strip() and value not in tokens:
                tokens.append(value.strip())
    return tokens


def _load_evidence(params: dict) -> tuple[dict, str]:
    raw = params.get("evidence") if params.get("evidence") is not None else params.get("snapshot")
    if raw is None and params.get("token"):
        raw = {"token": params["token"]}
    if raw is None:
        raise ValueError("缺少 params.evidence（NRAS JWT/JWKS 证据）")
    if isinstance(raw, dict):
        return raw, "<inline evidence>"
    text = str(raw).strip()
    if text.count(".") == 2 and "\n" not in text:
        return {"token": text}, "<inline token>"
    return _C.load_json_ref(raw), str(raw)


def _resolve_jwks(spec, params: dict) -> tuple[dict, str]:
    if isinstance(spec, dict):
        if "keys" in spec:
            return spec, str(params.get("jwks_source") or "inline")
        source = str(spec.get("source") or "cache").lower()
        if source in ("live", "fetch", "nras"):
            cache_dir = spec.get("cache_dir") or params.get("cache_dir")
            return online.fetch_nvidia_jwks(cache_dir=Path(cache_dir) if cache_dir else None), "live"
        spec = "cache"
    if spec in (None, "", "cache", "cached", "offline"):
        try:
            return online.cached_nvidia_jwks(
                Path(params["cache_dir"]) if params.get("cache_dir") else None), "cache"
        except online.OnlineError as exc:
            raise ValueError(
                f"{exc}；生产环境可传 jwks=\"live\" 或显式 JWKS JSON") from exc
    if str(spec).lower() in ("live", "fetch", "nras"):
        cache_dir = params.get("cache_dir")
        return online.fetch_nvidia_jwks(cache_dir=Path(cache_dir) if cache_dir else None), "live"
    path = Path(str(spec))
    if path.is_file():
        return _C.load_json_ref(path), str(path)
    raise ValueError(f"无法解析 JWKS：{spec!r}")


def _classify(errors: list[str]) -> list[tuple[str, str, str]]:
    """把校验器错误映射为 (severity, title, fix)。"""
    out: list[tuple[str, str, str]] = []
    joined = "；".join(errors)
    low = joined.lower()
    if "验签失败" in joined or "signature" in low:
        out.append(("high", "GPU CC 证明 JWT 验签失败",
                    "拒绝该证明；从 NRAS 重新获取 token 并核对 JWKS kid/算法"))
    if "nonce" in low:
        out.append(("high", "GPU CC 证明 nonce 不匹配（重放风险）",
                    "每次证明使用新 nonce；校验 eat_nonce 与请求值一致"))
    if "已过期" in joined or "exp" in low:
        out.append(("high", "GPU CC 证明已过期",
                    "缩短 token 缓存时间；过期后重新向 NRAS 证明"))
    if "dbgstat" in low or "调试" in joined:
        out.append(("high", "GPU CC 调试模式未禁用",
                    "关闭 CC-DevTools/调试模式；dbgstat 必须为 disabled"))
    if "secboot" in low or "安全启动" in joined:
        out.append(("high", "GPU CC 安全启动未启用",
                    "在 GPU/平台固件启用安全启动并重新证明"))
    if "overall" in low or "总体" in joined:
        out.append(("high", "GPU CC 总体证明结果非 true",
                    "任何单设备失败都拒绝发布密钥/模型"))
    if "iss" in low and "不匹配" in joined:
        out.append(("high", "GPU CC 证明签发者不匹配",
                    f"只接受 {NRAS_ISSUER} 签发的证明"))
    if "aud" in low and "不匹配" in joined:
        out.append(("high", "GPU CC 证明受众不匹配",
                    "校验 aud 为 nras/预期工作负载"))
    if "x-nvidia-ver" in low or "低于下限" in joined:
        out.append(("medium", "GPU CC 证明版本低于基线",
                    "升级 GPU 驱动/固件到支持的最低证明版本"))
    if "kid" in low:
        out.append(("high", "GPU CC 证明缺少 kid/JWKS 密钥",
                    "要求 header.kid 非空且能在 NRAS JWKS 中定位"))
    if "jwks" in low:
        out.append(("high", "NRAS JWKS 结构无效",
                    "校验 JWKS kty/alg/kid；拒绝未知算法"))
    if not out and errors:
        out.append(("high", "GPU CC 证明 claims 校验失败", "拒绝该证明并核对 claims 策略"))
    return out


def run(ctx: dict, params: dict) -> dict:
    doc, source = _load_evidence(params)
    tokens = _token_list(doc)
    if not tokens:
        raise ValueError("证据中没有 token/jwt/overall/tokens")
    jwks, jwks_source = _resolve_jwks(doc.get("jwks") or params.get("jwks"), params)
    nonce = doc.get("expected_nonce") or doc.get("nonce") or params.get("expected_nonce")
    issuer = doc.get("issuer") or params.get("issuer") or NRAS_ISSUER
    audience = doc.get("audience") or params.get("audience") or "nras"
    now = _C.now_ts(params)
    expected_claims = doc.get("expected_claims") or params.get("expected_claims") or {}

    findings: list[dict] = []
    verdicts: list[dict] = []
    claims: dict = {}
    for index, token in enumerate(tokens):
        verdict = online.verify_nvidia_jwt(
            token, jwks, expected_nonce=str(nonce) if nonce is not None else None,
            now=now, issuer=str(issuer), audience=audience,
        )
        checks = {c.get("name"): c.get("ok") for c in getattr(verdict, "checks", [])}
        signature_ok = bool(checks.get("jwt-signature", False))
        claims_ok = bool(checks.get("jwt-claims", False))
        item = {
            "index": index,
            "ok": bool(verdict.ok),
            "signature_valid": signature_ok,
            "claims_valid": claims_ok,
            "jwks_ok": bool(verdict.jwks_ok),
            "errors": list(verdict.errors),
            "claims": dict(verdict.claims),
        }
        verdicts.append(item)
        if verdict.claims:
            claims = claims or dict(verdict.claims)
        if verdict.ok:
            continue
        classified = _classify(verdict.errors)
        if not classified:
            classified = [("high", "GPU CC 证明校验失败", "拒绝该证明")]
        for sev, title, fix in classified:
            findings.append(_C.finding(
                sev, title,
                {"detected": True, "token_index": index, "errors": verdict.errors,
                 "signature_valid": signature_ok, "claims_valid": claims_ok,
                 "jwks_ok": verdict.jwks_ok, "nonce": nonce,
                 "claims": verdict.claims},
                evidence="; ".join(verdict.errors),
                mapping="NVIDIA NRAS attestation JWT / JWKS / EAT claims",
                fix=fix,
            ))

    if not nonce:
        findings.append(_C.finding(
            "medium", "未提供 nonce 期望值（无法验证新鲜性）",
            {"detected": True, "tokens": len(tokens)},
            fix="在证明请求中生成随机 nonce，并校验 JWT 的 eat_nonce",
        ))
    if jwks_source == "cache":
        findings.append(_C.finding(
            "info", "NRAS JWKS 来自本地缓存",
            {"detected": True, "cache": "trident/tee/online_cache"},
            fix="定期刷新 NRAS JWKS；缓存过期时拒绝新证明",
        ))

    actual_claims = dict(claims)
    for key, wanted in (expected_claims or {}).items():
        got = actual_claims.get(key)
        if got != wanted:
            findings.append(_C.finding(
                "high", f"GPU CC claim 与期望值不一致：{key}",
                {"detected": True, "claim": key, "expected": wanted, "actual": got,
                 "claims": actual_claims},
                mapping="NVIDIA attestation claims pinning",
                fix="把设备型号/架构/VBIOS/版本纳入证明策略并拒绝漂移",
            ))

    signature_valid = bool(verdicts) and all(v["signature_valid"] for v in verdicts)
    claims_valid = bool(verdicts) and all(v["claims_valid"] for v in verdicts)
    extra = {
        "tokens": len(tokens),
        "verified": sum(1 for v in verdicts if v["ok"]),
        "signature_valid": signature_valid,
        "claims_valid": claims_valid,
        "nonce_bound": nonce is not None,
        "jwks_source": jwks_source,
        "jwks_keys": len(jwks.get("keys") or []),
        "claims": actual_claims,
        "verdicts": verdicts,
        "gpu_name": actual_claims.get("x-nvidia-gpu-name"),
        "gpu_arch": actual_claims.get("x-nvidia-gpu-arch"),
    }
    summary = _C.summary_json("GPU CC 证明链", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "verdicts": verdicts, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
