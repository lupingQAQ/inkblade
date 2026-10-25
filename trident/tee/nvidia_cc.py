"""NVIDIA Confidential Computing（NRAS）attestation JWT 验证：RS256 + JWKS + claims 校验。

背景：GPU CC 证明（H100/H200/GB200）由 NVIDIA NRAS 签发改 attestation JWT，客户端用 NRAS 的
JWKS（RS256 公钥）验签，再校验 claims。本模块实现**离线**验证路径：

    1. JWS compact 解析（header.payload.signature），header.alg 必须 RS256；
    2. 用 JWKS 中 kid 匹配的 RSA 公钥做 PKCS#1 v1.5 SHA-256 验签；
    3. claims：exp/nbf/iat 时间窗、iss、aud、eat_nonce（nonce 绑定）、
       x-nvidia-overall-att-result=true、dbgstat=disabled、secboot=true、x-nvidia-ver 下限。

**边界**：NRAS 的 JWKS 是公开端点，本仓库用自签 RSA-2048 fixture 模拟（密钥硬编码在
`fixtures.py`，公开可见、仅供测试）。不联网取真实 JWKS，因此「验证通过」只证明解析与验签逻辑正确，
不代表 NVIDIA 真实证明链通过；真实环境应把 `jwks` 换成 https://nras.attestation.nvidia.com 的 JWKS。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from ._asn1 import DerError
from .keys import ALG_RSA_SHA256, PublicKey, b64url_decode

__all__ = ["NvidiaJwt", "NvidiaVerification", "parse_jwt", "verify_jwt", "NvidiaJwtError"]

NRAS_ISSUER = "https://nras.attestation.nvidia.com"
_MIN_VER = (2, 0)


class NvidiaJwtError(ValueError):
    """JWT 结构/编码非法。"""


@dataclass
class NvidiaJwt:
    header: dict
    claims: dict
    signing_input: bytes
    signature: bytes
    raw: str

    @property
    def kid(self) -> str:
        return str(self.header.get("kid") or "")

    @property
    def claim_summary(self) -> dict:
        keep = ("iss", "aud", "sub", "iat", "nbf", "exp", "eat_nonce", "x-nvidia-overall-att-result",
                "x-nvidia-ver", "dbgstat", "secboot", "measres", "x-nvidia-gpu-name",
                "x-nvidia-gpu-arch", "x-nvidia-attestation-type")
        return {k: self.claims.get(k) for k in keep if k in self.claims}


@dataclass
class NvidiaVerification:
    ok: bool
    jwt: NvidiaJwt | None
    signature_valid: bool
    claims_valid: bool
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.ok:
            return "NVIDIA CC JWT 本地验证通过（RS256 验签+claims）"
        return "NVIDIA CC JWT 验证失败：" + "；".join(self.errors)


def _decode_json(segment: str) -> dict:
    try:
        value = json.loads(b64url_decode(segment).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise NvidiaJwtError(f"JWT 段不是合法 JSON：{exc}") from exc
    if not isinstance(value, dict):
        raise NvidiaJwtError("JWT 段必须是 JSON 对象")
    return value


def parse_jwt(token: str) -> NvidiaJwt:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise NvidiaJwtError(f"JWT 必须是 3 段，收到 {len(parts)} 段")
    header = _decode_json(parts[0])
    claims = _decode_json(parts[1])
    signature = b64url_decode(parts[2])
    if header.get("alg") != "RS256":
        raise NvidiaJwtError(f"只接受 RS256，收到 {header.get('alg')!r}")
    if not signature:
        raise NvidiaJwtError("JWT 签名为空")
    return NvidiaJwt(header=header, claims=claims,
                     signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
                     signature=signature, raw=token)


def _select_keys(jwks: dict | list, kid: str) -> list[PublicKey]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else jwks
    if not isinstance(keys, list) or not keys:
        raise NvidiaJwtError("JWKS 中没有 keys")
    candidates = [entry for entry in keys if isinstance(entry, dict)]
    if kid:
        matched = [entry for entry in candidates if entry.get("kid") == kid]
        if matched:
            candidates = matched
    out: list[PublicKey] = []
    for entry in candidates:
        try:
            out.append(PublicKey.from_jwk(entry))
        except (DerError, KeyError, ValueError):
            continue
    if not out:
        raise NvidiaJwtError("JWKS 中没有可用的 RSA 公钥")
    return out


def _version_tuple(text) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(text).split("."))
    except ValueError:
        return (0,)


def verify_jwt(token: str, jwks: dict | list, *, issuer: str | None = NRAS_ISSUER,
               audience: str | list[str] | None = "nras",
               expected_nonce: str | bytes | None = None, now: float | None = None,
               leeway: float = 0.0, min_version: tuple[int, int] = _MIN_VER,
               require_overall: bool = True) -> NvidiaVerification:
    errors: list[str] = []
    try:
        jwt = parse_jwt(token)
    except NvidiaJwtError as exc:
        return NvidiaVerification(ok=False, jwt=None, signature_valid=False,
                                  claims_valid=False, errors=[str(exc)])

    signature_valid = False
    try:
        keys = _select_keys(jwks, jwt.kid)
    except NvidiaJwtError as exc:
        errors.append(str(exc))
        keys = []
    for key in keys:
        if key.verify(ALG_RSA_SHA256, jwt.signing_input, jwt.signature):
            signature_valid = True
            break
    if keys and not signature_valid:
        errors.append("RS256 验签失败（签名或 JWKS 不匹配）")
    if not jwt.kid:
        errors.append("JWT header 缺 kid（无法定位 JWKS 公钥）")

    claims_ok = True
    current = time.time() if now is None else now
    claims = jwt.claims

    def fail(message: str) -> None:
        nonlocal claims_ok
        claims_ok = False
        errors.append(message)

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        fail("claims 缺 exp")
    elif current > exp + leeway:
        fail(f"JWT 已过期（exp={exp}，now={int(current)}）")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and current + leeway < nbf:
        fail(f"JWT 尚未生效（nbf={nbf}）")
    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat > current + leeway + 300:
        fail("iat 在未来（时钟/伪造可疑）")
    if issuer is not None and claims.get("iss") != issuer:
        fail(f"iss 不匹配：{claims.get('iss')!r} != {issuer!r}")
    if audience is not None:
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        expected = audience if isinstance(audience, list) else [audience]
        if not any(item in aud_list for item in expected):
            fail(f"aud 不匹配：{aud!r}")
    if expected_nonce is not None:
        wanted = (expected_nonce.decode("ascii", "replace") if isinstance(expected_nonce, bytes)
                  else str(expected_nonce)).lower()
        got = str(claims.get("eat_nonce") or "").lower()
        if not got:
            fail("claims 缺 eat_nonce")
        elif got != wanted:
            fail("eat_nonce 与期望 nonce 不匹配")
    if require_overall and claims.get("x-nvidia-overall-att-result") is not True:
        fail("x-nvidia-overall-att-result 不为 true")
    if str(claims.get("dbgstat") or "").lower() != "disabled":
        fail(f"dbgstat 非 disabled：{claims.get('dbgstat')!r}")
    if claims.get("secboot") is not True:
        fail("secboot 不为 true")
    if min_version and _version_tuple(claims.get("x-nvidia-ver")) < tuple(min_version):
        fail(f"x-nvidia-ver 低于下限 {min_version}：{claims.get('x-nvidia-ver')!r}")

    ok = signature_valid and claims_ok
    return NvidiaVerification(ok=ok, jwt=jwt, signature_valid=signature_valid,
                              claims_valid=claims_ok, errors=errors)
