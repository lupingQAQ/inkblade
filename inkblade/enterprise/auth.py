# -*- coding: utf-8 -*-
"""OIDC / LDAP 登录适配层（无真实 IdP 时使用本地 mock）。

生产对接要点（不在本文件伪造）：
- OIDC 生产必须 RS256/ES256 + JWKS 轮换 + issuer/audience/nonce/时钟偏差校验；
  本文件的 HS256 仅用于本地契约测试，返回 ``mode=mock-hs256`` 与边界声明。
- LDAP 生产必须 LDAPS/StartTLS + service bind + 组同步；本文件的目录/口令哈希
  仅用于本地 mock，不连接真实目录。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any

DEFAULT_GROUP_ROLES = (
    ("trident-admins", "admin"),
    ("trident-security-owners", "admin"),
    ("trident-leads", "lead"),
    ("trident-testers", "tester"),
    ("trident-auditors", "auditor"),
)
MOCK_BOUNDARY = "本地 mock；不得作为生产身份源/信任链证明"


class AuthError(ValueError):
    """认证失败/令牌非法/目录不可用。"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _key_bytes(key: str | bytes) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else key


def map_groups(groups: list[str], mapping=DEFAULT_GROUP_ROLES) -> tuple[str, bool]:
    """组 → 平台角色；无匹配返回 auditor（最小权限），第二项标记 least_privilege。"""
    wanted = {str(g) for g in groups or []}
    for group, role in mapping:
        if group in wanted:
            return role, False
    return "auditor", True


def session_from_identity(identity: dict, *, store=None, workspaces=("*",),
                          token: str | None = None):
    """把 OIDC/LDAP 身份转成平台 Session（供 API/WebUI 登录接线）。

    注意：审批链的 ``security-owner`` 是**审批角色**，不是平台四角色之一；
    ``trident-admins``/``trident-security-owners`` 组映射到平台 ``admin``，
    调用审批 CLI 时需显式使用 `--as-role security-owner`（见 docs/OPERATIONS.md）。
    """
    from ..core.users import Session

    role = str((identity or {}).get("role") or "")
    subject = str((identity or {}).get("subject") or "")
    if not role or not subject:
        raise AuthError("identity 缺 role/subject，不能建立会话")
    mode = str((identity or {}).get("mode") or "idp")
    return Session(store, f"{mode}:{subject}", role, list(workspaces),
                   token or secrets.token_hex(16))


class OIDCAdapter:
    """OIDC 适配器（mock HS256；生产替换 verify 的算法/JWKS 实现）。"""

    def __init__(self, *, issuer: str, audience: str, secret: str | bytes,
                 group_role_map=DEFAULT_GROUP_ROLES, clock_skew: int = 60,
                 now=lambda: time.time()):
        if not issuer or not audience:
            raise AuthError("issuer/audience 必填")
        self.issuer = issuer
        self.audience = audience
        self.secret = _key_bytes(secret)
        if len(self.secret) < 16:
            raise AuthError("mock secret 至少 16 字节")
        self.group_role_map = tuple(group_role_map)
        self.clock_skew = int(clock_skew)
        self._now = now

    def issue_mock_token(self, subject: str, groups: list[str] | tuple[str, ...] = (),
                         *, ttl: int = 300, nonce: str = "", extra: dict | None = None) -> str:
        if not subject:
            raise AuthError("subject 必填")
        now = int(self._now())
        payload: dict[str, Any] = {
            "iss": self.issuer, "aud": self.audience, "sub": subject,
            "groups": list(groups), "iat": now, "nbf": now - 1, "exp": now + int(ttl),
            "nonce": nonce, "mode": "mock-hs256",
        }
        if extra:
            payload.update(extra)
        header = {"alg": "HS256", "typ": "JWT", "kid": "mock-hs256"}
        signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                         _b64url(json.dumps(payload, separators=(",", ":")).encode()))
        sig = hmac.new(self.secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return signing_input + "." + _b64url(sig)

    def verify(self, token: str, *, audience: str | None = None, nonce: str | None = None) -> dict:
        try:
            header_b64, payload_b64, sig_b64 = str(token).split(".")
        except ValueError as exc:
            raise AuthError("token 不是三段式 JWT") from exc
        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
            sig = _b64url_decode(sig_b64)
        except Exception as exc:  # noqa: BLE001
            raise AuthError(f"token 解码失败：{exc}") from exc
        if header.get("alg") != "HS256":
            raise AuthError(f"不支持的 alg={header.get('alg')!r}（mock 仅 HS256）")
        expect = hmac.new(self.secret, f"{header_b64}.{payload_b64}".encode("ascii"),
                          hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            raise AuthError("签名校验失败")
        if payload.get("iss") != self.issuer:
            raise AuthError("issuer 不匹配")
        aud = payload.get("aud")
        expected_aud = audience or self.audience
        if isinstance(aud, list):
            ok_aud = expected_aud in aud
        else:
            ok_aud = aud == expected_aud
        if not ok_aud:
            raise AuthError("audience 不匹配")
        now = self._now()
        try:
            exp = float(payload.get("exp"))
            nbf = float(payload.get("nbf", 0))
        except (TypeError, ValueError) as exc:
            raise AuthError("exp/nbf 非法") from exc
        if now > exp + self.clock_skew:
            raise AuthError("token 已过期")
        if now + self.clock_skew < nbf:
            raise AuthError("token 尚未生效")
        if nonce is not None and str(payload.get("nonce") or "") != str(nonce):
            raise AuthError("nonce 不匹配")
        groups = [str(g) for g in (payload.get("groups") or [])]
        subject = str(payload.get("sub") or "")
        if not subject:
            raise AuthError("subject 缺失")
        role, least = map_groups(groups, self.group_role_map)
        return {
            "subject": subject,
            "groups": groups,
            "role": role,
            "least_privilege": least,
            "issuer": self.issuer,
            "audience": expected_aud,
            "exp": exp,
            "nonce": str(payload.get("nonce") or ""),
            "mode": "mock-hs256",
            "boundary": MOCK_BOUNDARY,
        }


class MockLDAPDirectory:
    """本地目录：只用于契约测试；口令用 PBKDF2-SHA256 哈希。"""

    def __init__(self, users: list[dict] | None = None):
        self.users: list[dict] = []
        for user in users or []:
            self.add_user(user["dn"], user["password"], user.get("groups") or [],
                          display=user.get("display", ""), disabled=bool(user.get("disabled")))

    def add_user(self, dn: str, password: str, groups: list[str] | tuple[str, ...] = (),
                 *, display: str = "", disabled: bool = False) -> None:
        if not dn or not password:
            raise AuthError("DN/口令必填")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000).hex()
        self.users.append({
            "dn": str(dn), "salt": salt.hex(), "hash": digest,
            "groups": [str(g) for g in groups], "display": display,
            "disabled": bool(disabled),
        })

    def check(self, dn: str, password: str) -> dict | None:
        for user in self.users:
            if user["dn"].lower() != dn.lower():
                continue
            if user["disabled"]:
                return None
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                         bytes.fromhex(user["salt"]), 120_000).hex()
            if not hmac.compare_digest(digest, user["hash"]):
                return None
            return user
        return None

    def by_uid(self, uid: str) -> dict | None:
        matches = [u for u in self.users
                   if _uid_of_dn(u["dn"]).lower() == uid.lower() and not u["disabled"]]
        return matches[0] if len(matches) == 1 else None


_UID_RE = re.compile(r"^\s*(?:uid|cn)=([^,]+)", re.I)
_LDAP_UNSAFE = re.compile(r"[*()\\\x00]")


def _uid_of_dn(dn: str) -> str:
    m = _UID_RE.match(str(dn or ""))
    return m.group(1).strip() if m else ""


class LDAPAdapter:
    """LDAP 适配器（mock 目录；生产替换为 LDAPS bind + 组查询）。"""

    def __init__(self, directory: MockLDAPDirectory | str | Path,
                 group_role_map=DEFAULT_GROUP_ROLES):
        if isinstance(directory, (str, Path)):
            data = json.loads(Path(directory).read_text(encoding="utf-8"))
            directory = MockLDAPDirectory(data.get("users") or [])
        self.directory = directory
        self.group_role_map = tuple(group_role_map)

    def authenticate(self, username: str, password: str) -> dict:
        if not username or not password:
            raise AuthError("用户名/口令必填")
        if _LDAP_UNSAFE.search(username) or "\x00" in password:
            raise AuthError("用户名/口令含 LDAP 注入字符")
        if "," in username or "=" in username:
            raise AuthError("仅接受 uid，不接受 DN/过滤器表达式")
        user = self.directory.by_uid(username)
        if user is None:
            raise AuthError("用户不存在或已禁用")
        checked = self.directory.check(user["dn"], password)
        if checked is None:
            raise AuthError("口令错误或用户已禁用")
        groups = list(checked.get("groups") or [])
        role, least = map_groups(groups, self.group_role_map)
        return {
            "subject": username,
            "dn": checked["dn"],
            "display": checked.get("display", ""),
            "groups": groups,
            "role": role,
            "least_privilege": least,
            "mode": "mock-ldap",
            "boundary": MOCK_BOUNDARY,
        }
