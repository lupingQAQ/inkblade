"""私有零日武器库：加密存储 + 工作区级启用闸门（lead 审批）+ 模块隐藏过滤。

加密：优先 AES-256-GCM（若安装 cryptography）；否则 scrypt 派生密钥 + BLAKE2b 计数器密钥流 XOR + HMAC-SHA256
（显式降级：静态保护等级=混淆，文档需标注；升级路径=安装 cryptography）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore
from .roe import allowed, roe_status


class ZerodayLocked(Exception):
    """零日未启用/角色不足/级别不足。"""


# ---------- 加密信封 ----------
def _aes_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

        return True
    except Exception:
        return False


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.blake2b(key + nonce + counter.to_bytes(8, "big"), digest_size=64).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    if _aes_available():
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt = secrets.token_bytes(16)
        dk = hashlib.scrypt(key, salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        aes = AESGCM(dk)
        nonce = secrets.token_bytes(12)
        body = aes.encrypt(nonce, plaintext, b"trident-zeroday")
        return b"TRZD-AESGCM" + salt + nonce + body
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(key, salt=salt, n=2 ** 14, r=8, p=1, dklen=64)
    enc_key, mac_key = dk[:32], dk[32:]
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return b"TRZD-SCRYP" + salt + nonce + tag + ct


def _decrypt(key: bytes, blob: bytes) -> bytes:
    if blob.startswith(b"TRZD-AESGCM"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt, nonce, body = blob[10:26], blob[26:38], blob[38:]
        dk = hashlib.scrypt(key, salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        return AESGCM(dk).decrypt(nonce, body, b"trident-zeroday")
    salt, nonce, tag, ct = blob[10:26], blob[26:42], blob[42:74], blob[74:]
    dk = hashlib.scrypt(key, salt=salt, n=2 ** 14, r=8, p=1, dklen=64)
    enc_key, mac_key = dk[:32], dk[32:]
    expect = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise ValueError("zeroday store: 认证失败（密钥错误或数据被篡改）")
    return bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct))))


class ZerodayStore:
    def __init__(self, path: Path | str, key: bytes):
        self.path = Path(path)
        (self.path / "entries").mkdir(parents=True, exist_ok=True)
        self.key = key

    def put(self, entry_key: str, data: dict[str, Any]) -> None:
        blob = _encrypt(self.key, json.dumps(data, ensure_ascii=False).encode("utf-8"))
        (self.path / "entries" / f"{entry_key}.enc").write_bytes(blob)

    def get(self, entry_key: str) -> dict[str, Any]:
        f = self.path / "entries" / f"{entry_key}.enc"
        if not f.exists():
            raise KeyError(entry_key)
        return json.loads(_decrypt(self.key, f.read_bytes()).decode("utf-8"))

    def registry(self) -> str:
        """登记册（状态/版本），不含 PoC 细节。"""
        lines = ["# 零日登记册", "", "| 条目 | 状态 |", "|---|---|"]
        for f in sorted((self.path / "entries").glob("*.enc")):
            lines.append(f"| {f.stem} | 未披露（私有库） |")
        return "\n".join(lines) + "\n"


# ---------- 启用闸门 ----------
def _config(store: EvidenceStore) -> dict:
    p = store.ws_dir / "workspace.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def zeroday_enabled(store: EvidenceStore) -> bool:
    return bool(_config(store).get("zeroday", {}).get("enabled"))


def enable(store: EvidenceStore, session) -> None:
    if not session.can("approve-zeroday"):
        raise PermissionError(f"{session.name}({session.role}) 无 approve-zeroday 权限")
    cfg = _config(store)
    cfg.setdefault("zeroday", {})["enabled"] = True
    cfg["zeroday"]["enabled_by"] = session.name
    (store.ws_dir / "workspace.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def assert_allowed(store: EvidenceStore, session, meta: dict) -> None:
    if not zeroday_enabled(store):
        raise ZerodayLocked("工作区未启用零日（需 lead 审批 enable）")
    if not session.can("execute"):
        raise ZerodayLocked("角色无执行权限")
    cfg = _config(store).get("zeroday", {})
    roe_level = (store.consent() or {}).get("fields", {}).get("level", "只读侦察")
    need = meta.get("min_level", "只读侦察")
    if not allowed(need, roe_level):
        raise ZerodayLocked(f"级别不足：需 {need}，授权为 {roe_level}")


def filter_modules(mods: dict[str, dict], store: EvidenceStore) -> dict[str, dict]:
    if zeroday_enabled(store):
        return dict(mods)
    return {k: v for k, v in mods.items() if not v.get("private")}
