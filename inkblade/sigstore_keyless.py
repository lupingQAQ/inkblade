# -*- coding: utf-8 -*-
"""Sigstore keyless（cosign 风格）：Fulcio 证书 + Rekor 透明日志 + OIDC 身份。

本模块只依赖标准库，复用 `trident.tee.keys/x509/_asn1` 的 EC/RSA 与 DER 实现。

两种运行模式（**结果必须如实标注**）：

1. ``mode="live"``：调用 Sigstore 公共实例
   - Fulcio ``POST /api/v2/signingCert``（需要 OIDC identity token）
   - Rekor ``POST /api/v1/log/entries``（hashedrekord）
   本仓库的自动化测试不依赖网络；`docs/KEYLESS-VERIFICATION.md` 记录 2026-10-25
   的真实 Rekor 上传/验签与公共 keyless 条目验证。
2. ``mode="fixture"``：本地 Fulcio 兼容 CA + 本地 Rekor fixture。
   **不是生产信任链**，只用于离线单测与无 OIDC 环境的降级演示。

验证覆盖：
- artifact SHA-256 与 messageSignature 摘要一致；
- ECDSA 签名对 artifact 验签；
- leaf → 中间 → Fulcio 根证书链（pinned 根、有效期、CA 位、签名）；
- SAN 身份（email/URI）与 Fulcio OIDC issuer 扩展（1.3.6.1.4.1.57264.1.8 / .1.1）；
- Rekor canonicalizedBody 的 artifact 哈希/签名/证书三元组；
- Rekor logID = SHA-256(log public key SPKI)；
- SET（signedEntryTimestamp）JCS 规范化 JSON 验签；
- RFC6962 inclusion proof（递归按 treeSize 分片）；
- checkpoint note 签名（4 字节 key hint + DER ECDSA）；
- 可选在线重取 Rekor 条目比对；
- 可选吊销 serial 列表（离线 CRL/策略输入）与证书有效期。

公开 API：
    keyless_sign(artifact, ...) -> bundle
    keyless_verify(artifact, bundle, ...) -> verdict
    build_fixture_authority(...) -> FixtureAuthority
    bundle_from_rekor_entry(entry, artifact=None, uuid="") -> bundle
    upload_rekor_hashedrekord(...) -> dict
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .tee._asn1 import (DerError, bit_string, decode_oid, encode, integer, oid, read_tlv,
                        seq, set_of, utf8)
from .tee.keys import (ALG_ECDSA_SHA256, CURVES, PrivateKey, PublicKey,
                       b64url_decode, b64url_encode, load_pem_blocks, pem_wrap)
from .tee.x509 import Certificate, build_certificate, parse_certificate, verify_chain

__all__ = [
    "BUNDLE_MEDIA_TYPE", "DEFAULT_FULCIO_URL", "DEFAULT_REKOR_URL", "SigstoreError",
    "keyless_sign", "keyless_verify", "build_fixture_authority", "FixtureAuthority",
    "bundle_from_rekor_entry", "upload_rekor_hashedrekord", "fetch_trust_bundle",
    "fetch_rekor_log", "load_trust_bundle", "load_rekor_log", "sha256_hex",
]

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
_DATA = Path(__file__).resolve().parent / "data" / "sigstore"
_CACHE_TRUST = _DATA / "fulcio_trust_bundle.json"
_CACHE_LOG = _DATA / "rekor_log.json"
_CACHE_LOG_KEY = _DATA / "rekor_public_key.pem"
OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
_HASH_ALGS = {"sha256": "sha256", "SHA2_256": "sha256"}


class SigstoreError(ValueError):
    """Sigstore 输入/网络/格式错误。"""


# ---------------------------------------------------------------- 基础工具

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _canonical_json(payload: Any) -> bytes:
    """RFC 8785 风格的最小 JCS：键排序、无空格、UTF-8。Rekor SET 用此规范化。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _normalize_log_id(value: str) -> str:
    """Rekor logID：API 用 hex，Sigstore bundle v0.3 用 base64 bytes。"""
    text = str(value or "")
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return text.lower()
    try:
        return _unb64(text).hex()
    except Exception:
        return text


def _default_http(method: str, url: str, body: bytes | None = None,
                  headers: dict | None = None, timeout: float = 30) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except urllib.error.URLError as exc:
        raise SigstoreError(f"网络不可达 {url}: {exc.reason}") from exc


Http = Callable[..., tuple[int, dict, bytes]]


def _get_json(url: str, *, http: Http | None = None, timeout: float = 30) -> Any:
    status, _, body = (http or _default_http)("GET", url, None, {}, timeout)
    if status != 200:
        raise SigstoreError(f"GET {url} -> HTTP {status}: {body[:200]!r}")
    return json.loads(body)


def fetch_trust_bundle(fulcio_url: str = DEFAULT_FULCIO_URL, *,
                       http: Http | None = None, timeout: float = 30) -> dict:
    return _get_json(fulcio_url.rstrip("/") + "/api/v2/trustBundle",
                     http=http, timeout=timeout)


def fetch_rekor_log(rekor_url: str = DEFAULT_REKOR_URL, *,
                    http: Http | None = None, timeout: float = 30) -> dict:
    return _get_json(rekor_url.rstrip("/") + "/api/v1/log", http=http, timeout=timeout)


def fetch_rekor_public_key(rekor_url: str = DEFAULT_REKOR_URL, *,
                           http: Http | None = None, timeout: float = 30) -> str:
    status, _, body = (http or _default_http)(
        "GET", rekor_url.rstrip("/") + "/api/v1/log/publicKey", None, {}, timeout)
    if status != 200:
        raise SigstoreError(f"GET rekor publicKey -> HTTP {status}")
    return body.decode("ascii")


def load_trust_bundle(doc: dict | str | Path | None = None) -> dict:
    if doc is None:
        path = _CACHE_TRUST
        return json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        return copy.deepcopy(doc)
    path = Path(doc)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    raise SigstoreError(f"trust bundle 不存在: {doc}")


def load_rekor_log(doc: dict | str | Path | None = None) -> dict:
    if doc is None:
        return json.loads(_CACHE_LOG.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        return copy.deepcopy(doc)
    return json.loads(Path(doc).read_text(encoding="utf-8"))


def load_rekor_public_key(value: str | Path | None = None) -> PublicKey:
    if value is None:
        return PublicKey.from_pem(_CACHE_LOG_KEY.read_text(encoding="utf-8"))
    if isinstance(value, Path) or (isinstance(value, str) and "\n" not in value
                                    and Path(value).is_file()):
        return PublicKey.from_pem(Path(value).read_text(encoding="utf-8"))
    return PublicKey.from_pem(value)


# ---------------------------------------------------------------- X.509 扩展解析

def _cert_tbs_parts(der: bytes) -> tuple[bytes, bytes]:
    tag, cert_body, end = read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise SigstoreError("证书不是单个 SEQUENCE")
    tag, tbs_value, _ = read_tlv(cert_body, 0)
    if tag != 0x30:
        raise SigstoreError("tbsCertificate 非 SEQUENCE")
    return tbs_value, cert_body


def _extensions(der: bytes) -> dict[str, bytes]:
    tbs, _ = _cert_tbs_parts(der)
    off = 0
    if tbs and tbs[0] == 0xA0:
        _, _, off = read_tlv(tbs, off)
    for _ in range(6):  # serial / sigalg / issuer / validity / subject / spki
        _, _, off = read_tlv(tbs, off)
    out: dict[str, bytes] = {}
    while off < len(tbs):
        tag, value, off = read_tlv(tbs, off)
        if tag != 0xA3:
            continue
        _, exts, _ = read_tlv(value, 0)
        eoff = 0
        while eoff < len(exts):
            _, ext, eoff = read_tlv(exts, eoff)
            _, ext_oid_raw, xoff = read_tlv(ext, 0)
            ext_oid = decode_oid(ext_oid_raw)
            tag2, value2, xoff2 = read_tlv(ext, xoff)
            if tag2 == 0x01:  # critical BOOLEAN
                tag2, value2, xoff2 = read_tlv(ext, xoff2)
            if tag2 == 0x04:
                out[ext_oid] = value2
    return out


def _san_values(der: bytes) -> list[tuple[str, str]]:
    raw = _extensions(der).get(OID_SAN)
    if not raw:
        return []
    _, names, _ = read_tlv(raw, 0)
    out = []
    off = 0
    while off < len(names):
        tag, value, off = read_tlv(names, off)
        kind = {0x81: "email", 0x82: "dns", 0x86: "uri"}.get(tag)
        if kind:
            out.append((kind, value.decode("utf-8", "replace")))
    return out


def _ext_text(der: bytes, dotted_oid: str) -> str:
    raw = _extensions(der).get(dotted_oid)
    if not raw:
        return ""
    try:
        tag, value, _ = read_tlv(raw, 0)
        if tag == 0x04:  # 某些 Fulcio 版本把 UTF8String 再包一层
            tag, value, _ = read_tlv(value, 0)
        return value.decode("utf-8") if tag == 0x0C else ""
    except DerError:
        return ""


def cert_identity(cert: Certificate) -> dict:
    sans = _san_values(cert.der)
    issuer = (_ext_text(cert.der, OID_FULCIO_ISSUER_V2)
              or _ext_text(cert.der, OID_FULCIO_ISSUER_V1))
    return {
        "subject_cn": cert.subject_cn,
        "issuer_cn": cert.issuer_cn,
        "sans": [{"kind": k, "value": v} for k, v in sans],
        "oidc_issuer": issuer,
        "serial": cert.serial,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
    }


# ---------------------------------------------------------------- Fixture CA

def _name_der(cn: str) -> bytes:
    return seq(set_of(seq(oid("2.5.4.3"), utf8(cn))))


def _extension(dotted_oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [oid(dotted_oid)]
    if critical:
        parts.append(b"\x01\x01\xff")
    parts.append(encode(0x04, value))
    return seq(*parts)


def _build_leaf(*, subject_cn: str, issuer_name_der: bytes, public_key: PublicKey,
                signer: PrivateKey, serial: int, not_before: datetime,
                not_after: datetime, identity: str, issuer: str,
                basic_constraints_ca: bool = False) -> Certificate:
    sig_alg = ALG_ECDSA_SHA256 if public_key.curve == "P-256" else \
        "1.2.840.10045.4.3.3"
    alg_id = seq(oid(sig_alg))
    bc_value = seq(b"\x01\x01\xff" if basic_constraints_ca else b"")
    extensions = [
        _extension(OID_BASIC_CONSTRAINTS, bc_value, critical=True),
    ]
    if identity:
        san = seq(encode(0x81, identity.encode("utf-8")))
        extensions.append(_extension(OID_SAN, san))
    if issuer:
        extensions.append(_extension(OID_FULCIO_ISSUER_V2, utf8(issuer)))
    tbs = seq(
        encode(0xA0, integer(2)),
        integer(serial),
        alg_id,
        issuer_name_der,
        seq(encode(0x17, not_before.strftime("%y%m%d%H%M%SZ").encode()),
            encode(0x17, not_after.strftime("%y%m%d%H%M%SZ").encode())),
        _name_der(subject_cn),
        public_key.to_spki_der(),
        encode(0xA3, seq(*extensions)),
    )
    signature = signer.sign(sig_alg, tbs)
    return parse_certificate(seq(tbs, alg_id, bit_string(signature)))


def _det_private(curve: str, seed: str) -> PrivateKey:
    c = CURVES[curve]
    d = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") % c.n
    return PrivateKey(kind="ec", curve=curve, d=d or 1)


@dataclass
class FixtureAuthority:
    """本地 Fulcio 兼容 CA + Rekor fixture 日志（固定测试密钥，绝不用于生产）。"""

    root: Certificate
    root_key: PrivateKey
    intermediate: Certificate
    intermediate_key: PrivateKey
    log_key: PrivateKey
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def log_id(self) -> str:
        return sha256_hex(self.log_key.public_key().to_spki_der())

    @property
    def root_pem(self) -> str:
        return self.root.to_pem()

    def issue(self, public_key: PublicKey, *, identity: str, issuer: str,
              not_before: datetime | None = None, not_after: datetime | None = None,
              serial: int | None = None) -> Certificate:
        nb = not_before or (self.now - timedelta(minutes=5))
        na = not_after or (self.now + timedelta(hours=1))
        return _build_leaf(
            subject_cn="", issuer_name_der=seq(self.intermediate.subject_raw),
            public_key=public_key, signer=self.intermediate_key,
            serial=serial if serial is not None else secrets.randbits(63),
            not_before=nb, not_after=na, identity=identity, issuer=issuer)

    def trust_bundle(self) -> dict:
        return {"chains": [{"certificates": [self.intermediate.to_pem(),
                                             self.root.to_pem()]}]}


def build_fixture_authority(*, now: datetime | None = None,
                            seed: str = "trident-sigstore-fixture-2026-10") -> FixtureAuthority:
    now = now or datetime.now(timezone.utc)
    root_key = _det_private("P-256", seed + ":root")
    int_key = _det_private("P-256", seed + ":intermediate")
    log_key = _det_private("P-256", seed + ":rekor")
    root = build_certificate(
        subject="Trident Fixture Fulcio Root", issuer="Trident Fixture Fulcio Root",
        public_key=root_key.public_key(), signer=root_key.sign, serial=1,
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=365),
        is_ca=True)
    intermediate = build_certificate(
        subject="Trident Fixture Fulcio Intermediate",
        issuer="Trident Fixture Fulcio Root",
        public_key=int_key.public_key(), signer=root_key.sign, serial=2,
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=365),
        is_ca=True)
    return FixtureAuthority(root=root, root_key=root_key, intermediate=intermediate,
                            intermediate_key=int_key, log_key=log_key, now=now)


# ---------------------------------------------------------------- Rekor 条目

def _rekor_body(artifact_sha: str, signature: bytes, cert_or_key_pem: str) -> bytes:
    body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": artifact_sha}},
            "signature": {
                "content": _b64(signature),
                "publicKey": {"content": _b64(cert_or_key_pem.encode("utf-8"))},
            },
        },
    }
    return _canonical_json(body)


def _set_payload(body_b64: str, integrated_time: int, log_id: str, log_index: int) -> bytes:
    return _canonical_json({"body": body_b64, "integratedTime": integrated_time,
                            "logID": log_id, "logIndex": log_index})


def _checkpoint(origin: str, log_key: PrivateKey, tree_size: int, root_hash: str) -> str:
    root_b64 = _b64(bytes.fromhex(root_hash))
    text = f"{origin} - {int(sha256_hex(log_key.public_key().to_spki_der())[:16], 16)}\n" \
           f"{tree_size}\n{root_b64}\n"
    sig = log_key.sign(ALG_ECDSA_SHA256, text.encode("utf-8"))
    hint = bytes.fromhex(sha256_hex(log_key.public_key().to_spki_der()))[:4]
    return text + "\n\u2014 " + origin + " " + _b64(hint + sig) + "\n"


def _tlog_entry(*, body: bytes, log_key: PrivateKey, log_id: str, log_index: int,
                integrated_time: int, tree_size: int, root_hash: str,
                hashes: list[str], checkpoint: str, set_sig: bytes) -> dict:
    return {
        "logIndex": log_index,
        "logId": {"keyId": _b64(bytes.fromhex(log_id))},
        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
        "integratedTime": integrated_time,
        "inclusionPromise": {"signedEntryTimestamp": _b64(set_sig)},
        "inclusionProof": {
            "logIndex": log_index,
            "rootHash": root_hash,
            "treeSize": tree_size,
            "hashes": hashes,
            "checkpoint": checkpoint,
        },
        "canonicalizedBody": _b64(body),
    }


def _make_bundle(artifact: bytes, signature: bytes, cert_chain: list[Certificate],
                 log_key: PrivateKey, log_id: str, integrated_time: int,
                 log_index: int = 1, tree_size: int = 1, root_hash: str | None = None,
                 hashes: list[str] | None = None, checkpoint: str | None = None,
                 mode: str = "fixture", extra: dict | None = None) -> dict:
    body = _rekor_body(sha256_hex(artifact), signature,
                       cert_chain[0].to_pem() if cert_chain else "")
    body_b64 = _b64(body)
    root = root_hash or sha256_hex(b"\x00" + body)
    hashes = hashes or []
    cp = checkpoint or _checkpoint("fixture.rekor.local", log_key, tree_size, root)
    set_sig = log_key.sign(ALG_ECDSA_SHA256,
                           _set_payload(body_b64, integrated_time, log_id, log_index))
    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [{"rawBytes": _b64(c.der)} for c in cert_chain]
            },
            "tlogEntries": [_tlog_entry(body=body, log_key=log_key, log_id=log_id,
                                        log_index=log_index, integrated_time=integrated_time,
                                        tree_size=tree_size, root_hash=root,
                                        hashes=hashes, checkpoint=cp, set_sig=set_sig)],
        },
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256",
                              "digest": _b64(hashlib.sha256(artifact).digest())},
            "signature": _b64(signature),
        },
        "trident": {"mode": mode},
    }
    if extra:
        bundle["trident"].update(extra)
    return bundle


def upload_rekor_hashedrekord(artifact: bytes, private_key: PrivateKey, *,
                              cert_pem: str = "", public_key_pem: str = "",
                              rekor_url: str = DEFAULT_REKOR_URL,
                              http: Http | None = None,
                              timeout: float = 30) -> dict:
    """向 Rekor v1 上传 hashedrekord。cert_pem 优先（keyless）；否则用公钥（key-based）。"""
    signature = private_key.sign(ALG_ECDSA_SHA256, artifact)
    material = cert_pem or public_key_pem or pem_wrap(
        private_key.public_key().to_spki_der(), "PUBLIC KEY")
    body = _rekor_body(sha256_hex(artifact), signature, material)
    payload = json.loads(body)
    status, _, raw = (http or _default_http)(
        "POST", rekor_url.rstrip("/") + "/api/v1/log/entries",
        json.dumps(payload).encode("utf-8"), {"Content-Type": "application/json"}, timeout)
    if status not in (200, 201):
        raise SigstoreError(f"Rekor 上传失败 HTTP {status}: {raw[:400]!r}")
    data = json.loads(raw)
    uuid = next(iter(data))
    entry = data[uuid]
    return {"uuid": uuid, "entry": entry, "body": body, "signature": signature,
            "material": material}


def bundle_from_rekor_entry(entry: dict, *, artifact: bytes | None = None,
                            uuid: str = "", log_key_pem: str | None = None,
                            rekor_url: str = DEFAULT_REKOR_URL) -> dict:
    """把 Rekor API 条目转换为本模块 bundle（用于验证公共日志中的真实条目）。"""
    body = _unb64(entry["body"])
    doc = json.loads(body)
    spec = doc.get("spec") or {}
    signature = _unb64((spec.get("signature") or {}).get("content") or "")
    material_b64 = ((spec.get("signature") or {}).get("publicKey") or {}).get("content") or ""
    material = _unb64(material_b64).decode("utf-8") if material_b64 else ""
    digest = ((spec.get("data") or {}).get("hash") or {}).get("value") or ""
    verify_material: dict = {"tlogEntries": [{
        "logIndex": entry["logIndex"],
        "logId": {"keyId": entry["logID"]},
        "kindVersion": {"kind": doc.get("kind", "hashedrekord"),
                        "version": doc.get("apiVersion", "0.0.1")},
        "integratedTime": entry["integratedTime"],
        "inclusionPromise": entry.get("verification", {}).get("inclusionPromise"),
        "inclusionProof": entry.get("verification", {}).get("inclusionProof"),
        "canonicalizedBody": entry["body"],
    }]}
    if entry.get("verification", {}).get("signedEntryTimestamp"):
        verify_material["tlogEntries"][0]["inclusionPromise"] = {
            "signedEntryTimestamp": entry["verification"]["signedEntryTimestamp"]}
    if "BEGIN CERTIFICATE" in material:
        certs = load_pem_blocks(material, "CERTIFICATE")
        verify_material["x509CertificateChain"] = {
            "certificates": [{"rawBytes": _b64(der)} for der in certs]}
    elif material:
        verify_material["publicKey"] = {"hint": _b64(material.encode("utf-8"))}
    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": verify_material,
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256",
                              "digest": _b64(bytes.fromhex(digest)) if digest else ""},
            "signature": _b64(signature),
        },
        "trident": {"mode": "rekor-import", "rekor_uuid": uuid,
                    "rekor_url": rekor_url},
    }
    if artifact is not None:
        bundle["trident"]["artifact_sha256"] = sha256_hex(artifact)
    return bundle


# ---------------------------------------------------------------- 签名

def keyless_sign(artifact: bytes, *, identity_token: str | None = None,
                 fulcio_url: str = DEFAULT_FULCIO_URL,
                 rekor_url: str = DEFAULT_REKOR_URL,
                 identity: str = "fixture@trident.local",
                 issuer: str = "https://fixture.trident.local",
                 private_key: PrivateKey | None = None,
                 authority: FixtureAuthority | None = None,
                 upload: bool = True, live_rekor_key_entry: bool = False,
                 http: Http | None = None, now: datetime | None = None,
                 timeout: float = 30) -> dict:
    """生成 keyless bundle。

    - 有 OIDC token：Fulcio 公共实例签发证书 + Rekor 公共实例上传（live）。
    - 无 token：本地 Fulcio 兼容 CA + 本地 Rekor fixture（fixture，不上传）。
    - ``live_rekor_key_entry=True``：无 token 时额外向公共 Rekor 上传 **key-based**
      hashedrekord（证明真实日志可写/可验，但**不是 keyless**，bundle 单独返回）。
    """
    now = now or datetime.now(timezone.utc)
    key = private_key or PrivateKey(kind="ec", curve="P-256",
                                    d=secrets.randbelow(CURVES["P-256"].n - 1) + 1)
    artifact = bytes(artifact)
    extras: dict = {"artifact_sha256": sha256_hex(artifact),
                    "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}

    if identity_token:
        # Fulcio v2：PoP 对 SPKI DER 签名；不同部署对 content 的 PEM/DER 约定略有差异，
        # 这里按 v2 规范发送 DER base64，并在错误信息中保留响应体。
        spki = key.public_key().to_spki_der()
        pop = key.sign(ALG_ECDSA_SHA256, spki)
        req = {
            "credentials": {"oidcIdentityToken": identity_token},
            "publicKeyRequest": {
                "publicKey": {"algorithm": "ECDSA", "content": _b64(spki)},
                "proofOfPossession": _b64(pop),
            },
        }
        status, _, raw = (http or _default_http)(
            "POST", fulcio_url.rstrip("/") + "/api/v2/signingCert",
            json.dumps(req).encode(), {"Content-Type": "application/json",
                                       "Authorization": f"Bearer {identity_token}"}, timeout)
        if status not in (200, 201):
            raise SigstoreError(f"Fulcio 签发失败 HTTP {status}: {raw[:400]!r}")
        doc = json.loads(raw)
        signed = doc.get("signedCertificateEmbeddedSct") or doc.get("signedCertificateDetachedSct") or {}
        chain = ((signed.get("chain") or {}).get("certificates") or [])
        if not chain:
            raise SigstoreError("Fulcio 响应缺少证书链")
        certs = [parse_certificate(der) for der in load_pem_blocks("\n".join(chain), "CERTIFICATE")]
        if upload:
            up = upload_rekor_hashedrekord(artifact, key, cert_pem=certs[0].to_pem(),
                                           rekor_url=rekor_url, http=http, timeout=timeout)
            bundle = bundle_from_rekor_entry(up["entry"], artifact=artifact,
                                             uuid=up["uuid"], rekor_url=rekor_url)
            # Rekor body 只带 leaf 证书；把 Fulcio 返回的完整链一并放入 bundle
            bundle["verificationMaterial"]["x509CertificateChain"] = {
                "certificates": [{"rawBytes": _b64(c.der)} for c in certs]}
            bundle["trident"].update({**extras, "mode": "live",
                                      "rekor_uuid": up["uuid"],
                                      "rekor_url": rekor_url,
                                      "fulcio_url": fulcio_url})
            return bundle
        # 不上传 Rekor：只有 Fulcio 证书 + 签名（透明日志缺失，验证会明确失败）
        return _make_bundle(artifact, key.sign(ALG_ECDSA_SHA256, artifact), certs,
                            _det_private("P-256", "no-log"), "0" * 64,
                            int(now.timestamp()), mode="live-no-tlog", extra=extras)

    auth = authority or build_fixture_authority(now=now)
    leaf = auth.issue(key.public_key(), identity=identity, issuer=issuer,
                      not_before=now - timedelta(minutes=5),
                      not_after=now + timedelta(hours=1))
    sig = key.sign(ALG_ECDSA_SHA256, artifact)
    bundle = _make_bundle(artifact, sig, [leaf, auth.intermediate], auth.log_key,
                          auth.log_id, int(now.timestamp()), mode="fixture",
                          extra={**extras, "identity": identity, "issuer": issuer,
                                 "fulcio": "fixture-ca", "rekor": "fixture-log",
                                 "trust_bundle": auth.trust_bundle(),
                                 "rekor_public_key": pem_wrap(
                                     auth.log_key.public_key().to_spki_der(), "PUBLIC KEY")})
    if live_rekor_key_entry:
        up = upload_rekor_hashedrekord(artifact, key, rekor_url=rekor_url,
                                       http=http, timeout=timeout)
        bundle["trident"]["rekor_live_key_entry"] = {
            "uuid": up["uuid"], "logIndex": up["entry"]["logIndex"],
            "integratedTime": up["entry"]["integratedTime"],
            "url": f"{rekor_url.rstrip('/')}/api/v1/log/entries/{up['uuid']}",
            "note": "key-based hashedrekord（public key），不是 Fulcio keyless",
        }
    return bundle


# ---------------------------------------------------------------- 验证

def _verify_set(entry: dict, log_key: PublicKey) -> tuple[bool, str]:
    promise = entry.get("inclusionPromise") or {}
    set_b64 = promise.get("signedEntryTimestamp") or entry.get("signedEntryTimestamp") or ""
    if not set_b64:
        return False, "缺少 SET"
    body_b64 = entry.get("canonicalizedBody") or ""
    log_index = entry.get("logIndex")
    integrated = entry.get("integratedTime")
    log_id = _normalize_log_id((entry.get("logId") or {}).get("keyId") or "")
    if not log_id:
        return False, "SET 字段不完整"
    if not body_b64 or log_index is None or integrated is None:
        return False, "SET 字段不完整"
    payload = _set_payload(body_b64, int(integrated), log_id, int(log_index))
    try:
        ok = log_key.verify(ALG_ECDSA_SHA256, payload, _unb64(set_b64))
    except Exception as exc:  # noqa: BLE001
        return False, f"SET 解码失败: {exc}"
    return ok, "SET 签名有效" if ok else "SET 签名无效"


def _calc_merkle_root(leaf: bytes, index: int, tree_size: int,
                      hashes: list[bytes]) -> bytes:
    """RFC6962 审计路径：自顶向下按 treeSize 分片，最后一个 hash 是本层兄弟。"""
    if tree_size <= 1:
        return leaf
    if not hashes:
        raise SigstoreError("inclusion proof 哈希不足")
    k = 1
    while k * 2 < tree_size:
        k *= 2
    sibling = hashes[-1]
    rest = hashes[:-1]
    if index < k:
        child = _calc_merkle_root(leaf, index, k, rest)
        return hashlib.sha256(b"\x01" + child + sibling).digest()
    child = _calc_merkle_root(leaf, index - k, tree_size - k, rest)
    return hashlib.sha256(b"\x01" + sibling + child).digest()


def _verify_checkpoint(checkpoint: str, log_key: PublicKey, tree_size: int,
                       root_hex: str) -> tuple[bool, str]:
    if not checkpoint:
        return False, "缺少 checkpoint"
    lines = checkpoint.splitlines()
    if len(lines) < 4:
        return False, "checkpoint 行数不足"
    sig_line = next((ln for ln in lines if ln.startswith("\u2014") or ln.startswith("—")), "")
    if not sig_line:
        return False, "checkpoint 缺签名行"
    body_lines = [ln for ln in lines[:lines.index(sig_line)] if ln.strip()]
    if len(body_lines) < 3:
        return False, "checkpoint 正文不足"
    body = "\n".join(body_lines[:3]) + "\n"
    try:
        size = int(body_lines[1].strip())
        root_b64 = body_lines[2].strip()
        root = _unb64(root_b64)
    except Exception as exc:  # noqa: BLE001
        return False, f"checkpoint 解析失败: {exc}"
    if size != int(tree_size) or root.hex() != root_hex.lower():
        return False, "checkpoint 的 treeSize/rootHash 与 inclusion proof 不一致"
    token = sig_line.split()[-1]
    try:
        sig = _unb64(token)
    except Exception as exc:  # noqa: BLE001
        return False, f"checkpoint 签名解码失败: {exc}"
    if len(sig) < 8:
        return False, "checkpoint 签名过短"
    ok = log_key.verify(ALG_ECDSA_SHA256, body.encode("utf-8"), sig[4:])
    return ok, "checkpoint note 签名有效" if ok else "checkpoint note 签名无效"


def _trust_roots(bundle: dict) -> tuple[list[Certificate], list[Certificate]]:
    certs: list[Certificate] = []
    for chain in bundle.get("chains") or []:
        pem = "\n".join(chain.get("certificates") or [])
        certs.extend(parse_certificate(der) for der in load_pem_blocks(pem, "CERTIFICATE"))
    roots = [c for c in certs if c.is_ca and c.verify_self_signed()]
    intermediates = [c for c in certs if c.is_ca and not c.verify_self_signed()]
    return roots, intermediates


def _match_identity(cert: Certificate, identity: str | None,
                    identity_regex: str | None) -> tuple[bool, str]:
    sans = [v for _, v in _san_values(cert.der)]
    if not identity and not identity_regex:
        return True, "未指定身份（仅校验链）"
    if identity_regex:
        try:
            ok = any(re.fullmatch(identity_regex, value) for value in sans)
        except re.error as exc:
            return False, f"identity_regex 非法: {exc}"
        if ok:
            return True, f"SAN 匹配 regex: {identity_regex}"
        return False, f"SAN 不匹配 regex: {identity_regex}（{sans}）"
    ok = identity in sans
    return ok, f"SAN={sans} expected={identity}"


def _match_issuer(cert: Certificate, issuer: str | None) -> tuple[bool, str]:
    actual = (_ext_text(cert.der, OID_FULCIO_ISSUER_V2)
              or _ext_text(cert.der, OID_FULCIO_ISSUER_V1))
    if not issuer:
        return True, f"未指定 issuer（证书声明 {actual or 'missing'}）"
    ok = actual == issuer
    return ok, f"OIDC issuer={actual or 'missing'} expected={issuer}"


def keyless_verify(artifact: bytes | None, bundle: dict,
                   *, identity: str | None = None,
                   identity_regex: str | None = None,
                   issuer: str | None = None,
                   trust_bundle: dict | str | Path | None = None,
                   rekor_log: dict | str | Path | None = None,
                   rekor_public_key: str | Path | PublicKey | None = None,
                   log_key_pem: str | None = None,
                   online: bool = False,
                   rekor_url: str = DEFAULT_REKOR_URL,
                   http: Http | None = None,
                   revoked_serials: list[int | str] | None = None,
                   now: datetime | None = None,
                   require_tlog: bool = True) -> dict:
    """验证 keyless bundle；返回带逐项 checks 的 verdict（ok=全部通过）。"""
    now = now or datetime.now(timezone.utc)
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    if not isinstance(bundle, dict):
        raise SigstoreError("bundle 必须是 dict")
    media = str(bundle.get("mediaType") or "")
    msg = bundle.get("messageSignature") or {}
    material = bundle.get("verificationMaterial") or {}
    tlog_entries = material.get("tlogEntries") or []
    check("schema", media == BUNDLE_MEDIA_TYPE and isinstance(msg, dict)
          and isinstance(material, dict), f"mediaType={media or 'missing'}")

    # Sigstore 证书只有 ~10 分钟有效期；历史签名按 Rekor integratedTime 验证证书链，
    # 这是 keyless 离线验证的标准语义（SET 证明该时刻已入日志）。
    verify_time = now
    if tlog_entries and tlog_entries[0].get("integratedTime"):
        try:
            verify_time = datetime.fromtimestamp(int(tlog_entries[0]["integratedTime"]),
                                                 tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            verify_time = now

    # 1) artifact digest + signature
    digest_b64 = ((msg.get("messageDigest") or {}).get("digest") or "")
    artifact_sha = hashlib.sha256(artifact).hexdigest() if artifact is not None else ""
    digest_ok = False
    if digest_b64:
        try:
            digest_ok = _unb64(digest_b64).hex() == artifact_sha and bool(artifact_sha)
        except Exception:
            digest_ok = False
    check("artifact-digest", digest_ok or (artifact is None and bool(digest_b64)),
          f"artifact={artifact_sha[:16] or 'not-provided'}…")

    bundle_meta = bundle.get("trident") or {}
    certs: list[Certificate] = []
    leaf: Certificate | None = None
    x509_chain = material.get("x509CertificateChain") or {}
    for item in x509_chain.get("certificates") or []:
        try:
            certs.append(parse_certificate(_unb64(item.get("rawBytes") or "")))
        except Exception as exc:  # noqa: BLE001
            check("certificate-parse", False, f"证书解析失败: {exc}")
            certs = []
            break
    if certs:
        leaf = certs[0]
    if leaf is None and material.get("publicKey"):
        # key-based（非 keyless）条目：允许验证，但显式标注不是 keyless
        hint = (material.get("publicKey") or {}).get("hint") or ""
        try:
            pub = PublicKey.from_pem(_unb64(hint).decode())
        except Exception:
            pub = None
        check("keyless-certificate", False, "bundle 使用公钥而非 Fulcio 证书（key-based）")
        sig_ok = False
        if pub is not None and artifact is not None:
            sig_ok = pub.verify(ALG_ECDSA_SHA256, artifact, _unb64(msg.get("signature") or ""))
        check("message-signature", sig_ok, "public-key 模式验签")
    else:
        check("keyless-certificate", leaf is not None, "Fulcio 证书存在")
        sig_ok = False
        if leaf is not None and artifact is not None:
            sig = _unb64(msg.get("signature") or "")
            sig_ok = leaf.public_key.verify(ALG_ECDSA_SHA256, artifact, sig)
            if not sig_ok:  # 兼容对 digest 签名的实现
                sig_ok = leaf.public_key.verify(
                    ALG_ECDSA_SHA256, hashlib.sha256(artifact).digest(), sig)
        check("message-signature", sig_ok, "ECDSA 对 artifact 验签")

    # 2) 证书链
    if leaf is not None:
        tb_doc = trust_bundle if trust_bundle is not None else bundle_meta.get("trust_bundle")
        tb = load_trust_bundle(tb_doc)
        roots, intermediates = _trust_roots(tb)
        chain_errors: list[str] = []
        used_root = None
        for root in roots:
            chain = [leaf] + [c for c in certs[1:] if not c.verify_self_signed()]
            if not certs[1:]:
                chain = [leaf] + intermediates
            errs = verify_chain(chain, root, now=verify_time)
            if not errs:
                used_root = root
                break
            chain_errors.extend(errs)
        check("certificate-chain", used_root is not None,
              f"root={used_root.subject_cn if used_root else 'none'}; "
              f"at={verify_time.strftime('%Y-%m-%dT%H:%M:%SZ')}; errors={chain_errors[:4]}")
        time_ok = leaf.not_before <= verify_time <= leaf.not_after
        check("certificate-time", time_ok,
              f"integratedTime={verify_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
              f"cert={leaf.not_before.strftime('%Y-%m-%dT%H:%M')}~"
              f"{leaf.not_after.strftime('%Y-%m-%dT%H:%M')}")
        id_ok, id_detail = _match_identity(leaf, identity, identity_regex)
        check("identity", id_ok, id_detail)
        iss_ok, iss_detail = _match_issuer(leaf, issuer)
        check("issuer", iss_ok, iss_detail)
    else:
        check("certificate-chain", False, "无证书链")
        check("identity", identity is None and identity_regex is None, "无证书，仅允许不指定身份")
        check("issuer", issuer is None, "无证书，仅允许不指定 issuer")

    # 3) 吊销（离线 serial 列表；真实 CRL/OCSP 不在本模块范围）
    revoked = set()
    for item in revoked_serials or []:
        try:
            revoked.add(int(str(item), 0))
        except ValueError:
            revoked.add(int(str(item), 16))
    if leaf is not None:
        is_revoked = leaf.serial in revoked
        check("revocation", not is_revoked,
              f"serial={leaf.serial} revoked={is_revoked}")

    # 4) Rekor
    if require_tlog:
        if not tlog_entries:
            check("tlog", False, "缺少 tlogEntries")
        else:
            entry = tlog_entries[0]
            body_b64 = entry.get("canonicalizedBody") or ""
            try:
                body = json.loads(_unb64(body_b64))
            except Exception as exc:  # noqa: BLE001
                body = {}
                check("tlog-body-parse", False, f"body 解析失败: {exc}")
            spec = body.get("spec") or {}
            body_digest = ((spec.get("data") or {}).get("hash") or {}).get("value") or ""
            body_sig = _unb64(((spec.get("signature") or {}).get("content") or ""))
            msg_sig = _unb64(msg.get("signature") or "")
            check("tlog-body", body.get("kind") == "hashedrekord"
                  and body_digest == artifact_sha
                  and body_sig == msg_sig,
                  f"kind={body.get('kind')} hash={body_digest[:16]}…")

            log_doc = load_rekor_log(rekor_log)
            key_value = rekor_public_key
            if key_value is None and bundle_meta.get("rekor_public_key"):
                key_value = bundle_meta["rekor_public_key"]
            if key_value is None and log_key_pem:
                key_value = log_key_pem
            log_key = (load_rekor_public_key(key_value) if key_value else
                       PublicKey.from_pem(_CACHE_LOG_KEY.read_text()))
            log_id = sha256_hex(log_key.to_spki_der())
            entry_log_id = (entry.get("logId") or {}).get("keyId") or ""
            entry_log_id_hex = _normalize_log_id(entry_log_id)
            check("tlog-logid", entry_log_id_hex == log_id,
                  f"entry={str(entry_log_id)[:16]}… expected={log_id[:16]}…")
            ok, detail = _verify_set(entry, log_key)
            check("tlog-set", ok, detail)

            proof = entry.get("inclusionProof") or {}
            try:
                leaf_hash = hashlib.sha256(b"\x00" + _unb64(body_b64)).digest()
                hashes = [bytes.fromhex(h) if isinstance(h, str) and len(h) == 64 else _unb64(h)
                          for h in (proof.get("hashes") or [])]
                root = _calc_merkle_root(leaf_hash, int(proof.get("logIndex", entry.get("logIndex", 0))),
                                         int(proof.get("treeSize", 1)), hashes)
                inc_ok = root.hex() == str(proof.get("rootHash") or "").lower()
            except Exception as exc:  # noqa: BLE001
                inc_ok = False
                root = b""
                check("tlog-inclusion-error", False, str(exc))
            check("tlog-inclusion", inc_ok,
                  f"root={root.hex()[:16] if root else 'n/a'}…")
            cp_ok, cp_detail = _verify_checkpoint(str(proof.get("checkpoint") or ""), log_key,
                                                  int(proof.get("treeSize", 1)),
                                                  str(proof.get("rootHash") or ""))
            check("tlog-checkpoint", cp_ok, cp_detail)

            if online:
                try:
                    idx = int(entry.get("logIndex", proof.get("logIndex", 0)))
                    url = rekor_url.rstrip("/") + f"/api/v1/log/entries?logIndex={idx}"
                    remote = _get_json(url, http=http)
                    uuid = next(iter(remote))
                    remote_entry = remote[uuid]
                    same = (remote_entry.get("body") == body_b64
                            and remote_entry.get("logIndex") == entry.get("logIndex"))
                    check("tlog-online", same, f"{url} -> {uuid}")
                except Exception as exc:  # noqa: BLE001
                    check("tlog-online", False, f"在线重取失败: {exc}")
            else:
                check("tlog-online", True, "未请求在线重取（离线缓存/公共日志样本）")
    else:
        check("tlog", True, "调用方要求跳过透明日志")

    return {
        "schema": "trident-sigstore-keyless-verdict/2026-10",
        "ok": all(c["ok"] for c in checks),
        "checks": checks,
        "errors": [c["name"] for c in checks if not c["ok"]],
        "artifact": {"sha256": artifact_sha, "bytes": len(artifact) if artifact else 0},
        "identity": cert_identity(leaf) if leaf is not None else {},
        "log": {"logIndex": (tlog_entries[0].get("logIndex") if tlog_entries else None),
                "integratedTime": (tlog_entries[0].get("integratedTime") if tlog_entries else None)},
        "mode": (bundle.get("trident") or {}).get("mode", "unknown"),
    }
