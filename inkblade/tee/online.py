# -*- coding: utf-8 -*-
"""TEE 厂商公共证书链在线校验：Intel PCS / AMD KDS / NVIDIA NRAS。

设计原则：
- **真实端点优先**：`fetch_*` 走 HTTPS；响应（含签名链）可缓存到
  `inkblade/tee/online_cache/`，离线时对同一份官方样本复验并标注 `source=cache`。
- 密码学校验全部本地完成（标准库 + `inkblade.tee`），不依赖厂商 SDK。
- 不把「HTTP 200」当作「可信」：Intel TCB JSON 的 ECDSA 签名、AMD ASK/ARK/VCEK/CRL
  的 RSA-PSS 签名、NVIDIA JWT 的 RS256 都必须验过，并做有效期/吊销/降级策略判断。

覆盖：
- Intel PCS：TDX TCB Info（`/tdx/certification/v4/tcb?fmspc=...`）JSON + ECDSA 签名，
  `TCB-Info-Issuer-Chain` 证书链，issueDate/nextUpdate，TCB level 匹配与 Revoked/OutOfDate。
- AMD KDS：`/vcek/v1/{product}/cert_chain`（ASK→ARK，RSA-PSS-SHA384）、
  `/vcek/v1/{product}/{hwid}`（VCEK）、`/crl`（CRL 签名 + 吊销 serial）。
- NVIDIA NRAS：`/.well-known/jwks.json`（RS256 JWKS）+ attestation JWT claims
  （复用 `nvidia_cc.verify_jwt`：exp/nbf/iss/aud/eat_nonce/dbgstat/secboot/x-nvidia-ver）。

边界：
- 未实现 Intel QE Report/PCK 链的 E2E（需要真实 TDX quote）；本模块验证 TCB Info 签名链。
- AMD VCEK 的 sample hwid 来自公开测试仓库（enarx `vcek_url` 单测），只用于证明
  KDS 端点/证书链可用，**不代表任何生产芯片**。
- NVIDIA 没有公开的合法 attestation JWT 样本；真实 JWKS 只验证结构，JWT 合法/篡改/
  过期用仓库 fixture JWKS+JWT 验签（明确标注 `source=fixture`）。
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import nvidia_cc
from ._asn1 import DerError, decode_oid, parse_time, read_tlv
from .x509 import Certificate, load_certificates_pem, parse_certificate, verify_chain

__all__ = [
    "OnlineError", "IntelTcbInfo", "IntelVerification", "AmdCrl", "AmdVcekVerification",
    "NvidiaVerification",
    "fetch_intel_tcb", "verify_intel_tcb", "cached_intel_tcb",
    "fetch_amd_cert_chain", "fetch_amd_vcek", "fetch_amd_crl", "cached_amd",
    "verify_amd_vcek", "parse_crl",
    "fetch_nvidia_jwks", "cached_nvidia_jwks", "verify_nvidia_jwt", "verify_nvidia_jwks",
    "verify_all_cached",
]

INTEL_PCS = "https://api.trustedservices.intel.com"
AMD_KDS = "https://kdsintf.amd.com"
NVIDIA_NRAS = "https://nras.attestation.nvidia.com"
CACHE = Path(__file__).resolve().parent / "online_cache"
DEFAULT_FMSPC = "90c06f000000"
# 公开测试向量（enarx `src/backend/sev/snp/firmware/mod.rs::test_vcek_url`）
SAMPLE_MILAN_HWID = (
    "8ba826b2dd6ab65e401e0c4d4128ef4b434ed0ccb213f66c5f577b518730ef5892"
    "f78a78be259976973125a3b9b3d19f286c912cf5776fdfcee5260fa4576c4b"
)

Http = Callable[[str, dict | None, float], tuple[int, dict, bytes]]


class OnlineError(ValueError):
    """端点不可达/响应非 200/缓存缺失。"""


def _http_get(url: str, headers: dict | None = None, timeout: float = 30) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "inkblade-tee-online/2026"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except urllib.error.URLError as exc:
        raise OnlineError(f"网络不可达 {url}: {exc.reason}") from exc


def _get(url: str, http: Http | None = None, timeout: float = 30) -> tuple[int, dict, bytes]:
    return (http or _http_get)(url, None, timeout)


def _json_time(text: str) -> datetime:
    return datetime.fromisoformat(str(text).replace("Z", "+00:00"))


# ---------------------------------------------------------------- Intel PCS

@dataclass
class IntelTcbInfo:
    fmspc: str
    doc: dict
    chain: list[Certificate]
    headers: dict
    url: str
    source: str = "live"


@dataclass
class IntelVerification:
    ok: bool
    checks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tcb_level: dict | None = None

    @property
    def summary(self) -> str:
        return ("Intel TDX TCB 校验通过" if self.ok
                else "Intel TDX TCB 校验失败：" + "；".join(self.errors))


def _intel_signature_payload(tcb_info: dict) -> bytes:
    # Intel PCS TDX v4 对 tcbInfo 子对象的 minified JSON（保留字段顺序）签名。
    return json.dumps(tcb_info, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _intel_chain(headers: dict) -> list[Certificate]:
    raw = headers.get("TCB-Info-Issuer-Chain") or headers.get("tcb-info-issuer-chain") or ""
    if not raw:
        raise OnlineError("Intel 响应缺少 TCB-Info-Issuer-Chain")
    pem = urllib.parse.unquote(raw)
    return load_certificates_pem(pem)


def fetch_intel_tcb(fmspc: str = DEFAULT_FMSPC, *, http: Http | None = None,
                    timeout: float = 30, cache_dir: Path | None = None) -> IntelTcbInfo:
    url = f"{INTEL_PCS}/tdx/certification/v4/tcb?fmspc={fmspc}"
    status, headers, body = _get(url, http=http, timeout=timeout)
    if status != 200:
        raise OnlineError(f"GET {url} -> HTTP {status}: {body[:200]!r}")
    doc = json.loads(body)
    chain = _intel_chain(headers)
    info = IntelTcbInfo(fmspc=fmspc, doc=doc, chain=chain, headers=headers, url=url)
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"intel_tdx_tcb_{fmspc}.json").write_bytes(body)
        (cache_dir / f"intel_tdx_tcb_{fmspc}.headers.json").write_text(
            json.dumps({k: headers.get(k, "") for k in
                        ("TCB-Info-Issuer-Chain", "Date", "Content-Type")},
                       ensure_ascii=False, indent=1), encoding="utf-8")
    return info


def cached_intel_tcb(fmspc: str = DEFAULT_FMSPC,
                     cache_dir: Path | None = None) -> IntelTcbInfo:
    base = Path(cache_dir or CACHE)
    body_path = base / f"intel_tdx_tcb_{fmspc}.json"
    head_path = base / f"intel_tdx_tcb_{fmspc}.headers.json"
    if not body_path.is_file() or not head_path.is_file():
        raise OnlineError(f"缺少 Intel 缓存样本: {body_path}")
    headers = json.loads(head_path.read_text(encoding="utf-8"))
    return IntelTcbInfo(fmspc=fmspc, doc=json.loads(body_path.read_text(encoding="utf-8")),
                        chain=_intel_chain(headers), headers=headers,
                        url=f"cache://{body_path.name}", source="cache")


def _tcb_level_matches(level: dict, components: dict) -> bool:
    tcb = level.get("tcb") if isinstance(level.get("tcb"), dict) else level
    for field_name in ("sgxtcbcomponents", "tdxtcbcomponents"):
        wanted = components.get(field_name)
        have = tcb.get(field_name) or []
        if wanted is None:
            continue
        if len(wanted) != len(have):
            return False
        for svn, entry in zip(wanted, have):
            if int(entry.get("svn", 0)) > int(svn):
                return False
    if components.get("pcesvn") is not None:
        if int(tcb.get("pcesvn", 0)) > int(components["pcesvn"]):
            return False
    return True


def verify_intel_tcb(info: IntelTcbInfo | dict, *, now: datetime | None = None,
                     fmspc: str | None = None, components: dict | None = None,
                     allow_out_of_date: bool = False,
                     allow_revoked: bool = False,
                     trusted_root_sha256: str | None = None) -> IntelVerification:
    """校验 Intel TCB Info：链 + ECDSA 签名 + 有效期 + fmspc + TCB level 策略。"""
    now = now or datetime.now(timezone.utc)
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            errors.append(name)

    if isinstance(info, IntelTcbInfo):
        doc, chain = info.doc, info.chain
    else:
        doc, chain = info, []
    tcb = doc.get("tcbInfo") if isinstance(doc.get("tcbInfo"), dict) else {}
    sig_hex = str(doc.get("signature") or "")
    check("schema", bool(tcb) and bool(sig_hex), "tcbInfo + signature")

    chain_ok = False
    if chain:
        root = chain[-1]
        chain_ok = root.is_ca and root.verify_self_signed() and not verify_chain(chain[:-1], root, now=now)
    check("certificate-chain", chain_ok, f"certs={len(chain)}")
    if trusted_root_sha256 and chain:
        pin = hashlib.sha256(chain[-1].der).hexdigest()
        check("root-pin", pin == trusted_root_sha256.lower(),
              f"root={pin[:16]}… expected={trusted_root_sha256[:16]}…")

    sig_ok = False
    if chain and sig_hex:
        try:
            sig_ok = chain[0].public_key.verify("1.2.840.10045.4.3.2",
                                                _intel_signature_payload(tcb),
                                                bytes.fromhex(sig_hex))
        except (ValueError, DerError):
            sig_ok = False
    check("tcb-signature", sig_ok, "ECDSA P-256 over minified tcbInfo")

    want_fmspc = (fmspc or tcb.get("fmspc") or "").lower()
    check("fmspc", bool(want_fmspc) and str(tcb.get("fmspc") or "").lower() == want_fmspc,
          f"fmspc={tcb.get('fmspc') or 'missing'}")

    issue = next_ = None
    try:
        issue = _json_time(tcb.get("issueDate"))
        next_ = _json_time(tcb.get("nextUpdate"))
    except (TypeError, ValueError):
        pass
    check("validity-window", bool(issue and next_ and issue <= now <= next_),
          f"issue={tcb.get('issueDate')} next={tcb.get('nextUpdate')} now={now.isoformat()}")

    levels = tcb.get("tcbLevels") or []
    check("tcb-levels", bool(levels), f"levels={len(levels)}")
    matched = None
    if components:
        for level in levels:
            if _tcb_level_matches(level, components):
                matched = level
                break
        status = str((matched or {}).get("tcbStatus") or "NoMatch")
        check("tcb-level-match", matched is not None, f"status={status}")
        if status == "Revoked":
            check("tcb-not-revoked", bool(allow_revoked), "matched level is Revoked")
        elif status != "UpToDate":
            check("tcb-up-to-date", bool(allow_out_of_date), f"status={status}")
        else:
            check("tcb-up-to-date", True, "UpToDate")
    else:
        revoked = [x for x in levels if str(x.get("tcbStatus")) == "Revoked"]
        check("tcb-no-revoked-levels", not revoked, f"revoked_levels={len(revoked)}")

    return IntelVerification(ok=all(c["ok"] for c in checks), checks=checks,
                             errors=[c["name"] for c in checks if not c["ok"]],
                             tcb_level=matched)


# ---------------------------------------------------------------- AMD KDS / CRL

@dataclass
class AmdCrl:
    serials: list[int]
    this_update: datetime | None
    next_update: datetime | None
    issuer_raw: bytes
    signature_valid: bool
    raw: bytes
    errors: list[str] = field(default_factory=list)

    def is_revoked(self, serial: int, *, now: datetime | None = None,
                   allow_stale: bool = False) -> tuple[bool | None, str]:
        now = now or datetime.now(timezone.utc)
        if self.next_update and now > self.next_update and not allow_stale:
            return None, "CRL 已过期（fail-closed）"
        return serial in set(self.serials), (
            "serial 在 CRL 中" if serial in set(self.serials) else "serial 未吊销")


@dataclass
class AmdVcekVerification:
    ok: bool
    checks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    revoked: bool | None = None
    crl_status: str = ""

    @property
    def summary(self) -> str:
        return ("AMD VCEK 链+CRL 校验通过" if self.ok
                else "AMD VCEK 校验失败：" + "；".join(self.errors))


def fetch_amd_cert_chain(product: str = "Milan", *, http: Http | None = None,
                         timeout: float = 30) -> list[Certificate]:
    url = f"{AMD_KDS}/vcek/v1/{product}/cert_chain"
    status, _, body = _get(url, http=http, timeout=timeout)
    if status != 200:
        raise OnlineError(f"GET {url} -> HTTP {status}")
    certs = load_certificates_pem(body.decode("ascii"))
    if len(certs) < 2:
        raise OnlineError(f"AMD cert_chain 证书数不足: {len(certs)}")
    return certs


def fetch_amd_vcek(product: str = "Milan", hwid: str = SAMPLE_MILAN_HWID, *,
                   tcb: dict | None = None, http: Http | None = None,
                   timeout: float = 30) -> tuple[Certificate, bytes]:
    url = f"{AMD_KDS}/vcek/v1/{product}/{hwid}"
    if tcb:
        query = "&".join(f"{k}SPL={int(v):02d}" for k, v in
                         (("bl", tcb.get("bootloader", 0)), ("tee", tcb.get("tee", 0)),
                          ("snp", tcb.get("snp", 0)), ("ucode", tcb.get("microcode", 0))))
        url += f"?{query}"
    status, _, body = _get(url, http=http, timeout=timeout)
    if status != 200:
        raise OnlineError(f"GET {url} -> HTTP {status}")
    return parse_certificate(body), body


def fetch_amd_crl(product: str = "Milan", *, http: Http | None = None,
                  timeout: float = 30) -> AmdCrl:
    url = f"{AMD_KDS}/vcek/v1/{product}/crl"
    status, _, body = _get(url, http=http, timeout=timeout)
    if status != 200:
        raise OnlineError(f"GET {url} -> HTTP {status}")
    return parse_crl(body)


def parse_crl(raw: bytes, *, issuer: Certificate | None = None,
              now: datetime | None = None) -> AmdCrl:
    """解析 X.509 CRL v2（AMD KDS），可选验证签发者签名。"""
    errors: list[str] = []
    tag, body, end = read_tlv(raw, 0)
    if tag != 0x30 or end != len(raw):
        raise OnlineError("CRL 不是单个 SEQUENCE")
    _, tbs_value, tbs_end = read_tlv(body, 0)
    tbs = body[:tbs_end]
    cur = 0
    tag, value, cur = read_tlv(tbs_value, cur)
    if tag == 0x02:  # version
        tag, value, cur = read_tlv(tbs_value, cur)
    # signature AlgorithmIdentifier
    if tag != 0x30:
        raise OnlineError("CRL 缺 signatureAlgorithm")
    _, issuer_raw, cur = read_tlv(tbs_value, cur)
    tag, this_raw, cur = read_tlv(tbs_value, cur)
    this_update = parse_time(this_raw, tag)
    next_update = None
    tag, value, cur = read_tlv(tbs_value, cur)
    if tag in (0x17, 0x18):
        next_update = parse_time(value, tag)
        tag, value, cur = read_tlv(tbs_value, cur) if cur < len(tbs_value) else (0, b"", cur)
    serials: list[int] = []
    if tag in (0xA0, 0x30):
        pos = 0
        while pos < len(value):
            _, entry, pos = read_tlv(value, pos)
            _, serial_raw, _ = read_tlv(entry, 0)
            serials.append(int.from_bytes(serial_raw, "big", signed=False))
    # outer signatureAlgorithm / signatureValue
    _, alg, out_off = read_tlv(body, tbs_end)
    _, sig_alg_raw, alg_off = read_tlv(alg, 0)
    sig_alg = decode_oid(sig_alg_raw)
    sig_params = alg[alg_off:]
    sig_tag, sig_bits, _ = read_tlv(body, out_off)
    signature = sig_bits[1:] if sig_tag == 0x03 and sig_bits else b""
    signature_valid = False
    if issuer is not None:
        signature_valid = issuer.public_key.verify(sig_alg, tbs, signature, sig_params)
        if issuer.subject_raw != issuer_raw:
            errors.append("CRL issuer 与证书 subject 不匹配")
    if next_update and now and now > next_update:
        errors.append("CRL 已过期")
    return AmdCrl(serials=serials, this_update=this_update, next_update=next_update,
                  issuer_raw=issuer_raw, signature_valid=signature_valid, raw=raw,
                  errors=errors)


def cached_amd(product: str = "Milan", cache_dir: Path | None = None) -> dict:
    base = Path(cache_dir or CACHE)
    chain_p = base / f"amd_{product.lower()}_cert_chain.pem"
    crl_p = base / f"amd_{product.lower()}_crl.der"
    vcek_p = base / f"amd_{product.lower()}_vcek.der"
    for path in (chain_p, crl_p, vcek_p):
        if not path.is_file():
            raise OnlineError(f"缺少 AMD 缓存样本: {path}")
    chain = load_certificates_pem(chain_p.read_text(encoding="ascii"))
    crl = parse_crl(crl_p.read_bytes(), issuer=chain[-1])
    vcek = parse_certificate(vcek_p.read_bytes())
    return {"chain": chain, "crl": crl, "vcek": vcek,
            "source": "cache", "paths": {"chain": str(chain_p), "crl": str(crl_p),
                                          "vcek": str(vcek_p)}}


def verify_amd_vcek(vcek: Certificate, chain: list[Certificate], crl: AmdCrl | None,
                    *, now: datetime | None = None,
                    allow_out_of_date_crl: bool = False) -> AmdVcekVerification:
    now = now or datetime.now(timezone.utc)
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            errors.append(name)

    root = chain[-1]
    chain_ok = root.is_ca and root.verify_self_signed() and not verify_chain(chain[:-1], root, now=now)
    check("ask-ark-chain", chain_ok, f"certs={len(chain)}")
    vcek_ok = chain_ok and not verify_chain([vcek] + chain[:-1], root, now=now)
    check("vcek-chain", vcek_ok, f"vcek_issuer={vcek.issuer_cn!r}")
    check("vcek-validity", vcek.not_before <= now <= vcek.not_after,
          f"{vcek.not_before.date()}~{vcek.not_after.date()}")

    revoked = None
    status = "no-crl"
    if crl is not None:
        check("crl-signature", crl.signature_valid, "ARK/ASK 对 CRL 验签")
        check("crl-issuer", crl.issuer_raw == root.subject_raw, "CRL issuer = ARK")
        if crl.next_update:
            check("crl-fresh", now <= crl.next_update or allow_out_of_date_crl,
                  f"nextUpdate={crl.next_update.isoformat()}")
        revoked, status = crl.is_revoked(vcek.serial, now=now,
                                         allow_stale=allow_out_of_date_crl)
        check("vcek-not-revoked", revoked is False, status)
    else:
        check("crl", False, "未提供 CRL（fail-closed）")

    return AmdVcekVerification(ok=all(c["ok"] for c in checks), checks=checks,
                               errors=[c["name"] for c in checks if not c["ok"]],
                               revoked=revoked, crl_status=status)


# ---------------------------------------------------------------- NVIDIA NRAS

@dataclass
class NvidiaVerification:
    ok: bool
    jwt_ok: bool
    jwks_ok: bool
    checks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    claims: dict = field(default_factory=dict)

    @property
    def summary(self) -> str:
        return ("NVIDIA NRAS JWT/JWKS 校验通过" if self.ok
                else "NVIDIA NRAS 校验失败：" + "；".join(self.errors))


def fetch_nvidia_jwks(*, http: Http | None = None, timeout: float = 45,
                      cache_dir: Path | None = None) -> dict:
    url = f"{NVIDIA_NRAS}/.well-known/jwks.json"
    status, _, body = _get(url, http=http, timeout=timeout)
    if status != 200:
        raise OnlineError(f"GET {url} -> HTTP {status}")
    jwks = json.loads(body)
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "nvidia_nras_jwks.json").write_bytes(body)
    return jwks


def cached_nvidia_jwks(cache_dir: Path | None = None) -> dict:
    path = Path(cache_dir or CACHE) / "nvidia_nras_jwks.json"
    if not path.is_file():
        raise OnlineError(f"缺少 NVIDIA JWKS 缓存: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_nvidia_jwks(jwks: dict) -> tuple[bool, list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            errors.append(name)

    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    check("jwks-schema", isinstance(keys, list) and bool(keys), f"keys={len(keys or [])}")
    kids = [str(k.get("kid") or "") for k in keys or [] if isinstance(k, dict)]
    check("jwks-kid", all(kids) and len(set(kids)) == len(kids), f"kids={len(set(kids))}")

    inferred: set[str] = set()
    invalid: list[str] = []
    for key in keys or []:
        if not isinstance(key, dict):
            invalid.append("non-object")
            continue
        declared = str(key.get("alg") or "")
        if key.get("kty") == "RSA":
            inferred.add("RS256")
            if declared not in ("", "RS256") or not key.get("n") or not key.get("e"):
                invalid.append(str(key.get("kid")))
        elif key.get("kty") == "EC" and key.get("crv") in ("P-384", "P-256"):
            inferred.add("ES384" if key.get("crv") == "P-384" else "ES256")
            if declared not in ("", "ES384", "ES256") or not key.get("x") or not key.get("y"):
                invalid.append(str(key.get("kid")))
        else:
            invalid.append(str(key.get("kid")))
    check("jwks-alg", bool(inferred) and inferred <= {"RS256", "ES384", "ES256"}
          and not invalid, f"algs={sorted(inferred)} invalid={invalid[:3]}")
    return all(c["ok"] for c in checks), checks, errors


def verify_nvidia_jwt(token: str, jwks: dict, *, expected_nonce: str | None = None,
                      now: float | None = None,
                      issuer: str = nvidia_cc.NRAS_ISSUER,
                      audience: str | list[str] | None = "nras") -> NvidiaVerification:
    jwks_ok, checks, errors = verify_nvidia_jwks(jwks)
    verdict = nvidia_cc.verify_jwt(token, jwks, issuer=issuer, audience=audience,
                                   expected_nonce=expected_nonce, now=now)
    checks = list(checks) + [{"name": f"jwt-{e}", "ok": False, "detail": ""} for e in []]
    for name, ok, detail in (
        ("jwt-signature", verdict.signature_valid, "RS256"),
        ("jwt-claims", verdict.claims_valid, "exp/nbf/iss/aud/nonce/dbgstat/secboot/ver"),
    ):
        checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            errors.append(name)
    errors.extend([e for e in verdict.errors if e not in errors])
    return NvidiaVerification(ok=bool(jwks_ok and verdict.ok), jwt_ok=verdict.ok,
                              jwks_ok=jwks_ok, checks=checks, errors=errors,
                              claims=verdict.jwt.claim_summary if verdict.jwt else {})


# ---------------------------------------------------------------- 汇总

def verify_all_cached(*, now: datetime | None = None,
                      intel_now: datetime | None = None) -> dict:
    """对缓存的三家官方样本做离线复验（用于报告/CI，不联网）。"""
    now = now or datetime.now(timezone.utc)
    out: dict[str, Any] = {"schema": "inkblade-tee-online-verdict/2026-10",
                           "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "source": "online_cache (official samples fetched 2026-10-25)"}
    intel = cached_intel_tcb()
    iv = verify_intel_tcb(intel, now=intel_now or now)
    out["intel"] = {"ok": iv.ok, "errors": iv.errors, "checks": iv.checks,
                    "fmspc": intel.fmspc, "url": intel.url}
    amd = cached_amd()
    av = verify_amd_vcek(amd["vcek"], amd["chain"], amd["crl"], now=now)
    out["amd"] = {"ok": av.ok, "errors": av.errors, "checks": av.checks,
                  "revoked": av.revoked, "crl_status": av.crl_status,
                  "crl_serials": len(amd["crl"].serials),
                  "vcek_serial": amd["vcek"].serial,
                  "paths": amd["paths"]}
    nj = cached_nvidia_jwks()
    nok, nchecks, nerrors = verify_nvidia_jwks(nj)
    out["nvidia"] = {"ok": nok, "errors": nerrors, "checks": nchecks,
                     "keys": len(nj.get("keys") or []),
                     "note": "official JWKS structure only; JWT fixture tests in tests/test_tee_online.py"}
    out["ok"] = bool(iv.ok and av.ok and nok)
    return out
