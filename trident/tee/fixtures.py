"""自签 TEE fixture：TDX quote / SEV-SNP report / NVIDIA CC JWT + 对应证书链与 JWKS。

**fixture 来源与边界（必读）**
本文件的密钥与证书全部是**本仓库自建**的固定测试密钥（私钥硬编码、公开可见），
用真实厂商格式（Intel TDX quote v4 / AMD SNP report v2 / NVIDIA NRAS JWT）生成**结构合法**的样本。
它不是 Intel/AMD/NVIDIA 签发的真实证明，也不能用于任何生产信任判断：
- 验证「结构解析 + 签名/证书链/claims 校验逻辑」的正确性；
- 不能证明「这台机器是真实 TDX/SEV-SNP/CC 硬件」；
- 真实环境必须换成厂商 PCS/KDS/NRAS 的证书链与 JWKS（见 docs/TEE-VERIFICATION.md）。

固定密钥（只用于 fixture）：P-256 ×3（TDX root/intermediate/AK）、P-384 ×3（AMD root/ASK/VCEK）、
RSA-2048 ×1（NRAS JWKS）。生成过程确定性，同一参数每次输出字节一致。
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_SHA256, PrivateKey, b64url_encode,
                   pem_wrap, PublicKey)
from .nvidia_cc import NRAS_ISSUER
from .x509 import Certificate, build_certificate
from .tdx import HEADER_LEN, TD_REPORT_LEN, TDX_ATTR_DEBUG, TDX_TEE_TYPE, parse_quote
from .sev_snp import SNP_POLICY_DEBUG, SNP_REPORT_LEN, parse_report

__all__ = ["FIXTURE_NOW", "FixturePki", "TdxFixture", "SnpFixture", "NvidiaFixture",
           "tdx_fixture", "snp_fixture", "nvidia_fixture", "nras_jwks", "fixture_pki"]

FIXTURE_NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


def _key(curve: str, seed: str) -> PrivateKey:
    """由固定字符串派生确定性私钥（仅 fixture；不是安全随机数）。"""
    from .keys import CURVES

    curve_def = CURVES[curve]
    d = int.from_bytes(hashlib.sha256(seed.encode()).digest() * (curve_def.size // 32 + 1), "big")
    return PrivateKey(kind="ec", curve=curve, d=d % (curve_def.n - 1) + 1)


RSA_N = 0x883c58a5ac7476fb39fd342e0d601f9a5e3c4f155420c34d8c2ddd1693e4160a5a973cb476e11da1f848dd5f3a87bf214a702954d6e82473be0c507fecbffb2ac86bd28f16cde64c5becd50f04c784fb2a7bce72b7e5eac9401c7199fc29302080f88d45f8faa8c1bf74f5b04734ac994fbb057e373730b82ca64ee1674edb953b73ff54d827e6b65009226df9dc25462f34ee8eff9a45473c8830baa8160eac87d7adc9634a6ae73a965fedc09f72f06cc3bb4981152035eafcb692db40c3338608befe55a035b5e0ecd59e1cfbd116922a12d7d30792cdc3e32d4f838bc61a5e6042b6896eb1fd6e0f032c14c3e038c42b19fac43aae210d54cb48c3aec1e3
RSA_E = 65537
RSA_D = 0x38893a8c7e55d2ae8d311bbf64c39839da93928a1a60824c2339413fc65de81ba1de934d9cebecfd3369219d0c501b2c3894f54204f14f774cce1576110cd6b1b97cad63be25f2458bfc6baa90e42fb67fb9e341ce3936c70fb8fe17d6024dbb9f6a064e9c758124ee4c1e4d6a2f5cd53eb6312060cfa1833cdc436ddd0e67a713be47b7a6f61eb35742adaf3ae1e9ec65ce8d82f8eeb2e12245c75ec87b8f83bb394dc2cde92d483f8853f8d53bdda3b8b354276a8a3334bf071128987145b5161d0a3f949a2194491d93d5bd9cc081d4da3b83763bef9545486e0ddfb7f9d768663a00282907a3322ec6b30d43c204cd6ddb31ab9ef94564f5096ea7d5fda1


@dataclass
class FixturePki:
    tdx_root: Certificate
    tdx_intermediate: Certificate
    tdx_ak: Certificate
    amd_root: Certificate
    amd_ask: Certificate
    vcek: Certificate
    nras_key: PrivateKey
    nras_kid: str = "nras-fixture-2026"

    @property
    def tdx_chain(self) -> list[Certificate]:
        return [self.tdx_ak, self.tdx_intermediate]

    @property
    def vcek_chain(self) -> list[Certificate]:
        return [self.vcek, self.amd_ask]

    def jwks(self) -> dict:
        return {"keys": [self.nras_key.public_key().to_jwk(self.nras_kid)]}


_PKI_CACHE: FixturePki | None = None


def fixture_pki(now: datetime = FIXTURE_NOW) -> FixturePki:
    """构建确定性自签 PKI：TDX（P-256 三层）+ AMD（P-384 三层）+ NRAS（RSA-2048）。"""
    global _PKI_CACHE
    if _PKI_CACHE is not None:
        return _PKI_CACHE
    root_key = _key("P-256", "trident-fixture-tdx-root")
    inter_key = _key("P-256", "trident-fixture-tdx-intermediate")
    ak_key = _key("P-256", "trident-fixture-tdx-ak")
    amd_root_key = _key("P-384", "trident-fixture-amd-root")
    ask_key = _key("P-384", "trident-fixture-amd-ask")
    vcek_key = _key("P-384", "trident-fixture-amd-vcek")

    long_ago, far = now - timedelta(days=30), now + timedelta(days=3650)
    tdx_root = build_certificate(subject="Trident Fixture TDX Root CA", issuer="Trident Fixture TDX Root CA",
                                 public_key=root_key.public_key(), signer=root_key.sign, serial=0x1001,
                                 not_before=long_ago, not_after=far, is_ca=True)
    tdx_inter = build_certificate(subject="Trident Fixture TDX Intermediate", issuer="Trident Fixture TDX Root CA",
                                  public_key=inter_key.public_key(), signer=root_key.sign, serial=0x1002,
                                  not_before=long_ago, not_after=far, is_ca=True)
    tdx_ak = build_certificate(subject="Trident Fixture TDX AK", issuer="Trident Fixture TDX Intermediate",
                               public_key=ak_key.public_key(), signer=inter_key.sign, serial=0x1003,
                               not_before=long_ago, not_after=now + timedelta(days=365))
    amd_root = build_certificate(subject="Trident Fixture AMD ARK", issuer="Trident Fixture AMD ARK",
                                 public_key=amd_root_key.public_key(), signer=amd_root_key.sign, serial=0x2001,
                                 not_before=long_ago, not_after=far, is_ca=True)
    amd_ask = build_certificate(subject="Trident Fixture AMD ASK", issuer="Trident Fixture AMD ARK",
                                public_key=ask_key.public_key(), signer=amd_root_key.sign, serial=0x2002,
                                not_before=long_ago, not_after=far, is_ca=True)
    vcek = build_certificate(subject="Trident Fixture AMD VCEK", issuer="Trident Fixture AMD ASK",
                             public_key=vcek_key.public_key(), signer=ask_key.sign, serial=0x2003,
                             not_before=long_ago, not_after=now + timedelta(days=365))
    nras_key = PrivateKey(kind="rsa", n=RSA_N, e=RSA_E, d=RSA_D)
    _PKI_CACHE = FixturePki(tdx_root=tdx_root, tdx_intermediate=tdx_inter, tdx_ak=tdx_ak,
                            amd_root=amd_root, amd_ask=amd_ask, vcek=vcek, nras_key=nras_key)
    return _PKI_CACHE


def _ak_key() -> PrivateKey:
    return _key("P-256", "trident-fixture-tdx-ak")


def _vcek_key() -> PrivateKey:
    return _key("P-384", "trident-fixture-amd-vcek")


def _fill(buf: bytearray, offset: int, data: bytes) -> None:
    buf[offset:offset + len(data)] = data


def _build_tdx_body(report_data: bytes, *, debug: bool, mr_td: bytes, tcb: bytes,
                    xfam: int = 0xE000000000000000) -> bytes:
    body = bytearray(TD_REPORT_LEN)
    _fill(body, 0, tcb)                       # tee_tcb_svn
    _fill(body, 16, hashlib.sha384(b"fixture-seam").digest())         # mr_seam (48)
    _fill(body, 64, hashlib.sha384(b"fixture-signer-seam").digest())  # mr_signer_seam
    struct.pack_into("<Q", body, 112, 0)      # seam_attributes
    struct.pack_into("<Q", body, 120, TDX_ATTR_DEBUG if debug else 0)
    struct.pack_into("<Q", body, 128, xfam)
    _fill(body, 136, mr_td)
    _fill(body, 184, hashlib.sha384(b"fixture-config").digest()[:48])
    _fill(body, 232, hashlib.sha384(b"fixture-owner").digest()[:48])
    _fill(body, 280, hashlib.sha384(b"fixture-owner-config").digest()[:48])
    for i in range(4):
        _fill(body, 328 + 48 * i, hashlib.sha384(b"fixture-rtmr-%d" % i).digest())
    _fill(body, 520, report_data[:64].ljust(64, b"\x00"))
    return bytes(body)


@dataclass
class TdxFixture:
    raw: bytes
    pki: FixturePki
    report_data: bytes
    mr_td: bytes
    debug: bool = False
    tcb: bytes = b""
    extra: dict = field(default_factory=dict)

    @property
    def quote(self):
        return parse_quote(self.raw)


def tdx_fixture(*, report_data: bytes = b"", debug: bool = False, mr_td: bytes | None = None,
                tcb: bytes = bytes([3, 3, 6, 0, 3, 3, 0, 0]) + bytes(8),
                user_data: bytes = b"\x00" * 20) -> TdxFixture:
    """生成 TDX quote v4（AK 签名，证书链 PEM 内嵌）。report_data 不足 64B 右补零。"""
    pki = fixture_pki()
    report_data = (report_data or hashlib.sha256(b"fixture-nonce").digest() * 2)[:64].ljust(64, b"\x00")
    mr_td = mr_td or hashlib.sha384(b"fixture-td-measurement").digest()
    body = _build_tdx_body(report_data, debug=debug, mr_td=mr_td, tcb=tcb)

    header = struct.pack("<HHI", 4, 2, TDX_TEE_TYPE) + struct.pack("<HH", 3, 3) \
        + bytes.fromhex("939a7233f79c4ca9940a0db3957f0607") + user_data
    assert len(header) == HEADER_LEN
    signed = header + body + bytes(16) + hashlib.sha384(b"fixture-service-td").digest()

    signature = _ak_key().sign(ALG_ECDSA_SHA256, signed, raw=True)
    ak_pub = _ak_key().public_key()
    ak_raw = ak_pub.x.to_bytes(32, "big") + ak_pub.y.to_bytes(32, "big")
    cert_pem = (pki.tdx_ak.to_pem() + pki.tdx_intermediate.to_pem()).encode("ascii")
    qe_report = bytes(384)
    signature_data = (
        struct.pack("<HH", 2, len(signature)) + signature
        + struct.pack("<HH", 2, len(ak_raw)) + ak_raw
        + struct.pack("<I", len(qe_report)) + qe_report + bytes(64)
        + struct.pack("<H", 0)                  # qe_auth_data_size
        + struct.pack("<H", 5)                  # cert_data_type = PCK cert chain
        + struct.pack("<I", len(cert_pem)) + cert_pem
    )
    raw = signed + signature_data
    return TdxFixture(raw=raw, pki=pki, report_data=report_data, mr_td=mr_td,
                      debug=debug, tcb=tcb)


@dataclass
class SnpFixture:
    raw: bytes
    pki: FixturePki
    report_data: bytes
    measurement: bytes
    debug: bool = False

    @property
    def report(self):
        return parse_report(self.raw)


def snp_fixture(*, report_data: bytes = b"", measurement: bytes | None = None,
                debug: bool = False, reported_tcb: int = 0x0A00000000000000 + 0x001000000000000,
                chip_id: bytes = b"\x11" * 64) -> SnpFixture:
    """生成 SEV-SNP attestation report（version 3），VCEK P-384 签名（r||s 各 72B 字段）。"""
    pki = fixture_pki()
    report_data = (report_data or hashlib.sha256(b"fixture-snp-nonce").digest() * 2)[:64].ljust(64, b"\x00")
    measurement = measurement or hashlib.sha384(b"fixture-snp-measurement").digest()

    buf = bytearray(SNP_REPORT_LEN)
    struct.pack_into("<II", buf, 0, 3, 7)                    # version=3, guest_svn
    struct.pack_into("<Q", buf, 8, SNP_POLICY_DEBUG if debug else 0)
    _fill(buf, 16, b"\x01" * 16)                             # family_id
    _fill(buf, 32, b"\x02" * 16)                             # image_id
    struct.pack_into("<II", buf, 48, 0, 1)                   # vmpl=0, sig_algo=1(ECDSA-P384)
    struct.pack_into("<QQI", buf, 56, 0x000A000000000000, 0x0000000000000002, 0)  # platform info
    _fill(buf, 80, report_data)
    _fill(buf, 144, measurement)
    _fill(buf, 192, hashlib.sha256(b"fixture-host-data").digest())
    _fill(buf, 224, hashlib.sha384(b"fixture-id-key").digest())
    _fill(buf, 272, hashlib.sha384(b"fixture-author-key").digest())
    _fill(buf, 320, hashlib.sha256(b"fixture-report-id").digest())
    _fill(buf, 352, hashlib.sha256(b"fixture-report-id-ma").digest())
    struct.pack_into("<Q", buf, 384, reported_tcb)
    _fill(buf, 416, chip_id)
    struct.pack_into("<Q", buf, 480, reported_tcb)
    buf[488], buf[489], buf[490] = 0x0A, 0x01, 0x03            # current build/minor/major
    buf[492], buf[493], buf[494] = 0x0A, 0x01, 0x03            # committed
    struct.pack_into("<Q", buf, 496, reported_tcb)
    # 保留区/签名区保持零；签名覆盖前 672 字节（32 字节 SHA-384 record 已在上面填好）
    raw_sig = _vcek_key().sign(ALG_ECDSA_SHA384, bytes(buf[:672]), raw=True)
    _fill(buf, 672, raw_sig[:48].rjust(72, b"\x00"))
    _fill(buf, 744, raw_sig[48:].rjust(72, b"\x00"))
    return SnpFixture(raw=bytes(buf), pki=pki, report_data=report_data,
                      measurement=measurement, debug=debug)


def nras_jwks() -> dict:
    return fixture_pki().jwks()


@dataclass
class NvidiaFixture:
    token: str
    jwks: dict
    claims: dict
    nonce: str


def nvidia_fixture(*, nonce: str = "fixture-nonce-0001", exp_offset: int = 3600,
                   overall: bool = True, dbgstat: str = "disabled", secboot: bool = True,
                   version: str = "2.0", issuer: str = NRAS_ISSUER, audience: str = "nras",
                   now: datetime | None = None) -> NvidiaFixture:
    """生成 NRAS 风格 attestation JWT（RS256，kid 对应 fixture JWKS）。

    时间基准：默认取调用时刻（保证默认校验窗口内有效）；要构造「已过期/未生效」样本时显式传 now。
    """
    pki = fixture_pki()
    now = now or datetime.now(timezone.utc)
    header = {"alg": "RS256", "typ": "JWT", "kid": pki.nras_kid}
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": "trident-fixture-gpu-0",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(now.timestamp()) + exp_offset,
        "eat_nonce": nonce,
        "x-nvidia-overall-att-result": overall,
        "x-nvidia-ver": version,
        "dbgstat": dbgstat,
        "secboot": secboot,
        "measres": "success",
        "x-nvidia-gpu-name": "H100",
        "x-nvidia-gpu-arch": "Hopper",
        "x-nvidia-attestation-type": "GPU",
        "x-nvidia-vbios-version": "96.00.89.00.01",
    }
    h = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = pki.nras_key.sign(ALG_RSA_SHA256, signing_input)
    token = f"{h}.{p}.{b64url_encode(sig)}"
    return NvidiaFixture(token=token, jwks=pki.jwks(), claims=claims, nonce=nonce)
