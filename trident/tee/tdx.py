"""Intel TDX Quote 解析与本地密码学验证（Quote v3/v4，ECDSA-256/384）。

结构依据（公开规范，字段偏移逐字节实现）：
- Intel TDX DCAP `quote.h`：TDX Quote v4 = 48B header + 584B TD report + tee_tcb_svn2(16)
  + mr_servicetd(48) + signature data；签名输入是上述 696 字节。
- TD report 字段：tee_tcb_svn(16) / mr_seam(48) / mr_signer_seam(48) / seam_attributes(8) /
  td_attributes(8) / xfam(8) / mr_td(48) / mr_config_id(48) / mr_owner(48) / mr_owner_config(48) /
  rt_mr0..3(4×48) / report_data(64)。
- signature data：sig_type(2) / sig_size(2) / signature / ak_type(2) / ak_size(2) / ak /
  qe_report_size(4) / qe_report(384 for P-256) / qe_report_signature(64) / qe_auth_data_size(2) /
  qe_auth_data / cert_data_type(2) / cert_data_size(4) / cert_data(PEM)。

**本实现验证什么**：结构/长度一致性、Quote 对 Attestation Key 的 ECDSA 验签、
AK 证书链（fixture PKI）到 pinned 根、report_data 绑定（nonce）、mr_td 白名单、TCB 版本下限、
TD attributes 的 DEBUG 位。**不验证什么**：QE report 对 PCK 的签名、Intel PCS 的 PCK 证书链与
TCB Info/QL E2E（需要真实 Intel PCS 数据），因此不能据此声称「通过 Intel 认证」。

公开 API：
    parse_quote(raw) -> TdxQuote
    verify_quote(quote, *, ak_chain=None, trust_root=None, expected_report_data=None,
                 mr_td_allowlist=None, min_tcb_svn=None, now=None) -> TdxVerification
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime

from .keys import PublicKey, ALG_ECDSA_SHA256, ALG_ECDSA_SHA384
from .x509 import Certificate, load_certificates_pem, verify_chain

__all__ = ["TdxQuote", "TdxVerification", "parse_quote", "verify_quote", "TeeQuoteError",
           "TDX_TEE_TYPE", "TDX_ATTR_DEBUG"]

TDX_TEE_TYPE = 0x81
TDX_ATTR_DEBUG = 1 << 0
HEADER_LEN = 48
TD_REPORT_LEN = 584
V4_EXTRA_LEN = 16 + 48
_SIG_ALG_BY_TYPE = {2: ALG_ECDSA_SHA256, 3: ALG_ECDSA_SHA384}
_CURVE_BY_TYPE = {2: "P-256", 3: "P-384"}
_QE_REPORT_LEN = 384


class TeeQuoteError(ValueError):
    """Quote 结构非法（长度/版本/字段越界）。"""


@dataclass
class TdxQuote:
    raw: bytes
    version: int
    att_key_type: int
    tee_type: int
    qe_svn: int
    pce_svn: int
    qe_vendor_id: bytes
    user_data: bytes
    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    seam_attributes: int
    td_attributes: int
    xfam: int
    mr_td: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rt_mrs: tuple[bytes, bytes, bytes, bytes]
    report_data: bytes
    tee_tcb_svn2: bytes
    mr_servicetd: bytes
    signed_data: bytes
    signature_type: int
    signature: bytes
    attestation_key: PublicKey
    qe_report: bytes | None
    qe_report_signature: bytes | None
    qe_auth_data: bytes
    cert_chain_pem: bytes
    cert_chain: list[Certificate] = field(default_factory=list)

    @property
    def debug_enabled(self) -> bool:
        return bool(self.td_attributes & TDX_ATTR_DEBUG)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "tee_type": hex(self.tee_type),
            "att_key_type": self.att_key_type,
            "qe_svn": self.qe_svn,
            "pce_svn": self.pce_svn,
            "tee_tcb_svn": self.tee_tcb_svn.hex(),
            "td_attributes": hex(self.td_attributes),
            "xfam": hex(self.xfam),
            "mr_td": self.mr_td.hex(),
            "mr_seam": self.mr_seam.hex(),
            "report_data": self.report_data.hex(),
            "debug_enabled": self.debug_enabled,
            "signed_bytes": len(self.signed_data),
            "signature_type": self.signature_type,
            "cert_chain_len": len(self.cert_chain),
        }


@dataclass
class TdxVerification:
    ok: bool
    quote: TdxQuote | None
    signature_valid: bool
    chain_valid: bool
    policy_valid: bool
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.ok:
            return "TDX quote 本地验证通过（签名+证书链+策略）"
        return "TDX quote 验证失败：" + "；".join(self.errors)


def _u16(raw: bytes, off: int) -> int:
    return struct.unpack_from("<H", raw, off)[0]


def _u32(raw: bytes, off: int) -> int:
    return struct.unpack_from("<I", raw, off)[0]


def _u64(raw: bytes, off: int) -> int:
    return struct.unpack_from("<Q", raw, off)[0]


def parse_quote(raw: bytes) -> TdxQuote:
    if len(raw) < HEADER_LEN + TD_REPORT_LEN:
        raise TeeQuoteError(f"quote 太短：{len(raw)} < {HEADER_LEN + TD_REPORT_LEN}")
    version = _u16(raw, 0)
    if version not in (3, 4):
        raise TeeQuoteError(f"不支持的 TDX quote 版本 {version}")
    att_key_type = _u16(raw, 2)
    if att_key_type not in (2, 3):
        raise TeeQuoteError(f"不支持的 attestation key 类型 {att_key_type}")
    tee_type = _u32(raw, 4)
    signed_len = HEADER_LEN + TD_REPORT_LEN + (V4_EXTRA_LEN if version == 4 else 0)
    if len(raw) < signed_len + 8:
        raise TeeQuoteError("quote 缺 signature data")

    body = raw[HEADER_LEN:HEADER_LEN + TD_REPORT_LEN]
    offset = signed_len
    signature_type = _u16(raw, offset)
    signature_size = _u16(raw, offset + 2)
    offset += 4
    if signature_type not in _SIG_ALG_BY_TYPE:
        raise TeeQuoteError(f"不支持的 quote 签名类型 {signature_type}")
    if signature_size not in (64, 96):
        raise TeeQuoteError(f"quote 签名长度异常 {signature_size}")
    signature = raw[offset:offset + signature_size]
    offset += signature_size
    if len(signature) != signature_size:
        raise TeeQuoteError("quote 签名截断")
    ak_type = _u16(raw, offset)
    ak_size = _u16(raw, offset + 2)
    offset += 4
    ak_raw = raw[offset:offset + ak_size]
    offset += ak_size
    if len(ak_raw) != ak_size:
        raise TeeQuoteError("attestation key 截断")
    curve_size = 64 if ak_type == 2 else 96
    if ak_size != curve_size:
        raise TeeQuoteError(f"attestation key 长度 {ak_size} 与类型 {ak_type} 不符")
    if ak_type == 2:
        attestation_key = PublicKey(kind="ec", curve="P-256",
                                    x=int.from_bytes(ak_raw[:32], "big"),
                                    y=int.from_bytes(ak_raw[32:], "big"))
    else:
        attestation_key = PublicKey(kind="ec", curve="P-384",
                                    x=int.from_bytes(ak_raw[:48], "big"),
                                    y=int.from_bytes(ak_raw[48:], "big"))

    qe_report = qe_report_signature = None
    qe_auth_data = b""
    cert_chain_pem = b""
    if offset + 4 <= len(raw):
        qe_report_size = _u32(raw, offset)
        offset += 4
        if qe_report_size and offset + qe_report_size + 64 <= len(raw):
            qe_report = raw[offset:offset + qe_report_size]
            offset += qe_report_size
            qe_report_signature = raw[offset:offset + 64]
            offset += 64
            if offset + 2 <= len(raw):
                qe_auth_size = _u16(raw, offset)
                offset += 2
                qe_auth_data = raw[offset:offset + qe_auth_size]
                offset += qe_auth_size
                if offset + 6 <= len(raw):
                    offset += 2  # cert_data_type
                    cert_size = _u32(raw, offset)
                    offset += 4
                    cert_chain_pem = raw[offset:offset + cert_size]

    chain: list[Certificate] = []
    if cert_chain_pem:
        try:
            chain = load_certificates_pem(cert_chain_pem)
        except Exception:  # 证书块损坏时保留空链，由 verify 报告
            chain = []

    return TdxQuote(
        raw=raw, version=version, att_key_type=att_key_type, tee_type=tee_type,
        qe_svn=_u16(raw, 8), pce_svn=_u16(raw, 10),
        qe_vendor_id=raw[12:28], user_data=raw[28:48],
        tee_tcb_svn=body[0:16], mr_seam=body[16:64], mr_signer_seam=body[64:112],
        seam_attributes=_u64(body, 112), td_attributes=_u64(body, 120), xfam=_u64(body, 128),
        mr_td=body[136:184], mr_config_id=body[184:232], mr_owner=body[232:280],
        mr_owner_config=body[280:328], rt_mrs=tuple(body[328 + 48 * i:376 + 48 * i] for i in range(4)),
        report_data=body[520:584],
        tee_tcb_svn2=raw[HEADER_LEN + TD_REPORT_LEN:HEADER_LEN + TD_REPORT_LEN + 16],
        mr_servicetd=raw[HEADER_LEN + TD_REPORT_LEN + 16:signed_len],
        signed_data=raw[:signed_len], signature_type=signature_type, signature=signature,
        attestation_key=attestation_key, qe_report=qe_report,
        qe_report_signature=qe_report_signature, qe_auth_data=qe_auth_data,
        cert_chain_pem=cert_chain_pem, cert_chain=chain,
    )


def _tcb_components(svn: bytes) -> list[int]:
    """tee_tcb_svn 是 16 字节的分量数组（低 8 字节常用）；按非零字节逐位比较。"""
    return [b for b in svn if b]


def verify_quote(quote: TdxQuote, *, ak_chain: list[Certificate] | None = None,
                 trust_root: Certificate | None = None, expected_report_data: bytes | None = None,
                 mr_td_allowlist: list[bytes] | None = None, min_tcb_svn: bytes | None = None,
                 now: datetime | None = None) -> TdxVerification:
    errors: list[str] = []

    if quote.tee_type != TDX_TEE_TYPE:
        errors.append(f"tee_type={quote.tee_type:#x} 不是 TDX(0x81)")

    sig_alg = _SIG_ALG_BY_TYPE[quote.signature_type]
    signature_valid = quote.attestation_key.verify(sig_alg, quote.signed_data, quote.signature)
    if not signature_valid:
        errors.append("Quote 签名对 Attestation Key 验签失败")

    chain_valid = False
    chain = ak_chain if ak_chain is not None else quote.cert_chain
    if trust_root is not None:
        if not chain:
            errors.append("缺少 AK 证书链（quote 内 PEM 为空且未显式传入）")
        else:
            if chain[0].public_key.to_spki_der() != quote.attestation_key.to_spki_der():
                errors.append("AK 证书公钥与 quote 内 attestation key 不一致")
            chain_errors = verify_chain(chain, trust_root, now=now)
            errors.extend(chain_errors)
            chain_valid = not chain_errors and chain[0].public_key.to_spki_der() == \
                quote.attestation_key.to_spki_der()
    else:
        chain_valid = bool(chain) or ak_chain is not None  # 未给锚点 = 不作链结论

    policy_ok = True
    if expected_report_data is not None:
        expected = expected_report_data
        if len(expected) < 64:
            expected = expected.ljust(64, b"\x00")  # report_data 固定 64B，短 nonce 右补零
        if quote.report_data != expected:
            errors.append("report_data 与期望 nonce 不匹配")
            policy_ok = False
    if mr_td_allowlist is not None:
        if quote.mr_td not in mr_td_allowlist:
            errors.append("mr_td 不在白名单内")
            policy_ok = False
    if quote.debug_enabled:
        errors.append("TD attributes 含 DEBUG 位（调试模式不可信）")
        policy_ok = False
    if min_tcb_svn is not None:
        if any(a < b for a, b in zip(_tcb_components(quote.tee_tcb_svn), _tcb_components(min_tcb_svn))):
            errors.append("tee_tcb_svn 低于最低要求（TCB 降级）")
            policy_ok = False

    ok = signature_valid and policy_ok and (chain_valid if trust_root is not None else True)
    return TdxVerification(ok=ok, quote=quote, signature_valid=signature_valid,
                           chain_valid=chain_valid, policy_valid=policy_ok, errors=errors)
