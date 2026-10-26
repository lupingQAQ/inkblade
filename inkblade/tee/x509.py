"""最小 X.509 解析/构造与证书链校验（仅标准库）。

用途：TDX 的 PCK/AK 链、SEV-SNP 的 VCEK→ASK→ARK 链在**本地 fixture** 上的链式验签。
刻意缩小范围（并在文档中声明边界）：
- 只解析/校验：签名算法、issuer/subject（按 DER 原样比较）、有效期、SPKI、basicConstraints(cA)。
- **不校验**：EKU/keyUsage（服务器/客户端用途）、名称约束、策略 OID、CRL/OCSP、证书透明日志。
  这些在真实厂商 PKI 里由 OpenSSL/DCAP 库完成，本仓库不冒充。
- 不做主机名匹配：TEE 证明链不使用 DNS 身份。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ._asn1 import (DerError, bit_string, decode_oid, encode, explicit, integer, oid,
                    parse_time, read_tlv, seq, set_of, utc_time, utf8)
from .keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_PSS, ALG_RSA_SHA256,
                   ALG_RSA_SHA384, PublicKey, load_pem_blocks, pem_wrap)

__all__ = ["Certificate", "build_certificate", "verify_chain", "load_certificates_pem",
           "to_pem", "OID_BASIC_CONSTRAINTS", "OID_COMMON_NAME"]

OID_COMMON_NAME = "2.5.4.3"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
_KNOWN_SIG_ALGS = {ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_SHA256,
                   ALG_RSA_SHA384, ALG_RSA_PSS}


def _name_der(cn: str) -> bytes:
    return seq(set_of(seq(oid(OID_COMMON_NAME), utf8(cn))))


def _basic_constraints(ca: bool) -> bytes:
    """Extension: basicConstraints（critical）。返回值是 Extension 结构。"""
    value = seq(b"\x01\x01\xff" if ca else b"")
    return seq(oid(OID_BASIC_CONSTRAINTS), b"\x01\x01\xff", encode(0x04, value))


@dataclass(frozen=True)
class Certificate:
    der: bytes
    tbs: bytes
    sig_alg: str
    signature: bytes
    sig_params: bytes
    issuer_raw: bytes
    subject_raw: bytes
    issuer_cn: str
    subject_cn: str
    not_before: datetime
    not_after: datetime
    public_key: PublicKey
    is_ca: bool
    serial: int

    # ---------- 便捷 ----------
    def is_valid_at(self, when: datetime) -> bool:
        return self.not_before <= when <= self.not_after

    def verify_self_signed(self) -> bool:
        return (self.issuer_raw == self.subject_raw
                and self.public_key.verify(self.sig_alg, self.tbs, self.signature,
                                           self.sig_params))

    def to_pem(self) -> str:
        return pem_wrap(self.der, "CERTIFICATE")


def _parse_name_cn(raw: bytes) -> str:
    """从 Name(SEQUENCE 的 value) DER 里取第一个 CN（仅人类可读；链校验比较原始 DER）。"""
    try:
        _, set_body, _ = read_tlv(raw, 0)      # SET OF
        _, atv, _ = read_tlv(set_body, 0)      # AttributeTypeAndValue SEQUENCE
        _, oid_raw, off = read_tlv(atv, 0)
        if decode_oid(oid_raw) != OID_COMMON_NAME:
            return ""
        tag, value, _ = read_tlv(atv, off)
        return value.decode("utf-8") if tag == 0x0C else ""
    except DerError:
        return ""


def _parse_basic_constraints(extensions_body: bytes) -> bool:
    """返回 cA 标志；无 basicConstraints 视为 False（叶证书）。"""
    off = 0
    while off < len(extensions_body):
        _, ext_body, off = read_tlv(extensions_body, off)
        _, ext_oid_raw, ext_off = read_tlv(ext_body, 0)
        if decode_oid(ext_oid_raw) != OID_BASIC_CONSTRAINTS:
            continue
        # 跳过可选的 critical BOOLEAN
        tag, value, _ = read_tlv(ext_body, ext_off)
        if tag == 0x01:
            tag, value, _ = read_tlv(ext_body, ext_off + len(encode(0x01, value)))
        if tag != 0x04:
            return False
        _, bc_body, _ = read_tlv(value, 0)
        if not bc_body:
            return False
        ctag, cval, _ = read_tlv(bc_body, 0)
        return ctag == 0x01 and cval != b"\x00"
    return False


def parse_certificate(der: bytes) -> Certificate:
    tag, cert_body, end = read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise DerError("证书不是单个 SEQUENCE")
    tbs_tag, tbs_value, off = read_tlv(cert_body, 0)
    if tbs_tag != 0x30:
        raise DerError("tbsCertificate 非 SEQUENCE")
    tbs = cert_body[0:off]  # 含 tag+length：签名输入是完整 TLV
    alg_tag, alg_body, alg_next = read_tlv(cert_body, off)
    if alg_tag != 0x30:
        raise DerError("signatureAlgorithm 非 SEQUENCE")
    _, alg_oid_raw, alg_oid_end = read_tlv(alg_body, 0)
    sig_alg = decode_oid(alg_oid_raw)
    sig_params = alg_body[alg_oid_end:]
    if sig_alg not in _KNOWN_SIG_ALGS:
        raise DerError(f"不支持的证书签名算法 {sig_alg}")
    sig_tag, sig_bits, _ = read_tlv(cert_body, alg_next)
    if sig_tag != 0x03 or not sig_bits or sig_bits[0] != 0:
        raise DerError("signatureValue 非 BIT STRING")
    signature = sig_bits[1:]

    # ---- tbs 字段（从 value 部分解析；tbs 变量保留完整 TLV 供验签）
    cursor = 0
    if tbs_value[cursor] == 0xA0:  # version [0] EXPLICIT
        _, _, cursor = read_tlv(tbs_value, cursor)
    serial, cursor = _read_int(tbs_value, cursor)
    _, _, cursor = read_tlv(tbs_value, cursor)            # signature AlgorithmIdentifier
    _, issuer_raw, cursor = read_tlv(tbs_value, cursor)   # issuer Name
    _, validity, cursor = read_tlv(tbs_value, cursor)     # validity
    _, subject_raw, cursor = read_tlv(tbs_value, cursor)  # subject Name
    spki_start = cursor
    _, spki, cursor = read_tlv(tbs_value, cursor)         # subjectPublicKeyInfo
    spki_der = tbs_value[spki_start:cursor]
    is_ca = False
    while cursor < len(tbs_value):
        tag2, value, cursor = read_tlv(tbs_value, cursor)
        if tag2 == 0xA3:  # extensions [3] EXPLICIT
            _, ext_seq, _ = read_tlv(value, 0)
            is_ca = _parse_basic_constraints(ext_seq)
        # 其余字段（issuerUniqueID/subjectUniqueID 等）忽略
    nb_tag, nb_raw, voff = read_tlv(validity, 0)
    na_tag, na_raw, _ = read_tlv(validity, voff)
    return Certificate(
        der=der, tbs=tbs, sig_alg=sig_alg, signature=signature, sig_params=sig_params,
        issuer_raw=issuer_raw, subject_raw=subject_raw,
        issuer_cn=_parse_name_cn(issuer_raw), subject_cn=_parse_name_cn(subject_raw),
        not_before=parse_time(nb_raw, nb_tag), not_after=parse_time(na_raw, na_tag),
        public_key=PublicKey.from_spki(spki_der), is_ca=is_ca, serial=serial,
    )


def _read_int(data: bytes, off: int) -> tuple[int, int]:
    tag, value, nxt = read_tlv(data, off)
    if tag != 0x02:
        raise DerError(f"期望 INTEGER/SEQUENCE，得到 0x{tag:02x}")
    return int.from_bytes(value, "big", signed=True), nxt


def build_certificate(*, subject: str, issuer: str, public_key: PublicKey, signer,
                      serial: int, not_before: datetime, not_after: datetime,
                      is_ca: bool = False) -> Certificate:
    """构造 v3 证书（CN-only 名称 + basicConstraints），用 signer(alg, tbs) 签名。"""
    sig_alg = ALG_RSA_SHA256 if public_key.kind == "rsa" else (
        ALG_ECDSA_SHA256 if public_key.curve == "P-256" else ALG_ECDSA_SHA384)
    alg_id = seq(oid(sig_alg), b"\x05\x00") if public_key.kind == "rsa" else seq(oid(sig_alg))
    tbs = seq(
        explicit(0, integer(2)),
        integer(serial),
        alg_id,
        _name_der(issuer),
        seq(utc_time(not_before), utc_time(not_after)),
        _name_der(subject),
        public_key.to_spki_der(),
        explicit(3, seq(_basic_constraints(is_ca))),
    )
    signature = signer(sig_alg, tbs)
    der = seq(tbs, alg_id, bit_string(signature))
    return parse_certificate(der)


def verify_chain(chain: list[Certificate], trust_root: Certificate,
                 now: datetime | None = None) -> list[str]:
    """校验 leaf→…→root 的签名/名称链接/有效期/CA 位；root 必须是 pinned 的信任锚。

    chain = [leaf, (intermediate…)]，不含 root；root 单独传入并做「自签 + DER 等于锚」校验。
    返回错误字符串列表（空 = 通过）。
    """
    errors: list[str] = []
    now = now or datetime.now(timezone.utc)
    if not chain:
        return ["证书链为空"]
    if not (trust_root.is_ca and trust_root.verify_self_signed()):
        errors.append(f"信任锚不是自签 CA 证书：{trust_root.subject_cn}")
    full = list(chain) + [trust_root]
    for child, parent in zip(full, full[1:]):
        label = f"{child.subject_cn or '<leaf>'} ← {parent.subject_cn or '<root>'}"
        if child.issuer_raw != parent.subject_raw:
            errors.append(f"{label}: issuer/subject 不匹配")
        if not parent.is_ca:
            errors.append(f"{label}: 签发者不是 CA（basicConstraints cA=false）")
        if not child.is_valid_at(now):
            errors.append(f"{label}: 证书不在有效期内（{child.not_before:%Y-%m-%d}~{child.not_after:%Y-%m-%d}）")
        if not parent.public_key.verify(child.sig_alg, child.tbs, child.signature,
                                        child.sig_params):
            errors.append(f"{label}: 签名验签失败")
    if not chain[-1].is_ca and len(chain) > 1:
        pass  # 叶子可为非 CA；中间层在循环里已逐个校验 parent.is_ca
    if chain[-1].issuer_raw != trust_root.subject_raw:
        errors.append("链末端未被信任锚签发")
    return errors


def load_certificates_pem(pem: str | bytes) -> list[Certificate]:
    return [parse_certificate(der) for der in load_pem_blocks(pem, "CERTIFICATE")]


def to_pem(certs: list[Certificate]) -> str:
    return "".join(cert.to_pem() for cert in certs)
