"""AMD SEV-SNP Attestation Report 解析与本地密码学验证（report version 2/3）。

结构依据（AMD SNP ABI `attestation_report`，1184 字节定点布局）：
    version(4) guest_svn(4) policy(8) family_id(16) image_id(16) vmpl(4) signature_algo(4)
    platform_version(8) platform_info(8) flags(4) reserved(4) report_data(64) measurement(48)
    host_data(32) id_key_digest(48) author_key_digest(48) report_id(32) report_id_ma(32)
    reported_tcb(8) reserved(24) chip_id(64) committed_tcb(8) current_* (3+1) committed_* (3+1)
    launch_tcb(8) reserved(168)  → 0x2A0 = 672 字节
    signature: r(72, 前 48 有效) s(72, 前 48 有效) reserved(368) = 512 字节

签名算法：ECDSA P-384 + SHA-384，签名输入是前 672 字节；验签公钥来自 VCEK 证书。
（VCEK 私钥在芯片/AMD KDS 侧，报告本身不携带 VCEK，需外部证书。）

**本实现验证什么**：布局/版本、report 对 VCEK 公钥的 ECDSA-P384 验签、VCEK→ASK→ARK 链到 pinned
AMD 根、report_data 绑定、measurement 白名单、policy 的 DEBUG 位、reported_tcb 不低于下限。
**不验证什么**：AMD KDS 在线 CRL/TCB 比对、VCEK 吊销、guest policy 全字段语义。
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime

from .keys import ALG_ECDSA_SHA384, CURVES, PublicKey
from .x509 import Certificate, verify_chain

__all__ = ["SnpReport", "SnpVerification", "parse_report", "verify_report", "SnpReportError",
           "SNP_POLICY_DEBUG", "SNP_REPORT_LEN"]

SNP_REPORT_LEN = 1184
_SIGNED_LEN = 672
SNP_POLICY_DEBUG = 1 << 19        # policy bit 19 = DEBUG
SNP_SIGNATURE_ALGO_ECDSA_P384 = 1


class SnpReportError(ValueError):
    """SEV-SNP report 结构非法。"""


def _u32(raw: bytes, off: int) -> int:
    return struct.unpack_from("<I", raw, off)[0]


def _u64(raw: bytes, off: int) -> int:
    return struct.unpack_from("<Q", raw, off)[0]


@dataclass
class SnpReport:
    raw: bytes
    version: int
    guest_svn: int
    policy: int
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    platform_version: int
    platform_info: int
    flags: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: int
    chip_id: bytes
    committed_tcb: int
    current_tcb: tuple[int, int, int]
    committed_build: tuple[int, int, int]
    launch_tcb: int
    signature_r: int
    signature_s: int
    signed_bytes: bytes

    @property
    def debug_enabled(self) -> bool:
        return bool(self.policy & SNP_POLICY_DEBUG)

    @property
    def current_tcb_hex(self) -> str:
        return ".".join(str(v) for v in self.current_tcb)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "guest_svn": self.guest_svn,
            "policy": hex(self.policy),
            "vmpl": self.vmpl,
            "signature_algo": self.signature_algo,
            "report_data": self.report_data.hex(),
            "measurement": self.measurement.hex(),
            "chip_id": self.chip_id.hex(),
            "reported_tcb": hex(self.reported_tcb),
            "current_tcb": self.current_tcb_hex,
            "debug_enabled": self.debug_enabled,
            "signed_bytes": len(self.signed_bytes),
        }


@dataclass
class SnpVerification:
    ok: bool
    report: SnpReport | None
    signature_valid: bool
    chain_valid: bool
    policy_valid: bool
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.ok:
            return "SEV-SNP report 本地验证通过（VCEK 验签+证书链+策略）"
        return "SEV-SNP report 验证失败：" + "；".join(self.errors)


def parse_report(raw: bytes) -> SnpReport:
    if len(raw) != SNP_REPORT_LEN:
        raise SnpReportError(f"SEV-SNP report 长度必须是 {SNP_REPORT_LEN}，收到 {len(raw)}")
    version = _u32(raw, 0)
    if version not in (2, 3):
        raise SnpReportError(f"不支持的 report 版本 {version}（只支持 2/3）")
    signature_algo = _u32(raw, 52)
    if signature_algo != SNP_SIGNATURE_ALGO_ECDSA_P384:
        raise SnpReportError(f"不支持的签名算法 {signature_algo}（只支持 ECDSA-P384=1）")
    if raw[491] != 0 or raw[495] != 0:
        raise SnpReportError("保留字节非零（结构可疑）")
    r = int.from_bytes(raw[672:672 + 72], "big")
    s = int.from_bytes(raw[744:744 + 72], "big")
    return SnpReport(
        raw=raw, version=version, guest_svn=_u32(raw, 4), policy=_u64(raw, 8),
        family_id=raw[16:32], image_id=raw[32:48], vmpl=_u32(raw, 48),
        signature_algo=signature_algo, platform_version=_u64(raw, 56),
        platform_info=_u64(raw, 64), flags=_u32(raw, 72),
        report_data=raw[80:144], measurement=raw[144:192], host_data=raw[192:224],
        id_key_digest=raw[224:272], author_key_digest=raw[272:320],
        report_id=raw[320:352], report_id_ma=raw[352:384], reported_tcb=_u64(raw, 384),
        chip_id=raw[416:480], committed_tcb=_u64(raw, 480),
        current_tcb=(raw[490], raw[489], raw[488]),
        committed_build=(raw[494], raw[493], raw[492]), launch_tcb=_u64(raw, 496),
        signature_r=r, signature_s=s, signed_bytes=raw[:_SIGNED_LEN],
    )


def verify_report(report: SnpReport, *, vcek_chain: list[Certificate] | None = None,
                  trust_root: Certificate | None = None,
                  expected_report_data: bytes | None = None,
                  measurement_allowlist: list[bytes] | None = None,
                  min_tcb: int | None = None, now: datetime | None = None) -> SnpVerification:
    """VCEK 公钥来自 vcek_chain[0]；report 自身不含公钥。"""
    errors: list[str] = []
    chain = list(vcek_chain or [])

    signature_valid = False
    if not chain:
        errors.append("缺少 VCEK 证书（report 不含公钥，必须外部提供）")
    elif not (0 < report.signature_r < CURVES["P-384"].n and 0 < report.signature_s < CURVES["P-384"].n):
        errors.append("report 签名标量越界（伪造/损坏）")
    else:
        # ECDSA 验签接口按 (alg, message) 内部做 SHA-384；签名输入是 report 前 672 字节
        signature_valid = chain[0].public_key.verify(
            ALG_ECDSA_SHA384, report.signed_bytes,
            report.signature_r.to_bytes(48, "big") + report.signature_s.to_bytes(48, "big"))
        if not signature_valid:
            errors.append("report 对 VCEK 公钥验签失败")

    chain_valid = False
    if trust_root is not None:
        if not chain:
            errors.append("缺少 VCEK 证书链，无法校验到 pinned AMD 根")
        else:
            chain_errors = verify_chain(chain, trust_root, now=now)
            errors.extend(chain_errors)
            chain_valid = not chain_errors
    elif chain:
        chain_valid = True  # 未给锚点 = 只证明链内部一致，不作根信任结论

    policy_ok = True
    if expected_report_data is not None:
        expected = expected_report_data
        if len(expected) < 64:
            expected = expected.ljust(64, b"\x00")
        if report.report_data != expected:
            errors.append("report_data 与期望 nonce 不匹配")
            policy_ok = False
    if measurement_allowlist is not None and report.measurement not in measurement_allowlist:
        errors.append("measurement 不在白名单内")
        policy_ok = False
    if report.debug_enabled:
        errors.append("guest policy DEBUG 位已置位")
        policy_ok = False
    if min_tcb is not None and report.reported_tcb < min_tcb:
        errors.append("reported_tcb 低于下限（TCB 降级）")
        policy_ok = False
    if report.version == 3 and report.vmpl not in (0, 1, 2, 3):
        errors.append(f"VMPL 非法：{report.vmpl}")
        policy_ok = False

    ok = signature_valid and policy_ok and (chain_valid if trust_root is not None else True)
    return SnpVerification(ok=ok, report=report, signature_valid=signature_valid,
                           chain_valid=chain_valid, policy_valid=policy_ok, errors=errors)
