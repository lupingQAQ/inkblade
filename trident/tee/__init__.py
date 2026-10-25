"""trident.tee — 硬件 TEE 证明的**本地密码学**解析与验签（仅标准库）。

三个对象：
- `tdx`      Intel TDX Quote v3/v4：结构解析 + AK ECDSA 验签 + 证书链 + report_data/mr_td/TCB/DEBUG 策略；
- `sev_snp`  AMD SEV-SNP report v2/v3：结构解析 + VCEK ECDSA-P384 验签 + VCEK→ASK→ARK 链 + 策略；
- `nvidia_cc` NVIDIA NRAS attestation JWT：RS256 + JWKS + exp/nbf/iss/aud/eat_nonce/dbgstat/secboot 校验。

**边界**：本包不接触硬件、不联网。`fixtures.py` 生成的是自签样本（真实厂商格式 + 自建 PKI），
用于证明「解析与验签逻辑」；真实硬件结论必须用厂商 PCS/KDS/NRAS 的真实证书链与实机采集，
见 docs/TEE-VERIFICATION.md 的「本地密码学验证 vs 硬件实测」对照。

用法：
    from trident.tee import tdx, sev_snp, nvidia_cc, fixtures
    q = tdx.parse_quote(raw)
    result = tdx.verify_quote(q, ak_chain=q.cert_chain, trust_root=root, expected_report_data=nonce)
"""
from __future__ import annotations

from . import fixtures, keys, nvidia_cc, sev_snp, tdx, x509

__all__ = ["tdx", "sev_snp", "nvidia_cc", "fixtures", "keys", "x509"]
