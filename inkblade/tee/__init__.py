"""inkblade.tee — 硬件 TEE 证明的**本地密码学**解析与验签（仅标准库）。

三个对象：
- `tdx`      Intel TDX Quote v3/v4：结构解析 + AK ECDSA 验签 + 证书链 + report_data/mr_td/TCB/DEBUG 策略；
- `sev_snp`  AMD SEV-SNP report v2/v3：结构解析 + VCEK ECDSA-P384 验签 + VCEK→ASK→ARK 链 + 策略；
- `nvidia_cc` NVIDIA NRAS attestation JWT：RS256/ES384 + JWKS + exp/nbf/iss/aud/eat_nonce/dbgstat/secboot 校验；
- `online`   Intel PCS / AMD KDS / NVIDIA NRAS **在线**公共证书链/CRL/TCB 校验（可缓存离线复验）。

**边界**：`fixtures.py` 生成的是自签样本（真实厂商格式 + 自建 PKI），只证明「解析与验签逻辑」；
`online.py` 对官方公共样本做真实验签，但仍无 TDX/SEV-SNP/H100-CC 实机 quote/report。
见 docs/TEE-VERIFICATION.md 与 docs/TEE-ONLINE-VERIFICATION.md 的对照。

用法：
    from inkblade.tee import tdx, sev_snp, nvidia_cc, fixtures
    q = tdx.parse_quote(raw)
    result = tdx.verify_quote(q, ak_chain=q.cert_chain, trust_root=root, expected_report_data=nonce)
"""
from __future__ import annotations

from . import fixtures, keys, nvidia_cc, online, sev_snp, tdx, x509

__all__ = ["tdx", "sev_snp", "nvidia_cc", "online", "fixtures", "keys", "x509"]
