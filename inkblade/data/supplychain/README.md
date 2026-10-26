# 供应链 / 机密计算 fixture（仅本地测试）

本目录下的 JSON 全部是 **fixture**，用于驱动 `inkblade sbom | verify-model | attest`
的解析与策略断言，不构成生产信任根：

- `policy.json`：TDX / SEV-SNP / NVIDIA CC 的 nonce、模型哈希绑定、launch measurement
  白名单、TCB 状态、debug/GPU CC 模式与 fixture 信任密钥；
- `attestations/*.json`：三家 TEE 证明的最小字段集（`quote` + `claims` + `signature`）；
- `artifact.example.bin` + `provenance.example.json` + `trust-root.example.json`：
  cosign 风格 bundle 的可直接运行样例（`inkblade verify-model`）。
- 签名算法为 `HMAC-SHA256`（`INKBLADE-FIXTURE-ONLY-*` 密钥），用于证明「字段被篡改会
  被检出」；生产环境应替换为厂商 PKI 证书链（Intel PCS / AMD KDS / NVIDIA NRAS）并接入
  真实 TDX Quote / SEV-SNP Report / NVIDIA CC Attestation Report。

这些 fixture 与 `docs/SOTA-2026-10.md` 的「未达成：硬件 TEE 实测 / 生产级密钥less
模型签名」条目对应：解析与策略断言已实现，硬件与生产信任链仍需现场接入。
