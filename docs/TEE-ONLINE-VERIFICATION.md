# TEE 厂商公共证书链在线验证（2026-10-25）

> 结论：**厂商公共 PKI 链 + CRL + TCB Info 校验 = 真实验证**（真实端点、官方证书/签名、
> 本地密码学验签）；**硬件 TEE 实测 = 仍未达成**（没有 TDX/SEV-SNP/H100-CC 实机
> quote/report，也没有可验证的真实 NRAS attestation JWT）。
>
> 本次新增 `inkblade/tee/online.py`，并把本地 X.509/RSA 层扩展到 **RSA-PSS-SHA384**
> （AMD ASK/ARK/CRL 实际算法）与 **EC P-384 JWK / ES384**（NVIDIA NRAS 真实 JWKS 形态）。

## 1. 端点与抓取结果

抓取时间均为 **2026-10-25**（本机直连，无代理）；官方响应已缓存到
`inkblade/tee/online_cache/`，离线测试对同一份字节复验。

| 厂商 | 端点 | 结果 |
|---|---|---|
| Intel PCS | `GET https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000` | HTTP 200，5,679 B JSON；`TCB-Info-Issuer-Chain` 2 张证书（Intel SGX TCB Signing → Intel SGX Root CA） |
| AMD KDS | `GET https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` | HTTP 200，4,602 B PEM；2 张 RSA-4096 证书（ASK → ARK） |
| AMD KDS | `GET https://kdsintf.amd.com/vcek/v1/Milan/crl` | HTTP 200，866 B DER；1 个吊销 serial，`thisUpdate=2026-09-22`，`nextUpdate=2026-11-09` |
| AMD KDS | `GET https://kdsintf.amd.com/vcek/v1/Milan/{hwid}` | HTTP 200，1,350 B VCEK 证书（ECDSA P-384 公钥；hwid 为公开测试向量，见 §5） |
| NVIDIA NRAS | `GET https://nras.attestation.nvidia.com/.well-known/jwks.json` | HTTP 200，575,194 B；234 个 **EC P-384** JWK（kid `nv-eat-kid-prod-*`） |

缓存文件：

- `inkblade/tee/online_cache/intel_tdx_tcb_90c06f000000.json`（+ `.headers.json`）
- `inkblade/tee/online_cache/amd_milan_cert_chain.pem`
- `inkblade/tee/online_cache/amd_milan_crl.der`
- `inkblade/tee/online_cache/amd_milan_vcek.der`
- `inkblade/tee/online_cache/nvidia_nras_jwks.json`

## 2. Intel PCS（TDX TCB Info）

验证链：

1. 解析 `TCB-Info-Issuer-Chain`，验 `Intel SGX TCB Signing ← Intel SGX Root CA`，
   根自签 + CA 位 + 有效期；
2. **签名输入 = `tcbInfo` 子对象的 minified JSON（保留字段顺序）**；用 signing 证书
   ECDSA P-256 验 `signature`（hex，64 B）。这是本次实测确认的格式（不是 JWT）；
3. `tcbInfo.fmspc` 与请求值一致（`90c06f000000`）；
4. `issueDate=2026-10-25T15:14:48Z` / `nextUpdate=2026-11-24T15:14:48Z` 覆盖验证时间；
5. `tcbLevels` 4 档（`UpToDate` / `OutOfDate`）——按 quote 的 SGX/TDX TCB 分量 +
   `pcesvn` 匹配；`Revoked` 直接拒绝，`OutOfDate` 默认拒绝（可显式放宽）；
6. 根证书 SHA-256 pin 可选（`trusted_root_sha256`）。

负例：篡改 `tcbEvaluationDataNumber` → 签名失败；`now=2027` → 有效期失败；
请求错误 fmspc → 失败；匹配 `OutOfDate` 档 → 降级拒绝；fixture 签发的 `Revoked` 档
→ 吊销拒绝。**未验证**：QE Report/PCK 链 E2E（需要真实 TDX quote）。

## 3. AMD KDS（VCEK / ASK / ARK / CRL）

- ASK/ARK 与 CRL 都是 **RSA-PSS-SHA384**（OID 1.2.840.113549.1.1.10，MGF1-SHA384，
  salt=48）。本次在 `inkblade/tee/keys.py` 实现 PSS 验签（含 PSS 参数解析、MGF1、
  emBits 位裁剪），`x509.py` 保留 `sig_params` 并传参；ASK→ARK、VCEK→ASK、CRL→ARK
  三条链均真实通过。
- VCEK 有效期 `2026-10-24 ~ 2033-10-24`；CRL `serial 0` 未吊销（VCEK 证书 serial 为 0）。
- CRL 吊销：真实 CRL 含 1 个 serial；`is_revoked(serial)` 对真实吊销 serial 返回 True、
  随机 serial 返回 False；CRL 过期时 **fail-closed**（返回 unknown 并拒绝）。
- 负例：篡改 VCEK 签名 → 链失败；篡改 CRL 签名 → `crl-signature` 失败；2027 年验证
  → `crl-fresh` + `vcek-not-revoked` 失败。

## 4. NVIDIA NRAS（JWKS / attestation）

- 真实 JWKS 是 **234 个 EC P-384 公钥**（无 `alg` 字段，kid 形如
  `nv-eat-kid-prod-20261024125606471-*`），不是旧 fixture 的 RSA-2048/RS256。
  本次扩展 `PublicKey.from_jwk` 支持 EC P-256/P-384，`nvidia_cc.parse_jwt` 支持
  `ES384`/`ES256`（保留 RS256 兼容），JWKS 校验按 `kty/crv` 推断算法。
- **没有公开的真实 NRAS attestation JWT 样本**（NRAS 需要 GPU evidence 现场签发）。
  因此 JWT 合法/篡改/过期/ES384 用仓库 fixture 密钥自签验证；真实端点只验证
  JWKS 结构与 234 把 EC P-384 公钥可解析。此边界在 `verify_all_cached()` 的
  `nvidia.note` 中显式写出。

## 5. 公开样本来源与边界

- AMD hwid `8ba826b2...576c4b` 来自 enarx 仓库
  `src/backend/sev/snp/firmware/mod.rs::test_vcek_url` 的公开测试向量，仅用于证明
  KDS 端点和证书链可用；它属于某颗公开测试芯片，**不是本机硬件**，也不能据此推断
  任何生产节点的 TCB 状态。
- Intel TCB Info 是某 fmspc 的平台级 collateral，不是本机 quote；未做
  `report_data`/nonce/measurement 绑定。
- NVIDIA JWKS 是公共验签公钥；没有真实 GPU attestation JWT，不能声称 GPU CC 通过。
- 所有缓存样本可被替换/重抓；生产应配置 `nextUpdate` 告警与根证书 pin 轮换。

## 6. 复现

```bash
# 离线复验三家官方缓存样本（默认不联网）
python -c "from inkblade.tee.online import verify_all_cached; import json; print(json.dumps(verify_all_cached(), ensure_ascii=False, indent=2))"

# 重新抓取（联网）
python - <<'PY'
from inkblade.tee import online
from pathlib import Path
online.fetch_intel_tcb(cache_dir=online.CACHE)
print(len(online.fetch_amd_cert_chain()), online.fetch_amd_vcek()[0].serial)
print(len(online.fetch_amd_crl().serials))
print(len(online.fetch_nvidia_jwks(cache_dir=online.CACHE)["keys"]))
PY

python -m unittest tests.test_tee_online -v   # 21 tests
python -m unittest tests.test_tee -v          # 43 tests（回归）
```

产物：`reports/samples/tee-online/verdict.json`（2026-10-25 离线复验，三家全部 `ok=true`）。

## 7. 状态

| 子项 | 状态 |
|---|---|
| Intel PCS TCB Info 链/签名/有效期/降级拒绝 | **真实验证**（官方样本） |
| AMD KDS ASK/ARK/VCEK/CRL + 吊销 fail-closed | **真实验证**（官方样本） |
| NVIDIA NRAS 真实 JWKS 结构 + EC P-384/ES384 | **真实验证**（官方样本） |
| NVIDIA 真实 attestation JWT | **仍未达成**（无公开合法样本/无 GPU evidence） |
| TDX/SEV-SNP/H100-CC 实机 quote/report | **仍未达成**（无硬件） |
