# TEE 证明验证：本地密码学校验 vs 硬件实测

> 生成日期：2026-10-25　代码：`inkblade/tee/`　测试：`tests/test_tee.py`（43 项）
> 一句话边界：**本仓库现在做的是「格式 + 签名 + 证书链 + 策略」的本地密码学校验，样本是自签 fixture；
> 不是「在真实 TDX/SEV-SNP/H100-CC 机器上采集并验证厂商证明」。**

## 1. 实现范围

| 对象 | 模块 | 结构 | 验签算法 | 证书链 |
|---|---|---|---|---|
| Intel TDX Quote v3/v4 | `inkblade/tee/tdx.py` | 48B header + 584B TD report + v4: 16B `tee_tcb_svn2` + 48B `mr_servicetd` + signature data（AK、QE report、PEM 链） | ECDSA P-256/P-384（SHA-256/384），签名为 `r‖s` | AK → Intermediate → Root（pinned） |
| AMD SEV-SNP report v2/v3 | `inkblade/tee/sev_snp.py` | 1184B 定点布局，签名覆盖前 672B | ECDSA P-384 + SHA-384 | VCEK → ASK → ARK（pinned） |
| NVIDIA CC / NRAS JWT | `inkblade/tee/nvidia_cc.py` | JWS compact（header.payload.signature） | RS256（RSA-2048 PKCS#1 v1.5 + SHA-256） | JWKS（kid 匹配） |

密码学底座（无第三方依赖，纯标准库）：
`inkblade/tee/_asn1.py`（DER 严格解析/编码）、`inkblade/tee/keys.py`（P-256/P-384 曲线运算、RSA
PKCS#1 v1.5、PEM/JWK）、`inkblade/tee/x509.py`（X.509 v3 解析/构造、链校验、basicConstraints）、
`inkblade/tee/fixtures.py`（自签 fixture 生成）。

## 2. 验证了什么（可执行断言）

### TDX（`tests/test_tee.py::TdxQuoteTest`）

| 用例 | 断言 |
|---|---|
| 合法 quote | 签名 + 链 + 策略全通过（`ok=True`，696B 签名输入、48B `mr_td`、64B `report_data`） |
| 篡改 TD report（`mr_td` 首字节） | `signature_valid=False`，`ok=False` |
| 篡改签名首字节 | `signature_valid=False` |
| `report_data` ≠ nonce | 策略失败（`report_data 与期望 nonce 不匹配`） |
| `td_attributes.DEBUG=1` | 策略失败（调试模式不可信） |
| `mr_td` 不在白名单 | 策略失败 |
| `tee_tcb_svn` 低于下限 | TCB 降级失败 |
| 换 pinned root | 链失败（`chain_valid=False`） |
| 链里 AK 公钥 ≠ quote 内 AK | 失败（`AK 证书公钥与 quote 内 attestation key 不一致`） |
| AK 证书过期 | 链失败（有效期） |
| 截断/版本非法 | `TeeQuoteError` |

### SEV-SNP（`SnpReportTest`）

| 用例 | 断言 |
|---|---|
| 合法 report | VCEK 验签 + VCEK→ASK→ARK 链 + 策略通过 |
| 篡改 measurement | 验签失败 |
| 篡改签名标量 | `signature_valid=False`（含标量越界保护） |
| `report_data` ≠ nonce | 策略失败 |
| `policy.DEBUG=1` | 策略失败 |
| measurement 白名单 | 失败 |
| `reported_tcb` 低于下限 | 失败 |
| 换 ARK / 缺 VCEK | 链失败 / 明确报错 |
| 长度≠1184 或版本非 2/3 | `SnpReportError` |

### NVIDIA CC JWT（`NvidiaJwtTest`）

| 用例 | 断言 |
|---|---|
| 合法 JWT | RS256 验签 + claims 通过（`x-nvidia-gpu-name=H100`） |
| 改 payload（GPU 名） | 验签失败 |
| 改签名 | 验签失败 |
| 过期（`exp` 已过） | 失败（`JWT 已过期`） |
| 未生效（`nbf` 在未来） | 失败（`尚未生效`） |
| `eat_nonce` ≠ 期望 | 失败 |
| `dbgstat != disabled` | 失败 |
| `x-nvidia-overall-att-result != true` | 失败 |
| `x-nvidia-ver < 2.0` | 失败 |
| `iss`/`aud` 不符 | 失败 |
| `alg=none` | `NvidiaJwtError`（只接受 RS256） |
| JWKS 换成不同模数 | 验签失败（不是「有 key 就过」） |

底座用例（`CryptoPrimitiveTest`）：P-256/P-384 ECDSA 签名-验签-篡改、RSA-2048 PKCS#1 v1.5、
JWK 往返、X.509 三层链/缺中间证书/叶子冒充 CA、DER 拒绝 BER 不定长与越界长度。

## 3. 没有验证什么（不得越界宣称）

| 项 | 为什么没有 | 影响 |
|---|---|---|
| 真实 Intel TDX quote 与 Intel PCS PCK 链 | 需要 TDX 机器 + `sgx_quote`/DCAP 采集，且 QE report 对 PCK 的签名要用 Intel PCS 的 PCK 证书链与 TCB Info | 不能声称「通过 Intel 认证」 |
| QE report 签名 / QE 身份 | 本实现解析但不验证 QE report 对 PCK 的签名（需要 QE 身份与 PCK） | 中间人可替换 AK 而不被本实现发现（真实 DCAP 会校验） |
| TCB Info / QL（PCK CRL、TCB 评估） | 需要 Intel PCS 在线接口与最新 TCB 级别 | 不能判断「固件是否已打补丁」 |
| 真实 AMD SEV-SNP report 与 KDS | 需要 SNP 机器 + `sev-guest` 导出 report，VCEK 从 AMD KDS 取 | 不能声称「通过 AMD 认证」 |
| VCEK CRL / 吊销 | 需要 AMD KDS 的 CRL | 吊销状态未校验 |
| 真实 NVIDIA NRAS JWT 与 JWKS | 需要 H100/H200/GB200 CC 机器 + NRAS 在线服务 | 不能声称「GPU 处于 CC 模式」 |
| 端到端「证明→密钥释放」 | 需要 KBS/密钥管理服务（如 Trustee） | 只证明「证明本身可验」，不证明密钥分发链路 |
| GPU attestation 报告里的 measurements 语义 | NRAS claims 的 `measres` 只是字符串，本实现不重建 measurement 白名单 | 不能判断 VBIOS/驱动是否为目标版本 |

**fixture 的来源与可信度**：`inkblade/tee/fixtures.py` 使用**硬编码的固定私钥**（P-256×3、P-384×3、
RSA-2048×1），公开在源码里，任何人可伪造该 fixture 的任意「合法」证明。这是刻意的：
fixture 只用于测试解析与验签逻辑，不应被当作证据。证书主体一律是 `InkBlade Fixture …`，
NRAS `kid` 是 `nras-fixture-2026`，`tests/test_tee.py::FixtureBoundaryTest` 把它锁成可执行断言。

## 4. 与 SOTA 矩阵的关系

`docs/SOTA-2026-10.md` 的两行状态保持诚实：

- 「TEE 证明解析与策略断言（TDX/SEV-SNP/NVIDIA CC fixture）」：**部分** → 现在升为
  「解析 + 真实签名的本地密码学验证」，但仍是 fixture，**不升为已达成**；
- 「硬件 TEE 实测（TDX/SEV-SNP/NVIDIA CC）」：**未达成**（不变）。本任务的产出是**把 fixture 从
  HMAC 换成真实格式 + 真实 ECDSA/RSA 验签**，补齐了「解析器是不是真的能验签」这一层，
  但没有补齐「证明是不是来自真实硬件」。

## 5. 接真实硬件的落地步骤（未执行）

1. **TDX**：在 TDX 虚机内用 DCAP `tdx_quote`（或 `sgx-dcap-quote-verify` 的样例）导出 quote；
   从 Intel PCS 取 PCK 证书链与 TCB Info；把 `tdx.verify_quote(..., trust_root=<Intel Root CA>)`
   换成真实链，并补 QE report → PCK 验签（`qe_report`/`qe_report_signature` 字段已解析）。
2. **SEV-SNP**：`sev-guest-get-report` 导出 1184B report；从 AMD KDS 取 VCEK（
   `https://kdsintf.amd.com/vcek/v1/<product>/<hwid>?blSPL=..`）；`verify_report(vcek_chain=[vcek, ask],
   trust_root=ark)`。
3. **NVIDIA**：把 `nvidia_cc.verify_jwt(..., jwks=<NRAS JWKS>)` 的 JWKS 换成
   `https://nras.attestation.nvidia.com/.well-known/jwks.json`，nonce 用本地随机挑战值。
4. **CI**：无硬件时只跑 fixture 用例（当前 43 项）；有硬件时加一条「真实 quote 入库 + 每日复验」的
   独立 job，失败不得回退为 fixture 通过。

## 6. 复现

```bash
python -m unittest tests.test_tee -v          # 43 项
python lab/bench/_tee_probe.py                # 底座探针（开发用）
```

输出示例（fixture）：

```
quote bytes 2319  version 4  chain 2
tdx ok: True
snp ok: True  current_tcb 3.1.10
jwt ok: True  x-nvidia-ver 2.0
jwt wrong nonce: False ['eat_nonce 与期望 nonce 不匹配']
```
