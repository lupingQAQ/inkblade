# Sigstore keyless 验证记录（2026-10-25）

> 结论先行：**SOTA「生产级模型签名（cosign keyless / OIDC / Rekor）」= 模拟验证**
> （本仓库自有签名仍走本地 Fulcio 兼容 CA），但**验证侧**已对 Sigstore 公共实例的真实
> keyless 产物完成端到端真实验证（Fulcio 链 + Rekor SET + inclusion proof + checkpoint +
> 身份），并完成一次真实的公共 Rekor 写入/回读（key-based，非 keyless）。
> 没有 OIDC 身份，因此**没有**用公共 Fulcio 为本仓库产物签发证书。

## 1. 实现

| 文件 | 作用 |
|---|---|
| `trident/sigstore_keyless.py` | keyless 签名/验证：Fulcio v2 `/api/v2/signingCert`、Rekor v1 `/api/v1/log/entries`、Sigstore bundle v0.3、Fulcio 链/SAN/OIDC issuer、SET JCS、RFC6962 inclusion、checkpoint note、在线重取 |
| `trident/data/sigstore/fulcio_trust_bundle.json` | 2026-10-25 拉取的 Fulcio 公共根/中间证书（2 张，1 个自签根） |
| `trident/data/sigstore/rekor_log.json` | 2026-10-25 拉取的 Rekor 日志头（treeID/treeSize/inactiveShards） |
| `trident/data/sigstore/rekor_public_key.pem` | Rekor 公共日志公钥（ECDSA P-256） |
| `tests/test_sigstore_keyless.py` | 19 项（1 项在线重取默认 skip）：fixture 合法/篡改/吊销/过期/身份/issuer/日志键/CLI + 真实样本离线验证 |
| CLI | `trident sign-keyless` / `trident verify-keyless` |

验证覆盖：

1. artifact SHA-256 与 `messageSignature.messageDigest` 一致；
2. ECDSA 签名对 artifact 验签（兼容对 digest 签名）；
3. leaf → Fulcio 中间 → **pinned Fulcio 根**（自签、CA 位、有效期、链式签名）；
4. 证书有效期按 **Rekor integratedTime** 判定（Sigstore 证书仅 ~10 分钟，历史签名必须用
   日志时间；这是离线验证的标准语义）；
5. SAN email/URI 精确匹配或正则；Fulcio OIDC issuer 扩展
   `1.3.6.1.4.1.57264.1.8`（兼容旧 `.1.1`）；
6. Rekor `hashedrekord` body 的 hash/signature/cert 三元组；
7. `logID = SHA-256(log public key SPKI DER)`；
8. SET（`signedEntryTimestamp`）对 RFC8785 规范化 JSON 的 ECDSA 验签；
9. RFC6962 inclusion proof（按 treeSize 递归分片，避免只用 index bit 在非满树上的偏差）；
10. checkpoint note 签名（4 字节 key hint + DER ECDSA）；
11. `--online` 时按 logIndex 重新拉取 Rekor 条目并比对 body/logIndex；
12. `--revoked-serial` 离线吊销列表。

## 2. 真实网络证据（2026-10-25）

### 2.1 公共 Fulcio / Rekor 可达性

| 端点 | 结果 |
|---|---|
| `GET https://fulcio.sigstore.dev/api/v2/trustBundle` | HTTP 200，1,595 B，2 张证书（中间 + 自签根） |
| `GET https://rekor.sigstore.dev/api/v1/log` | HTTP 200，treeID `1193050959916656506`，treeSize > 3.34e9 |
| `GET https://rekor.sigstore.dev/api/v1/log/publicKey` | HTTP 200，ECDSA P-256 公钥；`logID` = `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` |

### 2.2 真实 keyless 产物验证（**完全通过**）

- 产物：`cosign_checksums.txt`（sigstore/cosign **v3.1.4** GitHub Release）
- SHA-256：`e70e59b328d52949b3a9ae3e0d04721ea8f380c4e91c28197aa91df02afbf4c0`
- Rekor 条目（按 hash 检索）：
  `https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677a8b1d3e62d82340146c10e82557e4590631fd942c698ed9a9f8015d018d82b62c`
- 条目 `logIndex=3341269697`，`integratedTime=1792519254`（2026-10-20T18:00:54Z）
- Fulcio 身份：SAN `keyless@projectsigstore.iam.gserviceaccount.com`，
  OIDC issuer `https://accounts.google.com`（Google 服务账号 keyless）
- 验证结果：`ok=true`；证书链、证书时间、身份、issuer、SET、inclusion、checkpoint、
  在线重取全部通过（`reports/samples/sigstore/real-keyless-verdict.json`）

> 这是**别人签发、我们验证**的真实 keyless 端到端样本。它证明验证器能正确处理公共
> Fulcio 短生命周期证书、Rekor 透明日志与在线一致性，而不是 fixture 自说自话。

### 2.3 真实 Rekor 写入/回读（key-based，**非 keyless**）

- 产物：`reports/samples/sigstore/live-rekor-artifact.txt`
- 条目：
  `https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677a1abbc42c871c2e7464e9c684908a504a3b83ec41758730a5f7bdf8fea556424f`
- `logIndex=3462554806`，`integratedTime=1792943014`（2026-10-25T15:43:34Z）
- 验证：`tlog-body / tlog-logid / tlog-set / tlog-inclusion / tlog-checkpoint` 全部
  通过；因为使用公钥而非 Fulcio 证书，`keyless-certificate` 与 `certificate-chain`
  明确失败（`ok=false`）——**不把它冒充 keyless**。

### 2.4 未执行项（诚实边界）

- **没有**向公共 Fulcio 申请本仓库产物的证书：需要 OIDC identity token，当前环境无
  可用的 Google/GitHub/Microsoft 身份，自动化也不应代替用户登录。
- 未验证 Sigstore **SCT**（Fulcio 证书内嵌的 CT 签名）；本模块验证链、身份、Rekor，
  不宣称完成 CT 审计。
- 未接真实 CRL/OCSP；吊销仅支持调用方传入 serial 列表（离线策略）。
- 未接 `cosign` CLI（本机未安装）；实现按 Sigstore bundle/spec 的密码学语义独立完成。

## 3. Fixture 降级（离线单测/演示）

无 OIDC 或无网络时：

```bash
python -m trident sign-keyless --artifact weights.bin --out bundle.json --offline-fixture
python -m trident verify-keyless --artifact weights.bin --bundle bundle.json \
  --identity fixture@trident.local --issuer https://fixture.trident.local
```

- 本地 Fulcio 兼容 CA：固定测试根/中间密钥（公开在代码中），签发带 SAN + OIDC issuer
  扩展的 10 分钟叶证书。
- 本地 Rekor fixture：单叶 Merkle 树（treeSize=1），SET/checkpoint 用固定日志密钥签名。
- bundle 内自带 `trident.trust_bundle` 与 `trident.rekor_public_key`，离线可复现；
  **这些不是生产信任锚**。

样本：`reports/samples/sigstore/fixture-keyless-bundle.json`（artifact/verdict 同目录）。

## 4. 测试

```bash
python -m unittest tests.test_sigstore_keyless -v   # 19 tests, 1 skip
TRIDENT_ONLINE=1 python -m unittest tests.test_sigstore_keyless.TestRealSigstoreSamples.test_real_keyless_bundle_online -v
```

测试面：合法签名/验证；artifact/签名/body/root/checkpoint/log key 篡改；错误身份/issuer；
吊销 serial；证书过期；缺 tlog；真实公共 keyless 样本离线验证；真实 Rekor key-based
日志四项；CLI 往返。

## 5. 状态判定

| 子项 | 状态 | 证据 |
|---|---|---|
| Sigstore 公共 Fulcio 链 + Rekor 验证（第三方真实产物） | **真实验证** | §2.2 + `reports/samples/sigstore/real-keyless-*` |
| 公共 Rekor 写入/回读（key-based） | **真实验证** | §2.3 + `live-rekor-*` |
| 本仓库产物经公共 Fulcio keyless 签发 | **仍未达成** | 无 OIDC 身份；§2.4 |
| 离线 fixture keyless（含篡改/吊销测试） | **模拟验证** | §3 + 19 tests |

因此 SOTA 总项仍标 **模拟验证**（验证链真实、签名身份未真实取得），不写成「已达成」。
