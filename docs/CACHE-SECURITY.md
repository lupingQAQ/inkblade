# 多租户推理缓存安全（Cache Security）

> 范围：vLLM 风格 prefix caching、SGLang 风格 radix prefix cache、GPTCache 风格近似/语义缓存、
> Mooncake/LMCache 风格远程 KV 池、EPP 路由器缓存指标面。
> 形态：本机 `lab/cache_sim.py`（仅 `127.0.0.1`，标准库）双姿态（`vulnerable` / `fixed`）真实 HTTP 差分；
> 证据只取响应状态码、`usage.cached_tokens`、`ttft_ms`、逐出计数、`matched` 条目、KV 块读回值与 sha256。
> **边界**：TTFT 为确定性仿真计时（命中 22–31ms / 未命中 185–274ms），用于验证“命中/未命中可观测”
> 这一侧信道前提，不代表真实 GPU 上的绝对时延；不声称对任何厂商生产集群的未授权利用。

---

## 1. 缓存类型 × 公开实现对照

公开实现的隔离语义（2026-10 对照官方文档/论文）：

| 缓存类型 | 代表实现 | 键 / 隔离语义（公开文档口径） | 可观测面 | 主要风险 |
|---|---|---|---|---|
| 自动前缀缓存（APC） | vLLM Automatic Prefix Caching | 以 block 的 token 内容哈希为键；`cache_salt` 可参与键派生，用于多租户隔离；默认按引擎/实例共享 | `usage.cached_tokens`、TTFT、`/metrics` | 未启用 salt/租户进键时，同 prefix 跨租户命中；命中时延差异可做成员推断 |
| Radix 前缀缓存 | SGLang RadixAttention | 请求前缀在 radix tree 中共享节点；多租户需独立 tree/会话隔离 | cached tokens、TTFT、树命中统计 | 共享 radix tree 的跨租户前缀复用；逐出/引用计数副作用 |
| 近似 / 语义缓存 | GPTCache | 向量相似度检索 + 阈值（如 cosine/相似度阈值）；命中返回缓存响应 | `matched` 条目、相似度分数、响应内容 | 阈值内“近似”误命中他租户语义条目；跨租户检索未按 tenant 过滤 |
| 远程 KV 池 | Mooncake | KV cache 池 + Transfer Engine，块按对象/键存取；租户命名空间需上层约定 | 块 ID、块归属、值/sha256、命中率 | 无命名空间校验时任意租户读写块；逐出后残留未清零 |
| 远程 KV 层 | LMCache | KV cache 层，支持本地/远程后端（Redis、S3 等）；键通常含模型/前缀信息 | 后端键、块内容、命中/逐出指标 | 键未含 tenant/salt 时跨租户复用；共享后端残留；指标泄露 |
| 路由器指标面 | EPP / KV-aware router | 按租户/实例暴露 KV 利用率、前缀命中率、前缀样本 | `/router/metrics`、`per_tenant` | 无鉴权/过宽粒度导致缓存状态侧信道，辅助前缀字典提取 |

对照要点：

- **vLLM**：APC 的块哈希本身解决“相同 token 复用”，但多租户隔离要显式把租户/`cache_salt` 纳入键；
  公开文档将 `cache_salt` 描述为可选的隔离/隐私参数。只开 APC 不等于租户隔离。
- **SGLang**：RadixAttention 以 radix tree 共享前缀，收益来自树节点复用；多租户部署需要独立
  tree/会话边界，否则“树命中”就是跨租户可观测信号。
- **GPTCache**：语义缓存的核心是相似度阈值；阈值越宽召回越高、误命中风险越大。检索范围必须
  先按 tenant 过滤，再做相似度排序，否则“相似”会直接变成“读回他租户响应”。
- **Mooncake / LMCache**：远程 KV 池/层的价值是跨实例复用与分层存储；块键、后端命名空间和
  逐出清零策略是租户隔离的三个关键点，缺一即可能出现“块 ID 可猜/可枚举 + 越权读”。
- **路由器**：缓存指标是运维面，也是攻击面；`per_tenant` 粒度 + 无鉴权 = 缓存行为侧信道。

---

## 2. 威胁 × 模块 × 证据矩阵

| # | 缓存类型 | 威胁 | 模块 | 真实 HTTP 证据（vulnerable） | fixed 对照 |
|---|---|---|---|---|---|
| 1 | prefix cache | 隔离策略缺失：`cache_salt` 未启用、键 scope 全局 | `cache-salt-policy-audit` | `GET /config` 200 且 `cache_salt_policy.enabled=false/key_scope=global`；A 租户带 salt 预热后 B 租户同 prefix 无 salt 复用，`usage.cached_tokens=2048` | `/config` 401；跨租户探测恒 miss（`cached_tokens=0`，不以 403 泄露存在性） |
| 2 | 近似/语义缓存 | 阈值内跨租户误命中，读回他租户响应 | `similarity-cache-false-hit` | `POST /approx/lookup` 200，`best_similarity=0.8824 ≥ 0.85`，`matched.tenant=tenant-b`，响应含 `INKBLADE-BENIGN-APPROX-VICTIM` | 仅本租户检索，`hit=false`、`matched=null` |
| 3 | prefix cache | TTFT 时序侧信道 → 成员推断 / 前缀字典提取 | `cache-timing-sidechannel` | N=60（30 成员 + 30 对照），均值 27.9ms vs 222.2ms，Δ=194.3ms，Welch `p=1.05e-28`，字典提取率 >0.9 | 两类皆 miss，Δ≈4ms，`p≈0.55`，不显著 |
| 4 | prefix cache + KV 池 | LRU 逐出后残留层跨租户可读 | `cache-eviction-residue` | 160 条唯一前缀洪泛 → `evictions_total +65`；`GET /cache/residue?prefix=…` 200，`tenant=tenant-b`，preview 含 `INKBLADE-BENIGN-RESIDUE-VICTIM` | 逐出即 zeroize，`/cache/residue` 404 |
| 5 | 远程 KV 池 | 块命名空间绕过：任意租户读他租户块 | `remote-kv-pool-isolation` | `GET /kvpool/blocks/tenant-b%2Fctx%2Fseed-001` 200，`tenant=tenant-b`，值含 `INKBLADE-BENIGN-POOL-VICTIM`；本租户对照块 200 | 越权 403 `kv_pool_namespace_isolation`；本租户对照仍 200 |
| 6 | 路由器指标 | 按租户缓存指标无鉴权泄露（缓存状态侧信道） | `router-cache-metrics-leak` | `GET /router/metrics` 200，`per_tenant` 含 `tenant-b`（KV 利用率/命中率/独立前缀数/前缀样本） | 无身份 401；租户头仅本租户视图，`scope=own-tenant` |
| 7 | 远程 KV 池 | 毒化块 `pinned` 存续（逐出策略绕过） | `cache-poison-persistence` | `backup-write`：写入带 run marker 的良性块并 `pinned=true`，160 条洪泛 `evictions +66` 后读回 200 且 sha256 一致 | `pinned` 被降级/拒绝（`pinning_denied=true`），洪泛后 404；probe-only 越权读 403 |

补充说明：

- 模块 1、2 的“配置面 + 行为面”双确认避免只凭 `/config` 文案误报；模块 3 用不重叠两档 +
  Welch 检验避免单次抖动误报；模块 4、5、7 的计数/sha256 均来自独立 HTTP 读回，不读仿真器内部状态。
- 模块 6 的 `top_prefix_samples` 只返回前缀片段（64 字符截断的前 32 字符），用于证明“样本可观测”，
  不复现真实业务语料。

---

## 3. 检测口径与模块证据链

| 模块 | 路由 | 判定（vulnerable high） | 判定（fixed info） |
|---|---|---|---|
| `cache-salt-policy-audit` | `GET /config` + `POST /v1/chat/completions` ×2 | `weak_config && cross_tenant_cached_tokens>0` | 配置 401/加固且跨租户 `cached_tokens=0` |
| `similarity-cache-false-hit` | `POST /approx/lookup`（正对照 + 单 token 变异） | `hit && matched.tenant != requester` 且 marker 在响应中 | 仅本租户候选，`hit=false` |
| `cache-timing-sidechannel` | `POST /v1/chat/completions` ×60 | `N≥50 && Δ≥30ms && p<alpha` | 键含 tenant/salt，两类皆 miss，无显著差分 |
| `cache-eviction-residue` | `/router/metrics` + 洪泛 + `GET /cache/residue` | `evictions_delta≥1 && residue.tenant != requester && marker` | zeroize → 404 |
| `remote-kv-pool-isolation` | `GET /kvpool/blocks/{block}`（对照 + 受害） | 受害块 200 且 `block.tenant != requester` | 403（对照块仍 200，排除“全站不可读”假阴性） |
| `router-cache-metrics-leak` | `GET /router/metrics` | 200 且 `per_tenant` 含受害租户 | 401 或仅本租户视图 |
| `cache-poison-persistence` | probe-only：读受害块；backup-write：写块 + 洪泛 + 独立读回 | pinned 生效 + 逐出压力下 sha256 读回一致 | pinning 被拒/降级，洪泛后 404 |

写类边界：`cache-poison-persistence` 的 `writes=true`，执行前必须通过 runner 备份闸门
（`backup_targets` 非空且快照回执成功），否则 `BackupGateRefused`（exit 91）；无备份时不落任何写请求。

---

## 4. 利用链

### 4.1 `approx-cache-cross-tenant-chain`

```text
cache-salt-policy-audit（配置面 salt 关闭 + 跨租户 cached_tokens>0）
  └─> similarity-cache-false-hit（单 token 变异触发阈值内检索）
        └─> 读回 tenant-b 缓存响应 + INKBLADE-BENIGN-APPROX-VICTIM
```

前置条件：`findings('cache-salt-policy-audit').any(severity == 'high')`。
证据：`http-trace`、`cache-policy-config`、`approx-similarity`、`victim-marker-readback`。
MITRE：T1552（Unsecured Credentials）、T1213（Data from Information Repositories）。

### 4.2 `cache-sidechannel-chain`

```text
cache-timing-sidechannel（N=60 TTFT 两档显著差分 → 成员推断）
  └─> router-cache-metrics-leak（per_tenant 命中率/前缀样本 → 字典收敛）
        └─> 前缀字典提取 / 成员确认
```

前置条件：`findings('cache-timing-sidechannel').any(severity == 'high')`。
证据：`http-trace`、`ttft-samples`、`welch-ttest`、`per-tenant-metrics`。
MITRE：T1592（Gather Victim Host Information）、T1213。

---

## 5. 规则覆盖（每条链 ≥1）

| 规则 | 引擎 | 覆盖链 | 关键选择器 |
|---|---|---|---|
| `sigma-cache-tenant-isolation-missing` | Sigma | `approx-cache-cross-tenant-chain` | `event=cache_policy_read` + `cache_salt_enabled=false` + `key_scope=global` |
| `sigma-cache-probing-burst` | Sigma | `cache-sidechannel-chain` | `action=chat_completion` + `distinct_prefix_probe_count ≥ 50` |
| `sigma-router-cache-metrics-leak` | Sigma | `cache-sidechannel-chain` | `action=metrics_read` + `per_tenant=true` + `authenticated=false` |
| `falco-cache-probe-burst` | Falco | `cache-sidechannel-chain`（监视） | `evt.type=cache_probe` + `probe_count ≥ 50` |
| `suricata-cache-plane-uri` | Suricata | 两条链 | `/kvpool/blocks`、`/approx/lookup`、`/cache/residue`、`/router/metrics` URI |

紫队验证：`inkblade.rules.validate` 对两条链重放真实 HTTP 探针，合成 Sigma/Falco/Suricata 事件，
两链均无“漏过”单元；规则包 `mapping.json` 的 `blocks_chains` 绑定到上述链。

---

## 6. 复现与测试

```powershell
# 仿真靶场（vulnerable / fixed 两姿态）
python -m lab.cache_sim --port 0 --mode vulnerable

# 4 项实效（生成 reports/samples/cache-security/effects.json|md）
python -m lab.cache_effects --out reports/samples/cache-security

# 模块 + 靶场 + 链/规则/文档 + 实效
python -m unittest tests.test_cache_sim tests.test_modules_cache tests.test_cache_security -v
```

---

## 7. 实效 +4（实测，2026-10-26）

来源：`reports/samples/cache-security/effects.json`（`lab.cache_effects --mode vulnerable`）。

| # | 实效 | 关键数值 | 判定 |
|---|---|---|---|
| 1 | 近似缓存误命中读回他租户 marker | 相似度 0.8824 ≥ 阈值 0.85；`matched.tenant=tenant-b`；响应含 `INKBLADE-BENIGN-APPROX-VICTIM` | PASS |
| 2 | TTFT 差异显著（N≥50） | N=60；27.9ms vs 222.2ms；Δ=194.3ms；Welch `t=-44.10`、`df=29.81`、`p=1.05e-28`；两档区间 [22,31] / [186,268] 不重叠 | PASS |
| 3 | 逐出残留跨租户可读 | 洪泛后 `evictions 0→65`；`/cache/residue` 200；`tenant=tenant-b`；preview 含 `INKBLADE-BENIGN-RESIDUE-VICTIM` | PASS |
| 4 | 远程 KV 池命名空间绕过 | `tenant-b/ctx/seed-001` 200；`tenant=tenant-b`；值含 `INKBLADE-BENIGN-POOL-VICTIM` | PASS |

`fixed` 姿态对照：4 项均不成立（跨租户 `cached_tokens=0`、近似 miss、TTFT 无显著差分、
残留 404、池读 403、pinning 被拒），由 `tests/test_cache_security.py::EffectDifferentialTest` 断言。

---

## 8. 非声称与限制

- 不声称对真实 vLLM/SGLang/GPTCache/Mooncake/LMCache 生产实例的未授权利用；本仓库只提供
  本机仿真 + 可复现检测口径，真实目标需授权。
- TTFT 是仿真计时，不是 GPU 实测；真实环境需按机型/负载重新标定 `min_effect_ms` 与 `alpha`。
- 远程 KV 池接口按 Mooncake/LMCache 的“块存储 + 传输”抽象建模，不绑定其具体 RPC 协议；
  真实适配需替换 `remote-kv-pool-isolation` 的 URL/认证参数。
- 指标/样本只使用 benign fixture（`INKBLADE-BENIGN-*`），不含真实业务数据或凭据。
- 写类验证仅在 `backup-write` + 备份回执下执行；生产使用需额外 ROE/范围闸门。

---

## 9. 公开资料对照（2026-10）

- vLLM Automatic Prefix Caching / `cache_salt`：<https://docs.vllm.ai/en/latest/features/automatic_prefix_caching.html>、
  <https://docs.vllm.ai/en/latest/api/vllm/engine/arg_utils.html>（`cache_salt` 请求参数语义以对应版本文档为准）。
- SGLang RadixAttention / 前缀缓存：<https://docs.sglang.ai/>、RadixAttention 论文
  <https://arxiv.org/abs/2312.07104>。
- GPTCache（语义缓存、相似度阈值、向量存储）：<https://gptcache.readthedocs.io/>、
  <https://github.com/zilliztech/GPTCache>。
- Mooncake（KVCache 池 / Transfer Engine）：<https://github.com/kvcache-ai/Mooncake>、
  <https://arxiv.org/abs/2407.00079>。
- LMCache（KV cache layer / 远程后端）：<https://github.com/LMCache/LMCache>、
  <https://docs.lmcache.ai/>。
