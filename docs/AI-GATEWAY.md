# AI 网关与配套基建专项（AI-GATEWAY）

本文件是 InkBlade 在 **AI 网关（LiteLLM / Higress / Envoy AI Gateway 风格）** 及其配套基建
（模型注册表、语义缓存、向量库、请求日志、配额）上的威胁模型、模块↔链映射与检测口径。配套代码：

- 仿真靶场：`lab/ai_gateway_sim.py`（真实 HTTP，仅 127.0.0.1，`vulnerable` / `fixed` 两态）
- 模块：`inkblade/modules/` 下 10 个模块（`aigateway-*` / `model-registry-exposure` / `vector-db-exposure`）
- 攻击链：`inkblade/chains/ai-gateway-key-exfil.json`
- 规则：Sigma×2（管理 API 无鉴权 / 默认 master key 使用）、Falco（网关上游凭据配置读取）、
  Suricata（`/key/generate`、`/config`、`/admin/console` 访问特征）
- 实效验证：`inkblade/verify-effects.py` 中 `gateway-*` 三项（见 `docs/EFFECT-VERIFICATION.md`）
- 紫队验证：`inkblade/rules/validate.py` 按 `sim=ai-gateway` 自动拉起仿真器重放真实 HTTP

**边界声明**：本文与仿真器描述的是**控制面语义同构的实验室效果级验证**，不是真实模型厂商账号、
真实 Envoy 数据面或生产密钥系统实测。真实结论必须来自客户网关的授权配置快照与真实审计日志。

---

## 1. 组件、资产与信任边界

| 组件 | 典型实现 | 关键资产 | 信任边界错配 |
|---|---|---|---|
| **AI 网关数据面** | LiteLLM proxy / Higress AI / Envoy AI Gateway | 上游 provider key、模型路由表、租户额度 | 网关被当作「内网可信」，默认凭据/匿名可用 |
| **管理面** | `/key/generate`、`/key/info`、`/config`、`/admin/console` | master key、租户 key、provider 配置、别名表 | 管理端口与业务端口同网段、无独立鉴权 |
| **模型注册表** | OpenAI 兼容 `/models`、`/ai/route` | 私有模型、租户归属、内网后端地址 | 模型清单被视为「公开元数据」 |
| **语义缓存** | Redis/向量缓存 + 相似度阈值 | prompt/response 原文、租户数据 | 缓存键只取 prompt 前缀（共享前缀键） |
| **向量库** | Milvus/pgvector/Qdrant/ES kNN | collection、embedding、文档内容 | collection 名即租户边界，检索面无 scope |
| **请求日志** | 网关 access log / LLM observability | 明文 prompt、PII、Authorization 头 | 日志属于「运维面」，默认跨租户可见 |
| **配额/限流** | Redis 计数器 + 网关插件 | 成本、租户额度、上游配额 | 直接信任 `X-Forwarded-For`/`X-Real-IP` |

**统一根因**：网关把「网络位置」当作身份，把「共享键」当作租户隔离，把「管理便利」当作默认放行。
一旦默认凭据或代理头可伪造，后续的 provider key、模型清单、缓存/向量数据都成为同一信任链上的下游资产。

---

## 2. 威胁模型

### 2.1 网关鉴权与默认凭据（`aigateway-fingerprint` / `aigateway-auth-bypass`）

- **错配**：示例配置的 `master_key` 未轮换；`/v1/*` 与 `/key/*` 共用同一监听口且匿名放行；
  网关直接采信 `X-Forwarded-User` / `X-Tenant`（本应由入口代理签发并剥离外部同名头）。
- **后果**：匿名或默认 master key 可调用推理面（耗尽上游额度）、读取全局 key 清单、伪造 admin
  身份读取全租户日志，构成「默认凭据 → 上游 key」链的第一跳。
- **判据**：真实 HTTP 状态差分——vulnerable：匿名/默认 key 200、伪造头 `scope=global`；
  fixed：匿名/默认 key 401、伪造头 403 `impersonation_rejected`、租户 key 仅本租户。

### 2.2 上游 provider key 外泄（`aigateway-upstream-key-exfil`）

- **错配**：`/config` 返回明文 `api_key`（OpenAI/Anthropic/Bedrock 等），`/key/info` 暴露 master key；
  管理面只靠「内网可达」保护。
- **后果**：攻击者获得模型厂商计费面控制权（替换模型、拉取私有模型、消耗额度），并可把 key 复用到
  其他区域/云资源；这是「模型/云资源接管」的核心凭据面。
- **判据**：`/config` 200 且响应含 `MOCK-` 前缀上游 key；finding 与报告只保留 `MOCK****尾4位`，
  完整值仅存归档 trace（`run/traces/aigateway-upstream-key-exfil.json`）。

### 2.3 路由与模型注册表（`aigateway-route-hijack` / `model-registry-exposure`）

- **错配**：`/ai/model-alias` 写入无鉴权且无后端 allowlist；`/models`、`/ai/route` 匿名返回私有模型、
  租户归属与内网 backend。
- **后果**：把公共别名（如 `gpt-4o-mini`）指向攻击者后端，后续所有租户请求（含 prompt/响应）被中继；
  私有模型清单为模型盗用/权重桶定位提供目标。
- **判据**：vulnerable：别名写入 200 + 后续 chat `backend=攻击者 URL`、`upstream=hijacked`；
  fixed：admin key + allowlist（非白名单 400 `backend_not_allowlisted`），匿名 401。
  写类模块 `writes=true`，必须经 runner 备份闸门（`backup_targets`，建议 `/ai/route` 状态快照）。

### 2.4 语义缓存跨租户（`aigateway-cache-cross-tenant`）

- **错配**：缓存键 = `hash(prompt 前缀)`，不含租户/模型/策略版本；相似度命中后直接返回他租户响应。
- **后果**：租户 A 用同一 prompt 前缀即可读到租户 B 的模型响应（商业数据、系统提示、检索结果）。
- **判据**：requester=tenant-a 的 `/cache/lookup` 返回 `hit=true` 且 `entry.tenant=tenant-b`，
  且与 tenant-b 查询得到同一 `cache_key`（共享前缀键）；fixed 键含租户 → miss 且键不同。

### 2.5 向量库暴露（`vector-db-exposure`）

- **错配**：`/vector/collections`、`/vector/query` 无鉴权或只按 collection 名过滤，未绑定调用者租户。
- **后果**：枚举全租户 collection、按相似度检索他人文档；embedding 端点同时泄露模型与维度信息。
- **判据**：匿名 collection 清单含他租户；query 命中 `tenant-b` 文档内容；fixed：匿名 401、
  租户 key 仅见本租户 + `shared`、越权 collection 403。

### 2.6 日志 PII 与配额绕过（`aigateway-log-pii-leak` / `aigateway-quota-bypass`）

- **错配**：`/logs` 保留明文 prompt、邮箱/电话/卡号与 `Authorization` 头；配额按 `X-Forwarded-For`
  分桶（可轮换伪造）。
- **后果**：日志成为 PII/凭据二次泄露源；配额绕过造成成本型滥用（盗刷上游额度、拖垮共享池）。
- **判据**：日志 PII 计数 >0 且 Authorization 明文；轮换 XFF 后 0 个 429 且桶数增长（vulnerable）；
  fixed：租户过滤 + `<email>/<phone>/<card>` 脱敏，配额绑定 API key 并返回 429。

### 2.7 Guardrail 绕过（`aigateway-guardrail-bypass`）

- **错配**：guardrail 只检查 `messages[0]` 或只识别 `user` 角色，后续 `user/developer` 消息未检查。
- **后果**：注入指令/密钥外泄指令直达模型，回显 system prompt canary。
- **判据**：vulnerable：多消息变体 200 且 `guardrail.inspected_messages=1`、`bypass_suspected=true`、
  响应含 `MOCK_SYSTEM_PROMPT_CANARY`；fixed：全量检查 400 `guardrail_blocked`。

---

## 3. 模块矩阵（10 个）

| 模块 | 系列 / 级别 | writes | 路由 | 关键证据 |
|---|---|---|---|---|
| `aigateway-fingerprint` | 侦察 / 只读侦察 | false | `/health`、`/models`、`/key/info`、`/config`、`/admin/console` | 产品版本 + 未鉴权面清单 + 默认 master key 泄露标志 |
| `aigateway-auth-bypass` | 横向利用 / 利用验证 | false | `/v1/chat/completions`、`/key/info`、`/logs` | 匿名/默认 key 状态矩阵、伪造头 `scope=global`、全租户日志 |
| `aigateway-upstream-key-exfil` | 窃取与数据泄露 / 利用验证 | false | `/config`、`/key/info` | provider key 尾4位 + 完整值归档 trace |
| `aigateway-route-hijack` | 横向利用 / 利用验证 | **true** | `GET/POST /ai/route`、`POST /ai/model-alias`、chat | 别名 baseline/attacker backend + `upstream=hijacked` + 备份回执 |
| `aigateway-cache-cross-tenant` | 窃取与数据泄露 / 利用验证 | false | `/cache/lookup`（requester/victim 双查） | `hit`、`entry.tenant`、共享 `cache_key` |
| `aigateway-quota-bypass` | 横向利用 / 主动探测 | false | `/quota`、`/v1/chat/completions`（XFF 轮换） | 状态序列、429 计数、桶数变化、`enforced` |
| `aigateway-log-pii-leak` | 窃取与数据泄露 / 主动探测 | false | `/logs` | PII 模式计数、Authorization 明文、脱敏标记数 |
| `aigateway-guardrail-bypass` | 横向利用 / 利用验证 | false | `/v1/chat/completions`（多角色变体） | `inspected_messages`、`bypass_suspected`、canary |
| `model-registry-exposure` | 侦察 / 只读侦察 | false | `/models`、`/ai/route` | 私有模型、他租户模型、backend 地址 |
| `vector-db-exposure` | 侦察 / 只读侦察 | false | `/vector/collections`、`/vector/query` | 他租户 collection、命中文档摘录（<=80 字符） |

写类约定：`aigateway-route-hijack` 的 `mode=backup-write` 才触碰 `/ai/model-alias`；无
`backup_targets` 时 runner 在模块执行前抛 `BackupGateRefused`（退出码 91），服务端别名表保持不变。

---

## 4. 链 `ai-gateway-key-exfil`

**类别**：`AI 网关链`；**前置**：`findings('aigateway-fingerprint').count >= 1`。

| 步骤 | 模块 | 依赖 | 产出 |
|---|---|---|---|
| `gateway-fingerprint` | `aigateway-fingerprint` | — | 产品指纹 + 未鉴权面 |
| `default-key-auth` | `aigateway-auth-bypass` | gateway-fingerprint | 默认凭据/伪造头越权证据 |
| `upstream-key-exfil` | `aigateway-upstream-key-exfil` | default-key-auth | provider key（掩码）+ 归档全文 |
| `model-registry-map` | `model-registry-exposure` | upstream-key-exfil | 私有模型/后端/租户归属 |
| `route-hijack` | `aigateway-route-hijack`（writes） | model-registry-map | 别名劫持 + backup receipt |

链语义：**默认 master key / 匿名管理面 → 上游 provider key → 模型清单 → 别名路由劫持**。
`mitre`：T1552（Unsecured Credentials）、T1078（Valid Accounts）、T1090（Proxy）。

---

## 5. 检测规则映射

| 规则 ID | 引擎 | 触发口径 | 关键调参 |
|---|---|---|---|
| `sigma-gateway-admin-api-no-auth` | Sigma | `verb=admin_api_call` + `path∈{/key/generate,/config,/admin/console}` + `auth∈{none,tenant}` | 管理员主体/运维网段白名单；key 签发记录目标租户 |
| `sigma-gateway-default-master-key-use` | Sigma | `verb=authenticate` + `key_class=default_master` + `status=200` | 任意时点成功即 critical；初始化窗口用一次性 bootstrap token |
| `falco-gateway-upstream-config-read` | Falco | 网关进程运行期读 `/config`、`/etc/litellm`、`provider-secrets` | 启动窗口抑制；非网关进程读取升级 |
| `suricata-ai-gateway-admin-uri` | Suricata | HTTP `/key/generate`、`/config`、`/admin/console` | 非 bastion/运维网段直接 alert；`/config` 叠加 200+响应体判定 |

紫队验证：`probes.json` 的 `ai-gateway-key-exfil` 计划标记 `sim=ai-gateway`，
`validate()` 自动启动 `lab/ai_gateway_sim.py`（vulnerable）重放 5 条真实 HTTP 探针，
合成 Sigma/Falco/Suricata 事件；覆盖率矩阵中该链状态为 `检测`（4/4 规则命中，0 漏过）。

---

## 6. 实验室仿真与两态不变量

`lab/ai_gateway_sim.py` 仅监听 `127.0.0.1`，单进程内存态：

- **LiteLLM 风格**：`/v1/chat/completions`、`/models`（`/v1/models` 别名）、`/v1/embeddings`、
  `/key/generate`、`/key/info`、`/config`、`/health`
- **Higress/Envoy AI 风格**：`/ai/route`、`/ai/model-alias`、`/admin/console`
- **语义缓存**：`/cache/store`、`/cache/lookup`（vulnerable 键=共享前缀哈希；fixed 键=租户+前缀哈希）
- **配套面**：`/logs`、`/quota`、`/vector/collections`、`/vector/query`、`/__routes__`

固定实验室凭据（全部 `MOCK` 前缀，无真实语义）：

| 凭据 | 值 | 两态语义 |
|---|---|---|
| 默认 master key | `MOCK-master-key-4c7a` | vulnerable 可用；fixed 401 |
| 轮换 admin key | `MOCK-rotated-admin-key-e5f6` | 仅 fixed 管理面可用 |
| 租户 A/B key | `MOCK-tenant-a-key-a1b2` / `MOCK-tenant-b-key-c3d4` | fixed 租户 scope |
| 上游 provider key | `MOCK-openai-upstream-key-9f3c` / `MOCK-anthropic-upstream-key-71ab` | vulnerable 明文；fixed 掩码 |

两态不变量：

| 面 | vulnerable | fixed |
|---|---|---|
| 匿名推理/模型/日志/配额/向量 | 200 | 401 |
| 默认 master key | 200（admin 全权） | 401 `default_master_key_rejected` |
| 伪造 `X-Forwarded-User` | 200（`scope=global`） | 403 `impersonation_rejected` |
| `/config` | 明文上游 key | admin key + `MOCK****尾4位` |
| 模型别名 | 任意 backend 生效 | admin + allowlist（400） |
| 语义缓存 | 跨租户命中（共享 key） | 租户键 → miss |
| 配额 | 按 XFF 分桶，无 429 | 绑定 key，超限 429 |
| 日志 | 全租户明文 PII | 租户过滤 + 脱敏 |
| Guardrail | 仅查首条消息 | 全量消息 400 |

---

## 7. 复现与验收

```bash
# 仿真器两态
python -m unittest tests.test_lab_ai_gateway -v

# 10 模块 vulnerable 命中 / fixed 干净 / 写类闸门 / 链执行
python -m unittest tests.test_modules_aigateway -v

# 规则覆盖 + 紫队验证（自动拉起 AI 网关仿真）
python -m unittest tests.test_rules tests.test_chains -v

# 实效验证（17 项，含 gateway-* 三项）
python -m inkblade.verify-effects --out reports/samples/effects/

# 全量回归
python -m unittest discover -s tests
```

## 8. Ruling 与边界

1. **凭据口径**：上游 key 全文只允许出现在归档 trace；finding/报告/摘要一律 `MOCK****尾4位`。
2. **默认凭据口径**：默认 master key 是「已知默认值」，fixed 语义为 401（未授权），而不是 403（权限不足）；
   轮换 admin key 才有管理面权限。
3. **缓存口径**：vulnerable 的跨租户命中要求 `entry.tenant != requester` 且两次 lookup 的 `cache_key`
   完全一致；仅「相似但不同键」不构成本 finding。
4. **配额口径**：只观测状态码与桶数，不消耗真实额度；fixed 必须在轮换 XFF 后仍出现 429。
5. **写面口径**：`aigateway-route-hijack` 为唯一写类模块，必须经 backup_targets 闸门；probe-only 只读。
6. **仿真边界**：内存态、`MOCK` 凭据、无真实模型厂商/Envoy/向量数据库；真实结论需客户环境的授权配置与审计日志。
