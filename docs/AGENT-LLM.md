# Agent and LLM configuration (optional) / Agent 与 LLM 配置（可选）

[English](#english) · [中文](#中文)

---

## English

### The scan path has no model in it

Recon, module execution, chain planning, evidence, exports and the body of every report run on the
Python standard library. Nothing in that path loads weights, calls an inference server or needs a
key. A laptop with the network unplugged produces the same plan, the same evidence tree and the same
report as a host with an endpoint configured.

A model, when you attach one, reorders work the rule engine already proposed. It cannot invent a
module, widen a scope, lower a technical level or approve an action.

### Where a model can be called

| Path | What the model does | With no endpoint |
|---|---|---|
| `explore propose` | Ranks the candidate list produced by the deterministic planner, returns at most five module keys | Rules order the list: read-only first, asset-targeted first |
| `explore autonomy --autonomy L3` | Same ranking inside the pre-authorized loop | `--llm` refuses at preflight; without `--llm` the loop runs on rules |
| `report-ctem` | Writes one optional narrative paragraph from a facts dictionary | A fixed template paragraph |

Everything else stays local: collect, discover, module runs, chains, backup, rollback, the three
evidence layers, report sections, SARIF/OCSF/VEX export and rule generation.

### Two ways to attach an endpoint

**Pool, `llm_pool.json`.** Several endpoints, weights, per-endpoint quotas, cooldown and failover.
This is what `explore` prefers once it is enabled. Two ways to enable it: `"enabled": true` in the
file, or the environment variable `INKBLADE_LLM_POOL=1`.

**One endpoint by environment.** `INKBLADE_LLM_BASE_URL`, `INKBLADE_LLM_API_KEY` and
`INKBLADE_LLM_MODEL`. The explorer and the L3 preflight read these. There are no weights, quotas or
health records on this path, and it is never enabled by accident: no base URL, no calls. When both
exist, the pool is tried first and the environment endpoint is the fallback.

```bash
export INKBLADE_LLM_API_KEY_LOCAL='<token>'
export SCHEME=https                # plaintext scheme only on loopback

# add one endpoint, then switch the pool on (lead or admin)
inkblade --home ./lab llm-pool add --workspace local-lab --role lead \
  --base-url "$SCHEME://127.0.0.1:8000/v1" \
  --model local-instruct \
  --api-key-env INKBLADE_LLM_API_KEY_LOCAL \
  --weight 1 --quota-requests 200 --quota-tokens 200000

inkblade --home ./lab llm-pool enable --workspace local-lab --role lead
inkblade --home ./lab llm-pool health --workspace local-lab --role lead
```

`$SCHEME` is `https` for a TLS gateway, or `http` only on loopback. `add` writes the entry but does
not enable the pool; `enable` does. `health` sends `GET /models` to every enabled endpoint and needs
the pool to be on.

### `llm_pool.json`

The CLI writes it to `<home>/evidence/<workspace>/llm_pool.json`. Hand edits are fine; the file is
read on every call. A minimal file:

```json
{
  "enabled": true,
  "endpoints": [
    {
      "id": "ep-01",
      "base_url": "<scheme>://127.0.0.1:8000/v1",
      "model": "local-instruct",
      "api_key_env": "INKBLADE_LLM_API_KEY_LOCAL",
      "weight": 1,
      "quota_requests": 200,
      "quota_tokens": 200000
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `enabled` | yes | Master switch. Missing or `false` means every `complete` call raises `PoolDisabled`. |
| `endpoints[].id` | no | Stable name; generated as `ep-01`, `ep-02` when omitted. |
| `base_url` | yes | OpenAI-compatible root. Host part is `127.0.0.1:8000/v1`; the loader rejects a value without a transport scheme, so write `<scheme>` as your gateway's scheme. |
| `model` | yes | Model name sent in the request body. |
| `api_key` | one of | Literal key kept in the workspace file. |
| `api_key_env` | one of | Name of the environment variable holding the key. Wins over `api_key` when both are set. |
| `weight` | no | 1 to 100, smooth weighted round-robin. Default 1. |
| `quota_requests` | no | Calls per endpoint per UTC day. `0` means no cap. |
| `quota_tokens` | no | Tokens per endpoint per UTC day. `0` means no cap. |

On failure the endpoint is cooled down for 30 seconds, then 60, 120 and so on, capped at 600. The
call moves to the next healthy endpoint within the same request. If every endpoint is down, cooled
down or out of quota, the caller gets `NoHealthyEndpoint` and falls back to rule ordering.

The pool stores health and daily usage in the same JSON file. It does not store prompts or
responses. `llm_pool_records.jsonl` keeps endpoint, model, purpose, token count, latency and the
error string. `audit.jsonl` gets an `llm.complete` row for each success and each failure.

### Commands

| Command | What it does | Role |
|---|---|---|
| `inkblade llm-pool status` | Config path, endpoints, health, usage, quota state | any |
| `inkblade llm-pool add` | Adds one endpoint (`--base-url`, `--model`, `--api-key-env`, `--weight`, `--quota-requests`, `--quota-tokens`, `--id`) | lead, admin |
| `inkblade llm-pool remove --id ep-01` | Drops the endpoint and its health/usage rows | lead, admin |
| `inkblade llm-pool enable` / `disable` | Flips the master switch | lead, admin |
| `inkblade llm-pool health` | Live `/models` probe, updates cooldown | lead, admin |
| `inkblade llm-pool models` | Endpoint and model pairs | any |
| `inkblade llm-pool records` | Metadata-only call log | any |
| `inkblade llm-pool tokens` | Token totals by day | any |
| `inkblade llm-pool reset --id ep-01 --usage` | Clears cooldown; `--usage` also clears the stored usage history | lead, admin |

The CLI has no flag that puts a key on the command line. Use `--api-key-env`, or edit the file if
your policy allows a literal key there.

### L3: what must be true before the loop runs

L3 is a lead pre-authorization with runtime edges, not a model with a shell. Preflight refuses
unless all of the following hold:

1. Consent is signed and the HMAC verifies. A missing or edited record stops here.
2. The technical level is the top one, full-impact demo. Exploit verification and below are
   refused.
3. `autonomy/grant.json` exists, carries an HMAC over every field, is `active` and has not expired.
4. `--preauth-token` matches `token_sha256` in constant time. The default TTL is 1800 seconds.
   `inkblade autonomy revoke` marks the grant `revoked`; the next preflight fails.
5. The allowlist is not empty. `max_actions` is 1 to 50, `max_steps` is 1 to 20, and all four
   budgets (tokens, latency, approvals, interventions) are positive. Zero is rejected: a budget of
   zero is not "unlimited".
6. With `--llm`, a real endpoint exists. No endpoint means refusal at startup, not a silent
   drop to rules.

At run time the guard checks every action against the allowlist, refuses writes unless
`--allow-writes` was granted, rechecks namespace/host scope, pre-charges the budget before the
action, enforces one per-step action cap, and stops after two consecutive failures. Write modules
still pass the runner's backup gate; the grant does not replace it.

Each step appends `autonomy.*` audit rows and a trace row carrying `plan_sha256` over the decision
surface. `inkblade autonomy replay` replays those decisions without executing modules. To run again,
issue a new grant.

```bash
inkblade autonomy grant --workspace l3-lab --role lead \
  --allowlist rbac-mapping,network-policy-coverage,escape-primitives \
  --max-actions 4 --max-steps 3 --ttl-seconds 1800 \
  --budget-tokens 20000 --budget-latency-ms 120000 \
  --budget-approvals 6 --budget-interventions 2

inkblade explore autonomy --workspace l3-lab --autonomy L3 \
  --llm --preauth-token '<token printed once>' --workers 2

inkblade autonomy status --workspace l3-lab
inkblade autonomy revoke --workspace l3-lab --reason "window closed"
```

### Data boundary

A prompt can contain candidate module keys, product names, asset counts, eligible chain ids, the
RoE level, and the blackboard summaries a lead pinned: finding title, severity, evidence anchor,
asset key, product, address and note. `report-ctem` sends a small facts dictionary: run name,
counts, module series, asset count, retest count.

It does not send credentials, service-account tokens, request or response bodies, evidence
archives, `context.jsonl.gz` content, report bodies or API keys. Audit records carry endpoint id,
model, token count and latency, not prompt text.

Use a local endpoint, or one your security team has approved for this data. Keep TLS for anything
that is not on the same host. Put the key in an environment variable through `api_key_env` and keep
it out of the repository. If you do use `api_key`, remember that the workspace file now holds a
secret.

### What changes without a model

| Behaviour | With an endpoint | Without |
|---|---|---|
| Candidate order | Model ranking, validated against the candidate set; out-of-set keys are dropped | Fixed rule order |
| Proposal mode | `llm` when the model returned a usable sequence | `rules`, no error |
| Report narrative | One model-written paragraph | Template paragraph |
| L3 with `--llm` | Runs | Refused at preflight |
| L3 without `--llm` | Rule-ranked loop | Same |
| Quotas and audit | `llm.complete` rows, per-endpoint counters | None |

If you want the deterministic path every time, pass `--use-llm false` to `explore propose`, or
leave both the file and the environment unset. L3 without `--llm` never calls a model.

---

## 中文

### 扫描本身不需要模型

侦察、模块执行、链规划、证据、导出、报告正文，全部只依赖 Python 标准库。这条路径不加载权重、不连推理
服务、也不要 key。断网的笔记本和配好端点的机器，产出的计划、证据树与报告是同一份。

接上模型以后，它只对规则引擎已经给出的候选做排序。它不能新增模块、放大范围、降低技术级别，也不能批准
动作。

### 会调用模型的三处

| 路径 | 模型做什么 | 没有端点时 |
|---|---|---|
| `explore propose` | 对确定性规划器给出的候选排序，最多返回 5 个模块 key | 规则排序：只读在前、有资产目标在前 |
| `explore autonomy --autonomy L3` | 在预授权循环里做同样的排序 | 带 `--llm` 时预检直接拒绝；不带则按规则跑 |
| `report-ctem` | 依据 facts 字段写一段可选叙述 | 固定模板段落 |

其余的 collect、discover、单模块、链、备份、回滚、三层证据、报告主体、SARIF/OCSF/VEX 导出、规则生成，
都不出网。

### 两种接法

**模型池 `llm_pool.json`。** 支持多端点、权重、端点级配额、冷却与失败切换。`explore` 在池开启时优先
用它。开启方式有两种：文件里 `"enabled": true`，或环境变量 `INKBLADE_LLM_POOL=1`。

**环境变量接单端点。** `INKBLADE_LLM_BASE_URL`、`INKBLADE_LLM_API_KEY`、`INKBLADE_LLM_MODEL`。
explorer 与 L3 预检会读它们。这条路径没有权重、配额和健康记录，也不会被误开：不设 base URL 就不调用。
两者同时存在时，先试池，失败再走环境端点。

```bash
export INKBLADE_LLM_API_KEY_LOCAL='<口令>'
export SCHEME=https                # 只有回环地址才用明文协议

# 加一个端点，再打开池（需要 lead 或 admin）
inkblade --home ./lab llm-pool add --workspace local-lab --role lead \
  --base-url "$SCHEME://127.0.0.1:8000/v1" \
  --model local-instruct \
  --api-key-env INKBLADE_LLM_API_KEY_LOCAL \
  --weight 1 --quota-requests 200 --quota-tokens 200000

inkblade --home ./lab llm-pool enable --workspace local-lab --role lead
inkblade --home ./lab llm-pool health --workspace local-lab --role lead
```

`$SCHEME` 在 TLS 网关上是 `https`，只有回环地址才用 `http`。`add` 只写端点，不打开池；`enable` 才
打开。`health` 会对每个启用端点发 `GET /models`，池未开启时拒绝执行。

### `llm_pool.json` 字段

CLI 把它写到 `<home>/evidence/<workspace>/llm_pool.json`。手改也可以，每次调用都会重新读。最小示例：

```json
{
  "enabled": true,
  "endpoints": [
    {
      "id": "ep-01",
      "base_url": "<scheme>://127.0.0.1:8000/v1",
      "model": "local-instruct",
      "api_key_env": "INKBLADE_LLM_API_KEY_LOCAL",
      "weight": 1,
      "quota_requests": 200,
      "quota_tokens": 200000
    }
  ]
}
```

| 字段 | 必填 | 含义 |
|---|---|---|
| `enabled` | 是 | 总开关。缺失或 `false` 时，`complete` 一律抛 `PoolDisabled`。 |
| `endpoints[].id` | 否 | 稳定名称；省略时按 `ep-01`、`ep-02` 生成。 |
| `base_url` | 是 | OpenAI 兼容根地址。主机部分是 `127.0.0.1:8000/v1`；加载器不接受没有传输协议的写法，所以 `<scheme>` 要换成网关实际使用的协议。 |
| `model` | 是 | 请求体里的模型名。 |
| `api_key` | 二选一 | 明文 key，落在工作区文件里。 |
| `api_key_env` | 二选一 | 存 key 的环境变量名。两者都在时以它为准。 |
| `weight` | 否 | 1 到 100，平滑加权轮询。默认 1。 |
| `quota_requests` | 否 | 每端点每 UTC 日请求数，`0` 表示不限。 |
| `quota_tokens` | 否 | 每端点每 UTC 日 token 数，`0` 表示不限。 |

端点失败后冷却 30 秒，随后 60、120 秒递增，上限 600 秒。同一次调用内切到下一个健康端点；全部不可用
时抛 `NoHealthyEndpoint`，调用方降级到规则排序。

池把健康状态与当日用量写回同一个 JSON，不保存提示词与响应。`llm_pool_records.jsonl` 只存端点、模型、
用途、token 数、时延与错误串。`audit.jsonl` 每次成功或失败都追加一行 `llm.complete`。

### 命令

| 命令 | 作用 | 角色 |
|---|---|---|
| `inkblade llm-pool status` | 配置路径、端点、健康、用量、配额状态 | 任意 |
| `inkblade llm-pool add` | 加端点（`--base-url`、`--model`、`--api-key-env`、`--weight`、`--quota-requests`、`--quota-tokens`、`--id`） | lead、admin |
| `inkblade llm-pool remove --id ep-01` | 删端点及其健康/用量记录 | lead、admin |
| `inkblade llm-pool enable` / `disable` | 切换总开关 | lead、admin |
| `inkblade llm-pool health` | 实时探测 `/models`，更新冷却 | lead、admin |
| `inkblade llm-pool models` | 端点与模型对照 | 任意 |
| `inkblade llm-pool records` | 只含元数据的调用记录 | 任意 |
| `inkblade llm-pool tokens` | 按天统计 token | 任意 |
| `inkblade llm-pool reset --id ep-01 --usage` | 清冷却；`--usage` 同时清掉已存的用量记录 | lead、admin |

CLI 没有把 key 放到命令行上的参数。用 `--api-key-env`；策略允许明文时才手改文件。

### L3 的前置条件

L3 是 lead 预授权加运行时硬边界，不是给模型一个 shell。以下任一条不成立，预检就拒绝：

1. 授权已签且 HMAC 验签通过。记录缺失或被改动，到这里就停。
2. 技术级别是最高级「全影响演示」。「利用验证」及以下直接拒绝。
3. `autonomy/grant.json` 存在，HMAC 覆盖全部字段，`status` 为 `active`，且未过期。
4. `--preauth-token` 与 `token_sha256` 常量时间比对通过。默认 TTL 1800 秒。`inkblade autonomy revoke`
   把 grant 标成 `revoked`，下一次预检即失败。
5. 白名单非空；`max_actions` 1 到 50，`max_steps` 1 到 20；tokens、latency、approvals、interventions
   四项预算都必须为正。写 0 会被拒：预算为 0 不等于「不限」。
6. 带 `--llm` 时必须存在真实端点。没有端点就在启动时拒绝，不静默降级。

运行时，护栏逐个动作检查白名单；未授权 `--allow-writes` 时拒绝写动作；复核 namespace/host 范围；
动作前预扣预算；限制单步动作数；连续两次失败即停。写模块照旧过 runner 的备份闸门，grant 不能替代它。

每一步都会写 `autonomy.*` 审计行，以及带 `plan_sha256` 的 trace。`inkblade autonomy replay` 只重放
决策，不执行模块。要再跑一次，只能签发新 grant。

```bash
inkblade autonomy grant --workspace l3-lab --role lead \
  --allowlist rbac-mapping,network-policy-coverage,escape-primitives \
  --max-actions 4 --max-steps 3 --ttl-seconds 1800 \
  --budget-tokens 20000 --budget-latency-ms 120000 \
  --budget-approvals 6 --budget-interventions 2

inkblade explore autonomy --workspace l3-lab --autonomy L3 \
  --llm --preauth-token '<只显示一次的 token>' --workers 2

inkblade autonomy status --workspace l3-lab
inkblade autonomy revoke --workspace l3-lab --reason "窗口结束"
```

### 数据边界

提示词里可能出现：候选模块 key、产品名、资产数量、成立的链 id、RoE 级别，以及 lead 固定到黑板的摘要
（发现标题、严重度、证据锚点、资产 key、产品、地址、备注）。`report-ctem` 会发一个很小的 facts 字典：
run 名、各项计数、模块系列、资产数、复测数。

不会发送：凭据、ServiceAccount 令牌、请求或响应正文、证据归档、`context.jsonl.gz` 内容、报告正文、
API key。审计只记端点、模型、token 数与时延，不记提示词。

端点用本地的，或者安全团队为这类数据批准过的。不在同一台主机上就上 TLS。key 放环境变量，通过
`api_key_env` 引用，不要进仓库。如果确实用了 `api_key`，就把工作区文件当成密件。

### 没有模型时差在哪

| 行为 | 有端点 | 没有 |
|---|---|---|
| 候选顺序 | 模型排序，并按候选集校验；集外 key 丢弃 | 固定规则顺序 |
| 提议模式 | 模型给出可用序列时记 `llm` | 记 `rules`，不报错 |
| 报告叙述 | 模型写的一段 | 模板段落 |
| 带 `--llm` 的 L3 | 运行 | 预检拒绝 |
| 不带 `--llm` 的 L3 | 规则排序循环 | 相同 |
| 配额与审计 | `llm.complete` 行与端点计数 | 无 |

想始终走确定性路径，就给 `explore propose` 加 `--use-llm false`，或者文件和两个环境变量都不设。不带
`--llm` 的 L3 不会调用模型。

---

See also: [Install](INSTALL.md) · [Usage](USAGE.md) · [Architecture](ARCHITECTURE.md) · [FAQ](FAQ.md)
