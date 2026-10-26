# LLM 探针矩阵（两态差分） · # LLM Probe Matrix (two-state differential)

共 **87** 个探针 / **13** 类，对 lab 两态靶场（vulnerable/fixed）真实 HTTP 差分：confirmed=87（攻击命中 74 + 对照不误报 13），判定分布 {"confirmed": 87}。分类映射 OWASP LLM Top 10 2026（LLM01–LLM10）与 OWASP Agentic AI（ASI01–ASI10）；每类 ≥1 条 SOC 检测规则键（规则包 sigma/llm-probe-*）。 · **87** probes across **13** categories, differentially executed against the vulnerable/fixed lab faces over real HTTP: confirmed=87 (attack hits 74 + clean controls 13), verdicts {"confirmed": 87}. Taxonomy maps OWASP LLM Top 10 2026 (LLM01-LLM10) and OWASP Agentic AI (ASI01-ASI10); every category links to at least one SOC detection rule (sigma/llm-probe-*).

| 类别 | 探针数 | confirmed | 漏报口径（未 confirmed） | OWASP LLM 2026 | ASI | 检测规则 |
|---|---:|---:|---|---|---|---|
| 越狱（多模板/多语言/编码） · Jailbreak (templates/multilingual/encoding) (`jailbreak`) | 12 | 12 | — | LLM01 | ASI01 | `sigma-llm-probe-jailbreak` |
| 提示注入（直接/间接/工具描述） · Prompt Injection (direct/indirect/tool-description) (`prompt-injection`) | 10 | 10 | — | LLM01 | ASI01, ASI06 | `sigma-llm-probe-prompt-injection` |
| 系统提示泄露 · System Prompt Leak (`sysprompt-leak`) | 6 | 6 | — | LLM08 | ASI01 | `sigma-llm-probe-sysprompt-leak` |
| 训练数据提取 · Training Data Extraction (`traindata-extraction`) | 5 | 5 | — | LLM02, LLM08 | ASI06 | `sigma-llm-probe-traindata-extraction` |
| PII 泄露 · PII Leakage (`pii-leak`) | 7 | 7 | — | LLM02 | ASI09 | `sigma-llm-probe-pii-leak` |
| 不安全建议 · Unsafe Advice (`unsafe-advice`) | 5 | 5 | — | LLM07 | ASI01 | `sigma-llm-probe-unsafe-advice` |
| 工具滥用（ASI） · Tool Misuse (ASI) (`tool-abuse`) | 7 | 7 | — | LLM03 | ASI02, ASI04, ASI05, ASI10 | `sigma-llm-probe-tool-abuse` |
| 多模态注入 · Multimodal Injection (`multimodal-injection`) | 4 | 4 | — | LLM01 | ASI01 | `sigma-llm-probe-multimodal-injection` |
| 长上下文攻击（淹没/中位注入/KV 利用） · Long-Context Attack (drowning/mid-position/KV abuse) (`longctx-attack`) | 9 | 9 | — | LLM01, LLM06 | ASI06, ASI08 | `sigma-llm-probe-longctx-attack` |
| 缓存投毒（语义缓存跨租户） · Cache Poisoning (semantic cache cross-tenant) (`cache-poison`) | 6 | 6 | — | LLM02, LLM05, LLM09 | ASI06 | `sigma-llm-probe-cache-poison` |
| 输出注入到下游 agent · Output Injection into Downstream Agents (`downstream-injection`) | 5 | 5 | — | LLM10 | ASI07, ASI08 | `sigma-llm-probe-downstream-injection` |
| 防护绕过（网关 guardrail 检查面） · Guardrail Bypass (gateway inspection surface) (`guardrail-bypass`) | 5 | 5 | — | LLM01 | ASI01 | `sigma-llm-probe-guardrail-bypass` |
| 网关资源/权限滥用 · Gateway Resource & Privilege Abuse (`gateway-abuse`) | 6 | 6 | — | LLM03, LLM04, LLM06 | ASI03, ASI08 | `sigma-llm-probe-gateway-abuse` |

严重度分布 {"low": 14, "high": 42, "critical": 22, "medium": 9}；目标面分布 {"gateway": 72, "relay": 6, "longctx": 9}；关联规则键 13 条。与 garak/PyRIT/promptfoo 的逐类对照（含计数口径与核验日期）见 `docs/PROBE-PARITY.md`。 · Severity distribution {"low": 14, "high": 42, "critical": 22, "medium": 9}; face distribution {"gateway": 72, "relay": 6, "longctx": 9}; 13 linked rule keys. Per-category parity with garak/PyRIT/promptfoo (counts and verification date) is in `docs/PROBE-PARITY.md`.
