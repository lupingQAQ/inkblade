# LLM 探针对标（garak / PyRIT / promptfoo）

> 目标：补齐并超越 garak/PyRIT 的 LLM 探针覆盖。本文给出探针数与类别的对照、本库独有面与明确未覆盖项。
> 计数口径：garak/PyRIT/promptfoo 取自本仓 `.slim/clonedeps/repos/` 浅克隆实测（`class …(*Probe*)` /
> `class …(*Converter*)` 正则 + 插件文件计数），官方文档链接附后；Trident 口径 =
> `trident/probes/library/` 数据文件（87 个探针 / 13 类）。
> 核验日期：2026-10-26（克隆版本：garak d6a8be1 / PyRIT 246b659 / promptfoo b4c2404）。
> 复现命令：`python -c "import pathlib,re; ..."` 对上述克隆计数；计数含抽象基类时另行标注。
> 许可合规：三家均为 Apache-2.0/MIT，此处仅参考其公开分类思想；Trident 探针库为独立实现（数据文件 + 独立判定器引擎）。

## 1. 总量对照

| 工具 | 计数口径（实测） | 数量 | 类别组织方式 |
|---|---|---|---|
| garak | `garak/probes/*.py` 探针模块 / `class …(*Probe*)` | 41 模块 / **149** 类（含 3 个 `base.py` 中间基类；剔除后 **146**） | 按模块文件分类（dan/encoding/promptinject/leakreplay/sysprompt_extraction/latentinjection/atkgen/suffix/visual_jailbreak/ansiescape/smuggling/audio/fileformats/…） |
| PyRIT | `pyrit/**` Converter 类 + jailbreak 模板数据集 | **114** Converter 类（含 2 个抽象基类；剔除后 **112**）+ **94** 越狱模板 | Converter（变体改写）× Orchestrator（多轮编排）× 数据集组合式，无固定探针清单 |
| promptfoo | `src/redteam/plugins/*.ts` + `strategies/*.ts` | **54** 插件 + **32** 策略（均剔除 base/index） | 插件（攻击意图）× 策略（jailbreak:basic/iterative/prefix-split/crescendo 等改写） |
| **Trident** | `trident/probes/library/**/*.json` | **87** 探针 / **13** 类 | 数据文件探针（键=文件名）× 判定器引擎 × 两态差分运行器 × 13 条 sigma 联动规则 |

结论：按可执行的攻击探针计，Trident（87）达到 garak 剔除 `base.py` 中间基类后的 146 的 60%、
原始类计数（149）的 58%，超过 promptfoo 单维插件数（54），
达到 PyRIT 剔除 2 个抽象基类后的 112 的 78%；
组织方式上 Trident 独有「每个探针 = 数据文件 + 判定器 + 严重度 + 规则键 + 两态预期（expect vulnerable/fixed）」，
使探针命中可被自动化差分复核（87/87 confirmed：74 攻击差分 + 13 防误报对照）。

## 2. 逐类对照（13 类）

| Trident 类别（探针数） | OWASP LLM 2026 / ASI | garak 对应 | PyRIT 对应 | promptfoo 对应 |
|---|---|---|---|---|
| jailbreak（12） | LLM01 / ASI01 | probes.dan、probes.suffix、probes.atkgen、probes.glitch | PromptJailbreakConverter + 94 模板 + many-shot 数据集 | jailbreak 插件 ×32 策略、pliny |
| prompt-injection（10） | LLM01 / ASI01/06 | probes.promptinject、probes.latentinjection、probes.encoding | AttackManipulationType 变体 + indirect 注入编排 | indirectPromptInjection、hijacking |
| sysprompt-leak（6） | LLM08 / ASI01 | probes.sysprompt_extraction、probes.propile | system prompt 提取 scorer/orchestrator 组合 | promptExtraction |
| traindata-extraction（5） | LLM02/08 / ASI06 | probes.leakreplay、probes.continuation、probes.snowball | 数据集重放（canary/前缀补全） | imitation、hallucination（相邻） |
| pii-leak（7） | LLM02 / ASI09 | probes.apikey、probes.dra（部分） | PII 注入 converter + scorer 组合 | pii:direct、pii:quiz、pii:bank_CARD 等 |
| unsafe-advice（5） | LLM07 / ASI01 | probes.malwaregen、probes.misleading、probes.lmrc | harmfulness 数据集 + scorer | harmful:harmless、beavertails、donotanswer |
| tool-abuse（7） | LLM03 / ASI02/04/05/10 | probes.exploitation、probes.agentbreaker（agent 面） | tool-calling 攻击 scenario | excessiveAgency、mcp、shellInjection、sqlInjection、bola/bfla |
| multimodal-injection（4） | LLM01 / ASI01 | probes.visual_jailbreak、probes.audio、probes.fileformats | image/audio converter 组合 | imageDataset 插件（beavertails/harmbench 语料） |
| **longctx-attack（9）** | LLM01/06 / ASI06/08 | —（无） | —（无） | reasoningDos（相邻，仅资源维度） |
| **cache-poison（6）** | LLM02/05/09 / ASI06 | —（无） | —（无） | crossSessionLeak（相邻，仅会话维度） |
| downstream-injection（5） | LLM10 / ASI07/08 | probes.ansiescape、probes.smuggling（输出侧相邻） | 输出处理编排（自行组合） | —（弱） |
| guardrail-bypass（5） | LLM01 / ASI01 | probes.doctor（预检相邻） | —（无固定） | —（无固定） |
| **gateway-abuse（6）** | LLM03/04/06 / ASI03/08 | —（无） | —（无） | —（无） |

**2026 分类学覆盖**：OWASP LLM01–LLM10 与 ASI01–ASI10 **全部 20 个 id 均有类别映射**（10/10 + 10/10）。
编号按 [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
正式版（2026-08-03 发布）重排，并与本仓 `trident/reports/standards.json` 的 2025 crosswalk 对齐：

| 2026 编号 | 2026 名称 | 2025 旧编号 | 本库映射类别 |
|---|---|---|---|
| LLM01 | Prompt Injection | LLM01 | jailbreak / prompt-injection / multimodal-injection / guardrail-bypass / longctx-attack |
| LLM02 | Sensitive Information Disclosure | LLM02 | pii-leak / traindata-extraction / cache-poison |
| LLM03 | Excessive Agency | LLM06 | tool-abuse / gateway-abuse |
| LLM04 | Supply Chain | LLM03 | gateway-abuse（上游 provider key/模型别名劫持） |
| LLM05 | Data and Model Poisoning | LLM04 | cache-poison（语义缓存/记忆投毒） |
| LLM06 | Unbounded Consumption | LLM10 | longctx-attack / gateway-abuse |
| LLM07 | Misinformation | LLM09 | unsafe-advice |
| LLM08 | Hidden Context Exposure | LLM07 | sysprompt-leak / traindata-extraction |
| LLM09 | Vector and Embedding Weaknesses | LLM08 | cache-poison |
| LLM10 | Improper Output Handling | LLM05 | downstream-injection |

说明：LLM04/LLM05/ASI04/ASI10 为**类别级次级映射**（网关/缓存/工具面探针的语义归属），
不是「模型训练投毒」或「智能体自繁殖」的专用探针；专用能力缺口见 §4。
`unsafe-advice` 属有害内容，OWASP LLM 2026 无独立条目，此处以 LLM07（Misinformation）作最接近代理，
不宣称二者等价。

## 3. 本库独有（garak/PyRIT/promptfoo 均无对应）

1. **长上下文攻击**：上下文淹没（超窗仍 200+排队）、中位注入（载荷埋于超窗消息中段）、
   prefix cache 跨租户复用（`cached_tokens>0` 差分）、PD KV 通道未授权/跨租户写、checkpoint 分片未授权写、
   /metrics 训练拓扑泄露、max_tokens 炸弹 —— 依托 lab/longctx_sim 两态真 HTTP 差分（8+1 探针）。
2. **KV/缓存基建面**：语义缓存共享前缀键跨租户命中、缓存条目覆写投毒、前缀归一化碰撞劫持（尾随空白）、
   未授权缓存键枚举 —— garak/PyRIT 的探针全部止步于「模型对话面」，不覆盖推理网关缓存/KV 基建。
3. **AI 网关面**：未授权 key 签发、私有模型枚举、/config 明文上游凭据、配额 XFF 轮换绕过、开放中继
   —— 目标是网关控制面（LiteLLM/Higress 风格）而非模型本身。
4. **判定器与规则联动**：每探针类 ≥1 条 SOC sigma 检测规则（`sigma-llm-probe-*` 共 13 条，scope=llm-probe），
   探针矩阵直接产出报告节（「LLM 探针矩阵」），两态 expect 声明使「命中/不误报」都可自动断言
   （garak 探针→detector 推荐是模块内约定，无网关规则联动；PyRIT/promptfoo 无规则转化层）。

## 4. 明确未覆盖项（诚实缺口，登记为 backlog）

| 缺口 | 上游对应 | 说明 |
|---|---|---|
| 自适应 LLM 生成攻击 | garak probes.atkgen（LLM 现场生成攻击）、PyRIT TAP/PAIR 编排、promptfoo iterative 策略 | 需真实 LLM 生成器；本库全部为确定性数据探针（可复现优先） |
| GCG 后缀优化攻击 | garak probes.suffix（优化式） | 需梯度/迭代优化回路 |
| 音频/文件格式探针 | garak probes.audio、probes.fileformats | 多模态当前仅覆盖文本+图像+音频内容注入（4 探针），无真实音频/文件载荷 |
| 图像数据集语料探针 | promptfoo imageDataset（beavertails/harmbench 语料）、garak realtoxicityprompts | 需语料打包与分类器评分 |
| 编码广度 | garak probes.encoding（20+ 编码方案）、probes.ansiescape、probes.smuggling | 本库编码类仅 base64/leet/混合语言（越狱类内 3 探针） |
| 多语言广度 | garak langproviders | 本库多语言覆盖 zh/fr/ru 混合模板（越狱类内 3 探针） |
| ML 分类器判定器 | garak 92 个 detector 类（毒性/分类器）、PyRIT scorers | 本库判定器为确定性（正则/关键词/长度/拒绝/状态/JSON 字段） |
| 有害内容安全对齐 | garak probes.lmrc/malwaregen、promptfoo harmful/beavertails/donotanswer | OWASP LLM 2026 无独立「有害内容」条目；本库 unsafe-advice 5 探针仅为代理，无毒性分类器评分 |
| 插件意图广度 | promptfoo politics/religion/competitors/rbac/crossSessionLeak/contracts 等 | 平台侧意图类插件未对标（以基建面探针替代） |
| 多轮编排 | PyRIT crescendo/pair 多轮 orchestrator | 本库多轮探针仅「多轮升级」（固定两轮） |

## 5. 来源

- garak 探针清单（官方文档）：<https://garak.readthedocs.io/en/latest/probes.html>（模块即类别）
- PyRIT 文档（converter/orchestrator/数据集口径）：<https://azure.github.io/PyRIT/>；
  本仓克隆 `microsoft__PyRIT@246b659`（`pyrit/` 实测 114 Converter 类，含 2 个抽象基类；94 jailbreak 模板）
- promptfoo red team 插件与策略（官方文档）：<https://www.promptfoo.dev/docs/red-team/>；
  本仓克隆 `promptfoo__promptfoo@b4c2404`（54 插件 + 32 策略，剔除 index/base 计数）
- 本库：`trident/probes/`（framework.py 分类学 + run.py 两态差分运行器 + library/ 87 探针），
  矩阵样张 `reports/samples/llm-probes/`，测试 `tests/test_llm_probes.py`（34 用例）
