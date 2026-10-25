# OWASP Agentic Top 10（ASI01–ASI10）

- 分类：agent-2026 / 安全基线
- 来源：OWASP GenAI Security Project — Agentic Security Initiative
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中十条名称与案例）

## 来源
- https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

## 核验（实际读到的）
- 发布：Agentic Top 10（2025-12-09 发布博文；Threat & Mitigations taxonomy 同步 1.1）。
- 十条（原文名称与示例）：
  - **ASI01 Agent Goal Hijack**（EchoLeak：隐藏提示劫持 copilot 外泄）
  - **ASI02 Tool Misuse**（Amazon Q：合法工具被扭转为破坏性输出）
  - **ASI03 Identity & Privilege Abuse**（凭据泄露导致超范围操作）
  - **ASI04 Agentic Supply Chain Vulnerabilities**（GitHub MCP exploit：动态 MCP/A2A 组件被投毒）
  - **ASI05 Unexpected Code Execution**（AutoGPT RCE：自然语言执行路径）
  - **ASI06 Memory & Context Poisoning**（Gemini Memory Attack：记忆投毒长期改变行为）
  - **ASI07 Insecure Inter-Agent Communication**（伪造 agent 间消息误导集群）
  - **ASI08 Cascading Failures**（错误信号在自动化管线中级联放大）
  - **ASI09 Human-Agent Trust Exploitation**（自信解释诱导人批准有害动作）
  - **ASI10 Rogue Agents**（Replit meltdown：错位/隐瞒/自主动作）
- 文档定位：threat-model-based reference + mitigations + 架构蓝图；配套 Agent Control Standard、AI-VSS。

## 架构要素
- 风险面覆盖：目标、工具、身份、供应链、代码执行、记忆、agent 间通信、级联、人机信任、失控。
- 关键洞察：**记忆是特性也是攻击面**；**人是最容易被说服的闸门**（ASI09）。

## 对我们的启示
- 我们已覆盖：ASI02/03/05 的部分（ROE、级别闸门、备份闸门、逐动作审计），ASI09 的部分（审批角色 lead、计划只读）。
- 明确未覆盖：**ASI06**（无记忆，所以暂时无投毒面，但一旦加记忆就必须先有写策略/来源/回滚）、**ASI07**（无 A2A，接入即需消息认证）、**ASI08**（无队列/预算，级联风险低但长任务失败会整链重跑）。
- 合规映射已有 `trident/reports/standards.json` 的 ASI01–ASI10 条目；本文档的差距清单应反向补进该映射的「控制措施」列。
