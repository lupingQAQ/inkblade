# OpenAI Aardvark — 分析→扫描→沙箱验证→修补的 agent 管线

- 分类：agent-2026 / 防御型安全 agent
- 来源：OpenAI 官方博客（含 2026-03-06 更新）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://openai.com/index/introducing-aardvark/
- https://openai.com/index/codex-security-now-in-research-preview/

## 核验（实际读到的）
- 定位：GPT-5 驱动的 **agentic security researcher**；持续分析源码仓库，找漏洞、评估可利用性、排序、给补丁。
- 明确不用传统 fuzzing/SCA，而用 **LLM 推理 + 工具使用**：读代码、分析、写并运行测试。
- 四阶段管线：**Analysis**（全仓威胁模型）→ **Commit scanning**（按提交增量扫描，首次连库扫历史）→ **Validation**（在**隔离沙箱**触发漏洞确认可利用性，降低误报）→ **Patching**（接 Codex 生成补丁，Aardvark 再扫描，人工 review 后一键修）。
- 指标：golden repos 上识别 **92%** 已知/合成注入漏洞；开源项目发现并负责任披露若干漏洞，其中 **10 个获得 CVE**；约 **1.2% 的 commit 引入 bug**；2024 年报告 4 万+ CVE。
- 2026-03-06 更新：Aardvark 成为 **Codex Security**，research preview，面向 Enterprise/Business/Edu。

## 架构要素
- 管线而非单 agent：每阶段有明确输入/输出与验证闸。
- 沙箱验证是降误报的核心；补丁也要再扫描（生成-验证闭环）。
- 与代码托管/工单深度集成，输出可直接行动。

## 对我们的启示
- 我们的 `verify-effects` 已有「真效果验证」的思想，但没有 agent 管线、没有沙箱（G08/G02/G09）。
- 可直接借用的结构：**威胁模型作为持久上下文**（对应我们的 workspace/资产库）、**commit/资产增量扫描**（scheduler）、**验证即证据**（我们的 effects）。
- 防御型 agent 的商业路径说明：同一套 agent 运行时既能打也能修；我们的「证据链」在修复验证场景同样值钱。
