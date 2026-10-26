# Agent Skills 规范 — SKILL.md、渐进披露与 allowed-tools

- 分类：agent-2026 / 技能库
- 来源：Agent Skills 规范（agentskills.io，Anthropic 推动的开放格式）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://agentskills.io/specification
- https://github.com/anthropics/skills （官方实现与模板）
- https://raw.githubusercontent.com/anthropics/skills/main/README.md

## 核验（实际读到的）
- 目录结构：`skill-name/SKILL.md` 必需；可选 `scripts/`（可执行代码）、`references/`（按需文档）、`assets/`（模板/资源）。
- Frontmatter：`name`（≤64，小写字母数字连字符，须与目录同名）、`description`（≤1024，说明做什么+何时用）必需；`license`、`compatibility`（≤500）、`metadata`、**`allowed-tools`（空格分隔的预批准工具，实验性）** 可选。
- **渐进披露三层**：元数据约 100 tokens（启动时全量加载）→ 指令 <5000 tokens（激活时加载）→ 资源（按需）。建议 `SKILL.md` <500 行，引用文件保持一层深度。
- 提供 `skills-ref validate` 校验命名与 frontmatter；正文无格式限制，推荐步骤/示例/边界情况。
- Anthropic 官方仓库说明：技能=「指令、脚本、资源的文件夹」，运行时动态加载；格式标准以 agentskills.io 为准。

## 架构要素
- 技能是**文件夹级**交付物：声明式元数据 + 程序性知识 + 可执行脚本 + 资源。
- 上下文经济学：默认只加载「索引」，避免工具/技能描述挤爆上下文。
- 权限声明前移：`allowed-tools` 让技能携带最小权限意图（仍由宿主强制）。

## 对我们的启示
- 与我们的模块契约（`module.json`：key/name/series/description/min_level/writes/requires）相比，技能契约多了**程序性知识与资源**，少了执行绑定——正好互补。
- 建议的 InkBlade 技能包：`skills/<name>/SKILL.md` + `scripts/`（只调用 `inkblade` CLI 的只读/受控命令）+ `references/`（产品指纹、判据、误报案例）。执行仍走模块与四闸门。
- 技能库要能被评测：每个技能带「触发条件/成功判据/反例」，进 CI 跑 `skills-ref validate` + 我们的 golden tasks。
