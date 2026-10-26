# Changelog / 变更日志

本文件记录 InkBlade（墨刃零）的版本级变更。格式参考 Keep a Changelog；版本号遵循语义化版本。

## 0.2.0 — 2026-10-27

**改名版本：Trident → InkBlade（墨刃零）。**

### Changed

- 项目品牌统一为 **InkBlade**，中文名 **墨刃零**；README、总报告、SOTA、
  0day 披露/预留、RUNBOOK、DELIVERY、DEV-LOG、披露包与报告模板中的品牌名、
  命令示例、路径与规则文本全部同步。
- Python 包目录 `trident/` → `inkblade/`；导入路径 `trident.*` → `inkblade.*`；
  模块入口 `python -m trident` → `python -m inkblade`。
- 发行包名 `trident-pentest` → `inkblade`；`pyproject.toml` 版本升至 `0.2.0`；
  新增 console script `inkblade=inkblade.cli:main`。
- 环境变量前缀 `TRIDENT_*` → `INKBLADE_*`（如 `INKBLADE_LLM_BASE_URL`、
  `INKBLADE_AGENT_POLICY`、`INKBLADE_SANDBOX_*`、`INKBLADE_DEBUG`）。
- 运行标记与夹具前缀 `TRIDENT-` → `INKBLADE-`（含 e2e/effects/上游核验标记）。
- 规则、注解与 schema 命名空间 `trident.io/*`、`trident-*.schema` → `inkblade.io/*`、
  `inkblade-*.schema`；Web UI 数据全局 `window.INKBLADE_DATA`。
- 目录与样张：`inkblade/{core,modules,chains,rules,reports,webui}`；
  `reports/samples/perf/grid/*-inkblade.json`、`reports/samples/rules-pack/{falco/inkblade-rules.yaml,suricata/inkblade.rules}`。

### Deprecated

- `trident` 命令行入口保留一个版本：执行时在 stderr 打印迁移提示，内部转交
  `inkblade`；计划在 0.3.0 移除。
- 旧环境变量 `TRIDENT_*` 仍会被读取，但触发 `DeprecationWarning`（每变量每进程
  一次），计划在 0.3.0 移除。请迁移到 `INKBLADE_*`。

### Compatibility notes

- 公开 Python API 仅发生包名替换，函数与参数语义未变；已保存的旧工作区（`evidence.db`、
  `runs/`、`reports/`）可直接用新包打开。
- 旧版生成物中的 `trident` schema/注解字符串按历史产物保留语义；新产物统一使用
  `inkblade` 前缀。

## 0.1.0 — 2026-10-26

- 首个公开版本（当时名为 Trident）：七层架构、275 个模块、三层证据、双语报告、
  规则转化、Web UI、MCP/A2A、供应链与 TEE 验证等能力基线。
