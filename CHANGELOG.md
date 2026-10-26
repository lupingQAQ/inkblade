# Changelog / 变更日志

本文件记录 InkBlade（墨刃零）的版本级变更。格式参考 Keep a Changelog；版本号遵循语义化版本。

## 0.2.0 — 2026-10-27

**改名版本：Trident → InkBlade（墨刃零）。**

### Changed

- 项目品牌统一为 **InkBlade**，中文名 **墨刃零**；README、总报告、SOTA、
  RUNBOOK、DELIVERY、DEV-LOG 与报告模板中的品牌名、
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

### Added

- 发布工程 / release engineering：`.github/workflows/{ci,release,docker}.yml`
  （Windows + Ubuntu × Python 3.10-3.13；tag 触发 wheel/sdist、CycloneDX SBOM、
  `SHA256SUMS`、cosign keyless bundle、GitHub Release、PyPI trusted publishing 占位；
  GHCR `linux/amd64` + `linux/arm64` manifest list）。所有发布步骤 opt-in，失败不阻塞 CI。
- 分发 / distribution：`Dockerfile`（python:3.12-slim、uid 10001、非 root、
  `HEALTHCHECK`、`ENTRYPOINT inkblade`）、`deploy/helm/inkblade`
  （Deployment/Service/PVC/ServiceAccount/RBAC/Ingress/NOTES，默认只读 RBAC）、
  `Makefile`、`scripts/release/{build,verify,sign}.{ps1,sh}` 以及
  build/sbom/compile-check/smoke/verify 门禁脚本。
- 插件 SDK / plugin SDK：`inkblade/sdk`（严格清单校验、entrypoint 目录约束、
  SHA-256 指纹 + trust store、结果 schema 校验、模板脚手架、
  `examples/hello-surface`）与 `inkblade sdk {new,lint,validate,trust,run,list}`。
- 试点 / pilot：`inkblade pilot --kubeconfig|--snapshot`（只读清点 → 画像/热图/计划/审批清单）、
  `pilot --dry-run`（离线演练，不连接集群）、`ui --host`（容器/反向代理部署）、
  `docs/PILOT-KIT.md`、`docs/FEEDBACK.md`。
- 治理与自审 / governance：`CODE_OF_CONDUCT.md`、`CODEOWNERS`、issue forms
  （bug/feature/security）、PR 模板、`docs/PLUGIN-SDK.md`、`docs/VERSIONING.md`
  （SemVer/LTS/弃用）、`docs/AUDIT-PACKAGE.md`（威胁模型/攻击面/测试证据/已知限制/外审清单）；
  `SECURITY.md` 补充 CVE 申请、CVSS 3.1 分级与 90 天公开窗口。

### Security

- 外部插件默认拒绝执行：SHA-256 指纹 + trust store 固定后才加载
  （否则必须显式 `allow_unsigned=True`）；清单在导入前校验：entrypoint 必须位于插件目录内、
  `writes=true` 至少需要 `利用验证` 级别、`research_only` 必须默认禁用。
- 容器与 Chart 默认最小权限：uid/gid 10001、drop ALL capabilities、
  只读根文件系统、RBAC 默认仅 get/list/watch（写权限需 `readOnly=false` 且
  `rbac.allowWrite=true`，并且仍需已签 RoE）。

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
