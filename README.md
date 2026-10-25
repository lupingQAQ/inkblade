# Trident — ML 训练/推理集群渗透测试平台

**Trident** 是面向授权安全测试的 K8s / ML 集群渗透测试平台：七层架构（授权治理 → 编排 → 模块 → 三层证据 → 双语报告 → 可视化 → 规则转化），仅依赖 Python 3.10+ 标准库。

**Trident** is an authorized-testing platform for Kubernetes / ML training and inference clusters. It follows a seven-layer architecture (authorization → orchestration → modules → three-layer evidence → bilingual reporting → visualization → rule conversion) and uses only the Python 3.10+ standard library.

> **授权使用 / Authorized use only**：仅可对获得书面授权的资产执行测试。平台内置 consent/ROE 签名、级别闸门、写类操作备份闸门与逐动作审计；未签署授权时 CLI 与 API 均拒绝执行。
>
> **Authorized use only.** Run Trident exclusively against assets covered by written authorization. Consent/ROE pinning, technical-level gates, a mandatory backup gate for write modules, and per-action auditing are enforced by design; without signed consent both CLI and API refuse to execute.

---

## 能力 / Capabilities

- **七层架构**：授权治理、链编排、模块库、三层证据、双语报告、六视图 SPA、规则包转化。详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
- **攻击链编排**：20 条链（经典攻击链 / 云侧权重桶链 / 网络利用链 / 零日级链），支持 dry-run 预览写面、依赖拓扑、并行执行与逐步回滚。
- **模块库**：侦察、横向利用、权限链、窃取与数据泄露、核心代码、网络架构、混合云、防护绕过、零日级漏洞模块（**共 6 个，均已公开**：dify-* 与 open-webui-*）。
- **证据三层**：上下文摘要（`context.jsonl.gz`）+ SQLite（`evidence.db`）+ 归档层（`steps/*.tar.gz` + `manifest.sha256`），支持篡改检测。
- **报告**：PTES 七段 + 五个 ML 专节 + NIST / 等保 / GB/T 20984 映射 + CVSS 3.1 + 证据锚；中英双语。
- **合规映射（2026-10）**：每条发现映射 OWASP LLM Top 10（2026 正式版，含 2025 编号 crosswalk）、OWASP Agentic AI Top 10（ASI01–ASI10）、MITRE ATLAS、NIST AI RMF、ISO/IEC 42001、EU AI Act GPAI 与 TC260/生成式AI管理办法条款；见 [`trident/reports/compliance.py`](trident/reports/compliance.py) 与 [`tests/test_compliance.py`](tests/test_compliance.py)。
- **MCP 与 agent 协作**：`trident mcp` 提供 5 个只读 stdio JSON-RPC 工具（复用授权锁、零写工具，MCP 2026-07-28 + 旧版 initialize 兼容）；`trident plan` 输出证据驱动的链推荐排序，固定 lead 审批、由人触发执行；见 [`trident/mcp_server.py`](trident/mcp_server.py)、[`trident/agent_planner.py`](trident/agent_planner.py)。
- **模型供应链与机密计算**：CycloneDX ML-BOM 风格 AI SBOM、cosign 风格 provenance 三元组校验、TDX/SEV-SNP/NVIDIA CC 证明解析与策略断言（本地 fixture 驱动，篡改必失败）；见 [`trident/supplychain.py`](trident/supplychain.py)。
- **机器可读导出**：`trident export --format sarif|ocsf|vex` 输出 SARIF 2.1.0、OCSF 1.x Detection Finding 与 OpenVEX 风格 JSON；见 [`trident/export.py`](trident/export.py)。
- **规则转化**：Kyverno / Gatekeeper / NetworkPolicy（native、Calico、Cilium）/ Sigma / Falco / Suricata，规则↔链覆盖率硬校验 + 紫队重放矩阵。
- **SOTA 能力矩阵**：2026-10 公开参照对照与诚实差距（万卡实测、真实 ARTEX 对比、硬件 TEE 实测等未达成项及追赶路径）见 [`docs/SOTA-2026-10.md`](docs/SOTA-2026-10.md)。
- **实效验证**：`trident/verify-effects.py` 在本机真实进程/真实 HTTP 上逐项验证管理面利用、权重投毒、备份回滚、RCE、数据泄露、检测规则、端到端链与长上下文/PD KV 四项效果（11/11 PASS）；见 [`docs/EFFECT-VERIFICATION.md`](docs/EFFECT-VERIFICATION.md) 与 [`docs/LONG-CONTEXT.md`](docs/LONG-CONTEXT.md)。
- **ARTEX clean-room 功能对齐（2026-10）**：按公开功能描述独立实现 LLM 多模型池、通知渠道与事件规则、任务模板（含从 run 反推）、一次性日历窗口、run 内侧问、图快照/跨 run 差异、跨 run 只读黑板、已批准提议的 bounded 并发执行（1–8，默认 1）；竞争矩阵 S/M backlog 30 项已清零。功能×实现×测试×状态见 [`docs/ARTEX-PARITY.md`](docs/ARTEX-PARITY.md)。

## 边界 / Boundaries

- **实验室优先**：默认靶场为 `lab/mock_targets.py` 与 `lab/longctx_sim.py`（均仅监听 `127.0.0.1`）。真实集群执行需自行提供 kubeconfig、网络可达性与授权材料。
- **不内置任何真实凭据**：fixture 与 mock 返回值均为 `MOCK*` / `FAKE*` 样值。
- **零日级模块已公开**：6 个 `dify-*` / `open-webui-*` 模块为公开模块（`private: false`），正常打包与展示细节。`trident/core/zeroday.py` 仅作为**默认关闭的可选加密扩展**，供未来真正未披露的私有材料使用，不构成这些公开模块的门槛。
- **效果级 vs 集群级**：本机验证为真实进程/真实 HTTP 的**效果级**证据，不等同于 live K8s 集群验证。KIND（hostNetwork 绕过 NetworkPolicy）与 ARTEX 黑盒对标需启用虚拟化后按 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh` 执行。
- **ARTEX 关系（clean-room）**：ARTEX 仅作为公开功能描述与外部黑盒对标对象；本仓库的 ARTEX 对齐功能均为**独立 clean-room 实现**（依据公开功能矩阵/文档与通用协议知识，**未读取、未复制、未逐行翻译其 AGPL 源码**）。详见 [`NOTICE`](NOTICE) 与 [`docs/ARTEX-PARITY.md`](docs/ARTEX-PARITY.md)。

## Clean-room 声明 / Clean-room statement

Trident 的 ARTEX 对齐功能（`trident/core/llmpool.py`、`notify.py`、`templates.py`、`calendar.py`、`threads.py`、`graphsnap.py`、`blackboard.py` 及 explorer 并发执行）是**净室实现**：

- 输入仅为公开功能描述（功能矩阵文档、竞争矩阵、公开协议/标准）与 Trident 自身架构约束；
- 未读取、未复制、未改编、未逐行翻译 ARTEX（Autumn-27/ARTEX、RuoJi6/ARTEX）的 AGPL-3.0 源码；
- 接口、数据模型、安全闸门与测试均为本项目独立设计；不存在代码级派生关系。

The ARTEX-parity features are clean-room implementations derived solely from public functional descriptions and generic protocol knowledge. No ARTEX (AGPL-3.0) source code was read, copied, adapted, or line-by-line translated; interfaces, data models, gates, and tests are independently designed.

## 快速开始 / Quick start

```bash
# 1) 安装（无运行时第三方依赖）
python -m pip install -e .

# 2) 运行测试
python -m unittest discover -s tests -v

# 3) 启动本地 mock 靶场（仅 127.0.0.1）
python lab/mock_targets.py --mode vulnerable

# 4) 查看模块清单 / 启动控制台
python -m trident module list --modules-dir trident/modules
python -m trident ui --port 8765

# 5) 端到端验收 + 实效验证（本机、可复现）
python trident/e2e-check.py
python -m trident.verify-effects --out reports/samples/effects/
```

工作区初始化、授权签署、四角色矩阵、链执行与报告导出的完整示例见 [`docs/RUNBOOK.md`](docs/RUNBOOK.md)。

For a minimal workspace bootstrap, consent signing, role matrix, chain execution and report export, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## 测试 / Tests

```bash
python -m unittest discover -s tests -v
python -m unittest tests.test_verify_effects -v   # 7 项实效验证
python scripts/check-public-tree.py                # 公开树 0 命中（无内部路径/工作区引用）
```

测试覆盖：授权与角色、模块两态（vulnerable/fixed）、链前置与执行、备份/回滚、三层证据与 manifest 篡改检测、双语报告、规则包与紫队矩阵、SPA 静态导出、公开树卫生、实效验证。

## 文档 / Documentation

| 文档 | 内容 |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 七层架构图与职责边界 |
| [`docs/design.md`](docs/design.md) | 设计基线与漏洞研究分类（中性引用） |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | 安装、授权、模块/链、报告、回滚、实验室边界 |
| [`docs/EFFECT-VERIFICATION.md`](docs/EFFECT-VERIFICATION.md) | 实效验证 PASS/FAIL 表与证据摘要 |
| [`docs/SOTA-2026-10.md`](docs/SOTA-2026-10.md) | 2026-10 SOTA 能力矩阵、诚实差距与追赶路径 |
| [`docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md`](docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md) | XBow/ARTEX/KubeTrail 对标反思：已对齐/待补/不补+理由（确定性执行差异化声明） |
| [`docs/DELIVERY.md`](docs/DELIVERY.md) | 交付包结构与样张说明 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 开发、测试、模块作者规范 |
| [`SECURITY.md`](SECURITY.md) | 漏洞披露政策（私密渠道 + 90 天） |

## 许可证 / License

Apache License 2.0 — 见 [`LICENSE`](LICENSE) 与 [`NOTICE`](NOTICE)。

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
