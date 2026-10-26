# Features / 特性

[English](#english) · [中文](#中文)

This page is the inventory. Marketing pages describe intentions; this one lists what is
built, what is only simulated, and what is still missing. If a row says “gap”, it is a gap.

---

## English

### The short version

InkBlade is a Python platform for testing Kubernetes and ML clusters under a signed scope.
It has 286 modules, 29 chains, a three-layer evidence store, bilingual reports, a local
console and a rule converter. It needs nothing installed on the cluster and makes no network
calls of its own.

The more useful version is the table below, because “has feature X” means very different
things in different rows.

### Capability inventory

| Area | What exists | State | Where to look |
|---|---|---|---|
| Consent and RoE | Signed records with hash pinning, four technical levels, four roles, per-action audit | Verified | `inkblade/core/roe.py`, `USAGE.md` |
| Orchestration | Ordered chain graphs, dry-run write surface, dependency topology, parallel steps, backup gate, rollback | Verified | `inkblade/core/chains.py` |
| Module library | 286 manifests: 67 recon, 66 lateral, 52 network, 43 priv-chain, 22 core-code, 19 exfil, 11 hybrid-cloud, 6 intel | Verified (runs), coverage varies by profile | `MODULES.md` |
| Surface realism | Six deployment profiles, production-testability matrix, `--collect` recomputation | Verified on fixtures | `MODULES.md` |
| Evidence | Context journal, SQLite audit tables, per-step archive with SHA-256 manifest | Verified | `inkblade/core/evidence.py` |
| Reporting | PTES-style pentest report, remediation view, CVSS 3.1, NIST / GB-T 20984 crosswalks, bilingual | Verified | `inkblade/reports/` |
| Exports | SARIF 2.1.0, OCSF detection findings, OpenVEX | Verified | `inkblade/export.py` |
| Console | Six-view local SPA, static export that opens from the filesystem | Verified | `inkblade/webui/` |
| Rule conversion | Admission / network / detection / convergence packs, replay coverage matrix | Verified against fixture targets | `inkblade/rules/` |
| Pilot mode | Read-only inventory, deployment profile, heat map, approval checklist | Verified | `inkblade/pilot.py` |
| Applicability | Version + precondition + evidence based CVE assessment over 152 catalogue entries | Partial: 37 verified, 6 exposure-verified | `inkblade/assess/` |
| Vulnerability coverage | 41 verified primitives across 24 components, packaged as 41 modules / 99 variants | Verified dynamically | `VULNERABILITY-COVERAGE.md` |
| Supply chain | CycloneDX ML-BOM style SBOM, model signature/hash/source check, attestation verification | Verified with fixtures; online TEE checks verified separately | `inkblade/supplychain.py` |
| Integrations | OIDC/LDAP test harness, Splunk HEC, Elastic bulk, webhook HMAC, Jira, ServiceNow | Verified locally | `inkblade/enterprise/` |
| Automation | MCP stdio server (read-only), planner proposals, bounded autonomy, scheduler | Verified | `inkblade/mcp_server.py` |
| Plugin SDK | Strict manifest, entrypoint containment, fingerprint trust store, result schema validation | Verified | `docs/PLUGIN-SDK.md` |
| In-pod probe | Static Rust collector: capabilities, seccomp, sensitive mounts, GPU/RDMA devices, token presence; one JSON document on stdout | Verified on Linux; musl amd64/arm64 built in CI | `probe/`, `ARCHITECTURE.md` |
| CI | `ci-gate` exit-code contract, SARIF export, baseline diffing | Verified | `USAGE.md` |
| Cloud / fabric simulation | IMDS paths, IRSA trust edges, 1,024–10,000 node fabric simulation, 8-tenant SaaS load | Simulated, not production | `ARCHITECTURE.md` |
| Real hardware coverage | BMC/Redfish/IPMI, NVSwitch, DPU, SONiC, InfiniBand paths as `writes=false` modules | Simulated + fixture; no real switch hardware | `MODULES.md` |

“Verified” means a test suite or a recorded test run backs it. “Simulated” means the logic is
exercised against a model of the environment, not the environment. “Gap” means exactly that.

### Numbers that keep us honest

| Number | Value | Why it matters |
|---|---:|---|
| Modules | 286 | 275 enabled by default, 11 quarantined for missing surfaces. |
| Chains | 29 (71 steps) | Five families: network, classic, cloud buckets, deep-dive, AI gateway. |
| Unit tests | 1,900+ offline | No cluster, no network, no LLM key needed. |
| Catalogue verification | 37 / 152 | Plus 6 exposure-verified. The rest are classified, not proven. |
| Production coverage | 60 – 71% | Kubernetes profiles. Slurm is 25% and says so. |
| Vulnerability coverage | 41 verified | 24 components, 41 rows after dedupe. |

### What we do not claim

- **Production readiness.** It is pre-1.0. No HA story, no vendor SLA, no certification.
- **Complete coverage.** Whole families are missing: real switch ASICs, some managed-control-plane
  internals, several vendor runtimes. The gap register lists them.
- **Autonomy.** The default stops at “propose and wait”. There is no standing write access.
- **Zero false positives.** Evidence-backed findings reduce them; they do not eliminate them.
  Test FP/FN numbers are published for the pilot scenarios, not for your cluster.
- **Deep research on demand.** The coverage table is what it is: 41 primitives, several of
  them variations on the same sink. We count carefully and publish the gap.

### Optional integrations are off

LLM pool, notifications, SIEM/ITSM adapters and the agent planner are disabled until
configured. The default build has no outbound calls, so an air-gapped run is the normal case,
not a special mode.

---

## 中文

### 一句话版本

InkBlade 是面向 Kubernetes 与 ML 集群的授权测试平台。286 个模块、29 条链、三层证据、双语报告、
本地控制台、规则转化。集群里不用装东西，工具自身不发网络请求。

更有用的版本是下面这张表。“有某个功能”在不同行里的含义差别很大。

### 能力清单

| 领域 | 已有 | 状态 | 位置 |
|---|---|---|---|
| 授权与交战规则 | 签署记录 + 哈希钉存、四级技术门槛、四类角色、逐动作审计 | 已验证 | `inkblade/core/roe.py`、`USAGE.md` |
| 编排 | 有序链图、dry-run 写面、依赖拓扑、并行步骤、备份闸门、回滚 | 已验证 | `inkblade/core/chains.py` |
| 模块库 | 286 个 manifest：侦察 67、横向 66、网络 52、权限链 43、核心代码 22、窃取 19、混合云 11、情报 6 | 能跑；覆盖率随画像变化 | `MODULES.md` |
| 部署面真实性 | 六种画像、生产可测矩阵、`--collect` 按实测重算 | fixture 上验证 | `SURFACE-REALISM.md` |
| 证据 | 上下文日志、SQLite 审计表、每步归档 + SHA-256 清单 | 已验证 | `inkblade/core/evidence.py` |
| 报告 | PTES 结构渗透报告、修复视图、CVSS 3.1、NIST / GB-T 20984 对照、双语 | 已验证 | `inkblade/reports/` |
| 导出 | SARIF 2.1.0、OCSF、OpenVEX | 已验证 | `inkblade/export.py` |
| 控制台 | 本地六视图 SPA、可从文件系统直接打开的静态导出 | 已验证 | `inkblade/webui/` |
| 规则转化 | 准入 / 网络 / 检测 / 收敛规则包、重放覆盖矩阵 | 对 fixture 目标验证 | `inkblade/rules/` |
| 试点模式 | 只读清点、部署画像、热图、审批清单 | 已验证 | `inkblade/pilot.py` |
| 适用性判断 | 版本 + 前置 + 证据的 CVE 判定，覆盖 152 条目录 | 部分：37 条验证、6 条暴露面验证 | `inkblade/assess/` |
| 漏洞覆盖 | 24 个组件、41 条已动态验证原语，打包为 41 模块 / 99 变体 | 动态验证 | `VULNERABILITY-COVERAGE.md` |
| 供应链 | CycloneDX ML-BOM 风格 SBOM、模型签名/哈希/来源校验、证明核验 | fixture 验证；TEE 在线校验另行验证 | `inkblade/supplychain.py` |
| 企业集成 | OIDC/LDAP 测试桩、Splunk HEC、Elastic bulk、Webhook HMAC、Jira、ServiceNow | 本地验证 | `inkblade/enterprise/` |
| 自动化 | MCP stdio 服务（只读）、规划器建议、有界自治、调度器 | 已验证 | `inkblade/mcp_server.py` |
| 插件 SDK | 严格 manifest、入口约束、指纹信任库、结果 schema 校验 | 已验证 | `docs/PLUGIN-SDK.md` |
| Pod 内探针 | 静态 Rust 采集器：能力位、seccomp、敏感挂载、GPU/RDMA 设备、令牌存在性；stdout 输出单个 JSON | Linux 已验证；CI 构建 musl amd64/arm64 | `probe/`、`ARCHITECTURE.md` |
| CI | `ci-gate` 退出码契约、SARIF 导出、基线差异 | 已验证 | `USAGE.md` |
| 云与 fabric 模拟 | IMDS 路径、IRSA 信任边、1,024–10,000 节点 fabric 模拟、8 租户 SaaS 压测 | 模拟，非生产 | `FABRIC-SIM-RESULTS.md` |
| 真实硬件覆盖 | BMC/Redfish/IPMI、NVSwitch、DPU、SONiC、InfiniBand，均为 `writes=false` 模块 | 模拟 + fixture，无真实交换机实验台 | `HARDWARE-SWITCH-COVERAGE.md` |

“已验证”指有测试套件或留档实验支撑。“模拟”指逻辑跑在环境模型上，不是真环境上。“缺口”就是缺口。

### 让数字自己说话

| 数字 | 值 | 为什么重要 |
|---|---:|---|
| 模块 | 286 | 默认启用 275，11 个因缺部署面被隔离。 |
| 链 | 29（71 步） | 五族：网络、经典、云侧权重桶、深度、AI 网关。 |
| 单元测试 | 1,900+，全离线 | 不需要集群、网络、LLM key。 |
| 目录验证 | 37 / 152 | 另有 6 条暴露面验证。其余已分级，不是已证明。 |
| 生产可测覆盖 | 60 – 71% | Kubernetes 系列画像。Slurm 是 25%，如实标注。 |
| 漏洞覆盖 | 41 条已验证 | 24 个组件，去重后 41 条。 |

### 我们不宣称的东西

- **生产就绪。** pre-1.0。没有 HA 方案、没有厂商 SLA、没有认证。
- **全覆盖。** 缺的是一整类：真实交换芯片、部分托管控制面内部、若干厂商运行时。缺口台账都列了。
- **自治。** 默认停在“提议并等待”。不存在常驻写权限。
- **零误报。** 带证据的发现能减少误报，不能消除。实验室 FP/FN 数字只针对试点场景，不针对你的集群。
- **按需产出深度研究。** 覆盖表就是这些：41 条原语，其中几条是同一 sink 的变体。我们仔细计数，也公开缺口。

### 可选集成默认关闭

LLM 池、通知、SIEM/ITSM 适配器、Agent 规划器都要配置后才启用。默认构建没有外发调用，
所以离线运行是常态，不是特殊模式。
