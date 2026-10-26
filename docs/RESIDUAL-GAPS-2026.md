# R01–R07 残余缺口落地（2026-10-26）

> 对应 `docs/CONFERENCE-2026-GAPS.md` 第 4 节 R01–R07。本文逐条记录**来源议题、
> 为什么是残余缺口、落地模块、检测点、默认开关、实效证据与仍然不覆盖的部分**。
> 不把“有快照检查”写成“已复现论文攻击”，也不把本地 fixture 写成客户生产验证。

## 1. 总表

| ID | 证据议题 | 落地模块（纯小写键） | 系列 / 级别 | writes | 默认 | 数据源 | 关键检测点 | 实效 |
|---|---|---|---|---|---|---|---|---|
| R01 | I01 HyperAudit（USENIX Security 2026） | `hypervisor-audit-integrity` | 侦察 / 只读侦察 | false | **off**（无面） | `audit/hypervisor-audit.json` + `audit-collector` | guest 内采集、日志 guest 可写、非 append-only、无 hypervisor 审计流/证明、竞态窗口 | `residual-hypervisor-audit-race` |
| R02 | I08 恶意 Agent Skills（USENIX Security 2026）、I35（BHUSA）、I54（OWASP AST） | `agent-skill-registry-supply-chain` | 情报 / 只读侦察 | false | **off**（无面） | `agent/skills/registry.json` | 未签名、发布者未知、fs/net/exec 通配、隐藏指令、`curl\|sh` 安装、哈希 rug-pull、未钉版本 | `residual-agent-skill-poison` |
| R03 | I11 Breaking the Bulkhead（NDSS 2026） | `operator-cross-namespace-reference` | 权限链 / 只读侦察 | false | on | CRD/Operator/RBAC/CR 引用图 | Operator 全 ns watch + 高权限、CR 跨 ns 引用 Secret/ConfigMap、secrets 通配 RBAC、conversion webhook 跳过校验 | `residual-operator-cross-namespace` |
| R04 | I21 MCP 生态攻击（IEEE S&P 2026）、I37 19,000 MCP servers（DEF CON 34） | `mcp-control-plane-governance` | 权限链 / 主动探测 | false | **off**（无面） | `mcp/servers.json` + `/mcp/tools` | 无认证 + 0.0.0.0、无 TLS、工具 scope 通配、写工具无审批、无 allowlist、清单哈希变化、无沙箱 | `residual-mcp-control-plane` |
| R05 | I55 AI Security in the Wild（RSA 2026） | `ai-infra-baseline` | 侦察 / 只读侦察 | false | on | `ai-infra/inventory.json` + `/v1/models` | Ray/Jupyter/vLLM 未认证全网、无 TLS、admin API、已知受影响版本、任意出网、IMDS 可达 | `docs/ENTERPRISE-LOCAL-VERIFICATION.md` + 专项测试 |
| R06 | I58 多租户 AI 推理（KCon 2026 方向） | `inference-tenant-isolation-baseline` | 情报 / 只读侦察 | false | on | `inference/tenant-policy.json` + 推理端点 | cache salt、prefix cache、权重/KV 命名空间、计时旁路、GPU 残留、租户配额、日志租户标识 | 专项测试 |
| R07 | I60 Agentic Cloud / MaaS（云栖大会 2026） | `agent-native-control-plane` | 混合云 / 只读侦察 | false | **off**（无面） | `agent/runtime.json` + `/agents` | agent 身份、工具出网 allowlist、共享记忆、写审批、沙箱、并发上限、MaaS 租户 key/轮换/审计 | 专项测试 |

**默认开关规则**：R01/R02/R04/R07 在六个主流画像中没有声明对应采集面，按
`default_enabled=false` 隔离；客户实际部署 Hypervisor 审计、Agent skill 注册表、
MCP 控制面或 Agent 原生运行时后，用 `--probe` 或采集到声明文件再启用。
R03/R05/R06 分别在 Kubernetes Operator、AI 基础设施和推理画像中有真实面，默认启用。

## 2. 逐条说明

### R01 Hypervisor 侧可信审计/日志竞态

- **来源**：USENIX Security 2026，HyperAudit: User Transparent and Highly Efficient
  System Auditing for Cloud Platforms（https://www.usenix.org/conference/usenixsecurity26/technical-sessions）。
- **为什么是残余**：既有 `kubetrail-collector` 只处理 K8s 审计日志；采集器仍在 guest
  内核内，和 rootkit 共享信任域，无法回答“日志是否在竞态窗口被改写”。
- **实现**：读审计管线导出，判定采集器位置、完整性证明、日志写入面、append-only/
  不可变存储、远程 mTLS、hypervisor audit stream/host agent、竞态窗口。
- **不覆盖**：不接入 libvirt/QEMU trace，不做 hypervisor 内存取证；`--probe` 只表示
  操作员确认部署，不产生真实采集。需要客户 hypervisor 侧采集器导出后才能生产判定。

### R02 Agent skill/MCP 注册表供应链

- **来源**：USENIX Security 2026 I08（98,380 skills / 157 malicious）、Black Hat USA
  2026 I35、OWASP Agentic Skills Top 10 AST02（https://owasp.org/www-project-agentic-skills-top-10/ast02）。
- **为什么是残余**：既有 `supply-chain-pinning` 看镜像/依赖钉住，`data-provenance-audit`
  看 SLSA/in-toto；都不解析 skill 注册表的权限清单、隐藏指令与安装钩子。
- **实现**：注册表签名要求、发布者 allowlist、逐 skill 的 fs/net/exec 权限、隐藏指令
  正则、`curl|sh` 安装脚本、版本/哈希钉住、前后哈希变化（rug-pull）。
- **不覆盖**：不执行 skill、不做动态 detonation；文档注入只做静态标记，最终仍需人工
  复核与沙箱动态验证。

### R03 Kubernetes Operator 跨 namespace 引用图

- **来源**：NDSS 2026，Breaking the Bulkhead: Demystifying Cross-Namespace Reference
  Vulnerabilities in Kubernetes Operators（https://www.ndss-symposium.org/ndss-paper/breaking-the-bulkhead-demystifying-cross-namespace-reference-vulnerabilities-in-kubernetes-operators/）。
- **为什么是残余**：`rbac-mapping` 只看单主体权限，不建 CR→Operator→Secret 的引用图；
  跨 ns 引用需要 CR 级数据。
- **实现**：CRD scope、Operator watch 范围/cluster_role、CR 引用 from/to namespace、
  Secret/SA/RoleBinding 敏感引用、全 ns secrets RBAC、conversion webhook CA/跳过校验。
- **不覆盖**：不调用 apiserver 动态 watch；引用图来自 `kubectl get -o json` 导出。
  真实 Operator 版本差异、webhook 实际证书链仍需客户环境复核。

### R04 MCP 控制面/工具权限统一治理

- **来源**：IEEE S&P 2026，Parasites in the Toolchain: Attacks on the MCP Ecosystem
  （https://sp2026.ieee-security.org/program.html）；DEF CON 34 Cloud Village，
  The Hidden Cost of Agentic Connectivity: 19,000 MCP Servers（https://www.cloud-village.org/dc34）。
- **为什么是残余**：`aigateway-*` 只看模型网关鉴权/路由/配额，不解析 MCP server 注册表
  与逐工具 scopes；`inkblade/probes` 只做提示注入测试。
- **实现**：server 认证/绑定/TLS、工具 scope 通配、写工具审批、工具 allowlist、server
  签名、manifest 哈希 rug-pull、exec/write 沙箱。
- **不覆盖**：不主动调用客户 MCP server 的工具（避免真实副作用）；`/mcp/tools` 只作为
  可选面，当前实现以注册表导出为主。

### R05 AI 基础设施统一基线

- **来源**：RSA Conference 2026，AI Security in the Wild: 2 Years of Hacking AI
  Infrastructure（https://www.rsaconference.com/library/blog/rsac-2026-conference-top-10-sessions-every-program-committee-wanted）。
- **为什么是残余**：Ray/Notebook/推理运行时分别有单点模块，但没有一条跨组件、可签核
  的统一基线回答“哪些 AI 服务暴露、是否可出网/触达 IMDS、版本是否受影响”。
- **实现**：服务清单逐项认证/绑定/TLS/admin API/版本；出网 allowlist、IMDS 可达性；
  已知受影响版本来自本地清单（客户可替换为自己的漏洞库）。
- **不覆盖**：版本清单是本地可维护列表，不等于实时 CVE 匹配；真实网络出网需客户
  NetworkPolicy/防火墙导出。

### R06 多租户推理统一隔离基线

- **来源**：KCon 2026 方向“多租户 AI 推理安全”（https://www.dwcon.cn/post/5060）。
- **为什么是残余**：`cache-salt-policy-audit`、`gpu-tenant-residue`、`vllm-timing-oracle`
  各自覆盖一个侧面，客户验收缺少一条统一、可签核的租户隔离基线。
- **实现**：把 cache salt、prefix cache、权重/KV namespace、计时旁路、GPU 残留、
  每租户配额、日志租户标识、tokenizer 共享合成一条基线，逐项给证据与修复。
- **不覆盖**：不产生真实跨租户请求；基线来自策略/配置导出，实际隔离效果仍需
  客户双租户联调（缓存命中、计时差分、显存读回）。

### R07 Agent 原生控制面（MaaS/Agent 运行时）

- **来源**：阿里云栖大会 2026，Agentic Cloud / MaaS 与 Agent 基础设施
  （https://yunqi.aliyun.com/2026/live）。
- **为什么是残余**：既有 `sandbox-runtime-surface`/`spiffe-spire-surface` 看容器与工作负载
  身份，不覆盖 agent 记忆、工具出网、MaaS 租户 key 与审批。
- **实现**：agent 身份、工具出网 allowlist、记忆存储隔离、写审批、沙箱、并发上限、
  MaaS 租户级 key/轮换/审计、控制面绑定/TLS、agent 工具/凭据通配。
- **不覆盖**：不启动 agent、不调用工具；运行时行为（记忆污染、跨 agent 提权）需客户
  在隔离环境做动态演练。

## 3. 实效验证（至少 3 项）

`inkblade/verify-effects.py` 新增 4 项 R 专项（每个 vulnerable → high/critical，fixed → 0 high）：

| 效果 ID | 模块 | 断言 |
|---|---|---|
| `residual-hypervisor-audit-race` | `hypervisor-audit-integrity` | guest 采集器 + 日志 guest 可写 + 竞态窗口 → ≥3 high；fixed 0 high |
| `residual-agent-skill-poison` | `agent-skill-registry-supply-chain` | 未签名 skill + `curl\|sh` → critical；fixed 0 high |
| `residual-operator-cross-namespace` | `operator-cross-namespace-reference` | Operator 全 ns watch + CR 跨 ns 引用 Secret → ≥3 high；fixed 0 high |
| `residual-mcp-control-plane` | `mcp-control-plane-governance` | MCP 无认证 + 0.0.0.0 → critical；fixed 0 high |

另加 2 项 Slurm 深度效果：`slurm-jwt-weak-key`、`slurm-cgroup-device-escape`。

## 4. 测试与证据

- `tests/test_modules_residual2026.py`：7 模块契约、默认开关、两态 fixture、字段、画像 verdict。
- `lab/fixtures/residual2026/{vulnerable,fixed}.json`：合成快照，不含真实凭据。
- `docs/CONFERENCE-2026-GAPS.md` 第 4 节已回填模块键；`docs/INFRA-COVERAGE-2026.md`
  增加 R01–R07 落地小节。
- 证据边界：全部为只读快照分析；R01 的 hypervisor 采集器、R02 的 skill 注册表、
  R04 的 MCP 控制面、R07 的 Agent 运行时都需要客户实际部署后导出，不能由本仓库
  的 fixture 代替。
