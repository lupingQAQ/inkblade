# InkBlade（墨刃零）

**面向训练与推理集群的探针式渗透测试产品**

`v0.2.0` · Apache-2.0 · 控制端 Python 3.10–3.13 · 目标端静态 Rust 探针 · 默认只读

> **仅限授权使用。** 只对你有书面授权的资产使用 InkBlade。consent 与 ROE 哈希钉存，范围、级别、时间窗由代码
> 强制执行，写操作必须有备份回执。没有签署记录就不投放探针，也没有跳过闸门的开关。

## 为什么把探针放进 Pod

集群扫描器能告诉你 namespace 是否特权、镜像有没有 CVE。它不能告诉你推理 Pod 实际看到了什么：SA token、挂载的
权重、RDMA 网卡、GPU 设备节点、cgroup 限制，以及同一网络命名空间里能摸到的邻居。

InkBlade 把一个静态链接的 Rust 二进制放进目标 Pod。模板是 JSON 数据，探针是目标侧唯一的执行逻辑。目标里不需要
Python、不需要 shell、不下发模块代码。

```
立足 → Rust 探针 → 帧通道 → Pod 内任务 → 子探针 → 证据
```

控制端是 Python，只负责授权、范围、模板选择、预算、证据归档、报告和规则生成；它不进入目标 Pod，不在目标里执行逻辑。

## 十层检测

前九层说明训练集群哪里和普通 K8s 不一样；第十层说明防守方是否真的看得见。

| 层 | 看什么 | 代表模板键 |
|---|---|---|
| 1. 架构层 | rail/多平面错配、PD 分离 KV 通道、IMEX 域、MoE/EP 集合通信、长上下文 KV 生命周期、多集群联邦 | `rail-mismatch-forcing`、`prefill-decode-kv-channel-unauth`、`nvlink-imex-isolation`、`nccl-collective-join` |
| 2. 产品/框架层 | 插件路由、管理面 fail-open、dev 模式、RL 控制面、WebUI、checkpoint loader | `vllm-plugin-auth-bypass`、`sglang-admin-failopen`、`verl-prime-code-exec`、`msswift-trust-remote-code` |
| 3. 组件/Operator 层 | Ray 与 LWS 控制面、GPU Operator、DRA、CSI、BMC/Redfish、DPU | `ray-dashboard-job`、`gpu-operator-driver-audit`、`gpu-dra-mig-policy`、`redfish-default-credentials` |
| 4. 网络/fabric 层 | hostNetwork/SR-IOV/macvlan 策略旁路、CNI 双控制面、IB SM、RoCE PFC/ECN、SHARP、NCCL bootstrap | `multus-sriov-rdma-bypass`、`ib-sm-partition-audit`、`roce-pfc-storm`、`sharp-in-network-poison` |
| 5. 数据/权重层 | checkpoint 与优化器分片、数据集管道、HF 缓存、权重桶、模型注册表 | `checkpoint-shard-poison`、`skyrl-fetch-weights-traversal`、`model-registry-exposure` |
| 6. 租户/隔离层 | MIG/MPS 残留、GPU 池化调度、`cache_salt`、路由指标泄露 | `gpu-tenant-residue`、`hami-scheduler-auth-gap`、`cache-salt-policy-audit` |
| 7. 供应链/身份层 | `trust_remote_code`、revision 固定、签名与证明、SBOM、IRSA 通配、IMDS | `trust-remote-code-supply-chain`、`gpu-cc-attestation-chain`、`cloud-irsa-trust-wildcard` |
| 8. 缓存安全层 | 跨租户前缀缓存、语义缓存误命中、逐出残留、远程 KV 池、EPP 指标、TTFT 时序 | `prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`remote-kv-pool-isolation`、`cache-timing-sidechannel` |
| 9. 跨组合层 | 两个或三个组件同时成立才有的问题；只在组合上报一次 | `vllm-plugin-auth-bypass` + `sglang-weight-exfil`、`imex-computedomain-gpu-memory-crossing`、`long-context-cache-leak` |
| 10. 防护绕过层 | HIDS、运行时策略、准入、镜像扫描、主机代理、WAF、流量可视化是否看得见良性授权行为 | `defense-bypass-elkeid`、`defense-bypass-falco`、`defense-bypass-admission`、`defense-bypass-waf-inference` |

逐层四列表（检测点、为何独有、模块/模板键、证据产出）见 [`docs/PRODUCT.md`](docs/PRODUCT.md)；
前九层的完整版见 [`docs/DETECTION-LAYERS.md`](docs/DETECTION-LAYERS.md)。

## 防护绕过与检测对抗

这是产品功能，不是附加演示。11 个 `defense-bypass-*` 模块正在迁移为 Rust 探针模板，只使用良性 marker，
并且对每个技术类别固定输出三类结果：**检测（detected）**、**盲区（blind spot）**、**硬化建议（hardening）**。
不携带恶意载荷、不做持久化、不关闭安全产品、不提供规避执法的话术。

| 产品族 | 模块 | 测什么 |
|---|---|---|
| Elkeid HIDS | `defense-bypass-elkeid` | agent/driver 指纹、白名单路径、工具改名、driver 未加载降级、规则盲区 |
| AgentSmith-HIDS | `defense-bypass-agentsmith` | `smith.ko` 是否存在、规则覆盖缺口、改名执行、良性 DNS |
| veinmind 容器扫描 | `defense-bypass-veinmind` | 分层镜像、改名工具、压缩样本、白名单样本名 |
| Falco | `defense-bypass-falco` | 无 driver 降级、规则缺口、ephemeral 容器、改名执行 |
| Tetragon / eBPF | `defense-bypass-tetragon` | 策略未挂载命名空间、短生命周期进程、hostNetwork |
| KubeArmor | `defense-bypass-kubearmor` | namespace posture、默认放行、hostNetwork 覆盖 |
| Kyverno / Gatekeeper | `defense-bypass-admission` | 豁免、Audit 模式、mutation 顺序、子资源 |
| Trivy / grype 镜像扫描 | `defense-bypass-imagescan` | 深层覆盖、改名工具、压缩样本、白名单样本名 |
| Wazuh / Osquery 主机代理 | `defense-bypass-hostagent` | agent 离线窗口、规则缺口、改名执行 |
| ModSecurity / Coraza / 雷池 WAF | `defense-bypass-waf-inference` | 编码、分块、Unicode、超长请求变体 |
| Cilium Hubble / Calico flows | `defense-bypass-netobserv` | hostNetwork、多网卡、短生命周期流 |

盲区直接反哺规则包：Kyverno/Gatekeeper 管准入，Sigma 管进程/文件/DNS，Falco/Tetragon 管运行时，Suricata/WAF 管
网络与请求归一化。产品交付规则和重放矩阵，不只给一句“你被绕过了”。

## 能力

- **一条执行路径。** 立足、Rust 探针、帧通道、Pod 内模板执行、子探针、证据。不在这张图上的路径不受支持。
- **目标侧零解释器。** 探针是静态二进制，模板是数据。distroless/scratch 推理镜像和 Python 镜像跑同一套模板。
- **探针树。** `probe_id` / `parent_id`、每个子探针独立 token、更严格的继承、深度/扇出限制、先子后父清理。
- **默认只读。** 写操作需要授权、`--allow-write`、`meta.writes`、`backup-write` 模式和备份回执。
- **证据在边界产生。** 任务结果、步骤日志、artifacts、SHA-256 manifest、探针身份、清理回执。
- **十层检测。** 287 个模块目录、29 条链、11 个防护绕过模块。
- **规则可重放。** 准入、运行时、网络三类规则包，输出拦截/检出/漏过矩阵。
- **无遥测。** 不要账号、不要云密钥、没有许可服务器。

## 成熟度

| 档位 | 范围 | 状态 |
|---|---|---|
| demo | mock 靶场与离线报告 | 探针架构不提供。mock 跑通只代表模板验证，不是客户结论。 |
| 试点 | 授权只读：一个 namespace、一个 Pod、一个模板，再扩到按层扫描 | 推荐的第一次项目形态；证据与限制都写清楚。 |
| 生产 | 完整链、企业集成、HA、on-call | 暂不建议。没有厂商 SLA，也没有认证。 |

禁止宣称：不承诺零误报、不承诺全覆盖、不宣称“生产认证”、不宣称“不可检测”。任何数字都要带任务集、版本和日期。

## 快速开始

产品路径是 `doctor → session → probe → exec/scan → report`。

```bash
python -m pip install -e .

# 1. 环境与探针二进制
python -m inkblade doctor

# 2. 授权会话
python -m inkblade session start \
  --name pilot-01 --workspace ./work \
  --kubeconfig ~/.kube/config \
  --scope namespace:ml-team --level read-only

# 3. 投放探针
python -m inkblade probe deploy \
  --session pilot-01 --target ml-team/infer-0 \
  --method kubectl-exec --binary ./inkblade-probe-linux-amd64

# 4. 单模板或按层扫描
python -m inkblade exec --session pilot-01 --probe p-7f3a1c9e \
  --template service-account-token-exposure
python -m inkblade scan --session pilot-01 --profile ray-vllm --layers 1,3,5

# 5. 报告
python -m inkblade report --session pilot-01 --lang bi
```

没有 demo/trial 路径：session 需要授权目标和签署记录。2026-10 探针迁移进入收尾，`doctor` 会报告实际可用的命令面；
当前完成度见 [`docs/DYNAMIC-VERIFICATION.md`](docs/DYNAMIC-VERIFICATION.md)。

## 命令表

| 任务 | 命令 |
|---|---|
| 环境自检 | `inkblade doctor` |
| 会话 | `inkblade session start|list|show|close` |
| 探针投放 | `inkblade probe deploy|list|show|collect|spawn|tree|cleanup` |
| 单模板 | `inkblade exec --template <key>` |
| 按层扫描 | `inkblade scan --profile <name> --layers <n,n>` |
| 只出计划 | `inkblade scan ... --dry-run` |
| 报告 | `inkblade report --session <id> --lang bi` |
| 导出 | `inkblade export --format sarif|ocsf|vex` |
| 规则包 | `inkblade rules generate|validate` |
| 模板检查 | `inkblade template lint|validate` |

## 文档

| 文档 | 用途 |
|---|---|
| [`docs/PRODUCT.md`](docs/PRODUCT.md) | 定位、适用对象、十层检测表、防护绕过的三类输出 |
| [`docs/ARCHITECTURE-PROBE.md`](docs/ARCHITECTURE-PROBE.md) | 唯一执行路径、探针树、运行时能力、控制端边界 |
| [`docs/PROBE-PROTOCOL.md`](docs/PROBE-PROTOCOL.md) | 帧格式、认证、任务/结果、预算、文件分块、清理、错误码 |
| [`docs/PROBE-DEPLOY.md`](docs/PROBE-DEPLOY.md) | RCE/memfd、kubectl、EphemeralContainer、共享卷、发布二进制、写闸门 |
| [`docs/DYNAMIC-VERIFICATION.md`](docs/DYNAMIC-VERIFICATION.md) | 两态 mock 验证标准、证据格式、覆盖率字段、当前状态 |
| [`docs/INSTALL.md`](docs/INSTALL.md) | 控制器与探针安装、离线、工作区布局 |
| [`docs/USAGE.md`](docs/USAGE.md) | 五步流程、场景、结果阅读、退出码 |
| [`docs/FAQ.md`](docs/FAQ.md) | 边界、迁移状态、写操作、检测、许可 |
| [`docs/DOC-INDEX.md`](docs/DOC-INDEX.md) | 完整文档索引 |
| [`docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md`](docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md) | 工程手册，含探针架构修订章 |

## 证据 / 限制

**证据**

- 探针运行时：`probe/src/{http,net,exec,fsops,k8s,spawn,collect,protocol}.rs`。
- 模板 schema：`probe/schema/probe-template.schema.json`；参考评估器：`inkblade/tpl/engine.py`（仅 mock/CI，
  默认拒绝运行）。
- 防护绕过评估：`inkblade/core/defenseprobe.py` 与 11 个 `inkblade/modules/defense-bypass-*` 模块。
- 当前计数：287 个模块目录（286 个模板 + 1 个 bootstrap）、29 条链、11 个防护绕过模块。迁移窗口内仍有
  286 个旧 `run.py`，发布前必须删除；注册表在过渡期忽略它们。
- Rust 运行时动态验证仍为 0。覆盖率报告里的 286/286 两态结果使用 `runtime=reference`；它们能验证模板逻辑，
  不能当作探针证据。

**限制**

- 2026-10 迁移进入收尾。探针 CLI 与 `session/probe/exec/scan` 命令面仍在完成中；本 README 描述目标契约，并标注当前状态。
- 防护绕过模块仍使用 Python 参考评估，不计入 Rust 模板覆盖率。
- 厂商盲区只对被测版本/配置成立；盲区不等于“该产品可被绕过”。
- 良性 marker 证明“可见性”，不证明“恶意行为不可见”。产品不提供恶意载荷、持久化或规避执法。
- 需要特权 Pod、hostNetwork、GPU 或节点访问的检测点，没有对应部署面时返回 `skipped` 或 `blocked`，永不写成 `verified`。

## AI 辅助说明

本 README 与部分文档由 AI 辅助起草，再由人工维护者编辑：跑了命令、对着代码与生成的报告核了数字，
删掉了复现不了的说法。

检测器彼此不一致，也和人类判断不一致，所以这里不声明“检测率”。读着像机器写的句子，多半最初就是那么来的；
数字不对就是 bug。

代码、manifest、规则包与证据产物来自软件本身；以上说明只针对文字。
