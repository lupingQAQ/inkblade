# 对标反思：ARTEX × KubeTrail（2026-10-25）

> 任务口径要求对标「KubeTrail（DataDog 开源，github.com/DataDog/kubetrail）」。**该前提经核验不成立**：
> `git ls-remote https://github.com/DataDog/kubetrail` → `Repository not found`（2026-10-25 实测，GitHub 404）。
> DataDog 组织下不存在 kubetrail 仓库。真实的两个对标锚点：
>
> - **KubeTrail** = [`ekkoo-z/KubeTrail`](https://github.com/ekkoo-z/KubeTrail)（云迹，Go 1.26 + Wails/Vue，
>   Apache-2.0，main@`ba8c3cf`，创建于 2026-05-12）：面向 K8s 授权红队的**容器内**态势感知与 AI 辅助攻防编排工具。
>   注意：其 README 页脚写「MIT License」但 LICENSE 文件实为 Apache-2.0，以 LICENSE 文件为准（已在 NOTICE 附录记录）。
> - **DataDog 的 K8s 审计工具** = [`DataDog/managed-kubernetes-auditing-toolkit`](https://github.com/DataDog/managed-kubernetes-auditing-toolkit)
>   （MKAT，Apache-2.0，main@`9fa7ff5`）：EKS 信任关系/硬编码云凭据/IMDS 审计工具箱。
>
> 两仓库均以 `--depth 1` 只读克隆至 `.slim/clonedeps/repos/`（ekkoo-z__KubeTrail、DataDog__managed-kubernetes-auditing-toolkit），
> 零代码复用（Apache-2.0 允许，但本仓库保持只读对标口径）。任务前提中「K8s API 审计轨迹记录/who-did-what/策略视图」
> 的能力归属同样不准确：KubeTrail 是**采集器**（点时快照），不是审计日志分析器——但这不影响结论：
> **「我们有 Sigma 规则模板却没有日志分析器」这一硬缺口是真的，本次补齐**（见 §3.1）。

## 1. KubeTrail 与 MKAT 能力清单（源码核验）

### 1.1 KubeTrail（ekkoo-z/KubeTrail，README + internal/ 源码）

| # | 能力 | 源码/参数证据 |
|---|---|---|
| 1 | 容器内原生采集（Pod 内 in-cluster SA 直连 apiserver，免 kubectl） | `cmd/kubetrail-server/main.go`、`internal/kube/`；`--kubeconfig` 本地兜底 |
| 2 | 分级安全模式：`safe`（只读本地 + API 只读）/ `full`（网络探测、Admission dry-run、syscall 探测） | `--mode/-m`；README「红队常见使用方法」 |
| 3 | 攻击面证据聚合：SA/RBAC/Pod 安全上下文/runtime socket/hostPath/cgroup/`/proc`/`/sys`/LPE/凭据痕迹/云 metadata | `internal/collectors/`（identity/serviceaccount/kubernetes_access/lpe/proc_sys_escape/credential_sweep/runtime_local/node_local…） |
| 4 | RBAC 高价值权限矩阵：SSRR/SSAR、secrets get/list、pods/exec、bind/escalate、impersonate、nodes/proxy、wildcard/cluster-admin 等价（`-r full` 深度扩展） | `internal/collectors/permissions.go`、`kubernetes_access.go`；检测能力矩阵「K8s RBAC 权限检测」 |
| 5 | 内核 LPE CVE 启发式矩阵（Dirty Pipe/Dirty COW/nf_tables/OverlayFS/PwnKit/Baron Samedit/2026 年新 CVE 等 17+ 条） | `internal/findings/lpe.go`；README「Linux 提权 / K8s 容器漏洞」表 |
| 6 | 敏感数据外发防护三态：`raw` / `redact` / `metadata`（默认引用式处理，降低凭据原文入 LLM 风险） | `--sensitive/-v`；`internal/sensitivity/` |
| 7 | legacy SA token Secret 审计：导出可见 token + JWT claims + 逐 token SSRR/SSAR 权限审计 | `--secretoutput`；`internal/collectors/serviceaccount_token_audit.go` |
| 8 | 启发式 findings 引擎（severity/category/confidence 排序）与结构化 JSON 输出（`dbus.json` Document：schemaVersion/run/target/collectors/facts/findings/errors） | `internal/findings/findings.go`、`internal/model/model.go` |
| 9 | AI 动态攻防编排：Claude/Codex provider，结合事实出攻击面/风险排序/验证模板，EXP Forge + C2 MCP + 实时回传 | `apps/agent/`；README 主要特性 |
| 10 | 本地后渗透桌面工作台（Wails+Vue）：Pod/Node terminal（helper Pod/netshoot）、文件上传下载删除、端口转发、shadow kubeconfig、Agent 会话/EXP 模板/报告导出管理 | `apps/desktop/`（kube/session/agentmgr/store） |
| 11 | 快捷权限维持模板：SA/RBAC、CSR 客户端证书、sidecar patch、imagePullSecret 注入、CronJob/Deployment（含清理提示，CSR/sidecar 标 dangerous） | README 检测能力矩阵「权限维持」段 |
| 12 | 检测面复核模板（只读命令生成）：kubelet/etcd/registry auth、Service/Ingress 暴露、横向网络路径、观测绕过、资源滥用/DoS、镜像供应链 | README「红队常见使用方法」「检测能力矩阵」 |

**不是**：审计日志（audit log）分析器、who-did-what 时序追溯、策略视图——KubeTrail 的「trail」指容器落点证据链（点时快照），非 apiserver 审计流。

### 1.2 DataDog MKAT（managed-kubernetes-auditing-toolkit）

| # | 能力 | 说明 |
|---|---|---|
| 1 | K8s SA ↔ AWS IAM 角色信任关系图（IRSA + EKS Pod Identity，表格/图两种视图） | `mkat eks find-role-relationships`；`cmd/.../role_relationships.go` |
| 2 | K8s 资源内硬编码 AWS 凭据发现 | `mkat eks find-secrets`；`find_secrets.go` |
| 3 | Pod → IMDS 可达性测试 | `mkat eks imds`；`imds.go` |
| 4 | 边界 | 仅 EKS（README 声明将扩展其他托管 K8s）；无审计日志分析面 |

## 2. 对 ARTEX 差距反思（任务指定六项）

参照物：`.slim/clonedeps/repos/RuoJi6__ARTEX`（v0.3.23，AGPL-3.0，只读黑盒对标）+ QEMU k3s 实测（`docs/ARTEX-BENCH-RESULT.md`）。
判定口径：**已对齐 / 待补 / 刻意不做（含理由）**。

| ARTEX 能力 | InkBlade 现状 | 判定 | 说明与理由 |
|---|---|---|---|
| agent 探索循环（自动多步渗透决策） | `inkblade/agent_planner.py` 证据驱动推荐排序 + lead 审批 pending；执行固定人工触发；测试锁定零 actions 写行 | **部分对齐 + 刻意不做（自主执行）** | 「规划≠执行」是 SOTA Ruling #2：自主闭环与可审计性（每步人类可复核、证据链可回放）冲突。我们补「更聪明的排序」，不补「自动扣扳机」。 |
| 资产图 | `inkblade/core/graph.py` + `reachability.py` + WebUI 攻击链图/工作流 DAG（离线 SPA 六视图） | **已对齐** | 且多一层：verdict 严重度着色 + 证据穿透（runs→steps→SHA256）。 |
| 人机审批（intercept 拦截审批） | ROE consent 哈希固化 + 级别闸门 + 四角色动作矩阵 + MCP 只读零写工具 + 写类备份闸门 91/回滚 | **已对齐（更强）** | ARTEX 审批是产品功能；InkBlade 把审批做成治理层（consent/角色/备份三闸门 + 审计日志），可独立复核。 |
| 流量录制（攻击流量留档回放） | 三层证据含 http-trace artifact；`rules/validate.py` 对 mock 靶场重放探针 | **待补（非阻塞）** | 缺全流量 pcap 级录制与回放器。现有 trace 足够规则验证闭环；pcap 录制列实验室增强项。 |
| 多模型池（llmpool worker 池） | 无运行时 LLM 依赖（planner 为离线规则排序；模块全部确定性） | **刻意不做** | 单机零依赖是资源优势的来源（实测对照：InkBlade 49MB/64ms 每轮 vs ARTEX 栈 169.8MiB、37.85s 可登录）。引入 LLM 池 = 引入非确定性步骤，破坏「每步证据可复现」的取证基线。LLM 辅助留给外部（MCP 消费我们的只读接口）。 |
| 通知调度（任务通知/异步调度） | CLI 同步执行 + run 审计日志；无通知通道/调度窗口 | **待补（低优）** | 多租户 SaaS/分布式调度本就是 SOTA 未达成项（诚实列示）；通知（IM/webhook）是轻量补齐项。 |

## 3. 对 KubeTrail 差距反思

### 3.1 硬缺口（本次补齐）：K8s API 审计轨迹分析

**缺口事实**：我们有 Sigma 模板（含 `sigma-rolebinding-cluster-admin`/`sigma-privileged-pod-create`/`sigma-secret-abnormal-read` 等审计面规则）与紫队重放合成事件，但没有「吃真实 apiserver audit log JSON Lines 流」的分析器——规则只被我们的合成事件喂过，从未对过真实形态的审计输入。

**本次补齐**（commit `feat: kubetrail reflection and k8s audit trail analysis`）：

- `inkblade/core/auditlog.py`：解析 audit.k8s.io/v1 JSON Lines（容错：注释/坏行跳过）；六类检测器——
  ①RoleBinding→cluster-admin 创建 ②特权/宿主面 Pod 创建 ③Ray 8265 作业提交的审计面投影（head SA 落 `rayjob-*` runtime Pod）④非基线主体 Secret 读 ⑤pods/exec 会话 ⑥权重 PVC 异常写（claim 级 patch + 非 baseline 主体挂载建 Pod）；
  输出 finding 携带**主体/动词/资源/时间/映射链名/建议规则键**；默认仅报已完成（2xx）动作，`include_denied=True` 时 403 尝试以 low 报（紫队验证准入拦截证据用）。
- `inkblade/modules/kube-audit-trail-analysis/`（侦察系列，只读，键名 k8s→**kube**：注册表命名规范禁数字键）：模块薄封装，支持 `auditlog` + `kubetrail_export` 双输入。
- `lab/fixtures/auditlog/`：`attack-trail.jsonl`（上述六类 + 良性噪声 + 403 拒绝尝试）/ `benign-trail.jsonl`（10 条加固基线正常运维 → **零误报断言**）/ `kubetrail-export.json`（KubeTrail dbus.json Document 形态）。
- **KubeTrail 导出适配器**：KubeTrail 有导出格式（`dbus.json` Document：schemaVersion/run/target/facts/findings）→ `detect_kubetrail_export()` 识别 + `adapt_kubetrail()` 适配（severity 保序，rbac/escape/lpe 三类别映射链与规则键；lpe 如实给空规则键 + 节点层治理建议）。
- **规则引擎联动闭环**：新增 Sigma×2——`sigma-pods-exec-lateral`（pods/exec，此前无规则）与 `sigma-weight-pvc-abnormal-write`（权重 PVC claim 写，此前只有 Falco 运行时面）；两规则的链重放计划（probes.json）各补审计 fixture，紫队矩阵维持零漏过。

### 3.2 其余差距逐项

| # | KubeTrail 能力 | InkBlade 现状 | 判定 | 理由 |
|---|---|---|---|---|
| 1 | K8s API 审计轨迹分析 | 本次从无到有（§3.1） | **已对齐（本次）** | 标准审计 JSON Lines + KubeTrail 导出双输入；六检测器 × 真实形态 fixture；与 Sigma/Falco/Kyverno 规则键联动。 |
| 2 | 容器内原生采集（in-pod agent：/proc /sys cgroup socket LPE 本地扫） | `escape-primitives`/`privileged-workloads`/`runtime-socket-escape` 等为 **apiserver 视角快照分析**；无 pod 内本地执行采集器 | **待补（实验室）** | 可在 QEMU k3s 靶场 + mock Pod 落点补一个只读 in-pod collector（safe 模式等价物）；Windows 宿主边界内先以 fixture 驱动。 |
| 3 | 内核 LPE CVE 启发式矩阵（17+ 条） | 无内核版本面 CVE 启发式（有 escape-primitives 原语判定） | **不补（平台定位）** | 节点内核面归主机安全产品（我们的 defense-bypass-elkeid/kubearmor/tetragon 族已覆盖其检测面）；渗透平台复刻 CVE 版本库维护成本高且快过期。 |
| 4 | RBAC 高价值权限矩阵（SSRR/SSAR/exec/bind/escalate/impersonate/wildcard） | `rbac-mapping`（can-i 矩阵/cluster-admin 绑定/通配符/扩散权限/Secret 盘点） | **已对齐** | 形态互有取舍：我们有 can-i 矩阵 + 审计轨迹回溯，KubeTrail 有 SSRR 原始展开。 |
| 5 | legacy SA token 逐 token 权限审计 | 无逐 token SSRR/SSAR；Secret 盘点只到名称级 | **待补（小）** | rbac-mapping 加 token 级展开即可，工程量小。 |
| 6 | 敏感数据三态（raw/redact/metadata） | `redact.cred` 尾 4 位 + 报告可选脱敏（`redact_zeroday`）；凭据全文只存归档 trace | **部分对齐** | 缺 metadata-by-reference 模式；可在 evidence 层补引用式存储。 |
| 7 | AI 动态攻防编排（Claude/Codex + EXP Forge + C2 MCP） | MCP 只读 5 工具 + planner 推荐 + lead 审批；零写工具 | **刻意不做** | 同 §2 多模型池理由 + C2 属攻击基础设施（KubeTrail 也只留集成入口不开源服务端）；我们的价值在紫队闭环（发现→规则→验证矩阵）。 |
| 8 | 桌面后渗透工作台（Node terminal/端口转发/shadow kubeconfig/文件管理） | 离线 SPA 六视图（file:// 审计复盘视角） | **刻意不做** | 后渗透操作台与「可审计交付」冲突（shadow kubeconfig/Node terminal 恰是防守方最恨的动作）；审计复盘视角已覆盖。 |
| 9 | 权限维持模板（CSR/sidecar patch/pull secret/CronJob） | 持久化演示仅在 ROE「全影响演示」级别 + backup 闸门下（privileged-gpu-pod-escape 演示分支） | **默认不做（演示受限）** | 模板化权限维持=武器化；保留授权演示级（可回滚、留证）即可。 |
| 10 | 检测面复核模板（kubelet/etcd/registry 只读命令生成） | `ray-control-plane`/`observability-exposure`/`framework-port-matching`/`storage-protocol-csi` 等 100+ 模块覆盖同面 | **已对齐** | 且多规则转化（每个发现给 Sigma/Falco/Suricata 键）。 |
| 11 | （MKAT）SA↔IAM 信任关系图 | `cloud-irsa-trust-wildcard`/`cloud-role-overprivilege` 模块 + 六云契约矩阵（6 云 × 4 场景 24/24） | **已对齐（超集）** | MKAT 仅 EKS；我们六云契约级（诚实：非真实账号实测）。 |
| 12 | （MKAT）K8s 资源内硬编码云凭据 | `supply-chain-credential-theft`（凭据文件面）+ `python-dangerous-sinks`（代码 sink）；manifest 对象内嵌云密钥扫描弱 | **待补（小）** | codescan 引擎加 AKIA*/AIza… 密钥正则即可。 |
| 13 | （MKAT）IMDS 可达性测试 | `ssrf-imds-credential`/`metadata-egress`/`multi-cloud-imds-credentials` + Suricata IMDS 出网签名 | **已对齐** | — |

### 3.3 计数

- **已对齐**：8 项（§2：资产图、人机审批；§3：审计轨迹分析(本次)、RBAC 矩阵、检测面复核、IRSA 信任图、IMDS、硬编码凭据—部分计已对齐口径见行内）
- **待补**：6 项（流量录制、通知调度、in-pod 采集器(实验室)、token 级审计、metadata 三态、manifest 云密钥扫描）
- **刻意不做**：6 项（agent 自主执行、多模型池、AI+C2 编排、桌面后渗透台、权限维持模板化、内核 LPE CVE 库）

## 4. 与本次提交的对应

| 产物 | 位置 |
|---|---|
| 分析引擎 | `inkblade/core/auditlog.py`（解析/六检测器/KubeTrail 适配器/统计） |
| 模块 | `inkblade/modules/kube-audit-trail-analysis/`（侦察/只读/writes=false） |
| 样本 | `lab/fixtures/auditlog/{attack-trail,benign-trail}.jsonl` + `kubetrail-export.json` |
| 规则联动 | `inkblade/rules/templates/sigma.json`（+2 规则）+ `templates/probes.json`（+2 审计 fixture） |
| 测试 | `tests/test_modules_auditlog.py`（21 项：六检测器命中/字段完整/良性零误报/拒绝尝试口径/适配器/注册契约/规则目录与重放 fixture） |
| SOTA | `docs/SOTA-2026-10.md` 新增「审计轨迹分析」行（已达成），KubeTrail/MKAT 对比入参照列 |
| 合规 | `NOTICE` 附录记录两仓库（Apache-2.0，只读克隆零复用）与 KubeTrail README/MIT 不一致说明 |

## 5. 残余边界（诚实声明）

1. 审计分析器目前吃的是**自建样本**（形态取自本仓库攻击链在 apiserver 的投影），未在真实生产集群审计流上标定误报率——上线前应以 ≥30 天真实 audit 基线调白名单（规则 tuning 字段已给方法）。
2. KubeTrail 适配器覆盖其 Document 公开形态（schemaVersion/facts/findings），其 `--secretoutput` 的 SATokenAuditDocument 子格式未适配（属 token 级审计待补项）。
3. 检测器为单事件单检测器（最严重面优先），未做跨事件序列关联（如「exec 后 60s 内 Secret 读」链式归因）——列为后续增强。
