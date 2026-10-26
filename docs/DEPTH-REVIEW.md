# 研究级深度复核（DEPTH-REVIEW）

- 复核日期：2026-10-26
- 范围：只提升既有高危单点的研究深度，不新增漏洞大类
- 方法基线：公开公告快照 + 语义引擎 + 两态差分 + 单元测试 + `verify-effects` 实效项
- 诚实边界：全部为本机快照/仿真/真实 HTTP（127.0.0.1），不是 live K8s、真实 GPU 驱动、真实交换机或真实云账号；版本矩阵只复述公告原始区间，不臆造修复版本

## 总览

| 类别 | 研究问题 | 研究用例 | 发现数 | 模块键 | 效果项 |
|---|---|---:|---:|---|---|
| vLLM/SGLang | 五类接口面是否共享同一鉴权域；版本补丁差异能否解释绕过 | vllm_fuzz 240 + vllm_matrix 40 | 144 个未认证 200 差分；40 条矩阵中 32 条带修复版本 | `vllm-surface-fuzz`、`vllm-sglang-patch-matrix` | `depth-vllm-fuzz` |
| K8s 准入 | Audit/豁免/mutation/子资源/CRD 语义是否产生系统性漏过 | admission 20 | 20 个绕过；加固后 0 | `admission-kyverno-semantics`、`admission-gatekeeper-semantics`、`admission-crd-subresource-gap` | `depth-admission-semantics` |
| eBPF 运行时 | Falco/Tetragon 的 syscall/上下文过滤留下哪些逃逸后盲区 | ebpf 14 | 默认漏过 14；加固后 0；6 类盲区 | `ebpf-runtime-coverage-gap` | `depth-ebpf-blindspot` |
| GPU Operator | privileged driver/MIG/DCGM/device plugin/DRA 是否把 GPU 节点变成共享信任域 | gpu 20 | 19 项失败（5 critical / 13 high / 1 medium）；加固后 0 | `gpu-operator-config-depth`、`gpu-dra-mig-policy` | `depth-gpu-operator-config` |
| SONiC/IB/SHARP | 配置面是否可被单点改写为 fabric 级停摆/静默损坏 | fabric 28 | 28 项失败；fabric_sim PFC 检测器命中；加固后 0 | `sonic-fabric-config-audit`、`sharp-session-trust-audit` | `depth-sonic-fabric-link` |
| 身份联邦 | IRSA/RRSA/PodIdentity/Workload Identity 的条件键能否被通配/缺失/混淆绕过 | identity 21 | 21 个跨租户 allow；加固后 0；合法请求 21/21 仍可用 | `identity-federation-trust-matrix`、`oidc-issuer-confusion` | `depth-identity-federation` |

> 用例总数：240 + 40 + 20 + 14 + 20 + 28 + 21 = **383**（≥280）。测试与效果项均可在本仓库离线复现。

---

## 1. vLLM/SGLang：版本补丁差异 × 五类接口面

### 研究问题

1. vLLM/SGLang 的 admin、plugin、dev-mode、serialization、weights 五个运维可见面，是否与 `/v1/*` 业务面共享同一 api-key 中间件？
2. 公开 CVE/GHSA 的 affected/fixed 区间能否形成一个可判定的版本—补丁矩阵，而不是“看到版本号就报高危”？
3. 仅改路径大小写、尾斜杠、百分号编码、代理头或方法覆盖，是否就能穿过边缘代理与应用的规范化差异？

### 方法

- 以 GitHub Security Advisories API 的 2026-10-26 快照为主，逐行保留 `affected`、`patched` 原始字符串；另以 CVE.org 目录条目补 4 条历史 vLLM 条目、6 条 SGLang 条目、2 条明确标注为 **lab-only** 的接口策略行。
- 版本区间解析器支持 `>=`、`<=`、`>`、`<`、`==`、逗号 AND 与 `All versions`；当 `fixed` 存在时，`observed >= fixed` 不再计入受影响。
- 五面 fuzz：`5 面 × 4 认证态 × 12 变形 = 240` 个确定性用例；认证态为 anon/low/wrong/admin，变形覆盖尾斜杠、大小写、百分号编码、双斜杠、点段、分号、查询覆盖、编码斜杠、`X-Forwarded-User`、`X-HTTP-Method-Override`、尾空格。
- 差分判据：同一目标 `/v1/models` 无 key 为 401/403，而任一受保护面在同请求下 200，即记 `bypass`；`lab/depth_sim.py` 的 vulnerable/fixed 两态仅监听 127.0.0.1。

### 发现

- vulnerable 靶场：240 用例中 **144** 个未认证 200 差分，五个面全部命中；fixed 靶场 **0** 个。
- 典型链：`/plugins/%6cist`、`/plugins/list/`、`/PLUGINS/LIST` 经边缘规范化后落到插件路由；`X-Forwarded-User: admin` 被后端直接信任；`X-HTTP-Method-Override: GET` 使 dev/serialization 的 POST 语义改变。
- 矩阵 40 行，32 行带修复版本；覆盖 CVE-2025-32444（Mooncake pickle）、CVE-2025-29783（ZMQ）、CVE-2025-47277（PyNccl）、CVE-2025-59425（时序）与 2026 年 28 条 GHSA（CORS、prompt/processor cache、SHM pickle、gRPC 参数、视频/音频解码等）。
- SGLang 的 6 条 CVE 当前未观察到官方修复版本，矩阵以 `fixed=null + fixed_note` 保留，不把“未修复”伪装成“已修复”。

### 证据

- 数据：`corpus/depth/vllm_ghsa_snapshot.json`（28 条快照）、`corpus/depth/vllm_patch_matrix.json`（40 行）
- 代码：`inkblade/depth/vllm.py`、`lab/depth_sim.py`
- 效果：`depth-vllm-fuzz`：cases=240，vulnerable_bypasses=144，fixed_bypasses=0，surfaces_hit=admin/dev-mode/plugin/serialization/weights
- 结果哈希：vulnerable `1c68f5b8…`，fixed `eae1ccd2…`（完整值见 effects.json）
- 测试：`tests/test_depth_vllm.py`（8 项）

### 模块键

`vllm-surface-fuzz`、`vllm-sglang-patch-matrix`

### 规则

`sigma-vllm-operator-surface-unauth`、`sigma-vllm-plugin-invoke-external`、`falco-vllm-worker-pickle-load`、`sigma-vllm-dev-code-revision`

---

## 2. K8s 准入绕过：Kyverno/Gatekeeper 语义差异

### 研究问题

1. `validationFailureAction=Audit`、`enforcementAction=dryrun/warn` 是否被误当成“已阻断”？
2. 工作负载可控的 exempt 标签、namespaceSelector、excludedNamespaces 是否让高权限命名空间成为盲区？
3. mutation 先于 validation 的执行顺序，是否会让“先写入 exempt 标签/先改写 selector 标签”成为稳定绕过？
4. `pods/exec`、`pods/ephemeralcontainers`、initContainers、CRD conversion、cluster-scoped 资源是否被只检查 `spec.containers` 的规则漏掉？

### 方法

- 实现一个小型但可回放的准入语义引擎：match（kind/namespace/operation/subresource/apiVersion/scope/labelSelector/namespaceSelector）→ exclude（namespace/label）→ precondition → mutate（标签）→ validate（privileged/hostNetwork/hostPath/image/exec_shell/capabilities/runAsRoot/labels）。
- 20 个用例，Kyverno 10 + Gatekeeper 10；每个用例同时给出 vulnerable 策略集与 hardened 策略集，输出逐策略 trace（mutate、validate-skip、audit-only、deny）。
- 机制覆盖：audit-mode、dryrun、exemption、mutation-order、subresource、ephemeral-container、init-container、precondition、crd-conversion、scope、parameter-wildcard。

### 发现

- 20/20 在 vulnerable 策略集下准入；hardened 策略集 0/20；合法对照不被误杀。
- 关键绕过：
  - Kyverno `Audit` 对 privileged Pod 只记录；
  - `exclude.labels: policy-exempt=true` 可被工作负载自填；
  - mutating policy 先写入 exempt 标签，validating policy 随后跳过；
  - 仅校验 `containers` 时 `initContainers.privileged` 与 `ephemeralContainers.privileged` 逃逸；
  - 未声明 `subresources` 时 `pods/exec` 与 `pods/ephemeralcontainers` 不进入规则；
  - CRD 规则匹配 `example.com/v1beta1` 而对象以 `v1` 提交；
  - Gatekeeper `dryrun/warn`、`excludedNamespaces`、空 `namespaceSelector`、`exemptImages: ["*"]` 与 Namespaced scope 对 cluster-scoped CRD 失效。

### 证据

- 代码：`inkblade/depth/admission.py`
- 效果：`depth-admission-semantics`：cases=20，vulnerable_admitted=20，hardened_admitted=0，findings=20
- 结果哈希：`cef2cf8d…`
- 测试：`tests/test_depth_admission.py`（7 项）

### 模块键

`admission-kyverno-semantics`、`admission-gatekeeper-semantics`、`admission-crd-subresource-gap`

### 规则

`kyverno-deny-privileged-all-containers`、`kyverno-deny-exec-subresource`、`gatekeeper-deny-auditmode-privileged`、`gatekeeper-crd-all-versions`

---

## 3. eBPF 运行时盲区：Falco/Tetragon 覆盖差

### 研究问题

1. 规则只监听 `execve`/`openat` 时，`execveat`、`fexecve`、`memfd_create`、`io_uring`、`ptrace`、`mount`、`clone3`、`bpf` 是否完全绕过？
2. 容器逃逸后事件落在 host PID/namespace，`container_id` 为空或 `host` 时，按容器过滤的规则是否失效？
3. hostNetwork、Multus 第二接口、短生命周期进程、父进程先退出、ring buffer 丢事件，是否造成“事件存在但未归属/未采样”？

### 方法

- 14 个合成事件，每个事件携带 eBPF 消费者可见字段：type、syscall、container_id、host_ns、host_pid、host_network、multus、parent_alive、duration_ms、ringbuf_dropped、follow_child。
- 两个引擎分别建模默认规则与加固规则；默认 Falco 仅 `execve` 且要求父进程存活、容器 ID 可归属；默认 Tetragon 仅 `execve/openat`、`followChildren=false`、仅主 CNI。
- 加固规则扩展到 15 个 syscall/事件类型，并以 hostPID+namespace 归属替代 container_id，hostNetwork/Multus 单独采集，短事件与 ring buffer 丢事件走旁路。

### 发现

- 默认规则 14/14 漏过；加固规则 14/14 检出；6 类盲区：syscall-filter（5）、post-escape（3）、host-network（2）、short-lived（2）、child-process（1）、container-identity（1）。
- 代表性盲区：`execveat` 加载器、`memfd_create+fexecve` 无文件执行、`nsenter` 进入 host PID namespace、hostNetwork 反连 4444、Multus 第二接口 C2、io_uring 读 `/etc/shadow`、`clone3` 子进程、ring buffer 丢事件、hostPID 下容器 ID 标为 host、容器内加载 eBPF。

### 证据

- 代码：`inkblade/depth/ebpf.py`
- 效果：`depth-ebpf-blindspot`：cases=14，missed=14，hardened_missed=0，coverage_gaps=6
- 结果哈希：`0f0b530d…`
- 测试：`tests/test_depth_ebpf.py`（4 项）

### 模块键

`ebpf-runtime-coverage-gap`

### 规则

`falco-execveat-memfd`、`falco-post-escape-host-namespace`

---

## 4. GPU Operator/NVIDIA：驱动、MIG、DCGM、device plugin、DRA

### 研究问题

1. privileged driver/toolkit Pod、`/dev/nvidia*` 宿主挂载与关闭 CDI，是否让 GPU 节点等价于宿主 root？
2. MIG manager 开启但 strategy=none、profile 与设备不匹配、device plugin 不 advertise MIG，是否让 MIG 隔离形同虚设？
3. DCGM exporter 以 NodePort/hostNetwork 暴露且无 TLS/鉴权、SA 绑 cluster-admin，是否泄露租户指标并可横向？
4. device plugin `shareCount>1`、Bidirectional mount propagation、DRA `adminAccess`/通配 deviceClass/恒真 CEL/Immediate 预分配，是否把设备管理权限交给业务 Pod？

### 方法

- 20 项配置检查，域为 driver、mig、dcgm、device-plugin、dra、workload；输入是 operator 配置快照（dict 或 JSON 路径），不连接真实 GPU。
- 每项检查返回 id/domain/severity/title；对 malformed 快照 fail-closed 为 finding。
- 两态 fixture：vulnerable（25.3.0、privileged driver、MIG strategy=none、DCGM NodePort+hostNetwork、shareCount=8、DRA adminAccess）与 hardened（25.7.2、CDI、MIG single、DCGM ClusterIP+mTLS、shareCount=1、DRA 精确 deviceClass/WaitForFirstConsumer）。

### 发现

- vulnerable：20 项中 19 项失败，5 critical / 13 high / 1 medium；hardened 0 项失败。
- 关键项：driver privileged + `/dev /run/nvidia /sys` 挂载、CVE-2025-23266 区间、CDI 关闭、MIG strategy=none、MIG profile 不在允许列表、DCGM NodePort 无鉴权、DCGM hostNetwork 无 TLS、DCGM privileged/hostPID、device plugin shareCount=8、DRA adminAccess=true、deviceClass `gpu.example.com/*`、空 nodeSelector、Immediate + 租户 claimTemplate、CEL `true`。

### 证据

- 代码：`inkblade/depth/gpu.py`
- 效果：`depth-gpu-operator-config`：checks=20，findings=19，critical=5，high=13，hardened_findings=0
- 快照哈希：`f20dc58f…`
- 测试：`tests/test_depth_gpu.py`（5 项）

### 模块键

`gpu-operator-config-depth`、`gpu-dra-mig-policy`

### 规则

`sigma-gpu-driver-privileged`、`sigma-dcgm-nodeport-unauth`、`gatekeeper-dra-admin-access`

---

## 5. SONiC/IB/SHARP：配置审计与 fabric_sim 联动

### 研究问题

1. SONiC 的 PFC watchdog/ECN/buffer/ACL/gNMI/SNMP/AAA/rsyslog/ZTP/镜像签名，哪些单点能把无损以太变成集群级停摆？
2. IB SM/Partition 的默认分区、跨租户成员、IPoIB、SM 计算节点、minhop 路由，是否让 RDMA 信任域脱离 K8s 租户边界？
3. SHARP 会话鉴权、reduce ACL、聚合树成员与版本一致性，是否足以阻止“在网聚合静默篡改”？

### 方法

- 28 项只读检查：SONiC 14、IB 8、SHARP 6；输入为配置快照，不登录交换机、不改 PFC/Partition/SHARP 会话。
- `fabric_sim_plan()` 把审计结果映射为 `pfc-storm`、`ecn`、`rail-mismatch` 场景；效果项实际调用 `lab.fabric_sim` 的 1024 节点拓扑，运行 `simulate()` 与 `detect()`，断言 PFC 检测器命中且 baseline 干净。

### 发现

- vulnerable：28/28 失败；hardened 0/28；域覆盖 sonic/ib/sharp。
- 关键项：PFC watchdog disabled、threshold=100、ECN/WRED disabled、buffer 3.5×、ACL any-any、gNMI 无 TLS/无鉴权、SNMP v2c public、SSH root、AAA 本地、rsyslog welf 注入、ZTP 开启、镜像未验签、管理 VRF 未隔离；IB SM 无备、默认分区 `*`、跨租户 Partition、IPoIB、SM 在计算节点、minhop、default VL、SHARP 未按 Partition 隔离；SHARP 会话无鉴权、跨租户共享、reduce 无 ACL、聚合树含非作业成员、遥测暴露 session、v3/v4 混跑。
- fabric_sim 联动：scenarios=`pfc-storm,ecn,rail-mismatch`；1024 节点 PFC 场景检出 `fabric.pfc-pause-storm`；baseline 仅 `fabric.baseline-clean`。

### 证据

- 代码：`inkblade/depth/fabric.py`、`lab/fabric_sim/*`
- 效果：`depth-sonic-fabric-link`：checks=28，failed=28，hardened_failed=0，detectors=[fabric.pfc-pause-storm]，baseline=[fabric.baseline-clean]
- 快照哈希：`d169da6b…`
- 测试：`tests/test_depth_fabric.py`（5 项）

### 模块键

`sonic-fabric-config-audit`、`sharp-session-trust-audit`

### 规则

`sigma-sonic-pfc-watchdog-off`、`falco-sharp-unauth-session`

---

## 6. 身份联邦：IRSA/RRSA/PodIdentity/Workload Identity

### 研究问题

1. AWS trust policy 的 `Principal: "*"`、`arn:aws:iam::*:root`、`StringLike repo:org/*`、缺失 sub/aud/iss、`ForAllValues` 空集、`Null` 误用、SourceAccount/SourceArn 缺失、ExternalId 可选，能否跨账户/跨租户 AssumeRole？
2. GCP Workload Identity 的 `principalSet` 通配、`attributeCondition` 缺失或 `assertion.sub == '*'`，能否让任意 service account 通过？
3. Azure federated credential 的 issuer/subject/audiences 通配或缺失，能否让攻击者 OIDC token 复用？
4. EKS Pod Identity association 的 namespace/serviceAccount 通配，能否让其他租户 Pod 继承角色？

### 方法

- 21 个 trust 用例，覆盖 aws-irsa、aws-rrssa、aws-pod-identity、gcp-wi、azure-wi；每个用例含 vulnerable trust、hardened trust、攻击 request、合法 request。
- AWS 条件解析支持 StringEquals/StringLike/ForAnyValue/StringEqualsIgnoreCase/ForAllValues/Null；Principal 支持 `*`、AWS ARN 通配、Federated OIDC provider 归一化；GCP 解析 `assertion.<field> == '<value>'`；Azure 比较 issuer/subject/audiences；Pod Identity 比较 namespace/serviceAccount。
- 判据：攻击 request 在 vulnerable 下 allow、在 hardened 下 deny，同时合法 request 在 hardened 下仍 allow（避免“一刀切拒绝”假修复）。

### 发现

- 21/21 攻击 request 通过 vulnerable；hardened 0/21；合法 request 21/21 仍通过。
- 8 类绕过：wildcard-principal、subject-wildcard、audience-wildcard、missing-condition、empty-set、oidc-confusion、source-account-missing、external-id-optional。
- 关键项：IRSA Principal `*`/root 通配；RRSA `sub` 通配；`aud` 缺失；`iss` 缺失导致 issuer 混淆；SourceAccount/SourceArn 缺失或通配；ExternalId 可选；`ForAllValues:StringLike` 空集真空为真；`Null:{sub:true}` 允许无 sub token；GCP `pool/*` 与 `assertion.sub == '*'`；Azure `repo:org/*`、issuer `https://*`、audiences 缺失；Pod Identity namespace/SA 通配。

### 证据

- 代码：`inkblade/depth/identity.py`
- 效果：`depth-identity-federation`：cases=21，allowed=21，hardened_allowed=0，legit_allowed=21，findings=21
- 结果哈希：`b2257d30…`
- 测试：`tests/test_depth_identity.py`（5 项）

### 模块键

`identity-federation-trust-matrix`、`oidc-issuer-confusion`

### 规则

`sigma-irsa-wildcard-principal`、`sigma-oidc-subject-wildcard`

---

## 检测规则索引

`corpus/depth/detection_rules.json` 收录 17 条规则：sigma 8、falco 4、kyverno 2、gatekeeper 3。规则是行为/策略语义，不含可直接复用的利用载荷；每个规则带 `module` 键，便于从 finding 反查规则。

## 用例计数

| 计数键 | 数量 | 说明 |
|---|---:|---|
| vllm_fuzz | 240 | 5 面 × 4 认证态 × 12 变形 |
| vllm_matrix | 40 | 28 GHSA + 4 历史 CVE + 6 SGLang CVE + 2 lab-only 接口行；32 条带 fixed |
| admission | 20 | Kyverno 10 + Gatekeeper 10 |
| ebpf | 14 | 6 类盲区 |
| gpu | 20 | 6 个域 |
| fabric | 28 | SONiC 14 + IB 8 + SHARP 6 |
| identity | 21 | 4 类联邦 provider + Pod Identity |
| **合计** | **383** | ≥280 |

## 新增模块（12）

1. `vllm-surface-fuzz` — 五面 240 用例差分
2. `vllm-sglang-patch-matrix` — 40 行版本补丁矩阵
3. `admission-kyverno-semantics` — 10 个 Kyverno 语义用例
4. `admission-gatekeeper-semantics` — 10 个 Gatekeeper 语义用例
5. `admission-crd-subresource-gap` — CRD/子资源/scope 缺口
6. `ebpf-runtime-coverage-gap` — Falco/Tetragon 14 事件
7. `gpu-operator-config-depth` — 20 项 GPU 配置检查
8. `gpu-dra-mig-policy` — MIG/DRA 专项
9. `sonic-fabric-config-audit` — 28 项 fabric 配置检查
10. `sharp-session-trust-audit` — SHARP 会话信任
11. `identity-federation-trust-matrix` — 21 个 trust 用例
12. `oidc-issuer-confusion` — issuer/audience/subject 混淆

## 复现与测试

```bash
python -m unittest tests.test_depth_vllm tests.test_depth_admission tests.test_depth_ebpf \
  tests.test_depth_gpu tests.test_depth_fabric tests.test_depth_identity tests.test_depth_docs
python -m inkblade.verify-effects --out reports/samples/effects/ --no-docs
python scripts/build-depth-corpus.py
```

## 边界与未覆盖

- 本研究项是语义/配置级实证，不是 live 集群、真实 GPU 驱动、真实交换机或真实云账号的利用。
- vLLM fuzz 使用本机两态 HTTP 靶场；真实目标需先授权并确认 `/v1/models` 对照面，避免把 401 业务面误判为绕过。
- 版本矩阵是公开公告快照，SGLang 多数条目尚无官方 fixed，已显式 `fixed=null`；不对未修复条目给出“升级即修复”的结论。
- 准入引擎覆盖常见语义，不覆盖所有 Kyverno JMESPath 函数、Gatekeeper Rego 自定义逻辑与真实 webhook 超时/失败策略；真实集群需以 dry-run 审计日志回归。
- eBPF 模型是规则语义重放，不是内核 eBPF 程序；真实部署需用 Falco/Tetragon 的规则测试框架与内核版本矩阵复核。
- GPU/fabric 审计输入为快照；未执行 nvidia-smi、DCGM 查询、SSH 到交换机、IB SM 或 SHARP 会话写操作。
