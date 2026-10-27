# Agent 覆盖闭包与跨集群中继

> 目标：把“agent 是否真的把可达面打完了”从自然语言自述变成可复核的机器判据。
> 图、判据、停止原因和缺口清单一律落盘，报告只能引用 proof，不能绕过 proof。

关联文档：[`AGENT-AUTONOMY.md`](AGENT-AUTONOMY.md)（调度/审批/预算）、
[`AGENT-ARCHITECTURE-2026.md`](AGENT-ARCHITECTURE-2026.md)、
[`PROBE-CHANNEL.md`](PROBE-CHANNEL.md)（probe stdio 与 SOCKS5 通道）、
[`COVERAGE-CLOSURE.md`](COVERAGE-CLOSURE.md)（两集群样例证明）。

## 1. 在系统中的位置

```
session / probe / channel（既有，协议不变）
        │  dial / exec / spawn
        ▼
inkblade.agent.relay      跨集群注册、投放、基线 collect
        │  register_probe / mark_baseline
        ▼
inkblade.agent.coverage   资产/服务/SA/权限边/检查/覆盖 proof
        │  intent_priority / closure gate
        ▼
inkblade.agent.scheduler  frontier 选择（未覆盖优先）
inkblade.agent.objective  证据门控 + 闭包闸门（未闭包不 success）
```

- probe 协议仍是 Rust 探针的 framed JSON；`relay` 只消费既有
  `dial`/`exec`/`spawn`，不新增线上消息。
- `coverage` 不执行探针，只记录“谁在哪个资产上做了什么检查”以及证据引用。
- `proof` 是派生产物：任何时候都可以从覆盖图重建；图本身可序列化进
  `coverage-proof.json` 的 `state` 字段，供 resume/replay 恢复。

## 2. 覆盖图模型

节点（`coverage.nodes[]`）：

| kind | 语义 | 关键字段 |
|---|---|---|
| `asset` | 工作负载/节点/API server/数据集/桶/注册表 | `cluster_id` `asset_kind` `name` `namespace` `address` `reachable` `checks[]` `templates[]` |
| `service` | 暴露的服务端点，经 `exposes` 边挂在资产下 | `port` `protocol` `address` `reachable` `checks[]` |
| `identity` | ServiceAccount/user/group/node 身份 | `identity_kind` `name` `namespace` |
| `probe` | 当前 run 的探针实例 | `probe_id` `cluster_id` `parent_id` `transport` `registered` `baseline` |

边（`coverage.edges[]`）：

| relation | 语义 | 闭包相关 |
|---|---|---|
| `reachable` | 网络/API 可达 | 否（用于解释路径） |
| `exposes` | 资产暴露服务 | 否 |
| `can` | 身份对对象的权限边；`exploitable=true` 才进入闭包 | 是 |
| `runs-as` / `member-of` | 工作负载身份 / 组成员 | 否 |

权限边按 `(subject, object, verb, resource, scope)` 去重，因此同一 SA 对同一
服务对象的 `get secrets` 与 `list configmaps` 是两条独立边，不会互相覆盖。

## 3. 四条闭包判据

`coverage.evaluate()` 返回固定四项（顺序稳定），任意一项为 false 即
`closed=false`：

### ① 每个可达资产至少一个探针或只读检查

- 范围：`kind in (asset, service)` 且 `reachable=true`。
- 计数：`checks[]` 非空即算已检查；检查可以是 `mode=probe` 或
  `mode=read-only`。
- 成功检查必须有证据引用；失败检查必须写原因。两者都保留在 proof 里，
  不会把失败伪装成覆盖成功。
- 缺口 reason：`unchecked-reachable-asset`。

### ② 每条可利用权限边要么成功、要么失败/blocked 且有原因

- 范围：`relation=can` 且 `exploitable=true`。
- `success` 必须带证据引用；`failed` / `blocked` 必须带非空 `reason`。
- 一次尝试即算“已尝试”；proof 保留 `outcome/reason/evidence/intent`，
  复核者能区分“打穿”“被拒”“只读边界拒绝”。
- 缺口 reason：`unattempted-exploitable-edge`。

### ③ 每个新探针已注册并完成基线 collect

- 每个 `probe` 节点必须 `registered=true`，且 `baseline.ok=true`。
- `mark_baseline` 只能在注册后调用；成功基线必须有证据引用，失败基线必须
  有原因；失败会保留为 `baseline-collect-failed` 缺口。
- 父探针链禁止成环；`cluster+probe` 由 relay 层去重。
- 缺口 reason：`probe-not-registered` / `baseline-collect-missing` /
  `baseline-collect-failed`。

### ④ 无未处理 frontier / 未收敛意图

- 输入：planner 图（`PlanGraph`）。所有 `open` / `claimed` 意图都算未收敛：
  ready 的记为 `unhandled-frontier`，依赖未满足且不可路由的记为
  `unroutable-intent`。
- 未提供 planner 图时不能证明 frontier 为空，输出
  `frontier-unavailable`，判据四为 false（诚实失败，不做默认通过）。
- 缺口 reason：`unhandled-frontier` / `unroutable-intent` / `frontier-unavailable`。

> 四条判据之外还有 objective 证据门控：`proof.success = closed AND
> objective_success != false`。闭包只证明“已声明可达面已处理”，不替代
> objective 的 confirmed facts / report / cleanup 检查。

## 4. 停止条件

`coverage-proof.json` 的 `stop_reason` 只允许以下值：

| stop_reason | 触发 |
|---|---|
| `closed` | 四条判据全部成立且 objective 未被判否 |
| `frontier-open` | 仍有缺口或未收敛意图（含 `coverage-gap` 状态） |
| `budget-exhausted` | 任一硬预算耗尽；proof 同时输出完整缺口清单 |
| `operator-stop` | kill switch / operator stop |
| `objective-unmet` | objective 自身未满足 |
| `policy-refused` | RoE/审批/防御闸门拒绝并阻塞 |
| `no-probes` | 存在覆盖缺口但没有任何已注册探针 |
| `dry-run` / `error` | 只规划 / 内部错误 |

预算耗尽不会把 run 标成成功：`CoverageSupervisor._finalize` 会写
`coverage-proof.json`，并在 summary 中同时给出 `coverage_gaps`（缺口清单）
与 `stop_reason=budget-exhausted`。

## 5. 与调度器/objective 的集成

### 5.1 frontier 优先未覆盖节点

`CoverageScheduler` 是 `TaskScheduler` 的透明子类，只改写 `_ordered()`：

- 意图可以通过 `tags=["coverage:<node-or-edge-id>"]` 或
  `params.coverage_refs` 声明自己覆盖哪些引用；
- 引用仍在覆盖 frontier（未检查资产、未尝试权限边、未基线探针）时，
  该意图加 100 分，稳定排序后先于更高 priority 的普通意图；
- 不改变 lease、policy、defense gate、预算或重试语义。

### 5.2 未闭包不得宣称完成

`ClosureGatedObjective` 包装原 objective：

- `evaluate(graph)` 追加 `coverage:closure` 检查，`missing` 会列出它；
- `success(graph)` 只有在闭包成立时才为 true；
- 原 objective 的 required facts / report / cleanup / read-only 检查保持不变。

`CoverageSupervisor` 是 `AgentSupervisor` 的 opt-in 子类：

```sh
inkblade agent run --coverage --objective read-only-recon --probe <probe> \
  --llm mock:script.json --workspace lab --coverage-doc docs/coverage.md
```

- 创建/恢复时接受 `coverage=CoverageGraph(...)`；
- `_status()` 在 objective 已满足但闭包未成立时返回 `coverage-gap`，绝不返回
  `success`；
- `_finalize()` 写 `<run>/coverage-proof.json`，发 `coverage.proof` 事件，
  `/agent status` 可读；
- `agent coverage status|proof` 读取或导出该 proof。

## 6. 跨集群中继

`inkblade.agent.relay` 维护一个持久的集群/探针注册表
（`<workspace>/agent/relay.json`），核心规则：

1. **多 kubeconfig / context**：每个 `ClusterTarget` 独立保存
   `kubeconfig`、`context`、`namespace`、`api_server`、`proxies`。
2. **reach 只用既有 dial**：`ProbeDialer` 直接调用
   `ProbeConnection.dial(host, port)`；`Socks5Dialer` 连接由
   `ChannelServer` 暴露的 loopback SOCKS5（其上游仍是 probe dial）。
   随后用最小 HTTP/1.1 GET 请求目标 API 的 `/version` 作为基线。
3. **投放新探针**：`KubectlDeployer` 支持
   - `kubectl apply -f -`（Pod 清单来自 `inkblade.probe.deploy`，只读、
     非 root、drop caps）；
   - `sa-token`（ServiceAccount 变体）；
   - `exec`（对既有 Pod 上传 probe 二进制并 `chmod 0700`，不依赖 Python）。
   argv 始终是列表，不经 shell；token 只以参数传入并在回执中掩码。
4. **注册 cluster_id / parent_id**：每次成功投放写
   `ProbeRecord(cluster_id, probe_id, parent_id, parent_cluster_id)`，并同步
   到覆盖图；父探针可以跨集群，proof 的 `edges` 记录 `relay` 关系。
5. **防环**：
   - 同 `cluster_id` 重复 add → `duplicate-cluster`；
   - 同 `(cluster_id, probe_id)` 重复 deploy → `duplicate-probe`；
   - cluster 父链 / probe 父链成环 → `RelayLoopError`；
   - 所有被拒绝的重复/环都写入 `prevented[]`，不是静默跳过。
6. **每集群独立 RoE/预算**：每个 cluster 有自己的 `roe_level`、
   `steps`/`actions` 上限；工作区 consent 仍是总闸门，cluster 级别不得高于
   工作区。一个集群预算耗尽只抛 `RelayBudgetExceeded`，不影响兄弟集群。
7. **失败回退**：按 `transport + fallback[]` 顺序尝试；每次失败记录
   `attempts[]` 的 transport/error，成功后返回 `fallback_from`。全部失败时
   probe 保持 `registered=false`，覆盖图立即出现 `probe-not-registered` 缺口。

CLI：

```sh
inkblade agent relay add --cluster-id prod-a --kubeconfig a.yaml --context a \
  --api-server https://10.0.0.10:6443 --namespace ml --roe-level 主动探测 \
  --transport kubectl --fallback sa-token,exec \
  --proxy socks5://127.0.0.1:1080 --budget-steps 20 --budget-actions 60

inkblade agent relay add --cluster-id prod-b --parent prod-a \
  --kubeconfig b.yaml --context b --api-server https://10.0.0.11:6443 \
  --namespace train --proxy socks5://127.0.0.1:1081

inkblade agent relay list
inkblade agent relay status --cluster-id prod-b
```

`relay status` 同时输出 `clusters`、`probes`、`prevented`、每集群 `budget`、
`coverage` 计数与 `gaps`（集群不可达、投放失败、基线缺失、预算耗尽等）。

## 7. 证明文件结构

`coverage-proof.json`（schema `inkblade-coverage-proof/1`）：

```json
{
  "schema": "inkblade-coverage-proof/1",
  "run_id": "coverage-demo-two-clusters",
  "objective": "read-only-recon",
  "closed": true,
  "success": true,
  "objective_success": true,
  "stop_reason": "closed",
  "criteria": [{"id": "coverage:assets", "ok": true, "gaps": []}],
  "coverage": {"reachable_assets": 4, "checked_assets": 4,
                "permission_edges": 3, "attempted_permission_edges": 3,
                "probes": 2, "baselined_probes": 2,
                "templates_checked": 2},
  "gaps": [],
  "gap_counts": {},
  "nodes": [],
  "edges": [],
  "state": {"schema": "inkblade-agent-coverage/1"}
}
```

- `coverage-proof.json` 是机器判据；`docs/COVERAGE-CLOSURE.md` 是它渲染出的
  人工复核面，两者内容同源。
- 样例：`reports/samples/coverage-closure/coverage-proof.json`（两集群 mock：
  4 个可达资产/服务、3 条可利用权限边覆盖 success/failed/blocked、2 个
  跨集群探针、0 缺口）。

## 8. 边界与未达成

- **声明面 ≠ 全宇宙**：证明只覆盖进入覆盖图的资产/权限边。资产发现本身的
  遗漏不在证明范围内；`coverage:assets` 不是“集群里不存在其他资产”的证明。
- **失败检查算“已检查”**：判据①要求的是“至少一个 probe/只读检查”，
  失败检查保留原因并计入已检查；proof 的 `check_ok` 与缺口清单会区分
  成功/失败，报告不得把失败写成覆盖成功。
- **mock 与真集群**：测试使用 fake kubectl + 本地 fake API + fake SOCKS5；
  真实集群的 TLS 客户端证书尚未从 kubeconfig 解析，`https` 仅支持
  直连/SOCKS 的系统信任链或显式 `insecure_tls`；经 probe dial 的 `https`
  需要外部 TLS 终止，当前明确拒绝而不是静默降级。
- **exec 投放**：`kubectl exec` 的 `sh -c` 只用于把静态 probe 写入临时路径；
  不执行任何目标侧 Python，不引入 host fallback；写面仍需 RoE/审批。
- **中继深度**：默认最多一层父子关系用于两集群；更深中继按 `parent_id`
  链式注册，但每层都消耗独立预算并受父链防环约束。
- **token 处理**：SA token 只经 argv 传给 kubectl；回执中掩码。生产建议用
  短期 token / kubeconfig 凭据插件，避免进程表泄露。

## 证据 / 限制

- 实现：`inkblade/agent/coverage.py`、`inkblade/agent/relay.py`；
  scheduler/objective 适配在 `CoverageScheduler` / `ClosureGatedObjective`，
  不改变既有 `TaskScheduler` 的默认语义。
- 测试：`tests/test_agent_coverage.py`、`tests/test_agent_relay.py`；覆盖
  四条判据、证据/原因强制、probe 基线、父链防环、两集群 fake kubectl/API
  投放、SOCKS5/dial、每集群 RoE/预算、失败回退、缺口输出、CLI。
- 样例证明：`reports/samples/coverage-closure/coverage-proof.json` 与
  [`COVERAGE-CLOSURE.md`](COVERAGE-CLOSURE.md)；数字来自 mock 两集群，
  不是真实生产集群结论。
- 未达成：真实多集群 kubeconfig 证书链、生产 SOCKS5、跨云网络策略、深层
  中继的带宽/时延实测；这些需要真实环境，当前只声明接口与闭环判据。
