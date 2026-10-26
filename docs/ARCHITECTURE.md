# InkBlade（墨刃零）架构 / Architecture

InkBlade 有两套“层”的说法，别混。**覆盖层**是测什么，一共十个；**运行层**是代码怎么分，一共七个。
运行时只依赖 Python 3.10+ 标准库；所有执行路径统一经过授权闸门与备份闸门。

## 十个覆盖层 / Ten coverage layers

| # | 覆盖层 | 主要对象 | 代表模块 |
|---|---|---|---|
| 1 | 架构层 | GPU 互联（rail / NVLink / IMEX）、PD 分离、MoE、多集群 | `fabric-topology-isolation`、`prefill-decode-kv-channel-unauth`、`nccl-collective-join` |
| 2 | 框架层 | vLLM、SGLang、RL 训练栈、`trust_remote_code`、推理网关、Agent 应用 | `vllm-plugin-auth-bypass`、`sglang-zmq-pickle-rce`、`litellm-config-update-rce` |
| 3 | Operator 层 | Ray / LWS、GPU Operator、DRA、CSI、BMC / Redfish、DPU | `ray-dashboard-job`、`gpu-operator-driver-escape`、`gpu-dra-mig-policy` |
| 4 | Fabric 层 | NetworkPolicy、CNI、SR-IOV / RDMA、IB、交换机 | `multus-sriov-rdma-bypass`、`cni-plugin-exec`、`ib-subnet-manager-hijack` |
| 5 | 数据与权重层 | checkpoint、数据集、tokenizer、模型仓库 | `checkpoint-shard-poison`、`training-data-leak`、`model-registry-exposure` |
| 6 | 租户隔离层 | namespace、MIG、GPU 池、共享存储 | `gpu-device-cross-namespace`、`inference-tenant-isolation-baseline`、`shared-volume-weight-copy` |
| 7 | 供应链与身份层 | 镜像、IRSA / Pod Identity、SPIFFE、证明链 | `supply-chain-pinning`、`cloud-irsa-trust-wildcard`、`spiffe-spire-audit` |
| 8 | 缓存层 | KV cache、前缀缓存、语义缓存、路由缓存 | `prefix-cache-cross-tenant-leak`、`kv-cache-integrity-poison`、`router-cache-metrics-leak` |
| 9 | 组合层 | 跨组件链、跨层提权、云边跳板 | `attack-path-ranking`、`combo-signature-static`、`hybrid-cloud-egress-pivot` |
| 10 | 防御绕过层 | 运行时检测、准入、镜像扫描、WAF | `defense-bypass-falco`、`defense-bypass-tetragon`、`defense-bypass-admission` |

覆盖表的行按这十层归位，模块 manifest 的 `series` 与之对应。层级只决定“测什么”，不改变执行闸门。

## 七个运行层 / Seven runtime layers

运行时自下而上：

1. **授权治理层** — `core/roe.py`, `core/users.py`, `core/evidence.py`：consent/ROE 签名 + 级别闸门 + 四角色 RBAC + 逐动作审计
2. **编排层** — `core/chains.py`, `core/runner.py`, `core/backup.py`：dry-run → execute；依赖拓扑与并行；写类模块先备份；失败回滚
3. **模块层** — `modules/<key>/{module.json, run.py}`：侦察 / 横向 / 权限链 / 窃取 / 核心代码 / 网络 / 混合云 / 绕过 / 深度
4. **证据层** — `core/evidence.py`：`context.jsonl.gz`（摘要）/ `evidence.db`（SQLite）/ `steps/*.tar` + SHA-256
5. **报告层** — `reports/`：PTES 七段 + 五个 ML 专节 + NIST/等保/GB-T 20984 + CVSS 3.1 + 双语渲染
6. **可视化层** — `webui/`：六视图 SPA（DAG/攻击链/时间线/证据/报告/规则）+ `export_static` 离线兜底
7. **规则转化层** — `rules/`：`generate_all` 做规则↔链覆盖率硬校验；`validate` 做 fixture 重放 + 简化匹配器矩阵

## 各运行层职责 / Runtime layer responsibilities

| 层 | 关键实现 | 职责 |
|---|---|---|
| ① 授权治理 | `core/roe.py`, `core/users.py`, `core/evidence.py` | consent/ROE 哈希签存；只读侦察 → 主动探测 → 利用验证 → 全影响演示四级闸门；admin/lead/tester/auditor 角色；每条执行与拒绝都写审计行 |
| ② 编排 | `core/chains.py`, `core/runner.py`, `core/backup.py` | 链前置三态判定（自实现表达式求值，禁 `eval`）；dry-run 预览写面；依赖拓扑与并行执行；备份闸门（退出码 91）；失败回滚 |
| ③ 模块 | `modules/*/module.json`, `modules/*/run.py` | 统一契约：`key/name/series/description/min_level/writes/requires`；`run(ctx, params) -> {summary, artifacts, findings}`；`private` 仅用于可选加密扩展 |
| ④ 证据 | `core/evidence.py` | 每步三层落证；`manifest.sha256` 逐文件校验；`findings`/`actions`/`backups`/`rollbacks` 审计表 |
| ⑤ 报告 | `reports/render.py`, `reports/cvss.py` | 双语渗透与修复报告；证据锚 = 步骤 + manifest sha256 前 16 位；`redact_novel=True` 可对深层细节做可选脱敏 |
| ⑥ 可视化 | `webui/server.py`, `webui/export_static.py` | 本地控制台与六视图；静态导出 `window.INKBLADE_DATA`，直接从本地目录打开，不需要起服务 |
| ⑦ 规则转化 | `rules/generate.py`, `rules/validate.py` | 规则包（准入/网络/检测/收敛）；每链 ≥1 规则；紫队重放覆盖率矩阵（拦截/检测/漏过） |

## 组件层：in-pod probe / In-pod probe

`probe/` 是一个独立的静态二进制（Rust，`[dependencies]` 为空），在受限 Pod 里只读采集部署面事实：
有效能力位、seccomp 模式、NoNewPrivs、敏感挂载、GPU/RDMA 设备、ServiceAccount 令牌是否存在及字节数，
以及安全相关环境变量的**名称**（值一律写成 `<present>`）。

- 协议：stdout 输出单个 JSON 文档（schema `inkblade-probe/1`）。`--emit probes` 只输出 `probes` 对象，
  可直接作为 `inkblade assess cves --probes probes.json` 的输入。
- 安全控制：固定只读路径白名单；单文件读取上限（默认 64 KiB，硬上限 4 MiB）；不建立网络连接；
  不执行子进程；不读取令牌内容；除 `--out` 外不写任何文件；不引入第三方 crate。
- 分发：Release 资产 `inkblade-probe-linux-amd64` / `inkblade-probe-linux-arm64` + `SHA256SUMS`，
  由 `.github/workflows/probe-release.yml` 以 musl 目标构建；仓库内不保存编译产物。
- 构建：`cd probe && cargo build --release`，交叉编译说明见 `probe/README.md`。
- 迁移状态：采集面正在从 Python 快照解析（`core/inpod.py`）迁到 Rust probe。0.2.0 里两条路径都在，
  Python 解析仍是参照实现；没有 `inkblade-probe` 二进制的部署继续走 Python 路径。

## 运行边界 / Runtime boundaries

- 控制台默认只监听 `127.0.0.1`；所有写盘限于 `--home` 指定的工作区目录。
- 真实集群测试需要显式授权、kubeconfig 与网络可达性；平台不内置任何真实凭据。
- 无集群时用 `pilot --dry-run` 验证计划结构；真实执行始终要求已签授权。
- LLM 不在运行层里，属于可选外设：默认关闭，无端点时 explorer 回到规则排序。配置见 `AGENT-LLM.md`。
