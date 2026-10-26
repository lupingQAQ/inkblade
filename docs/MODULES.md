# Module catalogue / 模块目录

[English](#english) · [中文](#中文)

286 manifests, 275 enabled by default, 11 quarantined. This page explains how the catalogue is
organised and how to browse it on your own machine. The authoritative list is always the tree:
`inkblade/modules/<key>/module.json`.

---

## English

### Browse it

```bash
python -m inkblade module list
python -m inkblade module list --modules-dir inkblade/modules
python -m inkblade surfaces --profile airgapped --fixture
```

`module list` prints key, series, technical level, read/write and required surface count per
module. Add `--json` where the subcommand supports it when you want to feed a dashboard.
`surfaces` answers a different question: of these modules, which ones can actually run against
this deployment shape?

### Families

| Family | Count | What it looks at |
|---|---:|---|
| Reconnaissance | 67 | Control plane objects, schedulers, gateways, storage, identity. Enumeration only. |
| Lateral movement | 66 | Service-to-service pivots, gateway abuse, worker takeover, token reuse. |
| Network architecture | 52 | CNI behaviour, policy coverage, service mesh, multi-NIC, fabric reachability. |
| Privilege chains | 43 | RBAC escalation, admission gaps, service-account trust, operator permissions. |
| Core code paths | 22 | Deserialisation, template injection, eval sinks, checkpoint loaders. |
| Exfiltration | 19 | Dataset, checkpoint and credential exposure across tenant boundaries. |
| Hybrid cloud | 11 | Instance metadata, workload identity, cloud storage trust edges. |
| Intelligence | 6 | Version and advisory correlation; turns inventory into applicability. |

### Technical levels

| Level | Count | What it may do |
|---|---:|---|
| Read-only recon | 119 | Enumerate. No state change. |
| Active probing | 72 | Send traffic to confirm a surface. Still no writes. |
| Exploit verification | 80 | Prove a primitive with a harmless marker inside the approved window. |
| Full-impact demo | 15 | Change state on purpose. Backup first, always. |

The level is enforced against the consent record, not against a flag. A level 3 module under a
level 2 record exits 91 before it opens a socket.

### Chains

29 chains, 71 steps, five families:

| Family | Count |
|---|---:|
| Network exploitation | 12 |
| Classic kill chain | 9 |
| Cloud weight buckets | 5 |
| Deep-dive chains | 2 |
| AI gateway chains | 1 |

Chain files live in `inkblade/chains/*.json`. Each step names one module, optionally depends on
earlier steps, and carries parameters. Preconditions use a small expression language — no
`eval` and no arbitrary Python.

### The manifest contract

```json
{
  "key": "example-module",
  "series": "权限链",
  "min_level": "只读侦察",
  "writes": false,
  "requires": ["k8s-object:ClusterRole"],
  "combo_signature": ["example-combination"],
  "produces": ["findings"]
}
```

Fields that matter: `writes` triggers the backup gate; `requires` drives the surface matrix;
`min_level` is checked against the consent record; `combo_signature` is what lets the platform
say “these two findings are one problem”.

### Quarantined modules

Eleven modules need a surface that none of the six reference profiles contains: agent-native
control planes, two vendor runtime APIs, one hardware-only path. They stay in the tree because
customers do deploy those things. They are excluded from coverage denominators and are never
enabled by a profile.

### Adding your own

```bash
python -m inkblade sdk new my-module
python -m inkblade sdk lint my-module
python -m inkblade sdk validate my-module
```

The SDK enforces a strict manifest profile, keeps the entry point inside the module directory,
records a SHA-256 fingerprint you accept explicitly, and validates the result schema. There is
no auto-trust: a plugin you have not fingerprinted will not run, even if it is on disk.

Submissions upstream need three things: a manifest, a dry-run path, and tests. Modules that
only work against a live cluster are welcome, but they need a recorded fixture so CI can
exercise them.

---

## 中文

### 怎么浏览

```bash
python -m inkblade module list
python -m inkblade module list --modules-dir inkblade/modules
python -m inkblade surfaces --profile airgapped --fixture
```

`module list` 每个模块一行：key、族、技术级别、读写属性、所需部署面数量。要喂给面板时，支持 `--json` 的子命令
直接加参数。`surfaces` 回答的是另一个问题：这些模块里，哪些真能对着这种部署形态跑。

### 模块族

| 模块族 | 数量 | 看什么 |
|---|---:|---|
| 侦察 | 67 | 控制面对象、调度器、网关、存储、身份。只做枚举。 |
| 横向利用 | 66 | 服务间横向、网关滥用、worker 接管、令牌复用。 |
| 网络架构 | 52 | CNI 行为、策略覆盖、服务网格、多网卡、fabric 可达性。 |
| 权限链 | 43 | RBAC 提权、准入缺口、服务账号信任、operator 权限。 |
| 核心代码 | 22 | 反序列化、模板注入、eval sink、checkpoint loader。 |
| 窃取与数据泄露 | 19 | 数据集、checkpoint、凭据的跨租户暴露。 |
| 混合云 | 11 | 实例元数据、工作负载身份、云存储信任边。 |
| 情报 | 6 | 版本与公告关联，把清单变成适用性判断。 |

### 技术级别

| 级别 | 数量 | 允许做什么 |
|---|---:|---|
| 只读侦察 | 119 | 枚举。不改状态。 |
| 主动探测 | 72 | 发流量确认部署面存在。仍然不写。 |
| 利用验证 | 80 | 在批准窗口内，用一个无害标记证明原语成立。 |
| 全影响演示 | 15 | 有意改变状态。必须先备份。 |

级别是对着授权记录校验的，不是对着命令行开关。2 级授权下的 3 级模块，在开 socket 之前就退出 91。

### 链

29 条链、71 步、五个族：

| 族 | 条数 |
|---|---:|
| 网络利用链 | 12 |
| 经典攻击链 | 9 |
| 云侧权重桶链 | 5 |
| 深度链 | 2 |
| AI 网关链 | 1 |

链文件在 `inkblade/chains/*.json`。每一步指定一个模块，可以依赖前面的步骤，并带参数。前置条件用一个小表达式语言，
不用 `eval`，也不跑任意 Python。

### manifest 契约

```json
{
  "key": "example-module",
  "series": "权限链",
  "min_level": "只读侦察",
  "writes": false,
  "requires": ["k8s-object:ClusterRole"],
  "combo_signature": ["example-combination"],
  "produces": ["findings"]
}
```

关键字段：`writes` 触发备份闸门；`requires` 驱动部署面矩阵；`min_level` 对着授权记录检查；
`combo_signature` 让平台能说“这两条发现其实是同一个问题”。

### 隔离模块

有 11 个模块需要的部署面，在六个参考画像里都不存在：Agent 原生控制面、两个厂商运行时 API、一条纯硬件路径。
它们留在树里，因为确实有客户那样部署；但不计入覆盖率分母，也不会被任何画像默认开启。

### 加自己的模块

```bash
python -m inkblade sdk new my-module
python -m inkblade sdk lint my-module
python -m inkblade sdk validate my-module
```

SDK 会强制严格 manifest、把入口限制在模块目录内、记录一个需要你显式接受的 SHA-256 指纹，并校验结果 schema。
没有自动信任：没录过指纹的插件，就算躺在磁盘上也不会运行。

向上游提交需要三样：manifest、dry-run 路径、测试。只能对着真实集群跑的模块也欢迎，但要附一份可回放的 fixture，
否则 CI 没法验证。
