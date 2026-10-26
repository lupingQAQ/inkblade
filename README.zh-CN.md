# InkBlade（墨刃零）

**训练与推理集群渗透测试平台**

`v0.2.0 preview` · Apache-2.0 · Python 3.10 – 3.13 · 零运行时依赖 · 默认离线

> **仅限授权使用。** InkBlade 只应指向有书面授权的资产。consent/ROE 哈希钉存、技术级别闸门、写类模块的强制备份闸门、
> 逐动作审计，全部由代码执行。没有签署记录时，CLI 与 HTTP API 都会拒绝执行，而且没有跳过闸门的开关。

预览说明：扫描、证据与报告路径可以用于试点。in-pod 采集正在迁往静态 Rust probe；迁移完成前，
`core/inpod.py` 的 Python 快照解析仍是参照实现。

## 为什么做这个

ML 平台多半是拼出来的，不是设计出来的。托管控制面在一处，GPU operator 在另一处，推理网关硬接在共享存储上，
训练栈默认信任每一个 checkpoint——因为 2023 年那会儿大家都这么写。

单看每块都讲得通。断在接缝上：能读模型仓库的服务账号、失败即放行的准入 webhook、没有鉴权的权重同步接口、
从没想过会加载不可信文件的 checkpoint loader。

InkBlade 在授权范围内捅这些接缝。不是对着什么端口都回话的服务喷洒 CVE 检查，而是按一个真有耐心的攻击者会走的路径走一遍，
每一步都停下来留证。

## 5 分钟上手

不需要集群也能先把安装跑通：

```bash
python -m inkblade doctor            # 解释器、写权限、端口、可选依赖
python -m inkblade pilot --dry-run   # 离线演练：空画像 + 计划，不连接任何集群
python -m inkblade ui                # 本地控制台 127.0.0.1:8765
python -m inkblade exploit --list    # 武器包及其部署前提
```

有可读集群时：

```bash
python -m inkblade pilot --kubeconfig ~/.kube/config --out reports/pilot
python -m inkblade run --module <名字> --params '{"target": "..."}'   # 需先签授权
```

在代码检出根目录执行。`python -m pip install -e .` 之后可以用短命令 `inkblade ...`，不装就用
`python -m inkblade ...`，两种都一样。

`pilot --dry-run` 只把 `pilot-report.json`、`pilot-report.md` 与 `approvals.json` 写到输出目录，不会建立任何连接。`doctor` 在笔记本上远低于 1 秒。

容器与 Kubernetes：

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 doctor

helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace
```

离线安装与全部细节见 [`docs/INSTALL.md`](docs/INSTALL.md)。

## 能力

- **十层覆盖、七层运行。** 覆盖层是测什么：架构、框架、Operator、Fabric、数据与权重、租户隔离、供应链与身份、缓存、组合、防御绕过。运行层是代码怎么分：授权、编排、模块、证据、报告、可视化、规则转化。每一层都有明确的拒绝方式。
- **286 个模块、29 条链。** 侦察、横向、网络架构、权限链、核心代码、窃取、混合云、情报。
- **每步三层证据。** 上下文日志、SQLite 审计表、带 SHA-256 清单的单步归档。报告锚点是步骤哈希。
- **双语报告。** PTES 结构的渗透叙事 + 修复清单，同一套证据，中英各一份。
- **规则转化与重放。** 准入、网络、检测、收敛四类规则包，重放后给出逐链的拦截 / 检出 / 漏过。
- **一张覆盖表，不是命中清单。** 24 个组件、41 条已动态验证的原语，只列组件、类别与受影响版本，不含复现步骤、载荷或目标清单。
- **诚实的缺口台账。** 152 条目录里 37 条动态验证、6 条暴露面验证，其余是带书面阻塞原因的分级假设。
- **无遥测、无账号、无云密钥。** 离线不是特殊模式，是常态。

### 成熟度

| 档位 | 含义 | 适合做什么 |
|---|---|---|
| 离线演练 | `pilot --dry-run` 与本地控制台，不碰真实环境 | 评估输出质量、培训、流程演练 |
| 试点 | 真实但只读，`pilot` + 1–2 级模块 | 摸清部署面、拿审批清单、算覆盖率 |
| 生产 | 完整链路、企业集成、HA 与运行手册 | 目前**不建议**；先按试点跑完一轮 |

> **禁止宣称**：本项目不是生产认证软件，不承诺零误报，不承诺全覆盖，也没有厂商 SLA。任何“已在生产环境验证”的说法，
> 都需要你自己的项目记录来支撑，而不是这本 README。

## 命令表

| 任务 | 命令 |
|---|---|
| 环境自检 | `inkblade doctor` |
| 离线演练 | `inkblade pilot --dry-run` |
| 本地控制台 | `inkblade ui` |
| 授权向导 | `inkblade quickstart` |
| 账号与角色 | `inkblade user add <名字> <口令> <角色>` |
| 授权状态 | `inkblade roe` |
| 模块清单 | `inkblade module list` |
| 部署面覆盖 | `inkblade surfaces --profile <p>` |
| 只读集群清点 | `inkblade pilot --kubeconfig <路径>` |
| 采集 / 发现 | `inkblade collect` · `inkblade discover` |
| 单模块 | `inkblade run --module <key>` |
| 链（计划 / 执行） | `inkblade execute --chain <id> --dry-run` · `execute --chain <id>` |
| 武器包 | `inkblade exploit --list` · `exploit <id> --real --backup-target <目录>` |
| 回退 | `inkblade rollback --run <id> --step <n>` · `inkblade abort` |
| 报告与导出 | `inkblade report --run <id> --lang bi` · `export --format sarif` |
| 防守规则 | `inkblade rules generate` · `rules validate` |
| 复测 / CI | `inkblade schedule run-due` · `ci-gate --fail-on high --new-only` |
| 嵌入 | `inkblade mcp` · `inkblade sdk list` |
| 可选模型 | `inkblade llm-pool status` · `llm-pool add`（默认关闭） |
| 有界自治 | `inkblade autonomy grant` · `explore autonomy --autonomy L3` |

每个参数见 [`docs/USAGE.md`](docs/USAGE.md)，那里还有完整的快速参考表。

## 模块与覆盖

| 模块族 | 数量 | | 技术级别 | 数量 |
|---|---:|---|---|---:|
| 侦察 | 67 | | 只读侦察 | 119 |
| 横向利用 | 66 | | 主动探测 | 72 |
| 网络架构 | 52 | | 利用验证 | 80 |
| 权限链 | 43 | | 全影响演示 | 15 |
| 核心代码 | 22 | | | |
| 窃取与数据泄露 | 19 | | **合计** | **286** |
| 混合云 | 11 | | 默认启用 | 275 |
| 情报 | 6 | | 隔离 | 11 |

覆盖率按部署画像给，不给一个笼统数字：离线 Kubernetes 70.91%，KubeRay + vLLM 68.73%，GPU 池化 60.00%，
裸金属 Slurm 25.09%。Slurm 低是因为三分之二的目录需要一个根本不存在的 Kubernetes API。模块浏览方式见
[`docs/MODULES.md`](docs/MODULES.md)。

## 漏洞覆盖

入选表格只有一条规则：在上游固定版本上动态复现成功，且查新没有找到匹配的公开 advisory。

| 组件 | 类别 | 受影响版本 | 状态 |
|---|---|---|---|
| 41 行 | 24 个组件 | — | 动态验证形态 |

只列组件、类别、受影响版本与验证形态；不含复现步骤、载荷或目标清单。部分条目来自内部研究，
按协调披露流程处理。

[`docs/VULNERABILITY-COVERAGE.md`](docs/VULNERABILITY-COVERAGE.md)

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | 完整命令指南、工作区布局、排障 |
| [`docs/INSTALL.md`](docs/INSTALL.md) | 下载、安装、容器、Helm、离线 |
| [`docs/FEATURES.md`](docs/FEATURES.md) | 能力清单：已验证 / 模拟 / 缺口 |
| [`docs/WORKFLOW.md`](docs/WORKFLOW.md) | 十一步流程，逐道闸门 |
| [`docs/MODULES.md`](docs/MODULES.md) | 模块族、级别、链、manifest 契约 |
| [`docs/VULNERABILITY-COVERAGE.md`](docs/VULNERABILITY-COVERAGE.md) | 组件/类别覆盖表 |
| [`docs/FAQ.md`](docs/FAQ.md) | 短答案，包括不太好回答的那些 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 十层覆盖、七层运行、各层职责 |
| [`docs/AGENT-LLM.md`](docs/AGENT-LLM.md) | 可选模型池、L3 前置条件、数据边界 |
| [`SECURITY.md`](SECURITY.md) | 漏洞报告与支持窗口 |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | pre-1.0 版本政策 |

文档站源码在 `docs/`，发布方式见 [`docs/README-SITE.md`](docs/README-SITE.md)。

## 边界与对比

InkBlade 不是“更好的扫描器”。形状不一样：它是给已经知道自己能测哪个集群的人用的、以证据为中心的作业平台。

- **覆盖不齐。** Kubernetes 画像 60–71%，Slurm 25%。缺的模块列出来，不平均。
- **验证是部分的。** 152 条里 37 条动态验证，其余是带书面阻塞原因的假设，而且会一直标着。
- **覆盖行是线索，不是判决。** 每条只在一个 commit、一种配置上复现过。
- **自治有边界。** 有规划器和探索器，默认停在“提议并等待”；L3 需要 lead 签发的 grant，带 TTL、白名单与预算硬顶。
- **pre-1.0。** 接口会动。合规试点请钉版本。

它不是什么：不是 SaaS，不是常驻写权限的 agent，不是零配置扫描器，也替代不了一场关于交战规则的对话。

## Clean-room 声明

与 ARTEX 对标的那部分特性，是按公开功能描述与通用协议知识独立实现的。**未读取、未复制**任何 AGPL 源码，
也没有逐行翻译；接口、数据模型、闸门与测试均为独立设计。完整声明在 [`NOTICE`](NOTICE) 中。

## AI 辅助写作说明

本 README 与部分文档由 AI 辅助起草，随后由人工维护者编辑：跑了命令、对着代码与生成的报告核了数字，删掉了复现不了的说法。

AI 文本检测器彼此不一致，也和人类判断不一致，所以这里不承诺任何“检测率”。读着像机器写的句子，多半最初就是那么来的；
数字不对就是 bug，提个 issue，下个版本修。

代码、模块 manifest、规则包与证据产物来自软件本身；以上说明只针对文字。

## 许可证与安全

Apache-2.0。可以商用、fork、嵌进服务；保留声明，包括 `NOTICE`（对标特性的 clean-room 声明）。许可证不授予商标权。

InkBlade 自身的漏洞：走托管平台的私密漏洞报告通道，协调处理目标 90 天。别开公开 issue 贴利用细节。
支持版本线：0.2.x。

---

English: [`README.md`](README.md)
