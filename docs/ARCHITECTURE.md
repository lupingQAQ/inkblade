# InkBlade（墨刃零）架构 / Architecture

InkBlade 采用七层架构，运行时仅依赖 Python 3.10+ 标准库；所有执行路径统一经过授权闸门与备份闸门。

七层，自下而上：

1. **授权治理层** — `core/roe.py`, `core/users.py`, `core/evidence.py`
   consent/ROE 签名 + 级别闸门 + 四角色 RBAC + 逐动作审计
2. **编排层** — `core/chains.py`, `core/runner.py`, `core/backup.py`
   dry-run → execute；依赖拓扑与并行；写类模块先备份；失败回滚
3. **模块层** — `modules/<key>/{module.json, run.py}`
   侦察 / 横向 / 权限链 / 窃取 / 核心代码 / 网络 / 混合云 / 绕过 / 深度
4. **证据层** — `core/evidence.py`
   `context.jsonl.gz`（摘要）/ `evidence.db`（SQLite）/ `steps/*.tar` + SHA-256
5. **报告层** — `reports/`
   PTES 七段 + 五个 ML 专节 + NIST/等保/GB-T 20984 + CVSS 3.1 + 双语渲染
6. **可视化层** — `webui/`
   六视图 SPA（DAG/攻击链/时间线/证据/报告/规则）+ `export_static` 离线兜底
7. **规则转化层** — `rules/`
   `generate_all`: 规则↔链覆盖率硬校验；`validate`: fixture 重放 + 简化匹配器矩阵

```

## 各层职责 / Layer responsibilities

| 层 | 关键实现 | 职责 |
|---|---|---|
| ① 授权治理 | `core/roe.py`, `core/users.py`, `core/evidence.py` | consent/ROE 哈希签存；只读侦察 → 主动探测 → 利用验证 → 全影响演示四级闸门；admin/lead/tester/auditor 角色；每条执行与拒绝都写审计行 |
| ② 编排 | `core/chains.py`, `core/runner.py`, `core/backup.py` | 链前置三态判定（自实现表达式求值，禁 `eval`）；dry-run 预览写面；依赖拓扑与并行执行；备份闸门（退出码 91）；失败回滚 |
| ③ 模块 | `modules/*/module.json`, `modules/*/run.py` | 统一契约：`key/name/series/description/min_level/writes/requires`；`run(ctx, params) -> {summary, artifacts, findings}`；`private` 仅用于可选加密扩展 |
| ④ 证据 | `core/evidence.py` | 每步三层落证；`manifest.sha256` 逐文件校验；`findings`/`actions`/`backups`/`rollbacks` 审计表 |
| ⑤ 报告 | `reports/render.py`, `reports/cvss.py` | 双语渗透与修复报告；证据锚 = 步骤 + manifest sha256 前 16 位；`redact_novel=True` 可对深层细节做可选脱敏 |
| ⑥ 可视化 | `webui/server.py`, `webui/export_static.py` | 本地控制台与六视图；静态导出 `window.INKBLADE_DATA`，`file://` 免服务打开 |
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

## 运行边界 / Runtime boundaries

- 控制台默认只监听 `127.0.0.1`；所有写盘限于 `--home` 指定的工作区目录。
- 真实集群测试需要显式授权、kubeconfig 与网络可达性；平台不内置任何真实凭据。
- 无集群时用 `pilot --dry-run` 验证计划结构；真实执行始终要求已签授权。
