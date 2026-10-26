# E2B Runtime — 每沙箱一个 Firecracker microVM

- 分类：agent-2026 / 沙箱执行
- 来源：E2B（Apache-2.0 runtime）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，runtime README 正文命中）

## 来源
- https://github.com/e2b-dev/runtime
- https://docs.e2b.dev/
- https://github.com/e2b-dev/E2B

## 核验（实际读到的）
- 一句话：**Firecracker microVMs that resume from a snapshot, run untrusted agent code, and pause when the agent stops.**
- 隔离：**每 sandbox 一个 Firecracker microVM**，独立 cgroup + network namespace，**per-sandbox nftables egress firewall**，支持 SNI/Host 检查的域名 allow/deny list。
- 生命周期：模板=预启动 VM 快照（内存+磁盘+机器状态）；创建=恢复快照而非 boot kernel；`userfaultfd` 惰性取页 + 只读镜像上的 CoW overlay；pause 差分内存/磁盘到对象存储；resume 优先同节点缓存；**fork 运行中 sandbox**（单请求最多 100 个）。
- 面：`envd` 在 VM 内提供进程/PTY/文件/端口转发 API；sandbox URL 可按端口暴露，带 per-sandbox access token；持久卷、secrets 不经过 API/日志/span、workload identity 发短期 token。
- 架构：控制面（API/placement/quota）与数据面（node orchestrator/Firecracker）分离，沙箱流量不经过 API；Go + Apache-2.0，可自托管（单机 Embed/云/K8s）。

## 架构要素
- 隔离单位=VM，不是容器/进程；快照恢复把冷启动压到接近 0。
- 网络是默认拒绝 + 显式 allowlist；秘密不落控制面。
- 可 Fork = 可并行探索；pause/resume = 长任务不烧钱。

## 对我们的启示
- 我们没有任何执行隔离：`runner._load_run_py` 直接 `exec_module`（`inkblade/core/runner.py:27-31`），模块能触碰宿主文件/网络（G08）。一旦接入 LLM 生成代码或第三方技能，这是最高危缺口。
- 迁移不必一步到 Firecracker：先做「子进程 + 只读根 + 独立 netns/egress allowlist + 一次性工作目录」，接口按 sandbox 抽象（create/exec/upload/download/pause/kill），后续可换 E2B/Firecracker。
- 「fork 运行中沙箱」对渗透很有价值：同一目标状态下并行试多条利用路径，且互不污染。
