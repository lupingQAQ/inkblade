# ARTEX 在 QEMU TCG k3s VM 内的实跑对标 — 结果

> 状态：**已在同一台宿主、同一 QEMU TCG 实验环境内实跑 ARTEX v0.3.23**（官方镜像
> `ruoji6/artex:v0.3.23`），取得冷启动 / 空闲 RSS / 镜像与磁盘占用 / API 延迟 / 单任务提交
> 五组实测数据。**扫描任务未跑到靶场**（mock LLM 无法产出合法 planner 计划），已在第 6 节
> 如实降级并标注。文中每个数字都可在 `reports/samples/artex-bench/artex-bench.json` 与
> `lab/qemu-k3s/out/artex-bench-raw.txt` 找到出处，没有估算值冒充实测。

## 0. 结论摘要

| 指标 | 实测值 | 证据 |
|---|---|---|
| VM 规格 | QEMU 11.1.0 `-accel tcg -machine pc -smp 6 -m 6144`，Alpine 3.24.3 / kernel 6.18.58-0-virt | `environment.vm`、`guest_facts` |
| k3s | `v1.36.5+k3s1` 单节点 **Ready**（同 VM 常驻，占用 CPU/内存） | `kubectl get nodes` |
| Docker | 29.9.2（Alpine 包）+ containerd 2.3.7，containerd-snapshotter/overlayfs | `docker info` |
| 镜像 | `ruoji6/artex:v0.3.23` 2.47 GB（压缩 668 MB）+ `postgres:16-alpine` 420 MB | `resources.images` |
| 冷启动（容器启动，镜像已预拉） | PostgreSQL ready **31.0 s**；ARTEX `/api/health` 200 **37.85 s**；auth **0.58 s** | `cold_start.*` |
| 可登录 | `/api/auth/init` 200 → `/api/auth/login` 200（token 147 字节），累计 **≈38.4 s** | `cold_start.auth_*` |
| 空闲 RSS | ARTEX **67.4 MiB** + PostgreSQL **102.9 MiB** = **169.8 MiB**（10 次采样最大值） | `resources.total_mib` |
| API 延迟（guest 回环） | `/api/health` min 60 / p50 70 / p95 70 / max 80 ms（n=20） | `api_latency.health` |
| API 延迟（宿主经 hostfwd） | 首次 39 ms，稳态 12/12/11/13 ms；`GET /` 返回 200（14 815 B） | 第 3.4 节 |
| 单任务提交 | `POST /api/tasks` → 201，**380 ms**；任务在 240 s 观察窗内保持 `running` | `task_run.*` |
| LLM 往返 | mock 收到 **4** 次 `chat/completions`（stream=true），工具集 3→40 个 | `task_run.llm_calls` |
| 靶场流量 | **0**（mock 计划无效，未产生 worker → 未发 HTTP 请求） | 第 6.2 节 |

对照 Trident（同宿主，Windows 原生，`lab/bench`）：空闲 RSS **49.0 MiB / 单进程**，
链路径 **64 ms/轮**、兜底五路由 **9 ms/轮**。

## 1. 环境

| 项 | 值 |
|---|---|
| 宿主 | Windows，Intel i5-10600KF（6C/12T），无 KVM / 无 Hyper-V / 无 WSL |
| 虚拟化 | QEMU `-accel tcg`（纯软件仿真），`-machine pc`，`-smp 6`，`-m 6144` |
| Guest | Alpine Linux 3.24.3，kernel 6.18.58-0-virt，ext4，磁盘 `disk/k3s.qcow2`（本次从 8 GB 扩到 16 GB，`growpart`+`resize2fs` → 13.4 GB 可用） |
| k3s | `v1.36.5+k3s1`，containerd `2.3.4-k3s1.36`，单节点 control-plane，`--disable traefik --disable metrics-server` |
| Docker（guest 内） | Alpine `docker` 29.9.2 + `docker-cli-compose` 5.6.1；containerd 2.3.7；存储驱动 overlayfs（containerd snapshotter） |
| 网络 | QEMU user-net：`10.0.2.2` = 宿主回环；dockerd 出网走 `http://10.0.2.2:7897`（宿主本地代理） |
| 端口映射 | 2222→22、6445→6443（k3s API）、30080→30080、**18787→8787（ARTEX UI/API）**、18788→8788 |
| 被测对象 | ARTEX `v0.3.23`（tag `v0.3.23`，commit `620ca5d`），AGPL-3.0，**零代码改造、纯黑盒** |
| LLM | 宿主 `lab/qemu-k3s/artex-mock-llm.py`（OpenAI 兼容，SSE，确定性回复） |
| 靶场 | 宿主 `lab/mock_targets.py --mode vulnerable`，guest 侧以 `http://10.0.2.2:18080` 访问 |

## 2. 步骤（脚本已交付）

全部入口：`powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1`
（`-SkipPull` 复用已拉镜像、`-SkipStart` 复用已在跑的 VM、`-Restart` 强制重启）。

1. **提高 VM 规格**：`start-vm.ps1` 参数化为 `-MemoryMB` / `-Smp`（旧 `-Memory`/`-Cpus` 保留为
   alias），新增 `-Machine`（默认 `pc`）、`-Accel`、`-ArtexPort`（18787→8787）/
   `-ArtexProxyPort`（18788→8788）。启动命令：
   `start-vm.ps1 -Mode run -MemoryMB 6144 -Smp 6`。冷启动到 SSH 可用 30.6 s；k3s 节点 Ready。
2. **guest 内装 Docker**：`apk add docker docker-cli-compose`；
   `rc-update add docker default; service docker start`；写 `/etc/docker/daemon.json`：
   ```json
   {"proxies":{"http-proxy":"http://10.0.2.2:7897","https-proxy":"http://10.0.2.2:7897",
               "no-proxy":"localhost,127.0.0.1,10.42.0.0/16,10.43.0.0/16,10.0.2.0/24"}}
   ```
   脚本：`lab/qemu-k3s/artex-bench-setup.sh pull`（幂等）。
3. **拉镜像**（固定 tag）：`ruoji6/artex:v0.3.23`、`postgres:16-alpine`。实测总耗时约
   15–20 分钟（2.89 GB 压缩层，含 TCG 下的解包；见 6.4）。镜像可用，**未触发源码构建 fallback**。
4. **启动栈**：`docker-compose.bench.yml` 在 v0.3.23 中已失效（见 6.1），故按
   `docker-compose.yml` 的服务拓扑用 `docker run` 起 `postgres:16-alpine` + `ruoji6/artex:v0.3.23`
   （`ARTEX_PG_DSN`、`ARTEX_LLM_*`、`OPENAI_API_KEY`、`-v /root/artex-data:/app/data`、`-p 8787:8787`）。
   脚本：`lab/qemu-k3s/artex-bench-run.sh`。
5. **LLM**：宿主 mock 监听 `127.0.0.1:18081`，guest 侧 `ARTEX_LLM_BASE_URL=http://10.0.2.2:18081/v1`、
   `ARTEX_LLM_PROVIDER=openai`、`ARTEX_LLM_MODEL=mock-agent-model`。
6. **采集**：`artex-bench-collect.py` 把 guest 的 `KEY=value` 原始转储 + mock LLM 的 JSONL
   日志合成为 `reports/samples/artex-bench/artex-bench.json|md`。

ARTEX 日志确认 LLM 配置生效与真实服务面：

```
[engine] LLM configured from env: openai / mock-agent-model
ARTEX 0.3.23 backend listening on :8787 (data=/app/data, workers=3)
[task] task #1 «ARTEX bench scan of mock target»
```

## 3. 原始数据

### 3.1 冷启动

| 阶段 | 实测 |
|---|---|
| `docker run postgres` → `pg_isready` OK | **31 020 ms** |
| `docker run artex` → `GET /api/health` = 200 | **37 850 ms**（含上面 31 s 的 PG 等待） |
| `POST /api/auth/init` (200) + `POST /api/auth/login` (200) | **580 ms**，token 147 B |
| 冷启动 → 可登录（health + auth） | **≈38.4 s** |

> 镜像已预拉；这里量的是容器启动 + 首次 schema 迁移，不含 `docker pull`。

### 3.2 空闲资源（`docker stats --no-stream`，2 s 间隔 ×10）

| 容器 | MemUsage 采样范围 | 峰值 |
|---|---|---|
| `artex` | 66.88 – 67.39 MiB | **67.39 MiB** |
| `artex-pg` | 102.1 – 102.9 MiB | **102.9 MiB** |
| 合计 | 169.0 – 169.8 MiB | **169.84 MiB**（mean 169.64） |

CPU（同一采样期）：artex 0.24–2.80%，postgres 0.07–0.89%。

### 3.3 镜像与磁盘

| 项 | 值 |
|---|---|
| `ruoji6/artex:v0.3.23` | 2.47 GB（`docker images` DISK USAGE），压缩 668 MB（Docker Hub `full_size`） |
| `postgres:16-alpine` | 420 MB（DISK USAGE），压缩 117 MB |
| `docker system df` | Images 2.892 GB / Containers 45 kB / Volumes 69.5 MB |
| `/var/lib/docker` | **4 901 942 371 B ≈ 4.7 GiB**（含 blob + 解包快照） |
| guest 根分区 | 用 3.7 GB / 13.4 GB（29%） |

### 3.4 API 延迟

| 路径 | 观测点 | 结果 |
|---|---|---|
| `GET /api/health` ×20 | guest 回环 | 60/60/70/70/70/60/60/70/70/70/70/60/70/70/70/70/80/70/70/70 ms → min 60, p50 70, p95 70, max 80 |
| `GET /api/tasks` | guest 回环 | 210 ms（首次列表，空库） |
| `GET /api/health` ×5 | 宿主经 hostfwd 18787 | 39 / 12 / 12 / 11 / 13 ms |
| `GET /`（内嵌前端） | 宿主 | 200，14 815 B |

> guest 回环 70 ms 与宿主 12 ms 的差值来自 TCG 下容器网络（veth/NAT）与 QEMU 用户态网络的
> 双跳，不是 ARTEX 业务逻辑开销。

### 3.5 单任务（API 提交 + LLM 步进）

| 项 | 值 |
|---|---|
| `POST /api/tasks` | **201**，`TASK_ACCEPT_MS=380`，`id=1` |
| 状态轨迹 | created(0 s) → running(3 s) → … → running(237 s)（每 3 s 轮询，79 次） |
| 观察窗结束状态 | **running**（未到终态），`TASK_MS=247540` |
| mock LLM 收到请求 | 4 次 `POST /v1/chat/completions`（stream=true）：第 1 次 tools=3（`set_goals`/`set_constraints`/`add_task_scope`），第 2–4 次 tools=40（planner 工具集） |
| 靶场请求 | **0**（`lab/mock_targets.py` 无任何入站请求） |

ARTEX 侧日志时序：`01:30:08 [task] 创建` → `01:30:08 [seed]` → `01:30:08 [goals]` →
`01:30:09 [planner] edge 分析` → `01:30:10 [planner] 空转`，随后 10 分钟后再次调用 LLM。

## 4. 与 Trident 对照

| 维度 | ARTEX（本 VM 实跑） | Trident（同宿主，`lab/bench`） | 说明 |
|---|---|---|---|
| 空闲 RSS | 169.8 MiB（2 容器：Go 服务 + PostgreSQL） | 49.0 MiB（1 个 Python 进程） | ARTEX ≈3.5× |
| 运行时依赖 | Docker + PostgreSQL + Go 二进制（镜像内另有 python/node/playwright 工具链） | Python 标准库单进程 | ARTEX 2.47 GB 镜像 vs 仓库内源码 |
| 冷启动到可用 | ≈38.4 s（TCG，含 PG 31 s） | 亚秒级（进程内启动） | 不同量级，环境差异巨大 |
| 镜像/磁盘 | 2.892 GB 镜像 / 4.7 GiB docker root | 源码 + 依赖，无容器 | |
| 同靶场扫描 | **未达成**（见第 6 节） | 链路径 64 ms/轮、5 轮 320 ms；兜底 9 ms/轮、25 请求全 200 | 不构成同口径对比 |
| 单任务提交 API | 380 ms（`POST /api/tasks` → 201） | 链执行 64 ms/轮（无任务队列） | 语义不同，仅记录 |
| LLM 依赖 | 必需（4 次调用；无真实模型） | **0 token** | Trident 全链确定性执行 |

**判读**：ARTEX 在「资源占用、启动时延、镜像体积」三项上明显重于 Trident，这是 LLM 驱动型
多 agent 平台的固有结构（LangGraph 式规划 + 容器化工具链 + PostgreSQL 持久化）。Trident 的
优势在确定性、零 token、单进程可嵌入。两者不在同一资源量级，**不应把二者的耗时直接相除**。

## 5. 复现

```powershell
# 完整（含拉镜像；首次约 15-20 分钟）
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1

# 镜像已拉、VM 已在跑
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1 -SkipPull -SkipStart

# 宿主直接访问 ARTEX（本次运行仍在线）
#   UI/API: http://127.0.0.1:18787   （管理员口令 ArtexBench2026）
#   health: curl http://127.0.0.1:18787/api/health
```

产物：`reports/samples/artex-bench/artex-bench.json`（机读）、`artex-bench.md`（人读）；
原始转储 `lab/qemu-k3s/out/artex-bench-raw.txt`、mock LLM 调用日志
`lab/qemu-k3s/out/mock-llm.jsonl`、容器日志 `lab/qemu-k3s/out/artex-container.log`（均在
`.gitignore` 覆盖的 `out/` 下，不入库）。回归：`python -m unittest tests.test_artex_bench_artifacts -v`。

## 6. 失败点、降级与限制（逐条如实记录）

### 6.1 `docker-compose.bench.yml` 在 v0.3.23 已不可用（证据）
该文件引用 `Dockerfile.bench` 与 `bench/.env`，仓库 v0.3.23（commit `620ca5d`）中**两者都不存在**
（全仓仅 `docker-compose.bench.yml` 一处出现 "bench"），且使用 `network_mode: host`——在 Alpine
guest 里会直接占用宿主网络栈、与 k3s 端口冲突。因此**未使用 bench compose**，改用
`docker-compose.yml` 的两服务拓扑 + `docker run` 精确计时。这是对上游材料的可复现性缺陷，
不改变被测二进制（仍是官方镜像）。

### 6.2 扫描任务降级：LLM 协议跑通、计划未跑通
mock LLM 收到 4 次真实 `chat/completions`，说明 ARTEX 的 OpenAI 客户端、SSE 流式解析、
工具集注入与环境变量配置全部生效；但确定性 mock 只能回固定文本 / 单一 tool-call，
无法产出 ARTEX planner 要求的计划 DSL，任务停在 `running`，worker 未启动，**靶场 0 请求**。
故本报告**不声称**「同靶场扫描对比」，只提供启动 / 资源 / API / 任务提交基准。若要真正扫靶场，
需接入真实模型（或按其 planner 协议写一个专用 mock），本次 timebox 内未做。

### 6.3 `-Smp 6` 在 TCG 下偶发启动 panic（已参数化规避）
6 vCPU + 6 GB 下，guest 偶发 `Kernel panic - not syncing: IO-APIC + timer doesn't work!`
（内核 `setup_IO_APIC` 定时器自检失败）。观测统计（10 次 6-vCPU 启动）：

| 机型 | 次数 | 结果 |
|---|---|---|
| QEMU 11.x 默认（q35） | 4 | **全部失败**：2 次 guest panic、2 次 QEMU 半途退出（openrc 阶段） |
| `-machine pc`（i440fx） | 6 | 5 次成功启动到 login，1 次 panic（发生在 k3s + 并行 60 Pod 压测 + 镜像解包同时进行时） |

同一 `-machine pc -smp 6 -m 6144` 配置也能「这次成功、下次 panic」，说明是 TCG 模拟时序问题，
非 ARTEX 缺陷。处置：`start-vm.ps1` 默认 `-machine pc`，`artex-bench.ps1` 增加「串口日志出现
panic 就重启」的重试循环（最多 3 次）。本次采集实例启动成功（`cpus=6 mem_mb=5934`）。

### 6.4 镜像拉取依赖宿主代理，耗时波动大
guest 直连 `dl-cdn.alpinelinux.org` 可用，但 Docker Hub 需经 `10.0.2.2:7897`。实测拉取速率在
0.14–9.8 MB/s 之间跳变（峰值 9.8 MB/s，平均约 2.5 MB/s），2.89 GB 压缩层合计约 15–20 分钟；
其中大部分时间消耗在 TCG 下的解包而非下载。无代理环境需换可达 mirror。

### 6.5 k3s 与 ARTEX 同 guest 竞争
整轮 bench 期间 k3s（单节点 control-plane）持续运行，空闲时仍占 1 个 CPU 核的 20–35%；
另有并行会话在同一集群做 `scale-lab-*` 压测（60 个 Pod 创建/销毁），一度把 load average
推到 32。这些都会放大冷启动与 API 延迟，**ARTEX 自身开销被高估而非低估**。

### 6.6 NodePort 目标在 VM 重启后不可达
VM 重启后 `trident-proof/mock-target` Pod 仍 Running，但 `127.0.0.1:30080`（hostfwd）与
guest 侧 `10.0.2.2:30080` 都超时（kube-proxy 规则未恢复/端口转发失效）。为保证 bench 可跑，
靶场改用宿主 `lab/mock_targets.py`（同一份路由表、`--mode vulnerable`），guest 经
`10.0.2.2:18080` 访问。注意：由于 6.2，本次并未真的打到靶场。

### 6.7 未做 UI 人工登录截图
登录是通过 API 验证的（`/api/auth/init` 200 → `/api/auth/login` 200 → token 147 B →
`GET /api/tasks` 200），宿主 `GET /` 也返回 200/14 815 B；但没有在浏览器里走 `/setup` 表单、
没有截图。timebox 内优先保证可复现的数字。

### 6.8 其它口径说明
- 冷启动**不含** `docker pull`；若含，则为「15–20 分钟」量级（见 6.4）。
- RSS 为 `docker stats --no-stream` 的 10 次采样，非瞬时峰值；ARTEX 启动参数 `workers=3`。
- 宿主 → ARTEX 的 12 ms 已包含 QEMU hostfwd 一跳，不能与 guest 内 70 ms 直接混用。
- 本次未测 token 成本（mock 不计费），未测多用户并发（单管理员）。
