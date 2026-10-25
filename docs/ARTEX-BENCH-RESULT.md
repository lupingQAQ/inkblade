# ARTEX 在 QEMU TCG k3s VM 内的实跑对标 — 结果

> 状态：**同靶场扫描对比已达成**。在同一台宿主、同一 QEMU TCG 实验环境内实跑 ARTEX
> v0.3.23（官方镜像 `ruoji6/artex:v0.3.23`，零代码改造、纯黑盒）：把宿主 mock LLM 从
> v1「单 tool-call 确定性回复」升级为 v2「脚本化计划器」（按 ARTEX 真实 LLM 协议返回确定
> 的 tool_calls 序列）后，ARTEX 任务完整走通 **目标拆解 → planner 派意图 → worker 真实
> 探测靶场 → report_finding 落库 → prove_goal 收官**，任务终态 `done`（13.5 s），worker 对
> 同一 mock 靶场发出 **3 个真实 HTTP 请求**（靶场计数器证据），ARTEX 侧产生 **1 条 high
> finding**；同一靶场同攻击面跑 Trident 对应链 `flat-network-admin-plane-weight-poison`
> 计时对比见 `reports/samples/artex-bench/same-target.json|md`。首轮（v1 mock）计划跑不通、
> 任务停在 running 的旧结论已由本轮撤销（历史记录见第 6.2 节）。文中数字均可在
> `reports/samples/artex-bench/artex-bench.json`、`same-target.json` 与
> `lab/qemu-k3s/out/`（gitignore 的原始转储）找到出处。

## 0. 结论摘要

| 指标 | 实测值（本轮 clean-slate 全量复跑） | 证据 |
|---|---|---|
| VM 规格 | QEMU 11.1.0 `-accel tcg -machine pc -smp 6 -m 6144`，Alpine 3.24.3 / kernel 6.18.58-0-virt | `environment.vm`、`guest_facts` |
| k3s | `v1.36.5+k3s1` 单节点 **Ready**（同 VM 常驻） | `kubectl get nodes` |
| 镜像 | `ruoji6/artex:v0.3.23` 2.47 GB + `postgres:16-alpine` 420 MB（共 2.892 GB） | `resources.images` |
| 冷启动（镜像已预拉） | PostgreSQL ready **19.2 s**；ARTEX `/api/health` 200 **35710 ms**；auth **0.48 s** | `cold_start.*` |
| 空闲 RSS（起栈后 60–90 s） | artex **27.0 MiB** + artex-pg **48.3 MiB** = **75.2 MiB**（10 次采样最大值） | `resources.total_mib` |
| API 延迟（guest 回环） | `/api/health` min 50 / p50 55 / p95 60 / max 60 ms（n=20） | `api_latency.health` |
| 同靶场扫描任务 | `POST /api/tasks` 201（240 ms）→ created → running → **done**，全程 **13 510 ms** | `task_run.*`、`same-target.json` |
| LLM 往返 | **12 次** `chat/completions`（goals 2 / planner 4 / worker 5 / other 1），全部 stream=true | `task_run.llm_calls`、`mock-llm.jsonl` |
| 靶场流量（ARTEX worker） | **3 个真实 HTTP 请求**：GET `/__routes__`、POST `/pause`、POST `/pull_weights`，全部 200 | 靶场 `/__stats__` 计数器（`same-target.json.target_hits`） |
| ARTEX finding | **1 条 high**（`report_finding` 落库，`distinct_findings.total=1`） | `TASKS_JSON`、`findings_by_severity` |
| token（按请求体估算） | 输入 ≈ **84 160** / 输出 ≈ **986**（请求体字符数/4；mock 非真实分词器） | `same-target.json.artex.tokens_*` |
| Trident 同链同靶场 | `flat-network-admin-plane-weight-poison` execute **105.6 ms**（两步 1.9/1.6 ms，dry-run 23.1 ms），5 请求，0 token | `same-target.json.trident` |

对照 Trident（同宿主，Windows 原生，`lab/bench`）：空闲 RSS 49.0 MiB/单进程、链路径
64 ms/轮、兜底五路由 9 ms/轮。**同靶场同面的逐步对比表在第 4 节。**

## 1. 环境

| 项 | 值 |
|---|---|
| 宿主 | Windows，Intel i5-10600KF（6C/12T），无 KVM / 无 Hyper-V / 无 WSL |
| 虚拟化 | QEMU `-accel tcg`（纯软件仿真），`-machine pc`，`-smp 6`，`-m 6144` |
| Guest | Alpine Linux 3.24.3，kernel 6.18.58-0-virt，ext4，磁盘 `disk/k3s.qcow2` 16 GB（13.4 GB 可用） |
| k3s | `v1.36.5+k3s1`，containerd `2.3.4-k3s1.36`，单节点 control-plane，`--disable traefik --disable metrics-server` |
| Docker（guest 内） | Alpine `docker` 29.9.2 + `docker-cli-compose` 5.6.1；containerd 2.3.7；overlayfs（containerd snapshotter） |
| 网络 | QEMU user-net：`10.0.2.2` = 宿主回环；dockerd 出网走 `http://10.0.2.2:7897`（宿主本地代理） |
| 端口映射 | 2222→22、6445→6443（k3s API）、30080→30080、**18787→8787（ARTEX UI/API）**、18788→8788 |
| 被测对象 | ARTEX `v0.3.23`（tag `v0.3.23`，commit `620ca5d`），AGPL-3.0，**零代码改造、纯黑盒** |
| LLM | 宿主 `lab/qemu-k3s/artex-mock-llm.py` **v2 脚本化计划器**（OpenAI 兼容，SSE；按 ARTEX 协议返回确定 tool_calls 序列） |
| 靶场 | 宿主 `lab/mock_targets.py --mode vulnerable`（新增 `/__stats__` 请求计数器），guest 侧以 `http://10.0.2.2:18080` 访问 |

## 2. 步骤（脚本已交付）

全部入口：`powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1`
（`-SkipPull` 复用已拉镜像、`-SkipStart` 复用已在跑的 VM、`-Restart` 强制重启）。
本轮全量复跑：`artex-bench.ps1 -SkipStart -SkipPull`（bench 墙钟 156.1 s）。

1. **VM**：`start-vm.ps1 -Mode run -MemoryMB 6144 -Smp 6 -Machine pc`（q35 在 6 vCPU 下
   4/4 启动失败，i440fx 稳定；panic 自动重试 ≤3 次）。
2. **guest Docker**：`apk add docker docker-cli-compose` + `daemon.json` 走宿主代理；脚本
   `lab/qemu-k3s/artex-bench-setup.sh pull`（幂等）。
3. **镜像**（固定 tag，已预拉）：`ruoji6/artex:v0.3.23` + `postgres:16-alpine`。
4. **起栈**：`docker-compose.bench.yml` 在 v0.3.23 已失效（见 6.1），按 `docker-compose.yml`
   拓扑 `docker run` 起 PG + ARTEX（`ARTEX_PG_DSN`、`ARTEX_LLM_BASE_URL=http://10.0.2.2:18081/v1`、
   `ARTEX_LLM_PROVIDER=openai`、`ARTEX_LLM_MODEL=mock-agent-model`）。脚本：
   `lab/qemu-k3s/artex-bench-run.sh`（clean-slate：删容器/删数据卷重计冷启动）。
5. **mock LLM v2（脚本化计划器）**：宿主监听 `127.0.0.1:18081`，协议逆向自
   `.slim/clonedeps/repos/RuoJi6__ARTEX`（agent/planner.go、worker.go、tools.go、
   toolcatalog.go、server/engine.go、goals.go）：
   - **按工具集识别请求方**：`set_goals`∧¬`add_intent` → goals 拆解器；`add_intent`∧`prove_goal`
     → planner（40 工具）；`report_finding`∧¬`add_intent` → worker（27 工具）；其余（30 工具
     的报告/复盘 agent 等）回终止文本；
   - **goals**：回一条真实 `set_goals`（批量 goals 数组，非空 text）；
   - **planner（内容驱动）**：解析注入在 user 消息里的 graph_overview JSON —— 有 finding →
     `prove_goal(goal_id, evidence_id)`；无 open/running 意图 → `add_intent(intents:[…])`；
     有在跑意图 → 结束本轮。**关键教训**：态势只在每次 Plan() 的首条 user 消息里注入，同一会话
     后续 turn 不会再刷新——因此脚本从会话内 tool 结果判断「本轮已派发过意图」（`intent created:`）
     即收口，并加 turn>4 硬顶。首轮 v1 无此逻辑时 planner 在单会话内连派 400+ 意图、3 个 worker
     并发空转（靶场被打 167 次），已修复并由
     `tests/test_artex_same_target.py` 的 dispatch-once/prove-once/turn-cap 用例锁定；
   - **worker（固定探测计划）**：`Bash`+`curl` 依次 GET `/__routes__` → POST `/pause` →
     POST `/pull_weights`（与 Trident 链同两个攻击面），每条命令带 `-w '[HTTP %{http_code}]'`
     标记；runner 依 tool 结果自适应降级 curl→wget→python3；第 4 轮 `report_finding`
     （evidence 引用前三轮真实输出、`intent_id` 从 system 提示的「意图 id: N」解析）；
     最后一轮纯文本收尾；
   - **审计日志**：每个请求完整记录（工具 schema、全量消息、epoch-ms 时间戳、请求体字符数
     → token 估算）到 `out/mock-llm.jsonl`。
6. **采集**：guest `artex-bench-run.sh` 输出 `KEY=value` 原始转储（含任务窗口
   `docker stats` 采样与 `TASKS_JSON`）；`artex-bench-collect.py` 合成
   `artex-bench.json|md`；靶场 `/__stats__` 快照（ARTEX 窗口）+ `same-target-trident.py`
   （同靶场跑 Trident 链计时）+ `same-target-collect.py` 合成 `same-target.json|md`。

ARTEX 日志确认本轮任务生命周期（clean-slate 后任务 #1）：

```
[task] 新建任务 #1 «ARTEX same-target bench scan …»  [goals] set_goals 落库
[planner] task 1 规划中…(edge 触发) → add_intent → [worker work#1] 领取意图 #2
[worker work#1] task 1 意图 #2 结束: done (写回 事实0 资产0 漏洞1)
[planner] task 1 规划中…(finding/done 触发) → prove_goal → 判定目标达成 → done
```

## 3. 原始数据

### 3.1 冷启动（clean-slate 全量复跑）

| 阶段 | 实测 |
|---|---|
| `docker run postgres` → `pg_isready` OK | **19 180 ms** |
| `docker run artex` → `GET /api/health` = 200 | **35710 ms**（含上面 19.2 s 的 PG 等待；首轮记录为 37 850 ms，同量级） |
| `POST /api/auth/init` (200) + `POST /api/auth/login` (200) | **480 ms** |
| 冷启动 → 可登录 | **≈36.2 s** |

> 镜像已预拉；量的是容器启动 + 首次 schema 迁移，不含 `docker pull`（含则 15–20 分钟量级，见 6.4）。

### 3.2 空闲资源（起栈后 60–90 s，`docker stats --no-stream` ×10）

| 容器 | 峰值 |
|---|---|
| `artex` | **27.02 MiB**（mean 26.76） |
| `artex-pg` | **48.32 MiB**（mean 47.92） |
| 合计 | **75.2 MiB**（mean 74.67） |

> 首轮长跑实例（起栈 11 h、经历 60+ 次心跳规划后）同口径为 169.8 MiB——差别主要来自
> PostgreSQL 缓存与 Go 堆随会话/图增长，两值都如实记录。任务窗口内（worker 活跃时）峰值为
> **84.4 MiB**（`same-target.json.artex.rss_mib_during_task`）。

### 3.3 镜像与磁盘

| 项 | 值 |
|---|---|
| `ruoji6/artex:v0.3.23` | 2.47 GB（`docker images`），压缩 668 MB（Docker Hub `full_size`） |
| `postgres:16-alpine` | 420 MB，压缩 117 MB |
| `docker system df` | Images 2.892 GB / Containers 45 kB / Volumes 130.6 MB |
| `/var/lib/docker` | **4 963 154 309 B ≈ 4.6 GiB** |

### 3.4 API 延迟

| 路径 | 观测点 | 结果 |
|---|---|---|
| `GET /api/health` ×20 | guest 回环 | min 50 / p50 55 / p95 60 / max 60 ms |
| `GET /api/tasks` | guest 回环 | 170 ms（首次列表，空库） |
| `GET /api/health` ×5 | 宿主经 hostfwd 18787 | 首轮记录 39/12/12/11/13 ms |

### 3.5 同靶场扫描任务（本轮核心）

| 项 | 值 |
|---|---|
| `POST /api/tasks` | **201**，`TASK_ACCEPT_MS=240`，clean-slate 后 `id=1` |
| 状态轨迹 | created(0 s) → running(3 s) → **done(6 s 轮询点)**；提交→终态 **13 510 ms**（3 s 轮询粒度） |
| LLM 调用 | **12 次**：goals t0 `set_goals`、goals t1 终止；planner t0 `add_intent`、t1 终止；worker t0–t2 `Bash`×3、t3 `report_finding`、t4 终止；planner t0 `prove_goal`、t1 终止；other t0 终止 |
| worker 靶场请求 | **3 个**（同靶场 `/__stats__`：GET `/__routes__` 200、POST `/pause` 200、POST `/pull_weights` 200，毫秒级时间戳在 `same-target.json.target_hits`） |
| ARTEX finding | **1 条 high**（`findings={"high":1}`，`distinct_findings.total=1`） |
| prove_goal | finding 节点作 evidence 证明唯一目标 → `goals_total=1, goals_met=1`，任务自动收官 `done` |
| token（请求体估算） | 输入 ≈ 84 160 / 输出 ≈ 986（`messages`+`tools` 字符数/4；ARTEX 自身 `tokens` 计数为 0——mock 回包无计费 usage） |

### 3.6 ARTEX 逐步时延（LLM 答复发完 → 靶场命中到达 / LLM 轮耗时）

| 步骤 | 时延 |
|---|---|
| goal-decompose（goals 两轮） | 214 ms |
| probe-1 GET `/__routes__` | 168 ms |
| probe-2 POST `/pause` | 159 ms |
| probe-3 POST `/pull_weights` | 2 159 ms（含 TCG 下靶场写 marker+权重+sha256） |
| `report_finding` / `prove_goal` LLM 轮 | 1–2 ms/轮（脚本回复近零耗时） |
| **合计（提交→done）** | **13 510 ms**（其中大头是 ARTEX 引擎编排：planner 唤醒 debounce、worker 领取轮询、3 s 状态轮询粒度，不是 LLM 或靶场耗时） |

## 4. 与 Trident 对照（同靶场同攻击面）

Trident 侧：`lab/qemu-k3s/same-target-trident.py` 在宿主对**同一** `lab/mock_targets.py`
实例（127.0.0.1:18080，与 ARTEX 经 10.0.2.2:18080 访问的是同一个进程）执行同一条链
`flat-network-admin-plane-weight-poison`（sglang-admin-failopen → slime-weight-pull-poison，
授权锁+备份闸门+三层证据全开，与 e2e 验收同一执行路径）。逐步/总数见下，机读对照
`same-target.json`（`comparison` 数组），人读 `same-target.md`：

| 维度 | ARTEX（VM 内，脚本化计划器 mock） | Trident（宿主原生） | 说明 |
|---|---|---|---|
| 任务/链总时延 | **13 510 ms**（提交→done） | **105.6 ms**（链 execute 墙钟；dry-run 另 23.1 ms） | ARTEX 含引擎编排与 3 s 轮询粒度；Trident 进程内同步执行 |
| 逐步时延 | goal 拆解 214 ms；探测 168/159/2 159 ms | 两步各 **1.9 ms / 1.6 ms** | 语义对齐：两侧都打了 `/pause` 与 `/pull_weights` 同两个面 |
| 靶场请求数 | **3**（routes/pause/pull_weights） | **5**（pause/resume/pull_weights GET 405 备份快照/pull_weights POST） | 靶场 `/__stats__` 计数器，同实例 |
| LLM 调用 / token | **12 次**；in≈84 160 / out≈986（按请求体估算） | **0 次 / 0 token** | Trident 全链确定性执行 |
| finding/证据 | 1 条 high finding（ARTEX 图谱+DB） | 2 步全 success（三层证据+备份回执+manifest） | 证据语义不同，各按各自平台落库 |
| 内存 | 任务窗口峰值 **84.4 MiB**（2 容器）+ 栈冷启动 35.7 s | **50.4 MiB**（1 进程）+ 亚秒启动 | ARTEX 另有 2.892 GB 镜像 / 4.6 GiB docker root |
| 攻击速率 | 3 请求 / 13.5 s ≈ **0.22 req/s** | 5 请求 / 0.106 s ≈ **47 req/s**（链路径；兜底路径首轮记录 25 请求全 200、9 ms/轮） | **≈200×**，但含 TCG 与引擎编排放大，见口径说明 |

**判读**：两侧差距的构成＝① QEMU TCG 纯软件仿真放大（所有 guest 内动作都慢一个量级）；
② ARTEX 的多 agent 编排固有节拍（planner 边沿唤醒 debounce、worker 领取轮询、状态轮询粒度）；
③ LLM 往返（即便 mock 每轮 <10 ms，引擎仍按「轮」推进）。Trident 的优势仍是确定性、零 token、
单进程可嵌入；ARTEX 的优势是自然语言意图驱动的开放面探索（本实验不评估其模型质量——决策是
写死的脚本，只验证协议与引擎真实执行）。**不应把 13 510/105.6 直接当作产品级倍率**。

## 5. 复现

```powershell
# 完整（含拉镜像；首次约 15-20 分钟）
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1

# 镜像已拉、VM 已在跑（本轮口径）
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\artex-bench.ps1 -SkipStart -SkipPull

# 宿主直接访问 ARTEX（本轮运行仍在线）
#   UI/API: http://127.0.0.1:18787   （管理员口令 ArtexBench2026）
#   health: curl http://127.0.0.1:18787/api/health
```

产物：`reports/samples/artex-bench/artex-bench.json|md`（启动/资源/API/任务提交基准）与
**`same-target.json|md`（同靶场对比，本轮新增）**；原始转储 `lab/qemu-k3s/out/`
（`artex-same-target-raw.txt`、`mock-llm.jsonl`、`mock-target-stats-artex.json`、
`trident-chain.json`、`artex-container.log`，均在 `.gitignore` 的 `out/` 下，不入库）。
迭代/调试可用轻量驱动 `lab/qemu-k3s/artex-same-target-lite.sh`（不重起栈，删任务→建任务→轮询，
配合 `--target-url` 指向的 mock 快速验证协议改动）。回归：`python -m unittest
tests.test_artex_same_target tests.test_artex_bench_artifacts -v`
（脚本化决策逻辑 + 证据结构 + 文档数字可溯源断言）。

## 6. 失败点、历史与限制（逐条如实记录）

### 6.1 `docker-compose.bench.yml` 在 v0.3.23 已不可用（证据）
该文件引用 `Dockerfile.bench` 与 `bench/.env`，仓库 v0.3.23（commit `620ca5d`）中**两者都不存在**，
且使用 `network_mode: host`——在 Alpine guest 里会占用宿主网络栈、与 k3s 端口冲突。因此未使用
bench compose，改按 `docker-compose.yml` 拓扑 `docker run` 精确计时。被测二进制仍是官方镜像。

### 6.2 首轮扫描跑不通 → 已由 v2 脚本化计划器补齐（历史）
首轮（v1 mock）收到 4 次真实 `chat/completions`，证明 OpenAI 客户端/SSE/工具注入/环境变量全部
生效；但 v1 只会回固定文本或「工具清单第一个工具 + 空参数」（`set_goals` 空参报错、planner 收到
终止文本空转），任务停在 `running`、worker 未启动、靶场 0 请求，当时如实降级为「只提供启动/资源/
API/任务提交基准」。本轮把 mock 升级为按 ARTEX 协议驱动的脚本化计划器（第 2 节第 5 步）后同靶场
扫描完整跑通；调试第一版脚本时还发现并修复了「planner 单会话意图工厂」缺陷（态势只在首条 user
消息注入），该缺陷曾让 3 个 worker 并发空转、靶场被打 167 次——修复后一轮任务恰好 3 请求、
12 次 LLM 调用。两次迭代均有完整 JSONL 证据（`mock-llm-iter1.jsonl` 留档）。

### 6.3 `-Smp 6` 在 TCG 下偶发启动 panic（已参数化规避）
首轮观测（10 次 6-vCPU 启动）：q35 默认机型 4/4 失败（2 guest panic + 2 QEMU 半途退出）；
`-machine pc`（i440fx）6 次中 5 次成功。同一配置「这次成功、下次 panic」说明是 TCG 模拟时序
问题，非 ARTEX 缺陷。处置：`start-vm.ps1` 默认 `-machine pc` + panic 重试循环（≤3 次）。

### 6.4 镜像拉取依赖宿主代理，耗时波动大
Docker Hub 需经 `10.0.2.2:7897`；实测 0.14–9.8 MB/s，2.89 GB 压缩层合计 15–20 分钟（大头是
TCG 解包）。无代理环境需换可达 mirror。

### 6.5 k3s 与 ARTEX 同 guest 竞争
k3s 单节点 control-plane 整轮常驻（空闲占 1 核 20–35%），另有并行会话在同一集群做压测。这些
放大冷启动与 API 延迟，**ARTEX 自身开销被高估而非低估**。

### 6.6 NodePort 目标在 VM 重启后不可达
VM 重启后 k3s NodePort 转发失效（kube-proxy 规则未恢复），靶场固定用宿主
`lab/mock_targets.py`（同一份路由表、`--mode vulnerable`），guest 经 `10.0.2.2:18080` 访问；
本轮为该实例加了 `/__stats__` 请求计数器（GET 读 / POST 清零，不影响路由表与原有行为）。

### 6.7 其它口径说明
- 冷启动不含 `docker pull`；RSS 为 `docker stats --no-stream` 采样（10 次/任务窗口逐轮询）；
  ARTEX 启动参数 `workers=3`。
- token 为按 ARTEX 请求体字符数/4 的估算（mock 不做真实分词、不回计费 usage，ARTEX 自身
  `tokens` 计数为 0）；未测多用户并发（单管理员）。
- ARTEX 的 `[seed]` 守卫把 `10.0.2.2` 识别为「LLM 网关主机」拒绝建站点资产（LLM base 与靶场
  同 host 所致）——不影响本次流程（意图不绑资产、探测仍真实执行），如实记录。
- mock v2 的 worker 探测计划是写死的（对应 Trident 链的两个攻击面），不代表真实模型的探索
  决策质量；本实验验证的是协议兼容与引擎真实执行。
