# 性能对比（实测矩阵 · 方法学 · 未测项说明）

生成：2026-10-25｜数据源：`reports/samples/artex-bench/*.json`、`reports/samples/perf/grid/live-*.json`、
`reports/samples/perf/grid/live-inkblade-extra.json`、`docs/SCALE-RESULTS.md`、`lab/bench/BENCH-RESULT.md`。
原则：**只写实测值**；未测单元一律 N/A 并注明原因，禁止外推。

## 环境与方法学

- ARTEX v0.3.23 运行于 QEMU 11.1.0 **TCG 纯软件仿真**（`-machine pc -smp 6 -m 6144`，Alpine 3.24.3 / k3s 1.36.5 同 guest），镜像 `ruoji6/artex:v0.3.23` + `postgres:16-alpine`；宿主为同一 Windows 机器（i5-10600KF）。
- InkBlade 运行于宿主（单 Python 进程 + SQLite），本轮 `inkblade ui --port 18790`，基准根含已签 consent（level=全影响演示）、6 步 run、20 findings、graph 节点/边、traffic 与 drift.json。
- **TCG 放大声明**：ARTEX 的所有绝对值包含软件仿真开销（kubectl 热路径 0.12–0.16s 即为例证），跨工具倍率仅作同宿主相对参考，不代表裸机性能。
- 全端点网格口径（本轮新增）：`lab/bench/perf_compare.py --n 10`，逐 GET 路由 10 次采样
  → min/median/p95/p99/max/mean/stdev；并发档 1/4/16/32，每档 30（ARTEX）/60（InkBlade）请求；
  InkBlade 附加查询串 `workspace=bench&run=perf-run`，写方法路由跳过（标 `mutating-method`）。
  ARTEX 路径参数以 `probe_path` 样本值替换（`{id}→1` 等）；SSE 端点只计首响应（3s 上限）。
- 会话来源：ARTEX `POST /api/auth/login`（账号 ARTEX，口令见 `docs/ARTEX-BENCH-RESULT.md`）；
  InkBlade `POST /api/login`（perf-lead）。令牌只用于本次测量，未落样张。
- 采样时点：2026-10-25（UTC+8 22:4x）；测量脚本与命令随样张 JSON 的 `measured_at`/`base`/`query` 字段可复跑。

## 实测对比矩阵

| 场景 | ARTEX | InkBlade | 口径/备注 |
|---|---:|---:|---|
| S1 冷启动到可用（可登录） | **37.85 s**（PG ready 31.0 s） | **0.81 s**（3 次：781/805/815 ms，中位 805 ms） | 同宿主；ARTEX 含 PG 初始化与 TCG 仿真开销；InkBlade 为进程启动→`/api/login` 200 |
| S2 空闲 RSS | **169.8 MiB**（artex 67.4 + PG 102.9） | **28.1 MB**（真实解释器进程 working set） | 同一宿主；InkBlade 历史值 49–50 MiB 为早期不同采样口径，以本轮直读为准 |
| S3 同靶场扫描总时延 | **13,510 ms**（3 个真实请求、1 finding、goal 1/1） | **105.6 ms**（2 步链，5 请求） | ≈128×，含 TCG 放大与 ARTEX 编排节拍（planner debounce/worker 轮询/3s 状态轮询），**非产品级倍率** |
| S3 单步（权重写） | 2,159 ms | 1.6 ms | 同靶场同语义请求（`/pull_weights`） |
| S3 单步（管理面探测） | 159 ms | 1.9 ms | `/pause` 类请求 |
| S3 Token 消耗 | in≈84,160 / out≈986（12 次 LLM） | **0** | ARTEX 为脚本化计划器，token 按请求体统计 |
| S4 API 延迟（全端点网格） | 124 只读端点：median-of-medians **11.19 ms**，p95-of-medians 48.79 ms，median-of-p95 27.62 ms，p95-of-p95 127.01 ms，max 3,026 ms（`/api/update/stream` SSE 首响应超时） | 16 只读端点：median-of-medians **2.12 ms**，p95-of-medians 6.67 ms，median-of-p95 4.14 ms，p95-of-p95 26.16 ms，max 31.41 ms | 每端点 N=10；ARTEX 92/124 端点 2xx，32 个 0-2xx 为缺真实对象 id/权限域（401/404，延迟仍有效）；InkBlade 16/16 端点 2xx |
| S5 吞吐（并发曲线） | `/api/agents`：**33.4 / 30.3 / 17.4 / 22.4 rps**（1/4/16/32，error 0） | `/api/v1/graph`：**138.6 / 297.7 / 286.3 / 268.0 rps**（1/4/16/32，error 0） | 同档位同请求数密度不同（30 vs 60），只看曲线形状与量级；InkBlade 在 4 并发后进入 ~270–300 rps 平台（GIL+JSON 渲染） |
| S6 负载峰值资源 | N/A（未测） | **峰值 33.0 MB**（16 并发 600 请求，50ms 采样 47 点；空闲 28.1 MB，压后 30.8 MB） | ARTEX 需 guest 内 `docker stats` 同步采样，本轮未接；不填数 |
| S7 规模（10k 对象） | N/A（不支持同口径） | **1.645 s / 54 MB RSS**（11 侦察+可达性+规则生成，10,891 findings） | 合成快照；真 k3s 仅 204 对象点（TCG 限制） |
| S8 报告/规则生成 | N/A（导出面未测） | 10,000 findings：渗透报告 **3.21 s / 2.9 MB**，修复报告 **3.48 s / 3.6 MB**，规则包生成 **63 ms** | 本机单进程渲染；ARTEX 报告导出未用同规模对象驱动 |
| S9 磁盘足迹 | 镜像 **2.892 GB**（+PG 420 MB） | 代码树 **8.9 MB**（+SQLite 证据库，按 run 增长） | `lab/qemu-k3s` 的 5.7 GB 为实验室虚拟机产物，不计产品足迹 |

## 端点清单（全量扫掠的输入，从源码提取后可复跑）

| 工具 | 端点数 | 只读/写 | 来源 |
|---|---:|---|---|
| ARTEX | **278** | 124 / 154 | `server/*.go`，commit 620ca5d，`reports/samples/perf/grid/routes-artex.json` |
| InkBlade | **32** | 16 / 16 | `webui/server.py` 字面量路由（含本轮新增 steps/evidence/graph/report/drift/workspaces/openapi），`routes-inkblade.json` |

> 注：InkBlade 的 `webui/api_ext.py`（并行任务的扩展路由，PATCH/DELETE 与部分 GET）以路由表而非
> 字面量注册，静态提取器不计入；该部分不在本轮网格内，未测即为未测。

## 全网格扫掠器（一键复跑）

```bash
# 离线：校验路由清单与产物结构
python -m lab.bench.perf_compare --routes reports/samples/perf/grid/routes-artex.json --offline \
  --out reports/samples/perf/grid/offline-artex.json

# ARTEX 在线：全 124 只读端点 × N=10 + 并发 1/4/16/32
python -m lab.bench.perf_compare --routes reports/samples/perf/grid/routes-artex.json \
  --base http://127.0.0.1:18787 --token <ARTEX_SESSION> --n 10 --levels 1,4,16,32 \
  --per-level 30 --out reports/samples/perf/grid/live-artex.json

# InkBlade 在线：全 16 只读端点 × N=10 + 并发 1/4/16/32（指定 JSON 端点做并发曲线）
python -m lab.bench.perf_compare --routes reports/samples/perf/grid/routes-inkblade.json \
  --base http://127.0.0.1:18790 --token <INKBLADE_SESSION> --n 10 --levels 1,4,16,32 \
  --per-level 60 --query "workspace=bench&run=perf-run" --concurrency-path /api/v1/graph \
  --out reports/samples/perf/grid/live-inkblade.json
```

统计口径：`stats()` 报 n/min/median/p95/p99/max/mean/stdev；写方法路由跳过（标 `mutating-method`），
不发破坏性请求；HTTP 4xx/5xx 计入延迟但单独计 `ok_rate`。

**本轮由网格发现并修复的实现问题**：`ThreadingHTTPServer` 默认 `request_queue_size=5`，16/32 并发下
出现连接排队/SYN 重启（修复前 16 并发仅 29 rps）。`webui/server.py` 已将 backlog 提升到 256
（`daemon_threads`/`allow_reuse_address` 同步开启），修复后同端点 16 并发 286 rps。

## 未测项（如实登记，待补）

1. **ARTEX 32 个 0-2xx 端点的有效载荷**：需要真实 task/asset/case 对象与更高权限域；本轮只测到
   401/404 分支（延迟有效，成功率不计入 2xx）。
2. **≥30 分钟稳定性与 RSS 增长拟合**：未跑（本轮 S6 为 600 请求短压）。
3. **启动分解（ARTEX 的 PG init/迁移逐项；InkBlade 进程/DB/UI）**：仅有总分项
   （ARTEX PG ready 31s、health 37.85s；InkBlade 冷启动 805ms）。
4. **UI 首屏/10k findings 渲染**、**10 万行证据库查询延迟**：未测。
5. KubeTrail 性能：构建未完成（Go/Wails，需在 VM 内），N/A。
6. ARTEX 与 InkBlade 的**同并发密度**曲线（目前 30 vs 60 请求/档）：可复跑脚本对齐，本轮不做二次采样。

> 结论边界：在已测维度上——冷启动 ≈47× 更快（805ms vs 37.85s，含 TCG 放大）、空闲内存 ≈6× 更省
> （28.1MB vs 169.8MiB）、同靶场扫描 ≈128×（TCG 放大，非产品倍率）、全端点中位延迟 ≈5× 更低
> （2.12ms vs 11.19ms）、并发量级 ≈10–16×（286 vs 17–22 rps @16）、token 0 vs 84k。
> **未测维度不作结论。**
