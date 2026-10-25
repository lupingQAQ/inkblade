# 性能对比（实测矩阵 · 方法学 · 未测项说明）

生成：2026-10-25｜数据源：`reports/samples/artex-bench/*.json`、`reports/samples/perf/grid/*.json`、`docs/SCALE-RESULTS.md`、`lab/bench/BENCH-RESULT.md`。
原则：**只写实测值**；未测单元一律 N/A 并注明原因，禁止外推。

## 环境与方法学

- ARTEX v0.3.23 运行于 QEMU 11.1.0 **TCG 纯软件仿真**（`-machine pc -smp 6 -m 6144`，Alpine 3.24.3 / k3s 1.36.5 同 guest），镜像 `ruoji6/artex:v0.3.23` + `postgres:16-alpine`；宿主为同一 Windows 机器（i5-10600KF）。
- Trident 运行于宿主（单 Python 进程 + SQLite），mock 靶场同宿主 `127.0.0.1`。
- **TCG 放大声明**：ARTEX 的所有绝对值包含软件仿真开销（kubectl 热路径 0.12–0.16s 即为例证），跨工具倍率仅作同宿主相对参考，不代表裸机性能。
- 每项样本量：同靶场 ARTEX N=1 clean-slate 复跑（脚本化 LLM，任务墙钟含 3s 轮询粒度）；Trident 链 N=1（证据库逐步计时）；RSS 为 10 次 `docker stats` 均值；规模压测每档 N=1（100–10k 合成快照）。**统计上不足**，故不给置信区间；全端点 p50/p95/p99 网格由下述扫掠器补齐（见「未测项」）。

## 实测对比矩阵

| 场景 | ARTEX | Trident | 口径/备注 |
|---|---:|---:|---|
| S1 冷启动到可用 | **37.85 s**（PG ready 31.0 s） | N/A（未单列实测） | Trident 进程启动为亚秒级，但未按同一「可登录」口径测量，不填数 |
| S2 空闲 RSS | **169.8 MiB**（artex 67.4 + PG 102.9） | **49.0–50.4 MiB**（单进程） | 同一宿主；ARTEX 另占镜像/容器层开销 |
| S3 同靶场扫描总时延 | **13,510 ms**（3 个真实请求、1 finding、goal 1/1） | **105.6 ms**（2 步链，5 请求） | ≈128×，含 TCG 放大与 ARTEX 编排节拍（planner debounce/worker 轮询/3s 状态轮询），**非产品级倍率** |
| S3 单步（权重写） | 2,159 ms | 1.6 ms | 同靶场同语义请求（`/pull_weights`） |
| S3 单步（管理面探测） | 159 ms | 1.9 ms | `/pause` 类请求 |
| S3 Token 消耗 | in≈84,160 / out≈986（12 次 LLM） | **0** | ARTEX 为脚本化计划器，token 按请求体统计 |
| S4 API 延迟 | health p50 **70 ms**（guest）/ **12 ms**（宿主经 hostfwd） | N/A（全端点网格待跑） | 扫掠器已就绪，见下 |
| S5 吞吐（并发曲线） | N/A（未测） | N/A（未测） | `perf_compare.concurrency_sweep` 1/4/16 级已实现 |
| S6 负载峰值资源 | N/A（未测） | N/A（未测） | 同上 |
| S7 规模（10k 对象） | N/A（不支持同口径） | **1.645 s / 54 MB RSS**（11 侦察+可达性+规则生成，10,891 findings） | 合成快照；真 k3s 仅 204 对象点（TCG 限制） |
| S8 报告/规则生成 | N/A（导出面未测） | N/A（时延未记录） | e2e 已验证功能正确性，非性能 |
| S9 磁盘足迹 | 镜像 **2.892 GB**（+PG 420 MB） | 代码树 **8.9 MB**（+SQLite 证据库，按 run 增长） | `lab/qemu-k3s` 的 5.7 GB 为实验室虚拟机产物，不计产品足迹 |

## 端点清单（全量扫掠的输入，已从源码提取）

| 工具 | 端点数 | 只读/写 | 来源 |
|---|---:|---|---|
| ARTEX | **278** | 124 / 154 | `server/*.go`，commit 620ca5d，`reports/samples/perf/grid/routes-artex.json` |
| Trident | **25** | 9 / 16 | `webui/server.py` + MCP/API，`routes-trident.json` |

## 全网格扫掠器（已交付，可一键复跑）

```bash
# 离线：校验路由清单与产物结构
python -m lab.bench.perf_compare --routes reports/samples/perf/grid/routes-artex.json --offline --out reports/samples/perf/grid/offline-artex.json
# 在线：逐端点 N 次 → min/median/p95/p99/max/mean/stdev；再对首个只读端点做 1/4/16 并发吞吐与错误率
python -m lab.bench.perf_compare --routes reports/samples/perf/grid/routes-artex.json \
  --base http://127.0.0.1:18787 --token <ARTEX_SESSION> --n 10 --out reports/samples/perf/grid/live-artex.json
```

统计口径：`stats()` 报 n/min/median/p95/p99/max/mean/stdev；写方法路由跳过（标 `mutating-method`），不发破坏性请求；HTTP 4xx/5xx 计入延迟但单独计错误率。

## 未测项（如实登记，待补）

1. ARTEX/Trident **全端点 p50/p95/p99**：扫掠器与 278+25 路由清单已就绪；ARTEX 需有效会话令牌且 QEMU VM 在线，本轮因并行 agent 用量限额中断，未执行。
2. **并发吞吐曲线（1/4/16/32/64）与错误率**：实现已就绪，未跑。
3. **≥30 分钟稳定性与 RSS 增长拟合**：未跑。
4. **启动分解（ARTEX 的 PG init/迁移逐项；Trident 进程/DB/UI）**：仅有 ARTEX 总分项（PG ready 31s、health 37.85s）。
5. **UI 首屏/10k findings 渲染**、**10 万行证据库查询延迟**：未测。
6. KubeTrail 性能：构建未完成（Go/Wails，需在 VM 内），N/A。

> 结论边界：在已测维度上——空闲内存 ≈3.4× 更省、同靶场扫描 ≈128×（TCG 放大，非产品倍率）、token 0 vs 84k、磁盘足迹 ~2.9GB vs 8.9MB。**未测维度不作结论**。
