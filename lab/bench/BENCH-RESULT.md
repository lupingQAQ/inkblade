# Trident bench 对比 — 冒烟初值与 ARTEX 对比方法

- 任务依据：Trident 设计 设计基线第 11 节（对标 ARTEX）/ 第 13 节（实验室 bench）
- 首次记录：2026-10-24（Windows 宿主实跑）；ARTEX 侧数据待 WSL 实验室补测（见下）

## Windows 冒烟初值（smoke）

运行命令（仓库根）：

```bash
python lab/bench/bench.py smoke --iterations 5
```

环境：Windows 11（10.0.26300）/ Python 3.12.15（reproenv-d，仅标准库）/ mock 靶场
`lab/mock_targets.py`（vulnerable 姿态，进程内 127.0.0.1）。

| 指标 | 链路径（当前实跑） | 兜底路径（强制空模块目录） |
|---|---|---|
| mode | chain（prefill-decode-kv-inference-manipulation） | fallback-urllib |
| elapsed_ms（总 / 每轮，5 轮） | 320.465 / 64.093 | 45.302 / 9.06 |
| max_rss_kb | 50176（≈49 MB，ctypes-GetProcessMemoryInfo） | 35424 |
| requests | 5（= 5 轮 × 1 链步骤，来源 chain-steps） | 25（= 5 轮 × 5 只读路由，全部 200） |

说明：链路径含链引擎全开销（证据库 SQLite + 审计 + 三层落证 + 模块 fixture 快照解析），
64 ms/轮 vs 兜底直探 9 ms/轮属预期；空闲 RSS ≈ 49 MB 满足 设计基线 11.1「< 150 MB」目标
（单 Python 进程，无 Node/PG 运行时）。

兜底五路由逐项计时（强制兜底 5 轮实测，状态全部 200 与预期一致）：

| 路由 | 方法 | 面向 | avg_ms | min_ms | max_ms |
|---|---|---|---|---|---|
| `/__routes__` | GET | 侦察发现 | 3.469 | 0.654 | 14.332 |
| `/api/jobs/` | GET | Ray 观测面 | 0.654 | 0.577 | 0.790 |
| `/plugins/list` | GET | vLLM 插件面 | 0.604 | 0.548 | 0.658 |
| `/v1/models` | GET | djev 开放代理面 | 0.612 | 0.556 | 0.738 |
| `/pause` | POST | SGLang 管理面 fail-open | 0.739 | 0.570 | 1.025 |

产物：`lab/bench/out/bench-smoke.json` + `bench-smoke.md`（每次运行覆盖，值随机器波动，
以 JSON 为准）；强制兜底样本 `out/fallback-smoke.json`。

## Ruling（链路径与兜底的切换记录）

bench 优先走链路径（`trident/core/chains.load_chains` 选只读链 + `chains.execute` 计时），
步骤执行失败（如模块要求 fixture 参数）即视为「对 HTTP 靶场未就绪」自动降级 urllib
五路由兜底，并在结果 JSON/MD 记录 Ruling 原文。两条 Ruling 均已实测发生：

1. 降级（首跑，当时链定义未带 snapshot）：

   > 选中只读链 prefill-decode-kv-inference-manipulation（1 个模块全就绪，链路径计时）；
   > 链执行失败（RuntimeError: … 步骤失败: {'kv-channel-probe': 'ValueError: 缺少
   > params.snapshot（fixture dict 或 lab/fixtures/network/ 路径）'}）→ urllib 五路由兜底

2. 链路径（并行任务为该链步骤补上 `snapshot: lab/fixtures/network` 后，bench 无需改码
   自动切回）：

   > 选中只读链 prefill-decode-kv-inference-manipulation（1 个模块全就绪，链路径计时）

兜底路径可确定性复现（空模块目录强制降级，见上表），不依赖仓库当时的模块就绪状态。

## ARTEX 同靶场对比方法

原则（设计基线 11.2）：同一 mock 靶场跑双方、只测不改造（ARTEX 为 AGPL，零代码复用）、
数据进交付附录「选型对比」，避免主观断言。

1. **共同靶场**：`python lab/mock_targets.py --port 18080 --mode vulnerable`
   （Trident 与 ARTEX 容器均访问同一 `MOCK_URL`，同一五路由集）。
2. **Trident 侧**：`python lab/bench/bench.py smoke --iterations 5`
   （上表即初值；全链 sweep 目标 < 3 分钟、0 token，见 设计基线 11.1）。
3. **ARTEX 侧**：`bash lab/bench/artex-bench.sh`（本目录，交付脚本 + 说明，本任务未执行）：
   - 用 ARTEX 自带 `docker-compose.bench.yml` 起栈（Go server + PostgreSQL + Next.js）；
   - 计冷启动（compose down→up 到全部容器 running，ms）；
   - `docker stats --no-stream` 轮询常驻内存（原文存 `out/artex-mem-samples.txt`）；
   - 端到端任务计时：经其 Web UI/API 提交指向 `MOCK_URL` 的同靶场探索任务（LLM 驱动，
     黑盒计时；未配置 API 时标记 `task_phase=manual` 人工回填）。
4. **对比表列**：冷启动 / 常驻内存 / 同靶场全链时长 / token 成本（ARTEX 全程 LLM 往返
   vs Trident 0 token）/ 进程与依赖数（多容器 vs 单 Python 进程）。
5. **公平性**：同机同硬件、同靶场同轮数、ARTEX 原样运行不改造；各自记录环境与时间戳。

## 实验室边界（显式声明）

- 本机（Windows 宿主）WSL2 不可用（`HCS_E_HYPERV_NOT_INSTALLED`），以下在 WSL 实验室
  执行后回填本文件与交付附录：
  - `lab/kind/run-proof.sh` — KIND 实证 hostNetwork Pod 绕过 NetworkPolicy
    （建群 disableDefaultCNI + Calico → default-deny → 普通 Pod 被拒 / hostNetwork Pod
    连通对照 → 写 `lab/kind/PROOF-hostnetwork-bypass.md`；注意 kindnet 不执行
    NetworkPolicy，必须装策略 CNI，否则实证无效）；
  - `lab/bench/artex-bench.sh` — ARTEX 同靶场计时（见上）。
- Windows 侧冒烟已实跑（本文初值）；Trident 目标空闲 RSS < 150 MB，当前 49 MB 满足
  （单进程、无 Node/PG 运行时）。
