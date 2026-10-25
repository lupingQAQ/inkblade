# mining-fixture — 挖掘流水线上游源码快照（最新 release tag，2026-10-25 抓取）

用途：`trident/mining.py`（漏洞挖掘流水线闭环）对「最新版本差异复核」环的输入。
每目录 = 一个上游仓库在最新 release tag 的代表性源文件（raw.githubusercontent.com 快照），
供 `codescan` 双通道（regex；.py 走 ast）提取 sink 命中并与 `core/data/mining-baseline.json` 差异。

| 目标 | 仓库 | tag | 文件 | 抓取方式 |
|---|---|---|---|---|
| vllm | vllm-project/vllm | v0.32.0 | api_server.py（弃用 shim）、routers.py、api_server_entry.py、serve_init.py、models_api_router.py | Invoke-WebRequest raw |
| sglang | sgl-project/sglang | v0.5.22 | http_server.py（管理路由面） | 同上 |
| kuberay | kuberay-project/kuberay | v1.7.1 | raycluster_controller.go（控制器） | 同上 |
| hami | Project-HAMi/HAMi | v2.10.0 | main.go（scheduler 入口：/filter /bind /webhook 路由 + pprof 旗标） | 同上 |
| litellm | BerriAI/litellm | v1.106.4 | proxy_server.py（proxy 管理面） | 同上 |

许可：上游均为 Apache-2.0（源文件头 SPDX 保留），快照仅作只读分析输入，零代码复用。
边界：命中 = sink 规则命中，非可利用性结论；候选一律 `pending-manual-review`（不自动入库）。
