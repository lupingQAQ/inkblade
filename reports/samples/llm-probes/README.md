# LLM 探针矩阵样张（two-state differential）

本目录是 `trident/probes/` 探针库的实测产物，不是静态说明：

| 文件 | 内容 |
|---|---|
| `llm-probe-matrix.json` | 87 个探针对 vulnerable/fixed 两态靶场的逐探针判定（状态码证据、expect、verdict） |
| `llm-probe-matrix.md` | 报告可直接引用的「LLM 探针矩阵」节（13 类 × OWASP LLM 2026 × ASI） |
| `rules/sigma/sigma-llm-probe-*.yaml` | 13 类各 1 条 SOC 检测规则（由 `trident/rules` 规则引擎生成，scope=llm-probe） |

复现（仅标准库，自动拉起/关闭 lab 仿真器）：

```bash
python trident/probes/run.py
```

结果口径：`probes=87 categories=13 confirmed=87 (attack=74 control=13)`，
即 74 个攻击探针在 vulnerable 命中且 fixed 不命中，13 个对照探针两态均不命中（防误报）。

判定只消费真实 HTTP 响应（状态码 / JSON 字段 / 文本），不读取仿真器内部答案；
每个探针声明 `expect.vulnerable` / `expect.fixed`，运行器按差分结果给出
`confirmed` / `not-vulnerable` / `not-differential` / `unexpected`。

报告集成：`trident/reports/render.py` 的渗透测试报告在 run 目录存在
`llm-probe-matrix.json` 时渲染「LLM 探针矩阵」节，缺产物时显式占位（不臆造命中）。

对标与缺口：`docs/PROBE-PARITY.md`（garak / PyRIT / promptfoo 官方计数与核验日期、
本库独有的长上下文 / KV / 缓存 / 网关面、明确未覆盖项）。
