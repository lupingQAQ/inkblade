# UI 渲染性能：10,000 条 findings 实测与优化

> 日期：2026-10-26
> 环境：Windows 11 · Chrome/Edge headless（Chromium `--headless=new`）· 本机 CPU ·
> 同一份静态导出 · 合成 10,000 条 findings
> 复现：`python scripts/ui-perf-bench.py --findings 10000` +
> `python scripts/ui-perf-run.py --runs 3`
> 原始数据：`reports/samples/ui-perf/10k-render.json`

## 1. 结论（先看数字）

| 指标（中位数，3 次） | 优化前：全量渲染 | 优化后：分页渲染 | 变化 |
|---|---:|---:|---:|
| 报告视图同步渲染耗时 | **114.2 ms** | **6.7 ms** | **↓ 94.1%（约 17× 更快）** |
| `tbody` 实际渲染行数 | 10,000 | 200 | ↓ 98% |
| 报告子树 DOM 元素 | 90,040 | 1,840 | ↓ 98.0%（约 49× 更少） |
| `body` DOM 元素总数 | 90,195 | 1,994 | ↓ 97.8% |
| JS 堆 `usedJSHeapSize`（渲染后） | 7,917,547 B（7.6 MiB） | 5,862,094 B（5.6 MiB） | ↓ 26.0% |
| 页面 load 耗时（含解析 2.5 MB 内嵌数据） | 268.7 ms | 319.7 ms | 无稳定差异（运行噪声） |
| 静态 `index.html` 大小 | 2,500,434 B（约 2.4 MiB） | 同左（数据未裁剪） | — |

> 口径说明：渲染耗时是点击「报告预览」后 `performance.now()` 的前后差（同步
> DOM 构建）；不含浏览器绘制/合成。DOM 数是 `document.querySelectorAll` 实测；
> 堆是该时刻的 `performance.memory.usedJSHeapSize`，不是精确 retained size。

## 2. 优化前（legacy 全量渲染）

原实现 `renderReportData` 对 `findings()` 直接 `forEach`，每条 finding 建 5 个
`<td>`、一个 badge、可能一个 detail `<div>`，一次性挂到 `tbody`：

- 10,000 行 → 90,040 个报告子树元素、90,195 个 body 元素；
- 单次同步渲染 110–116 ms（3 次：110.6 / 115.9 / 114.2 ms），主线程明显卡顿；
- 页面本身仍要解析 2.5 MB 内嵌 JSON，load 约 269–313 ms；
- 用户向下滚动时浏览器还要布局 9 万个节点。

这不是「数据获取慢」，而是**一次性 DOM 构建 + 布局**的成本；在低端笔记本/
集显上会放大。原实现没有任何分页/虚拟化/上限。

## 3. 优化后（产品路径）

变更（`trident/webui/static/app.js`）：

1. **分页渲染**：`REPORT_PAGE_SIZE = 200`，默认只构建前 200 行；`显示更多
   (+200)` 递增，不改变数据本身；
2. **DocumentFragment 批量插入**：200 行先在 fragment 中构建，再一次挂载，
   减少 layout thrash；
3. **统计与表格分离**：严重度计数仍单次遍历全量（O(n) 数值计算，不建 DOM），
   保证总数/分 severity 数字准确；
4. **可见进度**：`已渲染 200 / 10000 条（分页渲染，避免一次性构建 10000 个
   DOM 行）`，用户知道还有多少；
5. **legacy 基准开关**：`?perf=legacy`（或 `window.__TRIDENT_FORCE_LEGACY`）
   保留旧的全量路径，仅用于前后对比和回归，不进入普通用户默认路径；
6. **渲染元数据**：`window.__TRIDENT_REPORT_META = {total, renderedRows,
   pageSize, legacy, renderMs}`，自动化基准/测试可读，不含发现内容。

优化后：

- 200 行 → 1,840 个报告子树元素、1,994 个 body 元素；
- 同步渲染 5.3–7.7 ms（中位 6.7 ms）；
- 堆 5.6 MiB（比全量少 26%）；
- 首屏 load 约 270–320 ms，两种模式无稳定差异，主要成本是 2.5 MB 内嵌数据
  解析，而不是 DOM。

「显示更多」每次仍只增加 200 行；连续点击到 10,000 行时总成本接近旧路径，
但这是用户显式选择，且中途可交互，不会在打开报告时一次性冻结。

## 4. 复现步骤

```powershell
# 1) 生成 10,000 条合成 findings 的静态导出（写入 lab/bench/out，已 gitignore）
python scripts/ui-perf-bench.py --findings 10000

# 2) Chromium headless 实测两种模式，各 3 次，输出 JSON
python scripts/ui-perf-run.py --runs 3

# 3) 手动看页面
#    分页：lab/bench/out/ui-10k/export/index.html
#    全量：同一文件加 ?perf=legacy
```

脚本会把 `index.html` 复制到 `lab/bench/out/ui-bench/{paged,legacy}`，只在副本
注入测量脚本；legacy 副本在 `app.js` 之前设置 `window.__TRIDENT_FORCE_LEGACY`。
每次运行使用独立 `--user-data-dir`，避免缓存/扩展干扰。

## 5. 局限（不要过度解读）

1. **合成数据**：10,000 条 finding 的标题/详情长度同构；真实数据的 detail 长度、
   零日比例、HTML 转义成本会不同。
2. **本机单机**：Windows 11 + 本机 Chromium headless；不是低端终端、移动端或
   真实用户样本；数字用于**相对比较**，不是 SLA。
3. **测量点**：`performance.now()` 只覆盖同步 JS/DOM 构建，不含后续 paint/
   composite；DOM 节点数与堆是同一时刻快照，不是长期泄漏分析。
4. **load 时间**：2.5 MB 内嵌 JSON 是静态导出的设计取舍（免服务、离线单文件）；
   进一步优化可改为分片/懒加载 JSON，但会牺牲「单文件可拷走」。
5. **未做虚拟滚动**：200 行/页已把默认路径压到 5 ms；如未来需要「无限滚动 +
   搜索 10 万条」，应上虚拟列表（只保留视口行）而不是继续加大页大小。
6. **未测服务模式 API 分页**：本次只测静态导出；服务模式当前仍一次性返回
   findings，后端分页/游标是下一步（见 `docs/UX-EVALUATION.md` 的仍存风险）。

## 6. 回归断言

`tests/test_ux_productization.py::TestUIProductization` 断言：

- `REPORT_PAGE_SIZE` / `reportVisible` / `perf=legacy` / 显示更多 /
  `__TRIDENT_REPORT_META` 存在；
- 表格只遍历 `visibleFindings`（slice），不再直接 `fs.forEach` 建 10k 行；
- 静态导出/离线资产测试仍全绿（`tests/test_spa.py`）。
