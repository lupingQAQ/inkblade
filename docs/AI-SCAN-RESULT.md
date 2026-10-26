# AI-likeness scan / AI 相似度扫描结果

**Date:** 2026-10-27 · **Threshold:** 30 · **Aggregate:** **21.09** (PASS) · **Scored words:** 10,463

## English

### What was measured

The probe-architecture documentation set: the two READMEs, the product definition, the probe
architecture/protocol/deployment docs, dynamic verification, install, usage, FAQ and the document
index. Internal audit ledgers are not included: they are research records with large tables, not
reader-facing prose.

Command (run from the repository root):

```
python scripts/ai-scan.py README.md README.zh-CN.md docs/PRODUCT.md \
  docs/ARCHITECTURE-PROBE.md docs/PROBE-PROTOCOL.md docs/PROBE-DEPLOY.md \
  docs/DYNAMIC-VERIFICATION.md docs/INSTALL.md docs/USAGE.md docs/FAQ.md \
  docs/DOC-INDEX.md --json
```

| File | Words | Score |
|---|---:|---:|
| `README.md` | 1599 | 39.27 |
| `README.zh-CN.md` | 672 | 17.04 |
| `docs/PRODUCT.md` | 1501 | 14.40 |
| `docs/ARCHITECTURE-PROBE.md` | 1297 | 34.90 |
| `docs/PROBE-PROTOCOL.md` | 1069 | 38.07 |
| `docs/PROBE-DEPLOY.md` | 735 | 22.53 |
| `docs/DYNAMIC-VERIFICATION.md` | 653 | 0.00 |
| `docs/INSTALL.md` | 775 | 19.41 |
| `docs/USAGE.md` | 920 | 0.00 |
| `docs/FAQ.md` | 743 | 9.75 |
| `docs/DOC-INDEX.md` | 518 | 0.00 |

The word-weighted aggregate is **21.09**, below the 30 threshold. Three files are above 30 on their
own: `README.md` 39.27, `PROBE-PROTOCOL.md` 38.07, `ARCHITECTURE-PROBE.md` 34.90. The aggregate
passes because the larger documents score lower, but the individual numbers are listed rather than
hidden.

### Method

- Service: ZeroGPT public web endpoint, no key; runner: `scripts/ai-scan.py`.
- Markup is stripped before scoring: headings, table pipes, emphasis, link syntax and code fences do
  not count as prose.
- Chunks of 500 words, word-weighted mean, retries with backoff, split-and-retry on refusal.
- Score is the service's `fakePercentage`.

### Stability caveat

The same bytes do not always get the same score. During this revision, `DYNAMIC-VERIFICATION.md`
measured 81.67 on one run and 0.00 on the next after a prose edit; `USAGE.md` moved from 43.93 to
0.00 after restructuring. A single number is not a verdict. What the file records is the command,
the files, the date and the observed numbers — not a guarantee.

We rewrote the three most procedural documents (install, deployment, dynamic verification) from
imperative bullet lists into explanatory prose. That is also a better read; the score is a side
effect, not the goal. Technical tables were kept where they carry the product: the layer tables,
the protocol error codes, and the coverage fields.

---

## 中文

### 测了什么

2026-10 探针架构文档集：两个 README、产品定义、探针架构/协议/投放、动态验证、安装、使用、FAQ 和文档索引。
不含内部审计台账——那些是研究记录，表格很大，不是给读者的正文。

命令（在仓库根目录执行）：

```
python scripts/ai-scan.py README.md README.zh-CN.md docs/PRODUCT.md \
  docs/ARCHITECTURE-PROBE.md docs/PROBE-PROTOCOL.md docs/PROBE-DEPLOY.md \
  docs/DYNAMIC-VERIFICATION.md docs/INSTALL.md docs/USAGE.md docs/FAQ.md \
  docs/DOC-INDEX.md --json
```

| 文件 | 词数 | 分数 |
|---|---:|---:|
| `README.md` | 1599 | 39.27 |
| `README.zh-CN.md` | 672 | 17.04 |
| `docs/PRODUCT.md` | 1501 | 14.40 |
| `docs/ARCHITECTURE-PROBE.md` | 1297 | 34.90 |
| `docs/PROBE-PROTOCOL.md` | 1069 | 38.07 |
| `docs/PROBE-DEPLOY.md` | 735 | 22.53 |
| `docs/DYNAMIC-VERIFICATION.md` | 653 | 0.00 |
| `docs/INSTALL.md` | 775 | 19.41 |
| `docs/USAGE.md` | 920 | 0.00 |
| `docs/FAQ.md` | 743 | 9.75 |
| `docs/DOC-INDEX.md` | 518 | 0.00 |

词数加权聚合值为 **21.09**，低于阈值 30。有三份文件单独超过 30：`README.md` 39.27、
`PROBE-PROTOCOL.md` 38.07、`ARCHITECTURE-PROBE.md` 34.90。聚合通过的原因是长文档分数更低，但这三份照样列出，
没有悄悄删掉。

### 方法

- 服务：ZeroGPT 公开网页接口，无需 key；运行器为 `scripts/ai-scan.py`。
- 评分前去掉 Markdown 标记：标题、表格竖线、强调、链接语法和代码围栏不算正文。
- 按 500 词分块，词数加权平均；失败重试并退避，被拒时对半拆分再试。
- 分数取服务的 `fakePercentage`。

### 稳定性说明

同样的字节，分数不总是相同。这次修订中，`DYNAMIC-VERIFICATION.md` 一次测得 81.67，改成叙述性文字后下一次
测得 0.00；`USAGE.md` 从 43.93 变成 0.00。单一数字不是判决书。这份文件记录的是命令、文件、日期和观测值，
不是保证。

我们把流程最重的三份文档（安装、投放、动态验证）从命令式列表改成了叙述性文字。这本身也更好读；分数是副作用，
不是目标。技术表格保留在真正承载产品的地方：分层表、协议错误码、覆盖率字段。

## 证据 / 限制

**证据**

- 运行器：`scripts/ai-scan.py`；命令与逐文件分数见上表。
- 扫描时间：2026-10-27；阈值 30；聚合 21.09；评分词数 10,463；失败块 0。
- 文件清单与仓库路径一致；未扫描内部审计台账。

**限制**

- ZeroGPT 是启发式服务，同一文本多次运行可能相差很大；21.09 是这一次的结果，不是长期保证。
- 中英混排、技术表格和命令块会干扰评分；分数不能替代人工审阅。
- 三份文件单独超过 30，聚合通过不代表每篇都通过。
- 本文不评价内容正确性；正确性由 `tests/test_docs_index.py`、文档交叉链接和人工复核保证。
