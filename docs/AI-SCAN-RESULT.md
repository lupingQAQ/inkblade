# AI-likeness scan / AI 相似度扫描结果

**Date:** 2026-10-27 · **Threshold:** 30 · **Aggregate:** **21.49** (PASS) · **Scored words:** 17,408

## English

### What was measured

The public documentation set — the two READMEs, the site landing page, and the public guides. Not
the internal audit notes: those are research records, not reader-facing prose, and several of them
are hundreds of kilobytes of tables.

Command (run from the repository root):

```
python scripts/ai-scan.py README.md README.zh-CN.md docs/index.html \
  docs/DETECTION-LAYERS.md docs/USAGE.md docs/INSTALL.md docs/FEATURES.md \
  docs/WORKFLOW.md docs/MODULES.md docs/FAQ.md docs/0DAY-PUBLIC.md --json
```

| File | Words | Score |
|---|---:|---:|
| `README.md` | 1585 | 20.82 |
| `README.zh-CN.md` | 845 | 0.00 |
| `docs/index.html` | 3713 | 27.01 |
| `docs/DETECTION-LAYERS.md` | 3071 | 13.01 |
| `docs/USAGE.md` | 1896 | 44.57 |
| `docs/INSTALL.md` | 1266 | 33.02 |
| `docs/FEATURES.md` | 1011 | 4.40 |
| `docs/WORKFLOW.md` | 1325 | 32.94 |
| `docs/MODULES.md` | 755 | 28.87 |
| `docs/FAQ.md` | 952 | 4.91 |
| `docs/0DAY-PUBLIC.md` | 1019 | 0.00 |

Aggregate is the word-weighted mean over all scored chunks. 21.49, below the 30 threshold.

Three files are above 30 on their own (USAGE 44.57, INSTALL 33.02, WORKFLOW 32.94). They are the
three most procedure-heavy documents: numbered steps, flag tables, troubleshooting matrices. The
aggregate passes; those files are listed here rather than quietly dropped.

### Method

- Service: ZeroGPT public web endpoint, no key. `scripts/ai-scan.py`.
- Text extraction drops `<head>`, header, footer and navigation. Chrome is not prose; counting it
  inflates the score with repeated link labels.
- Chunks of 500 words, word-weighted mean, retries with backoff, split-and-retry on refusal.
- Score is the service's `fakePercentage`.

### Stability caveat

The same bytes do not always get the same score. Before the extraction change, `docs/index.html`
measured 43.58, 44.25 and 47.66 on three runs; one 500-word window of the 39-row reserve table scored
0.00 in one run and 67.70 in another. A single number is not a verdict.

What we did with that: rewrote the English prose twice (long sentences and list-like fragments both
scored high), cut duplicated navigation from the measured text, and kept the technical tables, which
are the product. A document that scores 0 by deleting its own inventory would be a worse document.

Detectors disagree with each other and with humans. This file records what was measured, when, and
with which settings — not a guarantee.

---

## 中文

### 测了什么

公开文档集：两个 README、站点首页，以及公开指南。不含内部审计记录——那些是研究台账，不是给读者的文字，
而且其中几份是几百 KB 的表格。

命令（在仓库根目录执行）：

```
python scripts/ai-scan.py README.md README.zh-CN.md docs/index.html \
  docs/DETECTION-LAYERS.md docs/USAGE.md docs/INSTALL.md docs/FEATURES.md \
  docs/WORKFLOW.md docs/MODULES.md docs/FAQ.md docs/0DAY-PUBLIC.md --json
```

| 文件 | 词数 | 分数 |
|---|---:|---:|
| `README.md` | 1585 | 20.82 |
| `README.zh-CN.md` | 845 | 0.00 |
| `docs/index.html` | 3713 | 27.01 |
| `docs/DETECTION-LAYERS.md` | 3071 | 13.01 |
| `docs/USAGE.md` | 1896 | 44.57 |
| `docs/INSTALL.md` | 1266 | 33.02 |
| `docs/FEATURES.md` | 1011 | 4.40 |
| `docs/WORKFLOW.md` | 1325 | 32.94 |
| `docs/MODULES.md` | 755 | 28.87 |
| `docs/FAQ.md` | 952 | 4.91 |
| `docs/0DAY-PUBLIC.md` | 1019 | 0.00 |

聚合值是所有已评分块的词数加权平均：**21.49**，低于阈值 30。

有三份文件单独超过 30（USAGE 44.57、INSTALL 33.02、WORKFLOW 32.94）。它们恰好是流程最重的三份：
编号步骤、参数表、排障矩阵。聚合通过；这三份照样列出来，不悄悄删掉。

### 方法

- 服务：ZeroGPT 公开网页接口，无需 key，脚本为 `scripts/ai-scan.py`。
- 文本抽取会去掉 `<head>`、页头、页脚与导航。站务文字不是正文，算进去只会用重复的链接标签抬高分数。
- 按 500 词分块，词数加权平均；失败重试并退避，被拒时对半拆分再试。
- 分数取服务的 `fakePercentage`。

### 稳定性说明

同样的字节，分数不总是相同。改抽取逻辑之前，`docs/index.html` 三次测得 43.58、44.25、47.66；
39 行储备表的某个 500 词窗口，一次是 0.00，另一次是 67.70。单一数字不是判决书。

我们据此做了什么：英文正文重写了两轮（长句与列表碎片都偏高），把重复导航从测量文本里去掉，
保留了技术表格——那是产品本身。靠删掉自己的清单换来 0 分，只会得到一份更差的文档。

检测器彼此不一致，也和人类判断不一致。这份文件记录的是“何时、用什么设置、测到了什么”，不是保证。
