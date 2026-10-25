"""终审 Minor#11：开发台账合并（编码损坏行修复 + progress.md 合流，保留 git 历史引用）。

断言：
- `docs/DEV-LOG.md` 存在，合并两处台账（SDD 逐任务 + 根 progress.md 里程碑）；
- SDD 段无替换字符/问号乱码，编码损坏行已按计划任务序复原为可读中文；
- 保留 git commit 短哈希引用（06a51ba/f9f0a5d/8aaf631/...）；
- 含本轮终审收尾批次（A1–A5、B6–B14、C/D）条目；
- 原两文件保持原样（外部引用不破坏）。
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEV_LOG = REPO / "docs" / "DEV-LOG.md"
PROGRESS = REPO / "progress.md"
SDD = REPO / ".superpowers" / "sdd" / "2026-10-25-trident-platform" / "progress.md"


class TestDevLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DEV_LOG.read_text(encoding="utf-8")

    def test_file_and_sources_present(self):
        self.assertTrue(DEV_LOG.is_file())
        self.assertIn("progress.md", self.text)
        self.assertIn(".superpowers/sdd/2026-10-25-trident-platform/progress.md", self.text)
        self.assertIn("## A. SDD 任务台账", self.text)
        self.assertIn("## B. 里程碑与验收记录", self.text)
        self.assertIn("## C. 2026-10-25 终审收尾批次", self.text)

    def test_git_history_refs_kept(self):
        for sha in ("06a51ba", "f9f0a5d", "8aaf631", "b171a6f", "61a6ce0",
                    "35d40de", "fb475ef", "0227920", "ba0b4e3", "a4633a1",
                    "f5db4ac", "f315160", "006ec60", "a0999d7", "188e0f1",
                    "7f02967", "1ced3fd", "e0148a6"):
            self.assertIn(sha, self.text, f"缺 git 提交引用 {sha}")

    def test_no_mojibake_in_sdd_section(self):
        sdd_part = self.text.split("## A. SDD 任务台账", 1)[1].split("## B.", 1)[0]
        self.assertNotIn("\ufffd", sdd_part, "SDD 段仍含替换字符")
        # 连续 3+ 个问号 = 编码损坏特征（正常文本不应出现）
        self.assertIsNone(re.search(r"\?{3,}", sdd_part), "SDD 段仍含 ??? 乱码")
        # 复原后的任务名必须可读
        for phrase in ("项目脚手架与骨架测试", "YAML 生成器", "证据三层存储",
                       "授权治理", "用户与工作区", "编排引擎", "零日武器库",
                       "Web API 服务器", "CLI 入口", "组合签名矩阵", "实验室 mock 靶场"):
            self.assertIn(phrase, sdd_part, f"缺复原任务名 {phrase}")

    def test_sdd_tasks_all_complete(self):
        sdd_part = self.text.split("## A. SDD 任务台账", 1)[1].split("## B.", 1)[0]
        tasks = [ln for ln in sdd_part.splitlines() if ln.startswith("- 任务「")]
        self.assertGreaterEqual(len(tasks), 18, f"SDD 任务条目过少: {len(tasks)}")
        for ln in tasks:
            self.assertIn("complete", ln, ln)

    def test_progress_entries_merged(self):
        progress = PROGRESS.read_text(encoding="utf-8")
        # 抽查三条里程碑标题（progress.md 原文）
        for phrase in ("万卡语料推倒重收", "SPA 六视图", "端到端验收",
                       "ARTEX 同靶场扫描对比", "agent 架构研究"):
            self.assertIn(phrase, progress, f"progress.md 原文缺 {phrase}（前置条件）")
            self.assertIn(phrase, self.text, f"DEV-LOG 未合流 {phrase}")

    def test_closure_batch_items_listed(self):
        for key in ("A1", "A2", "A3", "A4", "A5", "B6", "B7", "B8", "B9",
                    "B10", "B11", "B12", "B13", "B14"):
            self.assertIn(f"| {key} |", self.text, f"缺收尾项 {key}")
        self.assertIn("consent HMAC", self.text)
        self.assertIn("退出码 91", self.text)
        self.assertIn("openapi.json", self.text)

    def test_originals_unchanged(self):
        self.assertTrue(PROGRESS.is_file())
        self.assertTrue(SDD.is_file())
        # 原始 SDD 仍保留原编码（不强行改写，避免破坏外部引用）
        raw = SDD.read_bytes()
        self.assertTrue(raw.startswith(b"# SDD ledger"))


if __name__ == "__main__":
    unittest.main()
