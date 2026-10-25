"""tests/test_agent_architecture_docs.py — 架构升级文档存在性与边界声明（防止研究文档被覆盖）。"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "docs" / "AGENT-ARCHITECTURE-2026.md"
UPGRADE = ROOT / "docs" / "AGENT-ARCHITECTURE-UPGRADE-2026.md"


class ArchitectureDocsTest(unittest.TestCase):
    def test_research_doc_intact(self):
        self.assertTrue(RESEARCH.is_file())
        text = RESEARCH.read_text(encoding="utf-8")
        self.assertIn("2026 Agent 架构研究与差距反思", text)
        self.assertGreater(len(text), 20000, "研究文档不应被实施说明覆盖")

    def test_upgrade_doc_covers_seven_modules(self):
        self.assertTrue(UPGRADE.is_file())
        text = UPGRADE.read_text(encoding="utf-8")
        for module in ("journal", "supervisor", "memory", "skills", "reflexion", "a2a", "sandbox"):
            self.assertIn(module, text)
        for boundary in ("ApprovalRequired", "只读", "零执行", "禁网"):
            self.assertIn(boundary, text)

    def test_docs_are_distinct(self):
        research = RESEARCH.read_text(encoding="utf-8")
        upgrade = UPGRADE.read_text(encoding="utf-8")
        self.assertNotEqual(research[:200], upgrade[:200])


if __name__ == "__main__":
    unittest.main()
