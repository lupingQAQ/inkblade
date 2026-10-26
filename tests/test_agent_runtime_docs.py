# -*- coding: utf-8 -*-
"""Documentation contract for the 2026 event-sourced agent runtime."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTONOMY = ROOT / "docs" / "AGENT-AUTONOMY.md"
RESEARCH = ROOT / "docs" / "AGENT-ARCHITECTURE-2026.md"


class AgentRuntimeDocsTest(unittest.TestCase):
    def test_autonomy_doc_covers_architecture_boundaries(self):
        text = AUTONOMY.read_text(encoding="utf-8")
        for phrase in ("AgentSupervisor", "PlanGraph", "TaskScheduler", "probe_task",
                       "一次授权", "budget", "resume", "replay", "deterministic",
                       "MCP", "A2A", "Reflexion"):
            self.assertIn(phrase, text, phrase)
        self.assertNotIn("Observe→Think→Act→Reflect", text)
        self.assertNotIn("四阶段", text)

    def test_mapping_table_covers_a01_to_a16(self):
        text = RESEARCH.read_text(encoding="utf-8")
        self.assertIn("2026-10 实装映射", text)
        for i in range(1, 17):
            self.assertIn(f"A{i:02d}", text, f"A{i:02d}")
        for token in ("inkblade/agent/runtime.py", "inkblade/agent/graph.py",
                      "inkblade/agent/scheduler.py", "inkblade/agent/workers/",
                      "inkblade/agent/protocols.py", "inkblade/agent/skills.py",
                      "inkblade/agent/memory.py", "inkblade/agent/eval.py",
                      "未做", "部分"):
            self.assertIn(token, text, token)

    def test_autonomy_doc_has_no_local_absolute_paths(self):
        text = AUTONOMY.read_text(encoding="utf-8")
        self.assertNotRegex(text, re.compile(r"(?<![A-Za-z])[A-Za-z]:\\"))
        self.assertNotIn("21169", text)


if __name__ == "__main__":
    unittest.main()
