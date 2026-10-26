# -*- coding: utf-8 -*-
"""ARTEX parity/clean-room 文档与逐行处置的可验证性。"""

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PARITY_JSON = REPO / "docs" / "artex-parity-rows.json"
FEATURE_DOC = REPO / "docs" / "FEATURE-BY-FEATURE-ARTEX.md"
PARITY_MD = REPO / "docs" / "ARTEX-PARITY.md"
MATRIX = REPO / "docs" / "COMPETITIVE-MATRIX.md"

FEATURES = {
    "llmpool": ("inkblade/core/llmpool.py", "tests/test_llmpool.py"),
    "notify": ("inkblade/core/notify.py", "tests/test_notify.py"),
    "templates": ("inkblade/core/templates.py", "tests/test_templates.py"),
    "calendar": ("inkblade/core/calendar.py", "tests/test_calendar.py"),
    "threads": ("inkblade/core/threads.py", "tests/test_threads.py"),
    "graphsnap": ("inkblade/core/graphsnap.py", "tests/test_graphsnap.py"),
    "blackboard": ("inkblade/core/blackboard.py", "tests/test_blackboard.py"),
    "concurrency": ("inkblade/core/explorer.py", "tests/test_concurrency.py"),
}

BACKLOG = {
    "CM-01": "inkblade/core/intel.py", "CM-02": "inkblade/core/search.py",
    "CM-03": "inkblade/core/decisions.py", "CM-04": "inkblade/core/calendar.py",
    "CM-05": "inkblade/core/tokenaudit.py", "CM-06": "inkblade/core/intel.py",
    "CM-07": "inkblade/core/kb.py", "CM-08": "inkblade/modules/kubelet-surface/run.py",
    "CM-09": "inkblade/core/rulemacro.py", "CM-10": "inkblade/core/dispatch.py",
    "CM-11": "inkblade/core/cigate.py", "CM-12": "inkblade/core/evalconfig.py",
    "CM-13": "inkblade/core/importers.py", "CM-14": "inkblade/core/retest.py",
    "CM-15": "inkblade/core/connectors.py", "CM-16": "inkblade/core/lineage.py",
    "CM-17": "inkblade/core/dedupe.py", "CM-18": "inkblade/core/pcap.py",
    "CM-19": "inkblade/core/sankey.py", "CM-20": "inkblade/core/narrative.py",
    "CM-21": "inkblade/core/credcheck.py", "CM-22": "inkblade/core/inpod.py",
    "CM-23": "inkblade/core/pathcalc.py", "CM-24": "inkblade/core/admission.py",
    "CM-25": "inkblade/core/policygen.py", "CM-26": "inkblade/core/policygen.py",
    "CM-27": "inkblade/core/policygen.py", "CM-28": "inkblade/core/policygen.py",
    "CM-29": "inkblade/core/llmredteam.py", "CM-30": "inkblade/core/agentbench.py",
}


class TestParityRows(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(PARITY_JSON.read_text(encoding="utf-8"))

    def test_missing_rows_are_all_dispositioned(self):
        source_rows = [l for l in FEATURE_DOC.read_text(encoding="utf-8").splitlines()
                       if "| missing |" in l]
        self.assertEqual(self.doc["total_missing"], len(source_rows))
        self.assertEqual(len(self.doc["rows"]), len(source_rows))
        self.assertEqual(self.doc["missing_unclassified"], 0)
        statuses = {r["status"] for r in self.doc["rows"]}
        self.assertNotIn("missing", statuses)
        self.assertTrue(statuses <= {"done", "technical-infeasible", "not-applicable"})
        counts = {}
        for r in self.doc["rows"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        self.assertEqual(counts, self.doc["status_counts"])
        self.assertEqual(sum(counts.values()), 180)

    def test_done_rows_have_existing_evidence(self):
        for r in self.doc["rows"]:
            self.assertTrue(r["id"].startswith("ARTEX-MISS-"))
            if r["status"] != "done":
                self.assertTrue(r.get("reason"), r)
                continue
            self.assertTrue(r.get("evidence"), r)
            for chunk in r["evidence"].split(";"):
                for part in chunk.split(" + "):
                    path = part.strip()
                    if not path:
                        continue
                    self.assertTrue((REPO / path).exists(), f"{r['id']} 证据不存在：{path}")

    def test_technical_infeasible_has_reason(self):
        infeasible = [r for r in self.doc["rows"] if r["status"] == "technical-infeasible"]
        self.assertEqual(len(infeasible), 6)
        for r in infeasible:
            self.assertIn("update", r["item"].lower())
            self.assertIn("技术不可行", r["reason"])


class TestParityDoc(unittest.TestCase):
    def test_artex_parity_doc(self):
        text = PARITY_MD.read_text(encoding="utf-8")
        for needle in ("clean-room", "未读取", "missing 0", "8 / 8", "30 / 30",
                       "CM-30", "technical-infeasible"):
            self.assertIn(needle, text)
        for name in FEATURES:
            self.assertIn(name, text)

    def test_feature_and_backlog_files_exist(self):
        for name, (impl, test) in FEATURES.items():
            self.assertTrue((REPO / impl).is_file(), name)
            self.assertTrue((REPO / test).is_file(), name)
            self.assertIn("class Test", (REPO / test).read_text(encoding="utf-8"))
        for cm, impl in BACKLOG.items():
            self.assertTrue((REPO / impl).exists(), f"{cm}: {impl}")
        for cm in ("CM-31", "CM-32", "CM-33"):
            self.assertNotIn(cm, BACKLOG)

    def test_matrix_backlog_closed(self):
        text = MATRIX.read_text(encoding="utf-8")
        section = text[text.index("## 5."):text.index("## 6.")]
        self.assertIn("状态 / 证据", section)
        self.assertIn("S 13 + M 17 已全部实施并清零", section)
        for i in range(1, 31):
            row = next((l for l in section.splitlines() if l.startswith(f"| CM-{i:02d} ")), "")
            self.assertTrue(row, f"CM-{i:02d} missing")
            self.assertIn("done", row, f"CM-{i:02d} not done")
        for i in (31, 32, 33):
            row = next((l for l in section.splitlines() if l.startswith(f"| CM-{i} ")), "")
            self.assertIn("open — L", row)

    def test_clean_room_declarations(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        notice = (REPO / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Clean-room 声明", readme)
        self.assertIn("未读取、未复制", readme)
        self.assertIn("clean-room functional parity", notice)
        self.assertIn("No ARTEX source file was read", notice)
        self.assertIn("AGPL-3.0", notice)


if __name__ == "__main__":
    unittest.main()
