"""tests/test_agent_eval.py — Agent 评测集（≥12 任务，两模式可跑，结果结构完整）。"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "lab" / "agent-eval"


def _load():
    spec = importlib.util.spec_from_file_location("agent_eval_run", EVAL_DIR / "run_eval.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AgentEvalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()
        cls.tasks = cls.mod.load_tasks()
        cls.report = cls.mod.evaluate(cls.tasks, write=False)

    def test_task_set_contract(self):
        self.assertGreaterEqual(len(self.tasks), 12)
        categories = {t["category"] for t in self.tasks}
        self.assertEqual(categories, set(self.mod.CATEGORIES))
        counts = {}
        for task in self.tasks:
            counts[task["category"]] = counts.get(task["category"], 0) + 1
        for category in ("recon", "exploit", "chain", "long-context", "gateway", "gpu-tenant"):
            self.assertGreaterEqual(counts[category], 2, category)

    def test_both_modes_execute_all_tasks(self):
        modes = self.report["modes"]
        self.assertEqual(set(modes), {"deterministic", "supervisor-worker"})
        for name, block in modes.items():
            self.assertEqual(block["summary"]["tasks"], len(self.tasks))
            self.assertEqual(len(block["tasks"]), len(self.tasks))
            self.assertGreaterEqual(block["summary"]["success"], 1, name)
            self.assertGreater(block["summary"]["duration_ms"], 0, name)
            self.assertGreater(block["summary"]["tokens"], 0, name)
            for record in block["tasks"]:
                for field in ("id", "category", "ok", "findings", "titles", "duration_ms", "tokens"):
                    self.assertIn(field, record, f"{name}/{record.get('id')}")
                self.assertIsInstance(record["ok"], bool)
                self.assertGreaterEqual(record["duration_ms"], 0)
                self.assertGreater(record["tokens"], 0)

    def test_supervisor_recovers_injected_fault(self):
        det = {r["id"]: r for r in self.report["modes"]["deterministic"]["tasks"]}
        sup = {r["id"]: r for r in self.report["modes"]["supervisor-worker"]["tasks"]}
        self.assertFalse(det["gateway-auth"]["ok"])
        self.assertIn("injected", det["gateway-auth"]["reason"])
        self.assertTrue(sup["gateway-auth"]["ok"])
        self.assertGreaterEqual(self.report["modes"]["supervisor-worker"]["summary"]["retries"], 1)

    def test_approval_and_mode_config(self):
        det = self.report["modes"]["deterministic"]["summary"]
        sup = self.report["modes"]["supervisor-worker"]["summary"]
        self.assertEqual(det["approvals"], 1)
        self.assertGreater(sup["approvals"], det["approvals"])
        self.assertEqual(sup["workers"], 4)
        self.assertEqual(sup["max_attempts"], 2)
        self.assertEqual(det["max_attempts"], 1)
        self.assertEqual(self.report["config"]["fault_injection"][0]["task"], "gateway-auth")

    def test_comparison_and_chains(self):
        comparison = self.report["comparison"]
        for key in ("success_delta", "duration_delta_pct", "token_delta_pct", "approval_delta"):
            self.assertIn(key, comparison)
        self.assertGreater(comparison["success_delta"], 0)
        cheats = [r for r in self.report["modes"]["deterministic"]["tasks"] if r["category"] == "chain"]
        self.assertEqual(len(cheats), 2)
        for record in cheats:
            self.assertIsNotNone(record["chain"])
            self.assertTrue(record["chain"]["verdict"])
            self.assertGreaterEqual(record["chain"]["planned"], 2)

    def test_artifacts_written_and_consistent(self):
        json_path = Path(self.mod.JSON_OUT)
        doc_path = Path(self.mod.DOC_OUT)
        self.assertTrue(json_path.is_file())
        self.assertTrue(doc_path.is_file())
        data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "trident-agent-eval-v1")
        self.assertEqual(data["task_count"], len(self.tasks))
        self.assertEqual(set(data["modes"]), {"deterministic", "supervisor-worker"})
        doc = doc_path.read_text(encoding="utf-8")
        for token in ("deterministic", "supervisor-worker", "成功率", "审批", "token"):
            self.assertIn(token, doc)
        self.assertIn("| 任务 | 类别 | deterministic | supervisor-worker |", doc)

    def test_render_md(self):
        md = self.mod.render_md(self.report)
        self.assertIn("## 总览", md)
        self.assertIn("## 逐任务", md)
        self.assertIn("## 结论", md)


if __name__ == "__main__":
    unittest.main()
