"""tests/test_reflexion.py — 运行后自反思（失败/降级步骤 → 改进建议 → 审批入技能库），零执行。

断言：
- 失败动作/备份闸门拒绝/零发现被归纳为 failure/degraded；
- 建议包含 action + rationale + refs；
- 反思过程不执行任何模块（runner.run_module 被 monkeypatch 成炸弹也不触发）；
- 建议可转为 pending 技能（审批入库仍需 lead）。
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from inkblade.core import reflexion
from inkblade.core.evidence import EvidenceStore
from inkblade.core.skills import SkillLibrary
from inkblade.core.users import Session


class ReflectionTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        self.run = self.store.create_run("run-reflect")
        self.run.add_step("exposure-mapping", "snapshot", {"actor": "tester"}, "暴露面 2 条")
        self.run.add_finding("exposure-mapping", "high", "Ray 暴露", "LoadBalancer")
        self.run.log_action("tester", "execute", "priv-esc", {"mode": "x"}, "failed:BackupGateRefused")
        self.run.log_action("tester", "execute", "runtime-socket-escape", {}, "refused-no-backup")
        self.lead = Session(None, "lead", "lead", ["local-lab"], "t")
        self.tester = Session(None, "tester", "tester", ["local-lab"], "t2")

    def tearDown(self):
        self.td.cleanup()

    def test_reflect_failures_and_suggestions(self):
        rep = reflexion.reflect(self.run)
        self.assertFalse(rep["executed"])
        self.assertEqual(rep["run"], "run-reflect")
        failed = {f["step"]: f for f in rep["failures"]}
        self.assertIn("priv-esc", failed)
        self.assertIn("runtime-socket-escape", failed)
        self.assertTrue(any(f["kind"] == "backup-gate" for f in rep["failures"]))
        self.assertTrue(rep["suggestions"])
        for s in rep["suggestions"]:
            self.assertTrue(s["action"] and s["rationale"])
            self.assertIsInstance(s["refs"], list)
        self.assertEqual(rep["metrics"]["failures"], 2)
        self.assertEqual(rep["metrics"]["steps"], 1)

    def test_zero_execution_guarantee(self):
        with mock.patch("inkblade.core.runner.run_module", side_effect=AssertionError("must not run")) as spy:
            rep = reflexion.reflect(self.run)
            reflexion.render_md(rep)
        spy.assert_not_called()
        self.assertFalse(rep["executed"])

    def test_propose_skill_requires_approval(self):
        rep = reflexion.reflect(self.run)
        lib = SkillLibrary(self.store)
        pending = reflexion.propose_skill(rep, lib, self.tester, name="reflect-playbook")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["source"], "reflexion")
        approved = lib.approve(self.lead, pending["id"])
        self.assertEqual(approved["status"], "approved")
        self.assertTrue(approved["playbook"])

    def test_healthy_run_has_no_failures(self):
        clean = self.store.create_run("run-clean")
        clean.add_step("exposure-mapping", "snapshot", {}, "0 条")
        clean.add_finding("exposure-mapping", "info", "无暴露", "-")
        rep = reflexion.reflect(clean)
        self.assertEqual(rep["failures"], [])
        self.assertTrue(rep["healthy"])


if __name__ == "__main__":
    unittest.main()
