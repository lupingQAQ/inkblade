"""tests/test_agentops.py — Agent 运行门面（审批 → supervisor → journal → reflexion → 技能提案）。"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.agentops import run_approved_plan
from inkblade.core.evidence import EvidenceStore
from inkblade.core.skills import SkillLibrary
from inkblade.core.supervisor import ApprovalRequired
from inkblade.core.users import Session


class AgentOpsTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        self.lead = Session(None, "lead", "lead", ["local-lab"], "t")

    def tearDown(self):
        self.td.cleanup()

    def _executor(self, task):
        run = self.store.create_run(f"ops-{task['module']}")
        run.add_step(task["module"], str(task["params"]), {"actor": "lead"}, "ok")
        run.add_finding(task["module"], "high", "模拟发现", "evidence")
        return {"ok": True, "run": run.name}

    def test_unapproved_plan_rejected(self):
        with self.assertRaises(ApprovalRequired):
            run_approved_plan(self.store, self.lead, [{"module": "recon", "params": {}}],
                              executor=self._executor)

    def test_end_to_end_with_reflection_and_proposal(self):
        actions = [{"module": "exposure-mapping", "params": {},
                    "approval": {"status": "approved", "approved_by": "lead"}},
                   {"module": "escape-primitives", "params": {},
                    "approval": {"status": "approved", "approved_by": "lead"}}]
        out = run_approved_plan(self.store, self.lead, actions, workers=2,
                                executor=self._executor, propose_skills=True)
        self.assertEqual(out["mode"], "supervisor-worker")
        self.assertEqual(out["summary"]["success"], 2)
        self.assertEqual(out["summary"]["approvals"], 2)
        self.assertTrue(out["journal"]["ok"])
        self.assertEqual(len(out["reflections"]), 2)
        self.assertTrue(all(r["executed"] is False for r in out["reflections"]))
        self.assertEqual(len(out["proposals"]), 2)
        library = SkillLibrary(self.store)
        for proposal in out["proposals"]:
            self.assertEqual(proposal["status"], "pending")
            approved = library.approve(self.lead, proposal["id"])
            self.assertEqual(approved["status"], "approved")

    def test_submission_count(self):
        out = run_approved_plan(
            self.store, self.lead,
            [{"module": "a", "params": {}, "approval": {"status": "approved", "approved_by": "lead"}}],
            executor=self._executor)
        self.assertEqual(out["submitted"], 1)
        self.assertEqual(out["summary"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
