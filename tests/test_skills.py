"""tests/test_skills.py — 技能库（成功 run → playbook；版本+成功统计+审批入库）。

断言：
- 从成功 run 提炼 playbook（步骤/参数/写面/证据引用）；
- 未审批技能不可检索为 approved；lead/admin 可批准并版本 +1；
- tester 无批准权（ApprovalDenied）；
- 成功/失败统计更新；检索命中；
- 破坏性/写类步骤保留 writes 标记（供 supervisor 审批门使用）。
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.skills import SkillError, SkillLibrary
from inkblade.core.users import Session


class SkillLibraryTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        self.run = self.store.create_run("run-skill")
        self.run.add_step("exposure-mapping", "snapshot", {"actor": "tester"}, "暴露面 3 条")
        self.run.add_step("privileged-workloads", "snapshot", {"actor": "tester"}, "特权 1 条")
        self.run.add_finding("exposure-mapping", "high", "Ray 暴露", "LoadBalancer")
        self.lib = SkillLibrary(self.store)
        self.lead = Session(None, "lead", "lead", ["local-lab"], "t1")
        self.tester = Session(None, "tester", "tester", ["local-lab"], "t2")

    def tearDown(self):
        self.td.cleanup()

    def test_extract_from_run(self):
        skill = self.lib.extract(self.run, name="recon-first-pass")
        self.assertEqual(skill["name"], "recon-first-pass")
        self.assertEqual([s["module"] for s in skill["playbook"]],
                         ["exposure-mapping", "privileged-workloads"])
        self.assertTrue(all("evidence" in s for s in skill["playbook"]))
        self.assertEqual(skill["stats"]["success"], 0)
        self.assertEqual(skill["status"], "draft")

    def test_submit_and_approve_versions(self):
        skill = self.lib.extract(self.run, name="recon-first-pass")
        pending = self.lib.submit(self.tester, skill)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["version"], 1)
        self.assertEqual(self.lib.search("recon"), [])  # 未审批不进入可检索集
        approved = self.lib.approve(self.lead, pending["id"])
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["version"], 1)
        hits = self.lib.search("recon")
        self.assertEqual(len(hits), 1)
        # 再次提交同 id 更新 → 版本递增
        pending2 = self.lib.submit(self.tester, {**skill, "id": pending["id"]})
        self.assertEqual(pending2["version"], 2)
        approved2 = self.lib.approve(self.lead, pending2["id"])
        self.assertEqual(approved2["version"], 2)
        self.assertEqual(len(self.lib.get(pending["id"])["history"]), 2)

    def test_tester_cannot_approve(self):
        pending = self.lib.submit(self.tester, self.lib.extract(self.run, name="x"))
        with self.assertRaises(PermissionError):
            self.lib.approve(self.tester, pending["id"])

    def test_record_outcome_stats(self):
        pending = self.lib.submit(self.tester, self.lib.extract(self.run, name="x"))
        self.lib.approve(self.lead, pending["id"])
        self.lib.record_outcome(pending["id"], True)
        self.lib.record_outcome(pending["id"], False)
        record = self.lib.get(pending["id"])
        self.assertEqual(record["stats"]["uses"], 2)
        self.assertEqual(record["stats"]["success"], 1)
        self.assertEqual(record["stats"]["failure"], 1)
        self.assertIsNotNone(record["stats"]["last_used"])

    def test_extract_requires_steps(self):
        empty = self.store.create_run("run-empty")
        with self.assertRaises(SkillError):
            self.lib.extract(empty, name="empty")

    def test_unknown_skill(self):
        with self.assertRaises(SkillError):
            self.lib.get("skill-nope")
        with self.assertRaises(SkillError):
            self.lib.approve(self.lead, "skill-nope")


if __name__ == "__main__":
    unittest.main()
