"""tests/test_supervisor.py — 分层 supervisor-worker（队列/有界并发/失败重派/审批门）。

断言：
- 未批准动作拒绝入队（ApprovalRequired），队列零残留；
- workers 1..8 校验；并发峰值 ≤ workers 且 > 1；
- 失败重派至 max_attempts，成功后 attempts 计数正确；
- worker 只执行已批准动作（执行器只看到 approved）；
- 事件写入 journal；summary 结构完整。
"""

import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.journal import Journal
from trident.core.supervisor import ApprovalRequired, Supervisor, SupervisorError
from trident.core.users import Session


def approved(module, **params):
    return {"module": module, "params": params,
            "approval": {"status": "approved", "approved_by": "lead"}}


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        self.session = Session(None, "lead", "lead", ["local-lab"], "t")
        self.journal = Journal(Path(self.td.name) / "journal.jsonl")
        self.calls = []
        self.lock = threading.Lock()

    def tearDown(self):
        self.td.cleanup()

    def _executor(self, task):
        with self.lock:
            self.calls.append(task["module"])
        if task["module"] == "flaky" and task["attempts"] == 1:
            raise RuntimeError("transient")
        return {"ok": True, "findings": 1}

    def test_unapproved_action_rejected_without_queue_residue(self):
        sup = Supervisor(self.store, self.session, executor=self._executor,
                         journal=self.journal)
        with self.assertRaises(ApprovalRequired):
            sup.submit([{"module": "recon", "params": {}}])
        self.assertEqual(sup.tasks(), [])
        self.assertEqual(self.journal.events(), [])

    def test_workers_bounds(self):
        for bad in (0, 9, -1):
            with self.assertRaises(SupervisorError):
                Supervisor(self.store, self.session, workers=bad,
                           executor=self._executor)

    def test_execute_only_approved_and_retry(self):
        sup = Supervisor(self.store, self.session, workers=2, max_attempts=2,
                         executor=self._executor, journal=self.journal)
        tasks = sup.submit([approved("recon"), approved("flaky"), approved("exploit")])
        self.assertEqual([t["status"] for t in tasks], ["pending"] * 3)
        result = sup.run()
        summary = result["summary"]
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["success"], 3)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["retries"], 1)
        self.assertEqual(summary["approvals"], 3)
        flaky = next(t for t in result["tasks"] if t["module"] == "flaky")
        self.assertEqual(flaky["attempts"], 2)
        self.assertEqual(flaky["status"], "success")
        self.assertEqual(self.calls.count("flaky"), 2)
        kinds = [e["kind"] for e in self.journal.events()]
        self.assertIn("task.started", kinds)
        self.assertIn("task.retry", kinds)
        self.assertIn("task.succeeded", kinds)

    def test_failure_exhausts_attempts(self):
        def always_fail(task):
            raise RuntimeError("boom")

        sup = Supervisor(self.store, self.session, workers=1, max_attempts=2,
                         executor=always_fail, journal=self.journal)
        sup.submit([approved("bad")])
        result = sup.run()
        task = result["tasks"][0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["attempts"], 2)
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertIn("boom", task["error"])

    def test_bounded_concurrency(self):
        active = {"now": 0, "peak": 0}
        lock = threading.Lock()

        def slow(task):
            with lock:
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
            time.sleep(0.05)
            with lock:
                active["now"] -= 1
            return {"ok": True}

        sup = Supervisor(self.store, self.session, workers=3, max_attempts=1,
                         executor=slow, journal=self.journal)
        sup.submit([approved(f"m{i}") for i in range(9)])
        result = sup.run()
        self.assertEqual(result["summary"]["success"], 9)
        self.assertLessEqual(active["peak"], 3)
        self.assertGreater(active["peak"], 1)

    def test_requires_execute_permission(self):
        auditor = Session(None, "aud", "auditor", ["local-lab"], "t")
        sup = Supervisor(self.store, auditor, executor=self._executor)
        with self.assertRaises(PermissionError):
            sup.submit([approved("recon")])

    def test_proposal_level_approval(self):
        proposal = {"id": "prop-1", "status": "approved",
                    "approval": {"status": "approved", "approved_by": "lead"}}
        sup = Supervisor(self.store, self.session, executor=self._executor,
                         journal=self.journal)
        tasks = sup.submit([{"module": "recon", "params": {}}], proposal=proposal)
        self.assertEqual(tasks[0]["status"], "pending")
        self.assertIn("prop-1", tasks[0]["proposal"])

    def test_persisted_queue_resumes_pending(self):
        sup = Supervisor(self.store, self.session, executor=self._executor,
                         journal=self.journal)
        sup.submit([approved("recon")])
        # 新建实例（模拟控制面重启）：未执行任务仍在队列
        sup2 = Supervisor(self.store, self.session, executor=self._executor,
                          journal=self.journal)
        self.assertEqual(len(sup2.tasks()), 1)
        result = sup2.run()
        self.assertEqual(result["summary"]["success"], 1)


if __name__ == "__main__":
    unittest.main()
