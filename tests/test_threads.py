# -*- coding: utf-8 -*-
"""run 内侧问：tester 提问 → lead 回复、全程审计、绝不执行。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.threads import ThreadDenied, ThreadError, Threads
from inkblade.core.users import Session


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestThreads(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        self.run = self.store.create_run("run-qa")
        self.run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        self.th = Threads(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ask_reply_flow_and_no_execution(self):
        steps_before = self.run.query("SELECT COUNT(*) FROM steps")[0][0]
        t = self.th.ask(_session("tester"), "run-qa", "为什么先测 sglang？", "它暴露在 30000")
        self.assertEqual(t["status"], "awaiting_lead")
        self.assertFalse(t["execution"]["triggered"])
        rep = self.th.reply(_session("lead"), "run-qa", t["id"], "网关鉴权缺失，优先验证")
        self.assertEqual(rep["status"], "answered")
        self.assertEqual(len(rep["messages"]), 2)
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM steps")[0][0], steps_before)
        actions = [r[0] for r in self.run.query("SELECT action FROM actions")]
        self.assertIn("thread-question", actions)
        self.assertIn("thread-reply", actions)
        self.assertNotIn("execute", actions)
        events = self.th.events("run-qa", t["id"])["events"]
        self.assertEqual([e["kind"] for e in events], ["question", "reply"])
        self.assertTrue(all(e["digest"] for e in events))
        audit = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("thread-question", audit)
        self.assertIn("thread-reply", audit)

    def test_permission_matrix(self):
        with self.assertRaises(ThreadDenied):
            self.th.ask(_session("auditor"), "run-qa", "s", "b")
        t = self.th.ask(_session("tester"), "run-qa", "s", "b")
        with self.assertRaises(ThreadDenied):
            self.th.reply(_session("tester"), "run-qa", t["id"], "answer")
        with self.assertRaises(ThreadDenied):
            self.th.reply(_session("auditor"), "run-qa", t["id"], "answer")
        with self.assertRaises(ThreadDenied):
            self.th.close(_session("tester"), "run-qa", t["id"])

    def test_cancel_by_asker_and_close(self):
        t = self.th.ask(_session("tester"), "run-qa", "s", "b")
        c = self.th.cancel(_session("tester"), "run-qa", t["id"], reason="self")
        self.assertEqual(c["status"], "canceled")
        with self.assertRaises(ThreadError):
            self.th.ask(_session("tester"), "run-qa", "s2", "b2", thread_id=t["id"])
        t2 = self.th.ask(_session("tester"), "run-qa", "s2", "b2")
        closed = self.th.close(_session("lead"), "run-qa", t2["id"], resolution="done")
        self.assertEqual(closed["status"], "closed")
        with self.assertRaises(ThreadError):
            self.th.reply(_session("lead"), "run-qa", t2["id"], "late")

    def test_validation_and_unknown(self):
        with self.assertRaises(ThreadError):
            self.th.ask(_session("tester"), "ghost", "s", "b")
        with self.assertRaises(ThreadError):
            self.th.ask(_session("tester"), "run-qa", "", "b")
        with self.assertRaises(ThreadError):
            self.th.ask(_session("tester"), "run-qa", "s", "x" * 4001)
        with self.assertRaises(ThreadError):
            self.th.get("run-qa", "thr-9999")
        self.assertEqual(self.th.summary("run-qa")["threads"], 0)

    def test_list_all_runs(self):
        self.th.ask(_session("tester"), "run-qa", "q1", "b")
        self.assertEqual(len(self.th.list_threads()), 1)
        self.assertEqual(self.th.summary()["awaiting_lead"], 1)


if __name__ == "__main__":
    unittest.main()
