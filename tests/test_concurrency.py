# -*- coding: utf-8 -*-
"""已批准提议的 bounded 并发执行（1-8）：审批/角色/ROE 闸门与每动作独立审计。"""

import json
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import ApprovalDenied, Explorer, ExplorerError
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


CI_SLOW_WINDOWS = os.name == "nt" and bool(os.environ.get("CI"))


class TestConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        self.ex = Explorer(self.store, modules_dir=MODULES_DIR)
        self._proposal("p1", actions=2, status="pending_approval")

    def tearDown(self):
        self.tmp.cleanup()

    def _proposal(self, pid: str, *, actions: int, status: str):
        doc = [{"id": pid, "status": status, "mode": "rules", "created_by": "s-lead",
                "created_at": time.time(), "context": {},
                "actions": [{"seq": i + 1, "module": "auth-gap-detection",
                             "params": {}, "writes": False} for i in range(actions)],
                "approval": {"required": True, "status": "pending"},
                "execution": {"trigger": "human", "performed": False}}]
        self.ex.queue_path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")

    def test_workers_bounds(self):
        for bad in (0, 9, -1, True, "2", 2.5):
            with self.assertRaises(ExplorerError, msg=repr(bad)):
                self.ex.execute(_session("tester"), "p1", workers=bad)

    def test_requires_approval_and_role(self):
        with self.assertRaises(ExplorerError):
            self.ex.execute(_session("tester"), "p1", workers=1)
        self.ex.approve(_session("lead"), "p1")
        with self.assertRaises(ApprovalDenied):
            self.ex.execute(_session("auditor"), "p1", workers=1)
        out = self.ex.execute(_session("tester"), "p1", workers=1)
        self.assertFalse(out["parallel"])
        self.assertEqual(out["workers"], 1)

    def test_roe_gate(self):
        self.ex.approve(_session("lead"), "p1")
        (Path(self.store.ws_dir) / "consent.json").unlink()
        with self.assertRaises(ExecutionLocked):
            self.ex.execute(_session("tester"), "p1", workers=2)

    @unittest.skipIf(CI_SLOW_WINDOWS, "wall-clock scheduling assertions are unreliable on shared Windows CI")
    def test_parallel_timing_and_bounded(self):
        self.ex.approve(_session("lead"), "p1")
        calls = []
        lock = threading.Lock()

        def fake(store, session, module, params, modules_dir, run=None):
            with lock:
                calls.append(module)
                n = len(calls)
            time.sleep(0.2)
            return {"run": f"fake-{n}", "step": module}

        with patch("inkblade.core.runner.run_module", fake):
            t0 = time.time()
            out = self.ex.execute(_session("tester"), "p1", workers=2)
            elapsed = time.time() - t0
        self.assertTrue(out["parallel"])
        self.assertLess(elapsed, 0.35, "两个动作应并发执行")
        self.assertEqual(len(calls), 2)
        self.assertTrue(out["ok"])
        self.assertEqual({r["run"] for r in out["results"]}, {"fake-1", "fake-2"})

    def test_real_execution_audit_isolation(self):
        self._proposal("p2", actions=3, status="pending_approval")
        self.ex.approve(_session("lead"), "p2")
        out = self.ex.execute(_session("tester"), "p2", workers=3)
        self.assertTrue(out["ok"])
        runs = [r["run"] for r in out["results"]]
        self.assertEqual(len(set(runs)), 3)
        for run_name in runs:
            self.assertTrue((self.store.ws_dir / run_name / "evidence.db").is_file())
            run = self.store.open_run(run_name)
            actions = [r[0] for r in run.query("SELECT action FROM actions")]
            self.assertIn("execute", actions)
        stored = {p["id"]: p for p in self.ex.list_proposals()}
        self.assertEqual(stored["p2"]["execution"]["workers"], 3)
        self.assertEqual(stored["p2"]["execution"]["audit_isolation"],
                         "per-action run (evidence.db)")
        self.assertEqual(stored["p2"]["status"], "executed")

    def test_alias(self):
        self.ex.approve(_session("lead"), "p1")
        with patch("inkblade.core.runner.run_module",
                   lambda *a, **k: {"run": "r", "step": "s"}):
            out = self.ex.execute_parallel(_session("tester"), "p1", workers=2)
        self.assertEqual(out["workers"], 2)


if __name__ == "__main__":
    unittest.main()
