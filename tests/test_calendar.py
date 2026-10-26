# -*- coding: utf-8 -*-
"""计划任务日历：一次性窗口/暂停恢复/ROE 闸门/角色/视图。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.calendar import Calendar, CalendarError
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.users import Session

CHAINS_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "chains"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestCalendar(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        self.cal = Calendar(self.store, chains_dir=CHAINS_DIR, clock=lambda: 1000.0)

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_validation_and_permissions(self):
        with self.assertRaises(PermissionError):
            self.cal.add_window(_session("tester"), name="w", start=1000, end=2000,
                                chains=["no-such-chain"])
        with self.assertRaises(CalendarError):
            self.cal.add_window(_session(), name="w", start=1500, end=1000,
                                chains=["no-such-chain"])
        with self.assertRaises(CalendarError):
            self.cal.add_window(_session(), name="w", start=100, end=900,
                                chains=["no-such-chain"])
        w = self.cal.add_window(_session(), name="w", start=1000, end=2000,
                                chains=["no-such-chain"])
        self.assertEqual(w["status"] if "status" in w else "scheduled", "scheduled")
        self.assertEqual(w["duration_hours"], 0.28)

    def test_one_shot_due_and_run(self):
        self.cal.add_window(_session(), name="w", start=1000, end=2000,
                            chains=["no-such-chain"], window_id="w1")
        self.assertEqual([w["id"] for w in self.cal.due(1500)], ["w1"])
        out = self.cal.run_due(_session("tester"), now=1500)
        self.assertEqual(out["due"], ["w1"])
        self.assertEqual(out["results"]["w1"]["chains"][0]["status"], "skipped")
        self.assertEqual(self.cal.due(1600), [])
        self.assertEqual(self.cal.list()[0]["last_run"], 1500)

    def test_pause_resume(self):
        self.cal.add_window(_session(), name="w", start=1000, end=2000,
                            chains=["no-such-chain"], window_id="w1")
        with self.assertRaises(PermissionError):
            self.cal.pause(_session("auditor"), "w1")
        self.cal.pause(_session(), "w1")
        self.assertEqual(self.cal.due(1500), [])
        self.assertEqual(self.cal.list()[0]["paused"], True)
        self.cal.resume(_session(), "w1")
        self.assertEqual([w["id"] for w in self.cal.due(1500)], ["w1"])

    def test_roe_gate_and_role(self):
        store = EvidenceStore(Path(self.tmp.name) / "no-roe", workspace="no-roe")
        cal = Calendar(store, chains_dir=CHAINS_DIR, clock=lambda: 1000.0)
        cal.add_window(_session(), name="w", start=1000, end=2000,
                       chains=["no-such-chain"], window_id="w1")
        with self.assertRaises(ExecutionLocked):
            cal.run_due(_session("tester"), now=1500)
        init_roe(store, {"level": "只读侦察", "namespaces": ["ml"], "cidrs": []})
        with self.assertRaises(PermissionError):
            cal.run_due(_session("auditor"), now=1500)

    def test_views(self):
        self.cal.add_window(_session(), name="a", start=1000, end=2000,
                            chains=["no-such-chain"], window_id="w1")
        self.cal.add_window(_session(), name="b", start=300000, end=400000,
                            chains=["no-such-chain"], window_id="w2")
        up = self.cal.upcoming(now=1000, days=2)
        self.assertEqual([w["id"] for w in up], ["w1"])
        self.assertEqual(up[0]["status"], "due")
        events = self.cal.event_calendar(now=1000, days=2)
        self.assertEqual(len(events["days"]), 2)
        self.assertTrue(events["days"][0]["windows"])
        self.assertEqual(self.cal.remove(_session(), "w2"), {"removed": "w2"})


if __name__ == "__main__":
    unittest.main()
