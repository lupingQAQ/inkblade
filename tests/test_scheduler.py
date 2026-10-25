# -*- coding: utf-8 -*-
"""周期重测与漂移（XBow 对标 ③）测试：cron/interval/差异/run-due 落 drift。"""

import json
import time
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe
from trident.core.scheduler import (
    ScheduleError, Scheduler, diff_findings, next_fire, parse_cron,
)
from trident.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "trident" / "modules"
CHAINS_DIR = Path(__file__).resolve().parents[1] / "trident" / "chains"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestCron(unittest.TestCase):
    def test_parse_and_next(self):
        sets = parse_cron("*/5 * * * *")
        self.assertEqual(sets[0], {0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55})
        after = datetime(2026, 10, 25, 12, 3)
        self.assertEqual(next_fire("*/5 * * * *", after), datetime(2026, 10, 25, 12, 5))
        self.assertEqual(next_fire("0 3 * * *", after), datetime(2026, 10, 26, 3, 0))
        self.assertEqual(next_fire("30 8 1 * *", after), datetime(2026, 11, 1, 8, 30))

    def test_parse_ranges_and_lists(self):
        sets = parse_cron("1-3,5 8-9 15 2 1")
        self.assertEqual(sets[0], {1, 2, 3, 5})
        self.assertEqual(sets[3], {2})
        self.assertEqual(sets[4], {1})

    def test_invalid(self):
        for expr in ("* * * *", "60 * * * *", "* 24 * * *", "a * * * *", "*/0 * * * *",
                     "5-1 * * * *"):
            with self.assertRaises(ScheduleError, msg=expr):
                parse_cron(expr)


class TestDiffFindings(unittest.TestCase):
    def test_new_fixed_unchanged(self):
        prev = [{"step_key": "m1", "title": "A", "severity": "high"},
                {"step_key": "m1", "title": "B", "severity": "low"}]
        curr = [{"step_key": "m1", "title": "A", "severity": "high"},
                {"step_key": "m2", "title": "C", "severity": "critical"}]
        d = diff_findings(prev, curr)
        self.assertEqual([f["title"] for f in d["new"]], ["C"])
        self.assertEqual([f["title"] for f in d["fixed"]], ["B"])
        self.assertEqual(d["counts"], {"new": 1, "fixed": 1, "unchanged": 1})


class TestScheduler(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["10.0.0.0/8"]})
        self.sched = Scheduler(self.store, chains_dir=CHAINS_DIR, modules_dir=MODULES_DIR)

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_requires_trigger_and_chains(self):
        with self.assertRaises(ScheduleError):
            self.sched.add(_session(), chains=[])
        with self.assertRaises(ScheduleError):
            self.sched.add(_session(), cron="* * * * *", interval_seconds=60, chains=["x-chain"])
        item = self.sched.add(_session(), interval_seconds=60, chains=["demo-chain"])
        self.assertTrue(item["enabled"])
        with self.assertRaises(ScheduleError):
            self.sched.add(_session(), interval_seconds=60, chains=["demo-chain"],
                           schedule_id=item["id"])

    def test_interval_due_and_persistence(self):
        self.sched.add(_session(), interval_seconds=60, chains=["demo"], schedule_id="s1")
        self.assertEqual([s["id"] for s in self.sched.due(now=time.time() + 61)], ["s1"])
        self.assertEqual(self.sched.due(now=time.time()), [])
        # 重新加载（持久化）
        self.assertEqual([s["id"] for s in Scheduler(self.store).list()], ["s1"])

    def test_cron_due(self):
        self.sched.add(_session(), cron="*/5 * * * *", chains=["demo"], schedule_id="c1")
        now = time.time() + 3600
        self.assertEqual([s["id"] for s in self.sched.due(now=now)], ["c1"])

    def test_disable_blocks_due(self):
        self.sched.add(_session(), interval_seconds=1, chains=["demo"], schedule_id="s1")
        self.sched.set_enabled("s1", False)
        self.assertEqual(self.sched.due(now=time.time() + 120), [])

    def test_remove_unknown(self):
        with self.assertRaises(ScheduleError):
            self.sched.remove("ghost")

    def test_run_due_unknown_chain_records_skip(self):
        self.sched.add(_session(), interval_seconds=1, chains=["no-such-chain"],
                       schedule_id="s1")
        out = self.sched.run_due(_session("tester"), now=time.time() + 10)
        self.assertEqual(out["due"], ["s1"])
        self.assertEqual(out["results"]["s1"]["chains"][0]["status"], "skipped")

    def test_run_due_produces_drift(self):
        # 先造一个带 finding 的历史 run（作为「上次」）
        run = self.store.create_run("sched-prev")
        run.add_step("demo-step", "cmd", {}, "ok")
        run.add_finding("demo-step", sev="high", title="旧发现A", detail="x")
        item = self.sched.add(_session(), interval_seconds=1, chains=["no-such-chain"],
                              schedule_id="s2")
        # 手工把 last_run_name 指向历史 run，模拟第二轮
        items = self.sched.list()
        for s in items:
            if s["id"] == "s2":
                s["last_run_name"] = "sched-prev"
        (self.store.ws_dir / "schedules.json").write_text(
            json.dumps(items, ensure_ascii=False), encoding="utf-8")
        del item
        out = self.sched.run_due(_session(), now=time.time() + 10)
        res = out["results"]["s2"]
        # 无可执行链 → 不产生新 run，drift 为空计数（不崩溃）
        self.assertEqual(res["drift"]["counts"]["new"], 0)

    def test_drift_written_to_run_dir(self):
        # 构造两条链可执行：用内置侦察链 + 无前置链（只读、无 target 也安全）
        chains = sorted(p.stem for p in CHAINS_DIR.glob("*.json"))
        pick = None
        for cid in chains:
            doc = json.loads((CHAINS_DIR / f"{cid}.json").read_text(encoding="utf-8"))
            if not doc.get("preconditions") and all(
                    not s.get("writes") for s in doc.get("steps", [])):
                pick = cid
                break
        if pick is None:
            self.skipTest("无可用的无前置只读链")
        self.sched.add(_session(), interval_seconds=1, chains=[pick], schedule_id="s3")
        out = self.sched.run_due(_session(), now=time.time() + 10)
        res = out["results"]["s3"]
        self.assertEqual(res["chains"][0]["status"], "ok")
        run_name = res["chains"][0]["run"]
        self.assertTrue((self.store.ws_dir / run_name / "drift.json").is_file())
        drift = json.loads((self.store.ws_dir / run_name / "drift.json").read_text(encoding="utf-8"))
        self.assertEqual(drift["schedule"], "s3")
        self.assertIn("counts", drift)


if __name__ == "__main__":
    unittest.main()
