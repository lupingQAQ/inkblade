"""tests/test_journal.py — durable execution 事件日志（append-only + 校验链 + checkpoint + resume/replay）。

断言：
- 事件追加落盘、序号单调、哈希链可校验；
- 崩溃恢复：started 无 finished → resume.incomplete；重开实例后补齐 → completed/failed；
- checkpoint 可恢复边界；
- 篡改（改行/删行/改 payload）→ verify 报 broken_at 且不静默通过。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.journal import Journal, JournalError


class JournalAppendTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.path = Path(self.td.name) / "journal.jsonl"
        self.j = Journal(self.path)

    def tearDown(self):
        self.td.cleanup()

    def test_append_persists_and_chains(self):
        self.j.append("step.started", step="recon")
        self.j.append("step.finished", step="recon", payload={"ok": True})
        self.assertTrue(self.path.exists())
        events = self.j.events()
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(events[0]["kind"], "step.started")
        self.assertEqual(events[1]["payload"], {"ok": True})
        self.assertEqual(events[0]["prev"], "")
        self.assertEqual(events[1]["prev"], events[0]["hash"])
        self.assertTrue(self.j.verify()["ok"])

    def test_append_rejects_bad_input(self):
        with self.assertRaises(JournalError):
            self.j.append("", step="x")
        with self.assertRaises(JournalError):
            self.j.append("step.started", step="x", payload=["not", "dict"])

    def test_events_are_immutable_on_disk(self):
        self.j.append("step.started", step="a")
        before = self.path.read_bytes()
        self.j.events()
        self.assertEqual(self.path.read_bytes(), before)


class JournalResumeTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.path = Path(self.td.name) / "journal.jsonl"

    def tearDown(self):
        self.td.cleanup()

    def test_crash_recovery_lists_incomplete_step(self):
        j = Journal(self.path)
        j.append("step.started", step="recon")
        j.append("step.finished", step="recon", payload={"ok": True})
        j.append("step.started", step="exploit")
        # 进程「崩溃」：不写 finished，重新打开
        reopened = Journal(self.path)
        resume = reopened.resume()
        self.assertEqual(resume["completed"], ["recon"])
        self.assertEqual(resume["incomplete"], ["exploit"])
        self.assertEqual(resume["seq"], 3)
        reopened.append("step.finished", step="exploit", payload={"ok": False})
        resume2 = reopened.resume()
        self.assertEqual(resume2["failed"], ["exploit"])
        self.assertEqual(resume2["incomplete"], [])
        self.assertTrue(reopened.verify()["ok"])

    def test_checkpoint_and_replay_state(self):
        j = Journal(self.path)
        j.append("step.started", step="a")
        j.append("step.finished", step="a", payload={"ok": True})
        cp = j.checkpoint("after-a", {"next": "b"})
        self.assertEqual(cp["kind"], "checkpoint")
        j.append("step.started", step="b")
        resume = Journal(self.path).resume()
        self.assertEqual(resume["checkpoints"][0]["label"], "after-a")
        replay = Journal(self.path).replay()
        self.assertEqual(replay["steps"]["a"], "success")
        self.assertEqual(replay["steps"]["b"], "started")
        self.assertEqual(replay["last_seq"], 4)
        self.assertEqual(replay["kinds"]["checkpoint"], 1)


class JournalTamperTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.path = Path(self.td.name) / "journal.jsonl"
        j = Journal(self.path)
        for step in ("a", "b", "c"):
            j.append("step.started", step=step)
            j.append("step.finished", step=step, payload={"ok": True})

    def tearDown(self):
        self.td.cleanup()

    def _rewrite(self, mutate):
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines = mutate(lines)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_payload_tamper_detected(self):
        def mutate(lines):
            ev = json.loads(lines[2])
            ev["payload"] = {"ok": False}
            lines[2] = json.dumps(ev, ensure_ascii=False)
            return lines

        self._rewrite(mutate)
        verdict = Journal(self.path).verify()
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["broken_at"], 3)

    def test_dropped_line_detected(self):
        self._rewrite(lambda lines: lines[:3] + lines[4:])
        verdict = Journal(self.path).verify()
        self.assertFalse(verdict["ok"])
        self.assertIsNotNone(verdict["broken_at"])

    def test_truncated_tail_is_visible(self):
        # 最后一行不完整（模拟崩溃半写）：verify 报错而不是静默丢事件
        data = self.path.read_text(encoding="utf-8")
        self.path.write_text(data.rstrip("\n")[:-12], encoding="utf-8")
        verdict = Journal(self.path).verify()
        self.assertFalse(verdict["ok"])


if __name__ == "__main__":
    unittest.main()
