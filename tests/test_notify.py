# -*- coding: utf-8 -*-
"""通知渠道/规则/投递：默认禁用、审计、重试、邮件 stub、角色闸门、脱敏。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.notify import NotifyError, NotifyManager
from inkblade.core.users import Session


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestNotify(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        self.now = 1000.0
        self.sent = []

        def transport(channel, event, payload):
            self.sent.append((channel["id"], event, payload.get("title")))
            return {"ok": True, "status": 200}

        self.nm = NotifyManager(self.store, transport=transport, clock=lambda: self.now)
        self.cid = self.nm.add_channel(
            _session(), "webhook", "hook", {"url": "http://127.0.0.1:9/hook",
                                            "token": "secret-token"})["id"]
        self.nm.add_rule(_session(), "finding.critical", [self.cid], min_severity="high")

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_disabled_suppresses(self):
        out = self.nm.emit("finding.critical", {"title": "crit"}, severity="critical")
        self.assertEqual(out["deliveries"][0]["status"], "suppressed")
        self.assertEqual(self.sent, [])
        self.assertIn("notify disabled", out["deliveries"][0]["suppressed_reason"])
        self.assertEqual(self.nm.meta()["enabled"], False)

    def test_enable_dispatch_and_audit(self):
        self.nm.set_enabled(_session(), True)
        out = self.nm.emit("finding.critical", {"title": "crit"}, severity="critical")
        self.assertEqual(out["deliveries"][0]["status"], "delivered")
        self.assertEqual(len(self.sent), 1)
        lines = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertTrue(any("notify.emit" in line for line in lines))
        self.assertTrue(any("notify.delivery" in line for line in lines))

    def test_severity_rule_and_masking(self):
        self.nm.set_enabled(_session(), True)
        out = self.nm.emit("finding.critical", {"title": "low"}, severity="low")
        self.assertEqual(out["matched"], 0)
        channels = self.nm.list_channels()
        self.assertEqual(channels[0]["config"]["token"], "***")
        self.assertNotIn("secret-token", json.dumps(channels, ensure_ascii=False))

    def test_retry_backoff_until_delivered(self):
        attempts = {"n": 0}

        def flaky(channel, event, payload):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return {"ok": False, "detail": "temporary"}
            return {"ok": True}

        self.nm.set_enabled(_session(), True)
        out = self.nm.emit("finding.critical", {"title": "retry"}, severity="critical",
                           transport=flaky)
        self.assertEqual(out["deliveries"][0]["status"], "pending")
        self.assertEqual(out["deliveries"][0]["attempts"], 1)
        self.now += 6
        self.nm.dispatch(transport=flaky)
        self.now += 60
        self.nm.dispatch(transport=flaky)
        d = self.nm.deliveries()[-1]
        self.assertEqual(d["status"], "delivered")
        self.assertEqual(d["attempts"], 3)

    def test_email_is_stub(self):
        nm = NotifyManager(self.store, clock=lambda: self.now)
        cid = nm.add_channel(_session(), "email", "mail", {"to": "ops@example.invalid"})["id"]
        nm.add_rule(_session(), "test", [cid], min_severity="info")
        nm.set_enabled(_session(), True)
        d = nm.test_channel(_session(), cid)
        self.assertEqual(d["status"], "delivered")
        self.assertEqual(nm.list_channels()[-1]["kind"], "email")

    def test_role_gates(self):
        with self.assertRaises(PermissionError):
            self.nm.add_channel(_session("tester"), "webhook", "x",
                                {"url": "http://127.0.0.1:9/x"})
        with self.assertRaises(PermissionError):
            self.nm.add_rule(_session("tester"), "finding.critical", [self.cid])
        with self.assertRaises(PermissionError):
            self.nm.set_enabled(_session("auditor"), True)
        with self.assertRaises(PermissionError):
            self.nm.delete_channel(_session("tester"), self.cid)

    def test_invalid_channels(self):
        with self.assertRaises(NotifyError):
            self.nm.add_channel(_session(), "webhook", "bad", {})
        with self.assertRaises(NotifyError):
            self.nm.add_channel(_session(), "email", "bad", {"to": "not-an-email"})
        with self.assertRaises(NotifyError):
            self.nm.add_channel(_session(), "pager", "bad", {})

    def test_disabled_test_channel_suppressed(self):
        d = self.nm.test_channel(_session(), self.cid)
        self.assertEqual(d["status"], "suppressed")
        self.assertEqual(self.sent, [])

    def test_retry_suppressed_rejected(self):
        self.nm.emit("finding.critical", {"title": "x"}, severity="critical")
        d = self.nm.deliveries()[-1]
        with self.assertRaises(NotifyError):
            self.nm.retry(_session(), d["id"])


if __name__ == "__main__":
    unittest.main()
