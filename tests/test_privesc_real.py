"""提权实效：真集群 4 条路径工件 + fake-kubectl 闭环（escalate/bind/SA token/webhook）。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from lab.privesc_sim import SCENARIOS, run_fake_closure

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "reports" / "samples" / "privesc"
DOC = REPO / "docs" / "PRIVESC-VERIFICATION.md"


class TestFakeClosure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_fake_closure()

    def test_four_scenarios_pass(self):
        self.assertEqual(len(SCENARIOS), 4)
        self.assertEqual(self.result["summary"]["total"], 4)
        self.assertEqual(self.result["summary"]["passed"], 4, self.result)
        ids = {c["id"] for c in self.result["checks"]}
        self.assertEqual(ids, {"escalate", "bind", "sa-token", "webhook"})

    def test_escalate_before_after(self):
        check = next(c for c in self.result["checks"] if c["id"] == "escalate")
        self.assertFalse(check["evidence"]["before_admin"])
        self.assertTrue(check["evidence"]["after_admin"])
        self.assertEqual(check["evidence"]["escalate_allowed"], True)
        self.assertIn("esc", check["evidence"]["subject"])

    def test_bind_before_after(self):
        check = next(c for c in self.result["checks"] if c["id"] == "bind")
        self.assertFalse(check["evidence"]["before_admin"])
        self.assertTrue(check["evidence"]["after_admin"])
        self.assertTrue(check["evidence"]["binding_created"])

    def test_token_impersonation(self):
        check = next(c for c in self.result["checks"] if c["id"] == "sa-token")
        self.assertFalse(check["evidence"]["before_admin"])
        self.assertTrue(check["evidence"]["token_issued"])
        self.assertTrue(check["evidence"]["after_admin"])
        self.assertNotIn("token_value", check["evidence"])
        self.assertEqual(len(check["evidence"]["token_sha256_8"]), 8)

    def test_webhook_write_to_privileged_pod(self):
        check = next(c for c in self.result["checks"] if c["id"] == "webhook")
        self.assertTrue(check["evidence"]["webhook_written"])
        self.assertTrue(check["evidence"]["pod_privileged"])
        self.assertTrue(check["evidence"]["host_root_mounted"])
        self.assertTrue(check["evidence"]["escape_primitive"])


class TestRealArtifacts(unittest.TestCase):
    def test_real_paths_artifact(self):
        path = SAMPLES / "real-paths.json"
        self.assertTrue(path.is_file(), f"缺少真集群工件 {path}")
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(doc["summary"]["total"], 4)
        self.assertEqual(doc["summary"]["passed"], doc["summary"]["total"], doc)
        ids = {c["id"] for c in doc["checks"]}
        self.assertTrue({"escalate", "bind", "impersonate", "sa-token"} <= ids, ids)
        for check in doc["checks"]:
            self.assertEqual(check["status"], "PASS")
            self.assertFalse(check["before_admin"], check["id"])
            self.assertTrue(check["after_admin"], check["id"])

    def test_real_doc_mentions_boundaries(self):
        self.assertTrue(DOC.is_file(), DOC)
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("QEMU", text)
        self.assertIn("k3s", text)
        self.assertIn("fake-kubectl", text)
        for sid in ("escalate", "bind", "impersonate", "sa-token", "webhook"):
            self.assertIn(sid, text)


if __name__ == "__main__":
    unittest.main()
