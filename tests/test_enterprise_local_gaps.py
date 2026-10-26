# -*- coding: utf-8 -*-
"""Enterprise yellow-item local verification (ER-06/08/16/26/27/34/39/40/50/57)."""

from __future__ import annotations

import json
import re
import time
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.enterprise.delivery import (Deduplicator, DeliveryPolicyError,
                                         DeliveryQueue, EgressPolicy,
                                         event_fingerprint)
from trident.enterprise.evidence_pack import build_pack, verify_pack
from trident.enterprise.governance import (ChangeCalendar, ExceptionPolicy,
                                           GovernanceError, assert_no_regression)
from trident.enterprise.gpu_contract import (compatibility_matrix,
                                             validate_device_plugin, validate_dra)
from trident.enterprise.localcheck import run_local_checks
from trident.enterprise.registry import (RegistryError, parse_reference,
                                         reference_policy)
from trident.enterprise.retention import RetentionError, apply_retention
from trident.enterprise.scale import daily_million_projection, run_scale

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "ENTERPRISE-READINESS.md"


class RegistryTest(unittest.TestCase):
    def test_parse_and_policy(self):
        ref = parse_reference("registry.example.com/team/app@sha256:" + "a" * 64)
        self.assertEqual(ref["registry"], "registry.example.com")
        self.assertEqual(ref["repository"], "team/app")
        self.assertTrue(ref["pinned"])
        self.assertFalse(ref["tag_only"])
        tag = reference_policy("registry.example.com/team/app:latest")
        self.assertIn("tag-only", tag["risks"])
        self.assertIn("latest-tag", tag["risks"])
        with self.assertRaises(RegistryError):
            parse_reference("not a ref with spaces")


class RetentionTest(unittest.TestCase):
    def test_execution_and_guards(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "old.json"
            outside = root.parent / "outside-retention-unit.txt"
            old.write_text("{}", encoding="utf-8")
            outside.write_text("{}", encoding="utf-8")
            old_time = time.time() - 400 * 86400
            import os
            os.utime(old, (old_time, old_time))
            plan = {"legal_hold": False, "actions": [{"path": str(old), "action": "purge"}]}
            with self.assertRaises(RetentionError):
                apply_retention(plan, root=root, execute=True, approvals=("lead",))
            held = apply_retention(plan, root=root, execute=True,
                                   approvals=("lead", "security-owner"), legal_hold=True)
            self.assertTrue(old.exists())
            self.assertEqual(held["counts"]["hold"], 1)
            with self.assertRaises(RetentionError):
                apply_retention({"actions": [{"path": str(outside), "action": "purge"}]},
                                root=root, execute=True,
                                approvals=("lead", "security-owner"))
            done = apply_retention(plan, root=root, execute=True,
                                   approvals=("lead", "security-owner"))
            self.assertFalse(old.exists())
            self.assertTrue((root / "retention-audit.jsonl").is_file())
            self.assertEqual(done["counts"]["purge"], 1)


class GovernanceTest(unittest.TestCase):
    def test_freeze_and_exceptions_and_regression(self):
        cal = ChangeCalendar()
        now = time.time()
        cal.add_freeze("quarter", now - 60, now + 3600, owner="ops", ticket="CAB-1", now=now)
        with self.assertRaises(GovernanceError):
            cal.assert_change_allowed(now, now + 60)
        self.assertIn("BEGIN:VCALENDAR", cal.ics())

        policy = ExceptionPolicy()
        policy.add(image="nvcr.io/nvidia/gpu-operator", digest="sha256:" + "b" * 64,
                   namespace="gpu-operator", service_account="gpu-operator",
                   approver="security-owner", expires_at=now + 86400, now=now)
        self.assertTrue(policy.evaluate({"image": "nvcr.io/nvidia/gpu-operator",
                                         "digest": "sha256:" + "b" * 64,
                                         "namespace": "gpu-operator",
                                         "service_account": "gpu-operator"}, now=now)["allowed"])
        self.assertFalse(policy.evaluate({"image": "nvcr.io/nvidia/gpu-operator",
                                          "digest": "",
                                          "namespace": "gpu-operator",
                                          "service_account": "gpu-operator"}, now=now)["allowed"])
        with self.assertRaises(GovernanceError):
            policy.add(image="x", digest="sha256:" + "c" * 64, namespace="*",
                       service_account="sa", approver="lead", expires_at=now + 10)

        baseline = {"rules": {"r1": {}, "r2": {}}, "coverage": {"c1": "拦截", "c2": "检测"}}
        good = {"rules": {"r1": {}, "r2": {}}, "coverage": {"c1": "拦截+检测", "c2": "检测"}}
        bad = {"rules": {"r1": {}}, "coverage": {"c1": "漏过", "c2": "检测"}}
        self.assertTrue(assert_no_regression(baseline, good)["ok"])
        with self.assertRaises(GovernanceError):
            assert_no_regression(baseline, bad)


class DeliveryTest(unittest.TestCase):
    class _Adapter:
        def __init__(self, fail_first=0):
            self.calls = 0
            self.fail_first = fail_first

        def send(self, event):
            self.calls += 1
            return {"ok": False, "error": "503"} if self.calls <= self.fail_first else {"ok": True}

    def test_dedupe_retry_dead_letter(self):
        with TemporaryDirectory() as tmp:
            dedupe = Deduplicator(window_seconds=60)
            queue = DeliveryQueue(self._Adapter(1), dedupe=dedupe, max_attempts=2,
                                  dead_letter_path=Path(tmp) / "dlq.jsonl")
            event = {"step_key": "m", "title": "t", "resource": "r"}
            first = queue.send([event], tenant="a")
            second = queue.send([event], tenant="a")
            self.assertEqual(first["sent"], 1)
            self.assertEqual(first["attempts"], 2)
            self.assertEqual(second["duplicates"], 1)
            failing = DeliveryQueue(self._Adapter(99), max_attempts=2,
                                    dead_letter_path=Path(tmp) / "dlq2.jsonl")
            bad = failing.send([event], tenant="b")
            self.assertEqual(bad["dead_letters"], 1)
            self.assertTrue((Path(tmp) / "dlq2.jsonl").is_file())
            self.assertEqual(len(event_fingerprint(event, tenant="a")), 64)

    def test_egress_policy(self):
        policy = EgressPolicy(["127.0.0.1", "siem.customer.example"])
        self.assertTrue(policy.check_url("http://127.0.0.1:8088/x")["loopback"])
        with self.assertRaises(DeliveryPolicyError):
            policy.check_url("http://siem.customer.example/x")
        with self.assertRaises(DeliveryPolicyError):
            policy.check_url("https://evil.example/x")


class EvidencePackTest(unittest.TestCase):
    def test_build_verify_tamper(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "audit-log.json").write_text('{"a":1}', encoding="utf-8")
            (root / "evidence" / "rbac-approval.json").write_text('{"b":2}', encoding="utf-8")
            out = root / "pack.zip"
            built = build_pack([root / "evidence"], out, root=root, framework="iso27001")
            self.assertGreaterEqual(built["covered"], 2)
            self.assertTrue(verify_pack(out)["ok"])
            tampered = root / "tampered.zip"
            with zipfile.ZipFile(out) as src, zipfile.ZipFile(tampered, "w") as dst:
                for item in src.infolist():
                    data = src.read(item.filename)
                    if item.filename.endswith("audit-log.json"):
                        data = b'{"a":2}'
                    dst.writestr(item, data)
            self.assertFalse(verify_pack(tampered)["ok"])


class ScaleAndGpuTest(unittest.TestCase):
    def test_scale_small(self):
        result = run_scale(10_000)
        self.assertEqual(result["rows"], 10_000)
        self.assertGreater(result["events_per_second"], 0)
        self.assertIn("projected_daily_capacity", daily_million_projection(result))

    def test_gpu_contract(self):
        bad = validate_device_plugin({"resource_name": "gpu", "version": "v1alpha1",
                                      "endpoint": "/tmp/x.sock", "devices": []})
        self.assertFalse(bad["ok"])
        good = validate_device_plugin({"resource_name": "nvidia.com/gpu", "version": "v1beta1",
                                       "endpoint": "/var/lib/kubelet/device-plugins/gpu.sock",
                                       "devices": [{"id": "GPU-1", "health": "Healthy"}]})
        self.assertTrue(good["ok"])
        self.assertFalse(validate_dra({"apiVersion": "v1", "kind": "Pod"})["ok"])
        self.assertTrue(compatibility_matrix({"gpu_operator": "25.3.0", "driver": "580.65.06",
                                              "cuda": "12.4", "container_runtime": "containerd"})["ok"])


class LocalChecksTest(unittest.TestCase):
    def test_all_local_checks_pass_and_doc_counts(self):
        with TemporaryDirectory() as tmp:
            result = run_local_checks(Path(tmp))
            self.assertTrue(result["summary"]["ok"], result)
            self.assertGreaterEqual(result["summary"]["total"], 11)
            self.assertTrue((Path(tmp) / "local-checks.json").is_file())
            self.assertTrue((Path(tmp) / "local-checks.md").is_file())
        text = DOC.read_text(encoding="utf-8")
        rows = {}
        for line in text.splitlines():
            if line.startswith("| ER-"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) == 5:
                    rows[cells[0]] = cells
        for er in ("ER-08", "ER-16", "ER-26", "ER-27", "ER-34", "ER-39", "ER-40",
                   "ER-50", "ER-57"):
            self.assertIn(er, rows)
            self.assertTrue(rows[er][3].startswith("🟢"), er)
        m = re.search(r"绿\s*(\d+)\s*[·/]\s*黄\s*(\d+)\s*[·/]\s*红\s*(\d+).*?共\s*(\d+)\s*项", text)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(4)), len(rows))
        self.assertGreater(int(m.group(1)), 27)


if __name__ == "__main__":
    unittest.main()
