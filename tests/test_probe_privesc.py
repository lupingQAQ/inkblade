# -*- coding: utf-8 -*-
"""Privilege-chain templates against the privesc snapshot fixtures."""
from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.tpl.backends import LocalBackend
from inkblade.tpl.engine import Engine
from inkblade.tpl.schema import load_template

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
FIX = ROOT / "lab" / "fixtures" / "privesc"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"

CASES = {
    "rbac-escalate-verb": "rbac.json",
    "rbac-bind-verb": "rbac.json",
    "impersonate-abuse": "rbac.json",
    "sa-token-request": "rbac.json",
    "csr-approve": "rbac.json",
    "admission-webhook-write": "admission.json",
    "apiservice-hijack": "admission.json",
    "crd-conversion-webhook": "admission.json",
    "kubelet-10250-exec": "node.json",
    "etcd-direct-access": "node.json",
    "image-pull-secret-theft": "credentials.json",
    "gitops-secret-read": "platform.json",
    "gpu-operator-driver-escape": "platform.json",
    "cni-plugin-exec": "platform.json",
    "csi-node-plugin-escape": "platform.json",
}


def _run(key: str, fixture: str | None = None, empty: bool = False,
         mode: str = "probe-only", demo_target: str = "") -> dict:
    module_dir = MODULES / key
    meta = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=meta)
    with TemporaryDirectory() as tmp:
        if fixture:
            path = FIX / fixture
        else:
            path = Path(tmp) / "empty.json"
            path.write_text("{}", encoding="utf-8")
        params = {"fixture": str(path), "mode": mode, "demo_target": demo_target}
        return Engine(LocalBackend(workdir=tmp)).run(
            template, params, {"marker": "INKBLADE-LAB"})


def _digest(result: dict) -> str:
    return hashlib.sha256(json.dumps(
        {"findings": result["findings"], "steps": result["steps"]},
        ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


class TestPrivescTemplates(unittest.TestCase):
    evidence: dict = {}

    @classmethod
    def tearDownClass(cls):
        if not cls.evidence:
            return
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = {"schema": "inkblade-probe-coverage-evidence-v1", "entries": {}}
        doc.setdefault("entries", {})
        for key, entry in cls.evidence.items():
            current = doc["entries"].get(key) or {}
            if str(current.get("runtime") or "").startswith("rust"):
                continue  # native probe evidence is authoritative
            doc["entries"][key] = entry
        doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        EVIDENCE.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    def test_fixture_detection(self):
        for key, fixture in CASES.items():
            with self.subTest(module=key):
                result = _run(key, fixture)
                self.assertNotEqual(result["status"], "error", result.get("error"))
                sevs = {f["sev"] for f in result["findings"]}
                self.assertTrue({"critical", "high", "medium"} & sevs, f"{key}: {sevs}")
                self.assertTrue(result["artifacts"], key)
                self.evidence[key] = {
                    "tested": True, "mode": "fixture-positive/negative",
                    "runtime": result["runtime"],
                    "findings_positive": len(result["findings"]),
                    "findings_negative": 0, "steps": len(result["steps"]),
                    "evidence": _digest(result),
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "note": "privesc fixture detection",
                }

    def test_empty_snapshot_has_no_high_findings(self):
        for key in CASES:
            with self.subTest(module=key):
                result = _run(key)
                self.assertNotEqual(result["status"], "error", result.get("error"))
                sevs = {f["sev"] for f in result["findings"]}
                self.assertFalse({"critical", "high"} & sevs, f"{key}: {sevs}")

    def test_write_modules_skip_in_probe_only(self):
        for key in ("rbac-bind-verb", "admission-webhook-write"):
            with self.subTest(module=key):
                with TemporaryDirectory() as tmp:
                    target = Path(tmp) / "demo.yaml"
                    result = _run(key, CASES[key], mode="probe-only",
                                  demo_target=str(target))
                    self.assertFalse(target.exists())
                    self.assertTrue(any(s.get("skipped") for s in result["steps"]))
                    written = _run(key, CASES[key], mode="backup-write",
                                   demo_target=str(target))
                    self.assertTrue(target.exists())
                    self.assertIn("INKBLADE-", target.read_text(encoding="utf-8"))
                    self.assertTrue(any(f["id"] == "demo-written"
                                        for f in written["findings"]))


if __name__ == "__main__":
    unittest.main()
