# -*- coding: utf-8 -*-
"""CVE templates: real HTTP two-state replay against the mock range."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from inkblade.tpl.backends import LocalBackend  # noqa: E402
from inkblade.tpl.engine import Engine  # noqa: E402
from inkblade.tpl.schema import load_template  # noqa: E402
from template_range import Range  # noqa: E402

MODULES = ROOT / "inkblade" / "modules"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"

# 23 HTTP CVE templates generated from _cve-specs.py (snapshot analyzers excluded)
KEYS = [
    "ray-job-marker-rce", "sglang-zmq-pickle-rce", "sglang-route-poison",
    "sglang-weight-exfil", "vllm-pickle-pipe-rce", "vllm-timing-oracle",
    "litellm-default-key-exfil", "litellm-config-update-rce",
    "ipmi-cipher-zero-bypass", "redfish-default-credentials",
    "sonic-config-plane-write", "sonic-rsyslog-injection",
    "cumulus-nvue-injection", "dify-code-node-escape",
    "open-webui-file-overwrite", "mlflow-trace-write", "mlflow-model-rce",
    "llamafactory-checkpoint-rce", "msswift-dataset-pickle-rce",
    "megatron-checkpoint-rce", "deepspeed-checkpoint-rce",
    "torch-weights-bypass-rce", "hami-scheduler-auth-gap",
]

RESPONSE = {
    "ok": True, "found": True, "deleted": 1, "stored": True, "applied": True,
    "version": "0.6.9", "mode": "vulnerable", "marker": "INKBLADE-BENIGN",
    "upstreams": [{"provider": "openai", "api_key": "sk-live-abcdef123456"}],
    "master_key": "sk-master-abc", "key_class": "default", "cipher": 0,
    "privilege": "admin", "username": "admin", "session": "mock",
    "weights": "weights.bin", "jobs": [{"job_id": "job-1"}], "features": ["code"],
}


def _run(key: str, target: str, mode: str) -> dict:
    module_dir = MODULES / key
    meta = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=meta)
    with TemporaryDirectory() as tmp:
        return Engine(LocalBackend(workdir=tmp)).run(
            template, {"target": target, "mode": mode},
            {"marker": "INKBLADE-LAB"})


def _digest(result: dict) -> str:
    return hashlib.sha256(json.dumps(
        {"findings": result["findings"], "steps": result["steps"]},
        ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


class CveTemplates(unittest.TestCase):
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

    def test_vulnerable_and_fixed(self):
        for key in KEYS:
            meta = json.loads((MODULES / key / "module.json").read_text(encoding="utf-8"))
            mode = "backup-write" if meta["writes"] else "probe-only"
            with self.subTest(module=key):
                scenarios = {"vulnerable": {"*": {"status": 200, "json": RESPONSE}},
                             "fixed": {"*": {"status": 403,
                                             "json": {"error": "denied"}}}}
                with Range(scenarios) as rng:
                    positive = _run(key, rng.url(), mode)
                with Range(scenarios) as rng:
                    rng.set_profile("fixed")
                    negative = _run(key, rng.url(), mode)
                self.assertNotEqual(positive["status"], "error", positive.get("error"))
                self.assertNotEqual(negative["status"], "error", negative.get("error"))
                self.assertTrue({"high", "critical", "medium"} &
                                {f["sev"] for f in positive["findings"]},
                                f"{key}: {[f['sev'] for f in positive['findings']]}")
                self.assertFalse({"high", "critical"} &
                                 {f["sev"] for f in negative["findings"]},
                                 f"{key}: {[f['sev'] for f in negative['findings']]}")
                cves = [c for f in positive["findings"] for c in (f.get("cves") or [])]
                template = json.loads((MODULES / key / "template.json")
                                      .read_text(encoding="utf-8"))
                declared = [c for f in template["findings"] for c in (f.get("cves") or [])]
                if declared:
                    self.assertTrue(cves, f"{key}: CVE ids lost")
                self.evidence[key] = {
                    "tested": True, "mode": "vulnerable/fixed",
                    "runtime": positive["runtime"],
                    "findings_positive": len(positive["findings"]),
                    "findings_negative": len(negative["findings"]),
                    "steps": len(positive["steps"]), "evidence": _digest(positive),
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "note": "template_range HTTP replay; CVE ids preserved",
                }


if __name__ == "__main__":
    unittest.main()
