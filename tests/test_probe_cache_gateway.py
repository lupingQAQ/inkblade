# -*- coding: utf-8 -*-
"""Two-state dynamic verification: cache (7) and AI gateway (8) templates."""
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

from ai_gateway_sim import start_all as start_gateway  # noqa: E402
from cache_sim import start_all as start_cache  # noqa: E402
from inkblade.tpl.backends import LocalBackend  # noqa: E402
from inkblade.tpl.engine import Engine  # noqa: E402
from inkblade.tpl.schema import load_template  # noqa: E402

MODULES = ROOT / "inkblade" / "modules"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"

CACHE = ["cache-timing-sidechannel", "cache-eviction-residue", "cache-salt-policy-audit",
         "remote-kv-pool-isolation", "router-cache-metrics-leak",
         "similarity-cache-false-hit", "cache-poison-persistence"]
GATEWAY = ["aigateway-auth-bypass", "aigateway-cache-cross-tenant", "aigateway-fingerprint",
           "aigateway-guardrail-bypass", "aigateway-log-pii-leak", "aigateway-quota-bypass",
           "aigateway-route-hijack", "aigateway-upstream-key-exfil"]


class EvidenceMixin:
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


def _run(key: str, target: str, params: dict | None = None) -> dict:
    module_dir = MODULES / key
    meta = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=meta)
    payload = {"target": target, "mode": "probe-only", **(params or {})}
    with TemporaryDirectory() as tmp:
        return Engine(LocalBackend(workdir=tmp)).run(
            template, payload, {"marker": "INKBLADE-LAB"})


def _sev(result: dict) -> list[str]:
    return [f["sev"] for f in result["findings"]]


def _digest(result: dict) -> str:
    return hashlib.sha256(json.dumps(
        {"findings": result["findings"], "steps": result["steps"]},
        ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


class CacheTemplates(EvidenceMixin, unittest.TestCase):
    def test_cache_two_state(self):
        for key in CACHE:
            with self.subTest(module=key):
                with start_cache(mode="vulnerable") as lab:
                    positive = _run(key, lab.url(""))
                with start_cache(mode="fixed") as lab:
                    negative = _run(key, lab.url(""))
                self.assertNotEqual(positive["status"], "error", positive.get("error"))
                self.assertNotEqual(negative["status"], "error", negative.get("error"))
                self.assertTrue({"high", "critical"} & set(_sev(positive)),
                                f"{key}: {_sev(positive)}")
                self.assertFalse({"high", "critical", "medium"} & set(_sev(negative)),
                                 f"{key}: {_sev(negative)}")
                self.assertTrue(positive["artifacts"], key)
                self.evidence[key] = {
                    "tested": True, "mode": "vulnerable/fixed",
                    "runtime": positive["runtime"],
                    "findings_positive": len(positive["findings"]),
                    "findings_negative": len(negative["findings"]),
                    "steps": len(positive["steps"]), "evidence": _digest(positive),
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "note": "cache_sim two-state",
                }


class GatewayTemplates(EvidenceMixin, unittest.TestCase):
    def test_gateway_two_state(self):
        for key in GATEWAY:
            with self.subTest(module=key):
                with start_gateway(mode="vulnerable") as lab:
                    positive = _run(key, lab.url(""))
                with start_gateway(mode="fixed") as lab:
                    negative = _run(key, lab.url(""))
                self.assertNotEqual(positive["status"], "error", positive.get("error"))
                self.assertNotEqual(negative["status"], "error", negative.get("error"))
                self.assertTrue({"high", "critical"} & set(_sev(positive)),
                                f"{key}: {_sev(positive)}")
                self.assertFalse({"high", "critical", "medium"} & set(_sev(negative)),
                                 f"{key}: {_sev(negative)}")
                self.assertTrue(positive["artifacts"], key)
                self.evidence[key] = {
                    "tested": True, "mode": "vulnerable/fixed",
                    "runtime": positive["runtime"],
                    "findings_positive": len(positive["findings"]),
                    "findings_negative": len(negative["findings"]),
                    "steps": len(positive["steps"]), "evidence": _digest(positive),
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "note": "ai_gateway_sim two-state",
                }


if __name__ == "__main__":
    unittest.main()
