# -*- coding: utf-8 -*-
"""Long-context templates: two-state against lab/longctx_sim.py."""
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
from longctx_sim import start_all  # noqa: E402

MODULES = ROOT / "inkblade" / "modules"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"
KEYS = ["prefix-cache-cross-tenant-leak", "prefill-decode-kv-channel-unauth",
        "context-limit-bypass", "long-context-window-exhaustion",
        "long-context-memory-amplification", "kv-cache-integrity-poison",
        "checkpoint-shard-poison", "long-context-training-collective-surface"]
WRITE = {"kv-cache-integrity-poison", "checkpoint-shard-poison"}


def _run(key: str, target: str, mode: str) -> dict:
    module_dir = MODULES / key
    meta = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=meta)
    with TemporaryDirectory() as tmp:
        return Engine(LocalBackend(workdir=tmp)).run(
            template, {"target": target, "mode": mode, "tenant": "tenant-a"},
            {"marker": "INKBLADE-LAB"})


def _digest(result: dict) -> str:
    return hashlib.sha256(json.dumps(
        {"findings": result["findings"], "steps": result["steps"]},
        ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


class LongContextTemplates(unittest.TestCase):
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
        doc.setdefault("entries", {}).update(cls.evidence)
        doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        EVIDENCE.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    def test_two_state(self):
        for key in KEYS:
            mode = "backup-write" if key in WRITE else "probe-only"
            with self.subTest(module=key):
                with start_all(mode="vulnerable") as lab:
                    positive = _run(key, lab.url(""), mode)
                with start_all(mode="fixed") as lab:
                    negative = _run(key, lab.url(""), mode)
                self.assertNotEqual(positive["status"], "error", positive.get("error"))
                self.assertNotEqual(negative["status"], "error", negative.get("error"))
                self.assertTrue({"high", "critical", "medium"} &
                                {f["sev"] for f in positive["findings"]},
                                f"{key}: {[f['sev'] for f in positive['findings']]}")
                self.assertFalse({"high", "critical"} &
                                 {f["sev"] for f in negative["findings"]},
                                 f"{key}: {[f['sev'] for f in negative['findings']]}")
                self.assertTrue(positive["artifacts"], key)
                self.evidence[key] = {
                    "tested": True, "mode": "vulnerable/fixed",
                    "runtime": positive["runtime"],
                    "findings_positive": len(positive["findings"]),
                    "findings_negative": len(negative["findings"]),
                    "steps": len(positive["steps"]), "evidence": _digest(positive),
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "note": "longctx_sim two-state",
                }


if __name__ == "__main__":
    unittest.main()
