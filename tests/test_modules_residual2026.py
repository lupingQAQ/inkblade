# -*- coding: utf-8 -*-
"""R01–R07 residual gap modules: contract, two-state fixtures, sources and profile gating."""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.registry import LEVELS, SERIES, load_modules
from trident.core.roe import init_roe
from trident.core.runner import run_module
from trident.core.surface import matrix
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"
FIX = REPO / "lab" / "fixtures" / "residual2026"
KEYS = [
    "hypervisor-audit-integrity", "agent-skill-registry-supply-chain",
    "operator-cross-namespace-reference", "mcp-control-plane-governance",
    "ai-infra-baseline", "inference-tenant-isolation-baseline",
    "agent-native-control-plane",
]
DISABLED = {
    "hypervisor-audit-integrity", "agent-skill-registry-supply-chain",
    "mcp-control-plane-governance", "agent-native-control-plane",
}


def _isolated(root: Path) -> Path:
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULES_DIR / "_residual2026-common.py",
                dest / "_residual2026-common.py")
    for key in KEYS:
        shutil.copytree(MODULES_DIR / key, dest / key,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    load_modules(dest)
    return dest


def _summary(run, key):
    rows = run.query(
        "SELECT result_summary FROM steps WHERE run=? AND step_key=? ORDER BY id DESC LIMIT 1",
        (run.name, key),
    )
    return json.loads(rows[0][0]) if rows else {}


class ResidualContractTest(unittest.TestCase):
    def test_seven_modules_and_default_gating(self):
        with TemporaryDirectory() as tmp:
            mods = load_modules(_isolated(Path(tmp)))
        self.assertEqual(set(KEYS) - set(mods), set())
        for key in KEYS:
            meta = mods[key]
            self.assertIn(meta.series, SERIES, key)
            self.assertIn(meta.min_level, LEVELS, key)
            self.assertFalse(meta.writes, key)
            self.assertEqual(meta.requires, [], key)
            self.assertTrue(meta.knowledge, key)
            self.assertTrue(meta.necessity, key)
            self.assertIn("CONFERENCE-2026-GAPS", meta.knowledge, key)
            if key in DISABLED:
                self.assertFalse(meta.default_enabled, key)
                self.assertTrue(meta.default_disabled_reason, key)
            else:
                self.assertTrue(meta.default_enabled, key)

    def test_modules_do_not_import_fixture_builder(self):
        for key in KEYS:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("lab.residual", source, key)
            self.assertNotIn("fixtures/residual2026", source, key)

    def test_fixtures_exist(self):
        for posture in ("vulnerable.json", "fixed.json"):
            self.assertTrue((FIX / posture).is_file(), posture)


class ResidualTwoStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.modules = _isolated(Path(cls.tmp.name))
        cls.store = EvidenceStore(Path(cls.tmp.name) / "ws", workspace="lab")
        users = UserStore(Path(cls.tmp.name) / "users.json")
        users.create_user("tester", "x", "lead", ["lab"])
        cls.session = users.verify("tester", "x")
        init_roe(cls.store, {"level": "利用验证", "namespaces": ["ml"],
                             "cidrs": ["127.0.0.0/8"]})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, key, posture):
        run = self.store.create_run(f"{key}-{posture}")
        before = len(run.findings)
        params = {"snapshot": str(FIX / f"{posture}.json")}
        if key in DISABLED:
            params["probe"] = True
        run_module(self.store, self.session, key, params, modules_dir=self.modules,
                   run=run, surface_ctx={"probe": key in DISABLED, "enforce": True}
                   if key in DISABLED else None)
        return run, run.findings[before:], _summary(run, key)

    def test_vulnerable_high_fixed_none(self):
        for key in KEYS:
            with self.subTest(module=key):
                _, vuln, _ = self._run(key, "vulnerable")
                self.assertTrue([f for f in vuln if f["severity"] in ("critical", "high")],
                                f"{key} vulnerable 未产出 high/critical")
                _, fixed, _ = self._run(key, "fixed")
                self.assertEqual([f for f in fixed if f["severity"] in ("critical", "high")], [],
                                 f"{key} fixed 仍有 high/critical")

    def test_evidence_fields(self):
        expected = {
            "hypervisor-audit-integrity": {"collector_location": "guest",
                                           "guest_writable_log": True,
                                           "hypervisor_stream": False},
            "agent-skill-registry-supply-chain": {"signature_required": False,
                                                  "publisher_allowlist": 0},
            "operator-cross-namespace-reference": {"operators": 1, "cross_namespace_refs": 2},
            "mcp-control-plane-governance": {"servers": 1, "critical": 1},
            "ai-infra-baseline": {"services": 3, "insecure": 3, "egress_metadata": True},
            "inference-tenant-isolation-baseline": {"cache_salt": False,
                                                    "prefix_cache_shared": True,
                                                    "quota_per_tenant": False},
            "agent-native-control-plane": {"agents": 2, "agent_identity": False,
                                           "approval_gate": False, "sandbox": False},
        }
        for key, fields in expected.items():
            _, _, summary = self._run(key, "vulnerable")
            for field, value in fields.items():
                self.assertEqual(summary.get(field), value, f"{key}.{field}")


class ResidualProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods = load_modules(MODULES_DIR)

    def test_profile_verdicts(self):
        expected = {
            ("operator-cross-namespace-reference", "bare-k8s-gpu"): "production-testable",
            ("operator-cross-namespace-reference", "slurm-hpc"): "no-surface",
            ("ai-infra-baseline", "ray-vllm"): "production-testable",
            ("ai-infra-baseline", "slurm-hpc"): "production-testable",
            ("inference-tenant-isolation-baseline", "gpu-pooling"): "production-testable",
            ("inference-tenant-isolation-baseline", "slurm-hpc"): "production-testable",
            ("hypervisor-audit-integrity", "bare-k8s-gpu"): "no-surface",
            ("agent-skill-registry-supply-chain", "ray-vllm"): "no-surface",
            ("mcp-control-plane-governance", "bare-k8s-gpu"): "no-surface",
            ("agent-native-control-plane", "airgapped"): "no-surface",
        }
        cache = {}
        for (module, profile), verdict in expected.items():
            if profile not in cache:
                cache[profile] = matrix(profile, modules=self.mods)
            row = next(r for r in cache[profile]["modules"] if r["module"] == module)
            self.assertEqual(row["verdict"], verdict, f"{module}/{profile}")


if __name__ == "__main__":
    unittest.main()
