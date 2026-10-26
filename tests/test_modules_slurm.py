# -*- coding: utf-8 -*-
"""Slurm HPC depth modules: registry contract, two-state fixtures, surface profile."""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import LEVELS, SERIES, load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.surface import matrix
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
FIX = REPO / "lab" / "fixtures" / "slurm"
KEYS = [
    "slurmctld-config-audit", "slurmd-config-audit", "munge-auth-audit",
    "spank-plugin-integrity", "slurm-cgroup-constraint-audit",
    "slurm-node-partition-policy", "slurm-shared-storage-audit",
    "slurmrestd-exposure", "slurm-jwt-auth-audit", "slurm-accountingdbd-audit",
    "slurm-gres-gpu-isolation", "slurm-prolog-epilog-audit",
]


def _isolated(root: Path) -> Path:
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULES_DIR / "_slurm-common.py", dest / "_slurm-common.py")
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


class SlurmRegistryTest(unittest.TestCase):
    def test_twelve_modules_are_read_only_and_well_formed(self):
        with TemporaryDirectory() as tmp:
            mods = load_modules(_isolated(Path(tmp)))
        self.assertEqual(set(KEYS) - set(mods), set())
        for key in KEYS:
            meta = mods[key]
            self.assertIn(meta.series, SERIES, key)
            self.assertIn(meta.min_level, LEVELS, key)
            self.assertFalse(meta.writes, key)
            self.assertEqual(meta.requires, [], key)
            self.assertTrue(meta.required_surfaces, key)
            self.assertTrue(meta.knowledge, key)
            self.assertTrue(meta.necessity, key)

    def test_modules_do_not_depend_on_fixture_builder(self):
        for key in KEYS:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("lab.slurm", source, key)
            self.assertNotIn("fixtures/slurm", source, key)

    def test_fixture_files_exist(self):
        for posture in ("vulnerable", "fixed"):
            root = FIX / posture
            self.assertTrue(root.is_dir(), posture)
            for name in ("slurm.conf", "cgroup.conf", "plugstack.conf", "munge.conf",
                         "munge.key.meta", "slurmdbd.conf", "slurmrestd.env", "jwt.json",
                         "nodes.json", "partitions.json", "qos.json", "gres.json",
                         "prolog-epilog.json", "inventory.json"):
                self.assertTrue((root / name).is_file(), f"{posture}/{name}")


class SlurmTwoStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.modules = _isolated(Path(cls.tmp.name))
        cls.store = EvidenceStore(Path(cls.tmp.name) / "ws", workspace="lab")
        users = UserStore(Path(cls.tmp.name) / "users.json")
        users.create_user("tester", "x", "lead", ["lab"])
        cls.session = users.verify("tester", "x")
        init_roe(cls.store, {"level": "利用验证", "namespaces": ["ml"],
                             "cidrs": ["127.0.0.0/8", "10.0.0.0/8"]})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, key, posture):
        run = self.store.create_run(f"{key}-{posture}")
        before = len(run.findings)
        run_module(self.store, self.session, key, {"snapshot": str(FIX / posture)},
                   modules_dir=self.modules, run=run,
                   surface_ctx={"profile": "slurm-hpc", "enforce": True})
        return run, run.findings[before:], _summary(run, key)

    def test_vulnerable_has_high_fixed_has_none(self):
        for key in KEYS:
            with self.subTest(module=key):
                _, vuln, _ = self._run(key, "vulnerable")
                self.assertTrue([f for f in vuln if f["severity"] in ("critical", "high")],
                                f"{key} vulnerable 未产出 high/critical")
                _, fixed, _ = self._run(key, "fixed")
                self.assertEqual([f for f in fixed if f["severity"] in ("critical", "high")], [],
                                 f"{key} fixed 仍有 high/critical")

    def test_key_evidence_fields(self):
        checks = {
            "slurmctld-config-audit": {"auth_type": "auth/none", "disable_root_jobs": "NO"},
            "slurmd-config-audit": {"slurmd_user": "root"},
            "munge-auth-audit": {"key_mode": "0644", "reused_clusters": 2, "in_image": True},
            "spank-plugin-integrity": {"plugins": 2},
            "slurm-cgroup-constraint-audit": {"constrain_cores": False, "constrain_devices": False},
            "slurm-node-partition-policy": {"drain_nodes": 2, "open_partitions": 2},
            "slurm-shared-storage-audit": {"lustre": 1, "gpfs": 1},
            "slurmrestd-exposure": {"bind": "0.0.0.0:6820", "auth": "no", "jwt": "disabled"},
            "slurm-jwt-auth-audit": {"weak_hs_keys": 1, "key_file_mode": "0644"},
            "slurm-accountingdbd-audit": {"plaintext_password": True, "dbd_host": "0.0.0.0"},
            "slurm-gres-gpu-isolation": {"global_device_allow": True, "constrain_devices": False},
            "slurm-prolog-epilog-audit": {"contain": False, "scripts": 2},
        }
        for key, expected in checks.items():
            _, _, summary = self._run(key, "vulnerable")
            for field, value in expected.items():
                self.assertEqual(summary.get(field), value, f"{key}.{field}")


class SlurmProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods = load_modules(MODULES_DIR)

    def test_all_twelve_production_testable_on_slurm(self):
        doc = matrix("slurm-hpc", modules=self.mods)
        rows = {r["module"]: r for r in doc["modules"]}
        for key in KEYS:
            self.assertEqual(rows[key]["verdict"], "production-testable", key)
        self.assertGreaterEqual(doc["summary"]["default_production_testable"], 56)
        self.assertGreater(doc["summary"]["coverage_pct"], 20.0)

    def test_no_kubernetes_surface_on_slurm(self):
        doc = matrix("slurm-hpc", modules=self.mods)
        rows = {r["module"]: r for r in doc["modules"]}
        for key in ("ray-control-plane", "kubernetes-cve-catalog", "kubelet-surface"):
            if key in rows:
                self.assertEqual(rows[key]["verdict"], "no-surface", key)


if __name__ == "__main__":
    unittest.main()
