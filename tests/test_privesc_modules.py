"""提权模块族：15 个模块注册契约、脆弱夹具命中、写类备份闸门、级别闸门与演示回滚。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.backup import BackupManager
from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import ExecutionLocked, init_roe
from trident.core.runner import BackupGateRefused, run_module
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"
FIXTURES = REPO / "lab" / "fixtures" / "privesc"

CASES = {
    "rbac-escalate-verb": ("rbac.json", True, "利用验证"),
    "rbac-bind-verb": ("rbac.json", True, "利用验证"),
    "impersonate-abuse": ("rbac.json", False, "只读侦察"),
    "sa-token-request": ("rbac.json", False, "只读侦察"),
    "csr-approve": ("rbac.json", False, "只读侦察"),
    "admission-webhook-write": ("admission.json", True, "利用验证"),
    "apiservice-hijack": ("admission.json", False, "只读侦察"),
    "crd-conversion-webhook": ("admission.json", False, "只读侦察"),
    "kubelet-10250-exec": ("node.json", False, "只读侦察"),
    "etcd-direct-access": ("node.json", False, "只读侦察"),
    "image-pull-secret-theft": ("credentials.json", False, "只读侦察"),
    "gitops-secret-read": ("platform.json", False, "只读侦察"),
    "gpu-operator-driver-escape": ("platform.json", False, "只读侦察"),
    "cni-plugin-exec": ("platform.json", False, "只读侦察"),
    "csi-node-plugin-escape": ("platform.json", False, "只读侦察"),
}


class TestPrivescModules(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "利用验证", "namespaces": ["privesc-lab"], "cidrs": ["127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _params(self, fixture: str) -> dict:
        target = self.root / "demo-target.txt"
        target.write_text("original", encoding="utf-8")
        return {
            "fixture": str(FIXTURES / fixture),
            "backup_targets": [{"kind": "file", "path": str(target)}],
        }

    def test_catalog_contract(self):
        mods = load_modules(MODULES_DIR)
        for key, (fixture, writes, level) in CASES.items():
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertRegex(key, r"^[a-z][a-z0-9-]*$")
            self.assertEqual(meta.key, meta.path.name)
            self.assertEqual(meta.series, "权限链", key)
            self.assertEqual(meta.writes, writes, key)
            self.assertEqual(meta.min_level, level, key)
            self.assertTrue((meta.path / "run.py").is_file(), key)

    def test_fixture_detection_hits(self):
        for key, (fixture, _writes, _level) in CASES.items():
            with self.subTest(module=key):
                result = run_module(self.store, self.session, key, self._params(fixture),
                                    modules_dir=MODULES_DIR)
                run = self.store.open_run(result["run"])
                rows = [f for f in run.findings if f["step_key"] == key]
                self.assertGreaterEqual(len(rows), 1, f"{key} 未产出 finding")
                self.assertIn(rows[0]["severity"], ("critical", "high", "medium", "low", "info"))
                self.assertTrue(rows[0]["title"])

    def test_write_gate_refused_without_targets(self):
        for key, (_fixture, writes, _level) in CASES.items():
            if not writes:
                continue
            with self.subTest(module=key):
                with self.assertRaises(BackupGateRefused) as cm:
                    run_module(self.store, self.session, key,
                               {"fixture": str(FIXTURES / CASES[key][0])},
                               modules_dir=MODULES_DIR)
                self.assertEqual(cm.exception.exit_code, 91)

    def test_level_gate_blocks_readonly(self):
        store = EvidenceStore(self.root / "ro", workspace="ro-lab")
        init_roe(store, fields={"level": "只读侦察", "namespaces": ["privesc-lab"],
                                "cidrs": ["127.0.0.0/8"]})
        with self.assertRaises(ExecutionLocked) as cm:
            run_module(store, self.session, "rbac-escalate-verb",
                       self._params("rbac.json"), modules_dir=MODULES_DIR)
        self.assertIn("级别不足", str(cm.exception))

    def test_demo_write_then_rollback(self):
        for key, fixture in (("rbac-escalate-verb", "rbac.json"),
                             ("admission-webhook-write", "admission.json")):
            with self.subTest(module=key):
                target = self.root / f"{key}.txt"
                target.write_text("original", encoding="utf-8")
                params = self._params(fixture)
                params.update({
                    "mode": "backup-write",
                    "demo_target": str(target),
                    "backup_targets": [{"kind": "file", "path": str(target)}],
                })
                result = run_module(self.store, self.session, key, params,
                                    modules_dir=MODULES_DIR)
                written = target.read_text(encoding="utf-8")
                self.assertNotEqual(written, "original")
                self.assertIn("TRIDENT-", written)
                bm = BackupManager(self.store, self.store.open_run(result["run"]))
                rollback = bm.rollback(f"{key}-demo")
                self.assertGreaterEqual(rollback["restored"], 1)
                self.assertEqual(target.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()
