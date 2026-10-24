"""权限链模块族测试：fixture 检测命中 + 备份闸门/级别双重拦截 + 演示回滚。"""

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
FIXTURES = REPO / "lab" / "fixtures" / "perm"

PERM_KEYS = [
    "vllm-operator-rbac-escalation",
    "kuberay-operator-escalation",
    "lws-secrets-lateral",
    "overprivileged-sa-escalation",
    "privileged-gpu-pod-escape",
    "runtime-socket-escape",
]

# 模块 -> 检测 fixture
DETECT_FIXTURE = {
    "vllm-operator-rbac-escalation": "clusterroles.json",
    "kuberay-operator-escalation": "clusterroles.json",
    "lws-secrets-lateral": "clusterroles.json",
    "overprivileged-sa-escalation": "cani-matrix.json",
    "privileged-gpu-pod-escape": "privileged-pods.json",
    "runtime-socket-escape": "privileged-pods.json",
}


class TestPermModules(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "利用验证", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        return run_module(self.store, self.session, key, params, modules_dir=MODULES_DIR)

    def test_perm_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key in PERM_KEYS:
            self.assertIn(key, mods, f"缺少权限链模块 {key}")
            self.assertEqual(mods[key].series, "权限链")
            self.assertEqual(mods[key].min_level, "利用验证")
            self.assertTrue(mods[key].writes, "含演示分支的权限链模块必须 writes=true")

    def test_detection_hits_on_fixtures(self):
        for key in PERM_KEYS:
            fixture = FIXTURES / DETECT_FIXTURE[key]
            with self.subTest(module=key):
                result = self._run(key, {
                    "fixture": str(fixture),
                    "backup_targets": [{"kind": "file", "path": str(fixture)}],
                })
                run = self.store.open_run(result["run"])
                rows = [f for f in run.findings if f["step_key"] == key]
                self.assertGreaterEqual(len(rows), 1, f"{key} 检测未产出 finding")
                self.assertTrue(rows[0]["title"], "finding 必须有标题")
                self.assertIn(rows[0]["severity"], ("high", "medium", "low", "info"))

    def test_backup_gate_refused_without_targets(self):
        for key in PERM_KEYS:
            with self.subTest(module=key):
                with self.assertRaises(BackupGateRefused) as cm:
                    self._run(key, {"fixture": str(FIXTURES / DETECT_FIXTURE[key])})
                self.assertEqual(cm.exception.exit_code, 91)

    def test_level_gate_blocks_at_readonly(self):
        store = EvidenceStore(self.root / "ws-ro", workspace="ro-lab")
        init_roe(store, fields={"level": "只读侦察", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"]})
        fixture = FIXTURES / "clusterroles.json"
        with self.assertRaises(ExecutionLocked) as cm:
            run_module(store, self.session, "vllm-operator-rbac-escalation",
                       {"fixture": str(fixture),
                        "backup_targets": [{"kind": "file", "path": str(fixture)}]},
                       modules_dir=MODULES_DIR)
        self.assertIn("级别不足", str(cm.exception))

    def test_demo_write_then_rollback_restores(self):
        for key in ("vllm-operator-rbac-escalation", "privileged-gpu-pod-escape"):
            with self.subTest(module=key):
                demo = self.root / f"demo-{key}.txt"
                demo.write_text("original", encoding="utf-8")
                fixture = FIXTURES / DETECT_FIXTURE[key]
                result = self._run(key, {
                    "fixture": str(fixture),
                    "mode": "backup-write",
                    "demo_target": str(demo),
                    "backup_targets": [{"kind": "file", "path": str(demo)}],
                })
                self.assertNotEqual(demo.read_text(encoding="utf-8"), "original",
                                    f"{key} 演示分支未写入")
                self.assertIn("TRIDENT-", demo.read_text(encoding="utf-8"))
                bm = BackupManager(self.store, self.store.open_run(result["run"]))
                bm.rollback(f"{key}-demo")
                self.assertEqual(demo.read_text(encoding="utf-8"), "original",
                                 f"{key} 回滚后必须还原")

    def test_demo_requires_explicit_mode(self):
        demo = self.root / "demo-quiet.txt"
        demo.write_text("original", encoding="utf-8")
        fixture = FIXTURES / "clusterroles.json"
        self._run("vllm-operator-rbac-escalation", {
            "fixture": str(fixture),
            "demo_target": str(demo),
            "backup_targets": [{"kind": "file", "path": str(fixture)}],
        })
        self.assertEqual(demo.read_text(encoding="utf-8"), "original",
                         "未指定 mode=backup-write 时不得执行演示动作")


if __name__ == "__main__":
    unittest.main()
