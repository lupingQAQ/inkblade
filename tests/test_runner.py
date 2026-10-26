import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore


def _fixture_module(root: Path, key: str, writes: bool, fail: bool = False):
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "key": key, "name": {"zh": key, "en": key}, "series": "横向利用",
        "description": "t", "min_level": "利用验证", "writes": writes, "requires": [],
    }
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    body = "import pathlib\n\ndef run(ctx, params):\n"
    if fail:
        body += "    raise RuntimeError('boom')\n"
    else:
        body += (
            "    p = pathlib.Path(params['target'])\n"
            "    p.write_text('INKBLADE-' + ctx['marker'], encoding='utf-8')\n"
            "    return {'summary': 'wrote marker', 'artifacts': [str(p)],"
            " 'findings': [{'sev': 'high', 'title': 'marker written', 'detail': 'x'}]}\n"
        )
    (d / "run.py").write_text(body, encoding="utf-8")


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={"level": "利用验证", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"]})

    def tearDown(self):
        self.tmp.cleanup()

    def test_backup_gate_blocks_write(self):
        _fixture_module(self.root, "weight-pull-demo", writes=True)
        target = self.root / "victim.txt"
        target.write_text("original", encoding="utf-8")
        with self.assertRaises(BackupGateRefused) as cm:
            run_module(
                self.store, self.session, "weight-pull-demo",
                params={"target": str(target)},  # 无 backup_targets → 必须拒绝
                modules_dir=self.root / "modules",
            )
        self.assertEqual(cm.exception.exit_code, 91)
        self.assertEqual(target.read_text(encoding="utf-8"), "original")  # 模块未被执行

    def test_backup_then_execute_and_rollback(self):
        _fixture_module(self.root, "weight-pull-demo", writes=True)
        target = self.root / "victim.txt"
        target.write_text("original", encoding="utf-8")
        result = run_module(
            self.store, self.session, "weight-pull-demo",
            params={
                "target": str(target),
                "backup_targets": [{"kind": "file", "path": str(target)}],
            },
            modules_dir=self.root / "modules",
        )
        self.assertIn("INKBLADE-", target.read_text(encoding="utf-8"))
        bm = BackupManager(self.store, self.store.open_run(result["run"]))
        bm.rollback("weight-pull-demo")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_audit_row_written_and_failure_leaves_no_residue(self):
        _fixture_module(self.root, "boom-module", writes=False, fail=True)
        target = self.root / "residue.txt"
        run = self.store.create_run("boom-module")
        with self.assertRaises(RuntimeError):
            run_module(self.store, self.session, "boom-module",
                       params={"target": str(target)}, modules_dir=self.root / "modules", run=run)
        self.assertFalse(target.exists())
        rows = run.query("SELECT action, result FROM actions ORDER BY id")
        self.assertEqual(rows[-1][1].split(":")[0], "failed")

    def test_marker_namespaced(self):
        _fixture_module(self.root, "weight-pull-demo", writes=True)
        target = self.root / "m.txt"
        target.write_text("o", encoding="utf-8")
        result = run_module(self.store, self.session, "weight-pull-demo",
                            params={"target": str(target), "backup_targets": [{"kind": "file", "path": str(target)}]},
                            modules_dir=self.root / "modules")
        run = self.store.open_run(result["run"])
        self.assertTrue(run.name.startswith("run-"))


if __name__ == "__main__":
    unittest.main()
