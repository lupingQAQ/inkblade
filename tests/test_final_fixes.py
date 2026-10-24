import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.backup import BackupManager
from trident.core.evidence import EvidenceStore


class TestFinalFixes(unittest.TestCase):
    def test_backup_gate_invalid_targets(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="w")
            run = store.create_run("r")
            bm = BackupManager(store, run)
            # 空 → 无回执
            self.assertIsNone(bm.snapshot("s", []))
            # 非空但全无效（不存在路径/未知 kind）→ 必须同样无回执
            self.assertIsNone(bm.snapshot("s", [{"kind": "file", "path": str(Path(tmp) / "nope")}]))
            self.assertIsNone(bm.snapshot("s", [{"kind": "mystery", "path": "x"}]))
            # 部分有效 → 有回执
            f = Path(tmp) / "ok.txt"
            f.write_text("v", encoding="utf-8")
            self.assertIsNotNone(bm.snapshot("s", [
                {"kind": "file", "path": str(f)},
                {"kind": "mystery", "path": "x"},
            ]))

    def test_manifest_empty_is_false(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="w")
            run = store.create_run("r")
            run.add_step("s", "c", {}, "ok")
            run_dir = Path(tmp) / "evidence" / "w" / "r"
            self.assertTrue(store.verify_manifest("r"))
            (run_dir / "manifest.sha256").write_text("", encoding="utf-8")
            self.assertFalse(store.verify_manifest("r"))


if __name__ == "__main__":
    unittest.main()
