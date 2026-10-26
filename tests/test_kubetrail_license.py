"""tests/test_kubetrail_license.py — Apache-2.0 移植合规（NOTICE/归属头/许可检查工具）。"""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("check_notices", ROOT / "tools" / "check-notices.py")
check_notices = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_notices)


class LicenseCheckTest(unittest.TestCase):
    def test_repository_passes(self):
        self.assertEqual(check_notices.check(ROOT), [])
        self.assertEqual(check_notices.main(["--root", str(ROOT)]), 0)

    def test_every_port_file_has_attribution(self):
        files = sorted((ROOT / "inkblade" / "kubetrail").glob("*.py"))
        self.assertGreaterEqual(len(files), 6)
        for path in files:
            head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:16])
            self.assertIn("Apache-2.0", head, path.name)
            self.assertIn("KubeTrail", head, path.name)

    def test_notice_and_port_doc(self):
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("KubeTrail", notice)
        self.assertIn("https://github.com/ekkoo-z/KubeTrail", notice)
        self.assertIn("独立 Python 重写" if False else "independent Python reimplementation", notice)
        doc = (ROOT / "docs" / "KUBETRAIL-PORT.md").read_text(encoding="utf-8")
        self.assertIn("Apache-2.0", doc)
        self.assertIn("collector", doc)

    def test_missing_notice_fails(self):
        with TemporaryDirectory() as td:
            fake = Path(td)
            (fake / "LICENSE").write_text("Apache License Version 2.0", encoding="utf-8")
            errors = check_notices.check(fake)
            self.assertTrue(any("NOTICE" in e for e in errors))
            self.assertTrue(any("inkblade/kubetrail" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
