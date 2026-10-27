import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

PY = sys.executable


class TestCli(unittest.TestCase):
    def test_help_smoke(self):
        r = subprocess.run([PY, "-m", "inkblade", "--help"], capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("module", r.stdout.decode("utf-8", "replace"))

    def test_module_list(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp) / "modules" / "sample-probe"
            d.mkdir(parents=True)
            (d / "module.json").write_text(json.dumps({
                "key": "sample-probe", "name": {"zh": "样例", "en": "sample"},
                "series": "侦察", "description": "t", "min_level": "只读侦察",
                "writes": False, "requires": [],
            }), encoding="utf-8")
            (d / "template.json").write_text(json.dumps({
                "schema": "inkblade-probe-template-v1", "key": "sample-probe",
                "version": "1.0.0",
                "meta": {"name": {"zh": "sample", "en": "sample"}, "series": "侦察",
                         "min_level": "只读侦察", "writes": False, "requires": []},
                "steps": [{"id": "noop", "op": "fs", "action": "stat", "path": "/",
                           "save": "noop"}],
                "findings": [],
            }, ensure_ascii=False), encoding="utf-8")
            r = subprocess.run(
                [PY, "-m", "inkblade", "module", "list", "--modules-dir", str(Path(tmp) / "modules")],
                capture_output=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            self.assertIn("sample-probe", r.stdout.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
