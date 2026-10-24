import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

PY = sys.executable


class TestCli(unittest.TestCase):
    def test_help_smoke(self):
        r = subprocess.run([PY, "-m", "trident", "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("module", r.stdout)

    def test_module_list(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp) / "modules" / "sample-probe"
            d.mkdir(parents=True)
            (d / "module.json").write_text(json.dumps({
                "key": "sample-probe", "name": {"zh": "样例", "en": "sample"},
                "series": "侦察", "description": "t", "min_level": "只读侦察",
                "writes": False, "requires": [],
            }), encoding="utf-8")
            (d / "run.py").write_text("def run(ctx, params):\n    return {'summary': 'ok'}\n", encoding="utf-8")
            r = subprocess.run(
                [PY, "-m", "trident", "module", "list", "--modules-dir", str(Path(tmp) / "modules")],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("sample-probe", r.stdout)


if __name__ == "__main__":
    unittest.main()
