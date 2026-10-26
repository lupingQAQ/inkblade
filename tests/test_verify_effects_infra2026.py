"""tests/test_verify_effects_infra2026.py — 2026 infra 三项实效。

隔离加载模块（跳过并行在途的不合法 module.json），只断言本任务新增的三项存在、PASS、
证据字段正确。
"""

import json
import re
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.registry import LEVELS, SERIES, load_modules

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "inkblade" / "verify-effects.py"
MODULES_DIR = REPO / "inkblade" / "modules"
INFRA_IDS = {
    "infra2026-coco-attestation-mismatch",
    "infra2026-spire-wildcard-identity",
    "infra2026-pq-tls-weak-posture",
}
_KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def _sanitized_modules(root: Path) -> Path:
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    for common in MODULES_DIR.glob("_*.py"):
        shutil.copy(common, dest / common.name)
    for folder in sorted(p for p in MODULES_DIR.iterdir() if p.is_dir()):
        manifest = folder / "module.json"
        if not manifest.is_file() or not (folder / "run.py").is_file():
            continue
        try:
            raw = json.loads(manifest.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if (raw.get("key") != folder.name or not _KEY_RE.match(str(raw.get("key", "")))
                or raw.get("series") not in SERIES or raw.get("min_level") not in LEVELS):
            continue
        shutil.copytree(folder, dest / folder.name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    load_modules(dest)
    return dest


def load_verify():
    import importlib.util
    spec = importlib.util.spec_from_file_location("inkblade_verify_effects_infra", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Infra2026EffectsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        verify = load_verify()
        verify.MODULES_DIR = _sanitized_modules(Path(cls.tmp.name))
        cls.result = verify.run_verification(Path(cls.tmp.name) / "effects",
                                             write_docs=False)
        cls.by_id = {c["id"]: c for c in cls.result["checks"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_three_checks_present_and_pass(self):
        self.assertTrue(INFRA_IDS <= set(self.by_id),
                        f"缺少 infra 效果项: {sorted(INFRA_IDS - set(self.by_id))}")
        for cid in INFRA_IDS:
            self.assertEqual(self.by_id[cid]["status"], "PASS", self.by_id[cid])
        self.assertGreaterEqual(self.result["summary"]["total"], 34)

    def test_coco_evidence(self):
        ev = self.by_id["infra2026-coco-attestation-mismatch"]["evidence"]
        self.assertTrue(ev["detected"])
        self.assertEqual(ev["http_status"], 200)
        self.assertNotEqual(ev["measurement"], ev["expected_measurement"])
        self.assertTrue(ev["debug"])
        self.assertEqual(ev["tee"], "sev-snp")

    def test_spire_evidence(self):
        ev = self.by_id["infra2026-spire-wildcard-identity"]["evidence"]
        self.assertTrue(ev["detected"])
        self.assertGreaterEqual(ev["wildcard_entries"], 1)
        self.assertFalse(ev["admin_acl"])
        self.assertEqual(ev["trust_domain"], "example.org")

    def test_pq_tls_evidence(self):
        ev = self.by_id["infra2026-pq-tls-weak-posture"]["evidence"]
        self.assertTrue(ev["detected"])
        self.assertEqual(ev["min_version"], "TLS1.2")
        self.assertEqual(ev["key_exchange"], "rsa")
        self.assertEqual(ev["hybrid_group"], "")
        self.assertTrue(ev["hndl_exposed"])

    def test_effects_do_not_include_private_keys(self):
        text = json.dumps(self.result, ensure_ascii=False).lower()
        self.assertNotIn("private_key", text)
        self.assertNotIn("begin rsa", text)


if __name__ == "__main__":
    unittest.main()
