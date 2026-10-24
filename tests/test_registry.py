import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.registry import ModuleMeta, load_modules, order_dependencies


def _mk(root: Path, key: str, requires=None, series="侦察", min_level="只读侦察"):
    d = root / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "key": key,
        "name": {"zh": key, "en": key},
        "series": series,
        "description": "test module",
        "min_level": min_level,
        "writes": False,
        "requires": requires or [],
    }
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    (d / "run.py").write_text("def run(ctx, params):\n    return {'ok': True}\n", encoding="utf-8")


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_contract_enforced(self):
        _mk(self.root, "good-one")
        mods = load_modules(self.root)
        self.assertIn("good-one", mods)
        self.assertIsInstance(mods["good-one"], ModuleMeta)
        # 键含数字 → 拒绝
        _mk(self.root, "key-007")
        with self.assertRaises(ValueError):
            load_modules(self.root)
        (self.root / "key-007" / "module.json").unlink()
        # 缺字段
        d = self.root / "no-series"
        d.mkdir()
        (d / "module.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_modules(self.root)

    def test_topo_order(self):
        _mk(self.root, "exposure-mapping")
        _mk(self.root, "framework-port-matching", requires=["exposure-mapping"])
        _mk(self.root, "combo-signature-static", requires=["framework-port-matching"])
        order = order_dependencies(load_modules(self.root))
        self.assertLess(order.index("exposure-mapping"), order.index("framework-port-matching"))
        self.assertLess(order.index("framework-port-matching"), order.index("combo-signature-static"))


if __name__ == "__main__":
    unittest.main()
