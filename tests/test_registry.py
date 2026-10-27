import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.registry import ModuleMeta, load_modules, order_dependencies
from tests.template_module_fixture import write_template_module


def _mk(root: Path, key: str, requires=None, series="横向利用", min_level="只读侦察"):
    write_template_module(root, key, series=series, min_level=min_level,
                          requires=requires or [], flat=True)


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
        _mk(self.root, "key_007")
        with self.assertRaises(ValueError):
            load_modules(self.root)
        (self.root / "key_007" / "module.json").unlink()
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
