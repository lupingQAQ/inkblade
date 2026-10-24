import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe
from trident.core.runner import run_module
from trident.core.users import UserStore
from trident.core.zeroday import ZerodayLocked


class TestRunnerZerodayGate(unittest.TestCase):
    def test_private_module_blocked_when_disabled(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "modules" / "dify-probe-secret"
            d.mkdir(parents=True)
            (d / "module.json").write_text(
                '{"key":"dify-probe-secret","name":{"zh":"x","en":"x"},"series":"横向利用",'
                '"description":"t","min_level":"只读侦察","writes":false,"requires":[],"private":true}',
                encoding="utf-8")
            (d / "run.py").write_text("def run(ctx, params):\n    return {'summary':'ok'}\n", encoding="utf-8")
            store = EvidenceStore(root, workspace="local-lab")
            init_roe(store, fields={"level": "全影响演示"})
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["local-lab"])
            s = users.verify("tester", "x")
            with self.assertRaises(ZerodayLocked):
                run_module(store, s, "dify-probe-secret", params={}, modules_dir=root / "modules")


if __name__ == "__main__":
    unittest.main()
