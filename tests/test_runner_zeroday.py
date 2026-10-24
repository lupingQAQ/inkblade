"""runner 零日闸门测试。

- 通用可选扩展：显式 ``private: true`` 的未来模块仍受 ZerodayLocked 闸门保护；
- 零日级漏洞模块（已公开，6 个 dify-*/open-webui-*）不标记 private，
  未启用零日扩展时也可见、可直接执行（无需 enable）。
"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import init_roe
from trident.core.runner import run_module
from trident.core.users import UserStore
from trident.core.zeroday import ZerodayLocked, filter_modules

from lab.mock_targets import start_all

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"

PUBLIC_ZERODAY_CLASS = (
    "dify-control-plane-failopen",
    "dify-stub-token-forgery",
    "dify-snapshot-cross-tenant-theft",
    "dify-local-sandbox-unauth-rce",
    "open-webui-code-execute-rce",
    "open-webui-indirect-injection-exec",
)


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

    def test_public_zeroday_class_modules_not_gated(self):
        """公开零日级模块：默认可见（filter_modules）且 runner 不触发零日闸门。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="local-lab")
            init_roe(store, fields={"level": "全影响演示", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["local-lab"])
            session = users.verify("tester", "x")

            mods = load_modules(MODULES_DIR)
            visible = filter_modules({k: m.__dict__ for k, m in mods.items()}, store)
            for key in PUBLIC_ZERODAY_CLASS:
                self.assertIn(key, mods, f"缺模块 {key}")
                self.assertFalse(mods[key].private, f"{key} 已公开，不得标记 private")
                self.assertIn(key, visible, f"零日扩展未启用时 {key} 也应可见")

            # 真实 mock 靶场：重点断言不抛 ZerodayLocked（公开模块无需 enable）。
            with start_all(mode="vulnerable") as lab:
                result = run_module(
                    store, session, "dify-control-plane-failopen",
                    {"base_url": lab.url("/"),
                     "backup_targets": [{"kind": "http", "url": lab.url("/"), "state": {}}]},
                    modules_dir=MODULES_DIR,
                )
            self.assertEqual(result["step"], "dify-control-plane-failopen")


if __name__ == "__main__":
    unittest.main()
