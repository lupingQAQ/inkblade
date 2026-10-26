import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.users import UserStore
from inkblade.core.evidence import EvidenceStore
from inkblade.core.zeroday import (
    ZerodayLocked,
    ZerodayStore,
    assert_allowed,
    enable,
    filter_modules,
    zeroday_enabled,
)


class TestZeroday(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="client-b")
        users = UserStore(self.root / "users.json")
        users.create_user("lead", "x", "lead", ["client-b"])
        users.create_user("tester", "x", "tester", ["client-b"])
        self.lead = users.verify("lead", "x")
        self.tester = users.verify("tester", "x")
        from inkblade.core.roe import init_roe

        init_roe(self.store, fields={"level": "利用验证", "namespaces": ["agent"], "cidrs": ["127.0.0.0/8"]})

    def tearDown(self):
        self.tmp.cleanup()

    def test_store_no_key_unreadable(self):
        zs = ZerodayStore(self.root / "zeroday", key=b"correct-horse")
        zs.put("dify-local-sandbox-unauth-rce", {"poc": "SECRET-DETAIL", "versions": ["1.17.1"]})
        blob = next((self.root / "zeroday" / "entries").glob("*.enc")).read_bytes()
        self.assertNotIn(b"SECRET-DETAIL", blob)
        wrong = ZerodayStore(self.root / "zeroday", key=b"wrong")
        with self.assertRaises(Exception):
            wrong.get("dify-local-sandbox-unauth-rce")
        right = ZerodayStore(self.root / "zeroday", key=b"correct-horse")
        self.assertEqual(right.get("dify-local-sandbox-unauth-rce")["poc"], "SECRET-DETAIL")

    def test_disabled_hidden_and_gate(self):
        self.assertFalse(zeroday_enabled(self.store))
        meta = {"key": "dify-stub-token-forgery", "private": True, "min_level": "利用验证"}
        with self.assertRaises(ZerodayLocked):
            assert_allowed(self.store, self.tester, meta)
        mods = {
            "public-probe": {"key": "public-probe"},
            "dify-stub-token-forgery": meta,
        }
        visible = filter_modules(mods, self.store)
        self.assertEqual(sorted(visible), ["public-probe"])

    def test_enable_requires_lead_then_gate_opens(self):
        with self.assertRaises(PermissionError):
            enable(self.store, self.tester)
        enable(self.store, self.lead)
        self.assertTrue(zeroday_enabled(self.store))
        assert_allowed(self.store, self.tester, {"key": "dify-stub-token-forgey", "private": True,
                                                 "min_level": "利用验证"})
        # 级别闸门仍生效（复用 roe 级别）
        with self.assertRaises(ZerodayLocked):
            assert_allowed(self.store, self.tester, {"key": "x", "private": True,
                                                     "min_level": "全影响演示"})


if __name__ == "__main__":
    unittest.main()
