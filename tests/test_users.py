import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.users import UserStore


class TestUsers(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = UserStore(Path(self.tmp.name) / "users.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_hash_roundtrip(self):
        self.store.create_user("alice", "S3cret!", "admin", ["local-lab", "client-a"])
        raw = (self.tmp and Path(self.tmp.name, "users.json").read_text(encoding="utf-8")) or ""
        self.assertNotIn("S3cret!", raw)
        self.assertIsNotNone(self.store.verify("alice", "S3cret!"))
        self.assertIsNone(self.store.verify("alice", "wrong"))

    def test_role_matrix(self):
        self.store.create_user("lead", "x", "lead", ["local-lab"])
        self.store.create_user("tester", "x", "tester", ["local-lab"])
        self.store.create_user("auditor", "x", "auditor", ["local-lab"])
        s_lead = self.store.verify("lead", "x")
        s_tester = self.store.verify("tester", "x")
        s_aud = self.store.verify("auditor", "x")
        self.assertTrue(s_tester.can("execute"))
        self.assertFalse(s_tester.can("approve"))
        self.assertTrue(s_lead.can("approve"))
        self.assertTrue(s_lead.can("approve-zeroday"))
        self.assertFalse(s_aud.can("execute"))
        self.assertTrue(s_aud.can("read"))

    def test_cross_workspace_denied(self):
        self.store.create_user("bob", "x", "auditor", ["local-lab"])
        s = self.store.verify("bob", "x")
        self.assertEqual(s.visible_workspaces(), ["local-lab"])
        with self.assertRaises(PermissionError):
            s.open_store(Path(self.tmp.name), "client-secret")

    def test_admin_sees_all(self):
        self.store.create_user("root", "x", "admin", ["*"])
        (Path(self.tmp.name) / "evidence" / "client-secret").mkdir(parents=True, exist_ok=True)
        s = self.store.verify("root", "x")
        self.assertIn("client-secret", s.visible_workspaces(root=Path(self.tmp.name)))


if __name__ == "__main__":
    unittest.main()
