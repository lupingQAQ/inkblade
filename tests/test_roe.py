import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import (
    ExecutionLocked,
    assert_execution_allowed,
    allowed,
    init_roe,
    in_scope,
    roe_status,
)


def _meta(min_level="只读侦察", writes=False):
    return {"key": "probe", "series": "侦察", "min_level": min_level, "writes": writes}


class TestRoe(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="client-a")

    def tearDown(self):
        self.tmp.cleanup()

    def test_locked_without_roe(self):
        with self.assertRaises(ExecutionLocked):
            assert_execution_allowed(self.store, _meta())

    def test_unlock_after_init(self):
        init_roe(
            self.store,
            fields={
                "client": "甲",
                "auth_ref": "AUTH-001",
                "namespaces": ["train"],
                "cidrs": ["10.0.0.0/8"],
                "window": {"start": "2026-10-25", "end": "2026-11-01"},
                "level": "只读侦察",
            },
        )
        self.assertEqual(roe_status(self.store), "complete")
        assert_execution_allowed(self.store, _meta())  # 不抛

    def test_level_gate(self):
        init_roe(self.store, fields={"level": "只读侦察"})
        with self.assertRaises(ExecutionLocked):
            assert_execution_allowed(self.store, _meta(min_level="全影响演示"))
        self.assertFalse(allowed("全影响演示", "只读侦察"))
        self.assertTrue(allowed("利用验证", "全影响演示"))
        self.assertTrue(allowed("只读侦察", "只读侦察"))

    def test_scope_cidr_and_namespace(self):
        init_roe(
            self.store,
            fields={"namespaces": ["train", "ray-system"], "cidrs": ["10.1.0.0/16"], "level": "只读侦察"},
        )
        self.assertTrue(in_scope(self.store, target_ns="train", target_addr=None))
        self.assertFalse(in_scope(self.store, target_ns="prod", target_addr=None))
        self.assertTrue(in_scope(self.store, target_ns=None, target_addr="10.1.2.3"))
        self.assertFalse(in_scope(self.store, target_ns=None, target_addr="10.9.0.1"))
        self.assertFalse(in_scope(self.store, target_ns="prod", target_addr="10.1.2.3"))

    def test_roe_hash_pinned(self):
        init_roe(self.store, fields={"level": "只读侦察"})
        run = self.store.create_run("r")
        rows = run.query("SELECT workspace, scope_sha256, status FROM roe")
        self.assertEqual(rows[0][0], "client-a")
        self.assertEqual(rows[0][2], "complete")
        self.assertEqual(len(rows[0][1]), 64)


if __name__ == "__main__":
    unittest.main()
