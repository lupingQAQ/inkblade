import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore


class TestBackupSnapshotThreeStates(unittest.TestCase):
    """C-1：快照回执三态——空 targets / 全无效 / 部分有效。"""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        self.run = self.store.create_run("backup-gate")
        self.bm = BackupManager(self.store, self.run)
        self.valid = self.root / "victim.txt"
        self.valid.write_text("original", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_snapshot_receipt_three_states(self):
        missing = str(self.root / "not-exist.txt")
        cases = [
            # (case, targets, expect_receipt)
            ("empty-targets", [], False),
            ("all-invalid", [
                {"kind": "file", "path": missing},   # 路径不存在
                {"kind": "unknown-kind"},            # 未知 kind
            ], False),
            ("partial-valid", [
                {"kind": "file", "path": missing},   # 无效
                {"kind": "file", "path": str(self.valid)},  # 有效
                {"kind": "unknown-kind"},            # 无效
            ], True),
        ]
        for case, targets, expect_receipt in cases:
            with self.subTest(case=case):
                rid = self.bm.snapshot(f"step-{case}", targets)
                if expect_receipt:
                    self.assertIsNotNone(rid, f"{case}: 至少一条有效快照必须给回执")
                else:
                    self.assertIsNone(rid, f"{case}: 无任何成功快照不得给回执")

        # 仅部分有效场景落一条备份记录（有效 target 才入账）
        rows = self.run.query("SELECT step_key, target FROM backups ORDER BY id")
        self.assertEqual(
            [(r[0], r[1]) for r in rows],
            [("step-partial-valid", str(self.valid))],
        )

    def test_all_invalid_then_valid_target_still_restorable(self):
        """部分有效场景的有效快照可用于回滚（回执语义与回滚联动）。"""
        rid = self.bm.snapshot("step-mixed", [
            {"kind": "file", "path": str(self.root / "ghost.txt")},
            {"kind": "file", "path": str(self.valid)},
        ])
        self.assertIsNotNone(rid)
        self.valid.write_text("tampered", encoding="utf-8")
        receipt = self.bm.rollback("step-mixed")
        self.assertEqual(receipt["restored"], 1)
        self.assertEqual(receipt["failed"], 0)
        self.assertEqual(self.valid.read_text(encoding="utf-8"), "original")


class TestRollbackStates(unittest.TestCase):
    """终审 Important#2：kube/http 回滚不再假 ok=1 —— 显式 pending/unsupported + 明细回执。"""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        self.run = self.store.create_run("rollback-states")
        self.bm = BackupManager(self.store, self.run)
        self.victim = self.root / "victim.txt"
        self.victim.write_text("original", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_mixed_actions_states_and_receipt(self):
        rid = self.bm.snapshot("mixed", [
            {"kind": "file", "path": str(self.victim)},
            {"kind": "kube", "kind_ref": "deployment/api", "manifest": "apiVersion: v1\nkind: Deployment\n",
             "name": "api"},
            {"kind": "http", "url": "http://127.0.0.1:18080/pause", "state": {"paused": False}},
        ])
        self.assertIsNotNone(rid)
        # 手工登记一条未知动作，验证 unsupported 分支
        carrier = self.root / "x.bak"
        carrier.write_bytes(b"snapshot-bytes")
        self.run.record_backup("mixed", "mystery/target", carrier, "carrier-pigeon")
        self.victim.write_text("tampered", encoding="utf-8")

        res = self.bm.rollback("mixed")
        self.assertEqual(res["attempted"], 4)
        self.assertEqual(res["restored"], 1)
        self.assertEqual(res["pending"], 2)
        self.assertEqual(res["unsupported"], 1)
        self.assertEqual(res["failed"], 0)
        self.assertEqual(len(res["items"]), 4)
        by_target = {i["target"]: i for i in res["items"]}
        self.assertEqual(by_target[str(self.victim)]["state"], "restored")
        self.assertEqual(self.victim.read_text(encoding="utf-8"), "original")

        # kube/http：明确 pending（需外部执行器），不再声称成功
        kube = [i for i in res["items"] if i["action"] == "kubectl-apply"][0]
        http = [i for i in res["items"] if i["action"] == "http-restore"][0]
        self.assertEqual(kube["state"], "pending")
        self.assertEqual(http["state"], "pending")
        self.assertIn("kubectl", kube["detail"])
        self.assertIn("HTTP", http["detail"])

        # 未知动作：unsupported
        unknown = [i for i in res["items"] if i["action"] == "carrier-pigeon"][0]
        self.assertEqual(unknown["state"], "unsupported")

        # 数据库：仅 restored 记 ok=1
        rows = self.run.query(
            "SELECT b.rollback_action, r.ok FROM backups b JOIN rollbacks r ON r.backup_id=b.id"
            " WHERE b.step_key='mixed' ORDER BY b.id")
        self.assertEqual([(a, ok) for a, ok in rows],
                         [("file-restore", 1), ("kubectl-apply", 0),
                          ("http-restore", 0), ("carrier-pigeon", 0)])

        # 明细回执落盘（可供人工/后续模块执行 pending 项）
        receipt = self.run.dir / "backups" / "rollback-mixed.json"
        self.assertTrue(receipt.is_file(), "回滚明细回执未落盘")
        doc = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(doc["step_key"], "mixed")
        self.assertEqual({i["state"] for i in doc["items"]},
                         {"restored", "pending", "unsupported"})

    def test_missing_backup_file_marks_failed(self):
        ghost = self.root / "ghost.bak"
        ghost.write_bytes(b"temp")
        self.run.record_backup("broken", str(self.victim), ghost, "file-restore")
        ghost.unlink()  # 模拟快照丢失/被清理
        res = self.bm.rollback("broken")
        self.assertEqual(res["failed"], 1)
        self.assertEqual(res["restored"], 0)
        self.assertEqual(res["items"][0]["state"], "failed")
        rows = self.run.query("SELECT ok FROM rollbacks")
        self.assertEqual(rows[-1][0], 0)

    def test_empty_step_returns_zero_receipt(self):
        res = self.bm.rollback("nothing-here")
        self.assertEqual(res["attempted"], 0)
        self.assertEqual((res["restored"], res["pending"], res["unsupported"], res["failed"]),
                         (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
