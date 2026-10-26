# -*- coding: utf-8 -*-
"""审批制自主探索器（XBow 对标 ②）测试：提议/审批状态机/执行闸门/LLM 降级。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import ApprovalDenied, Explorer, ExplorerError
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


SEEDS = {"services": [
    {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11", "port": 30000,
     "labels": {"app": "sglang"}},
]}


class TestExplorerLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = EvidenceStore(root, workspace="local-lab")
        AssetInventory(self.store).ingest(SEEDS, source="seed")

    def tearDown(self):
        self.tmp.cleanup()

    def _sign_roe(self, level="利用验证"):
        init_roe(self.store, {"level": level, "namespaces": ["ml"], "cidrs": ["10.0.0.0/8"]})

    def _explorer(self):
        return Explorer(self.store, modules_dir=MODULES_DIR)

    def test_propose_without_roe_has_no_candidates(self):
        """ROE 未签署 → 模块级别闸门过滤后无候选（确定性拒绝，不静默降级）。"""
        with self.assertRaises(ExplorerError):
            self._explorer().propose(_session())

    def test_propose_rules_mode_pending(self):
        self._sign_roe()
        ex = self._explorer()
        p = ex.propose(_session("tester"))
        self.assertEqual(p["mode"], "rules")
        self.assertEqual(p["status"], "pending_approval")
        self.assertTrue(p["actions"])
        self.assertTrue(all(a["dry_run"] and "writes" in a["dry_run"] for a in p["actions"]))
        # 提议只读：不产生任何 run（执行才建 run）
        self.assertFalse(any((x / "evidence.db").exists() for x in self.store.ws_dir.iterdir()
                             if x.is_dir()))
        # sglang 资产 → 候选应含 sglang 模块
        self.assertIn("sglang-admin-failopen", [a["module"] for a in p["actions"]])

    def test_propose_no_candidates_raises(self):
        store = EvidenceStore(Path(self.tmp.name) / "empty-ws", workspace="empty-ws")
        store.ws_dir.mkdir(parents=True, exist_ok=True)
        init_roe(store, {"level": "利用验证", "namespaces": [], "cidrs": []})
        with self.assertRaises(ExplorerError):
            Explorer(store, modules_dir=MODULES_DIR).propose(_session())

    def test_approval_permissions(self):
        self._sign_roe()
        ex = self._explorer()
        p = ex.propose(_session("tester"))
        with self.assertRaises(ApprovalDenied):
            ex.approve(_session("tester"), p["id"])  # tester 无 approve
        approved = ex.approve(_session("lead"), p["id"])
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approval"]["approved_by"], "s-lead")

    def test_execute_requires_approval_and_roe(self):
        self._sign_roe()
        ex = self._explorer()
        p = ex.propose(_session())
        with self.assertRaises(ExplorerError):
            ex.execute(_session(), p["id"])  # 未批准
        ex.approve(_session("lead"), p["id"])
        # 撤销 consent（删除 consent.json）→ 执行仍被 ROE 锁拒绝
        (Path(self.store.ws_dir) / "consent.json").unlink()
        with self.assertRaises(ExecutionLocked):
            ex.execute(_session(), p["id"])

    def test_reject_flow(self):
        self._sign_roe()
        ex = self._explorer()
        p = ex.propose(_session())
        rej = ex.reject(_session("lead"), p["id"], reason="lab")
        self.assertEqual(rej["status"], "rejected")
        with self.assertRaises(ExplorerError):
            ex.approve(_session("lead"), p["id"])  # 已拒绝不可再批

    def test_execute_with_consent(self):
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["10.0.0.0/8"]})
        ex = self._explorer()
        p = ex.propose(_session())
        ex.approve(_session("lead"), p["id"])
        result = ex.execute(_session("tester"), p["id"])
        self.assertIn("results", result)
        # 每个动作有终态（成功或失败皆可——靶场不存在时失败也必须被记录而非崩溃）
        for r in result["results"]:
            self.assertIn(r["status"], ("success", "failed"))
        # 提议状态推进 + 队列持久化
        stored = {q["id"]: q for q in ex.list_proposals()}
        self.assertEqual(stored[p["id"]]["status"], "executed")

    def test_unknown_proposal(self):
        with self.assertRaises(ExplorerError):
            self._explorer().approve(_session(), "prop-nope")

    def test_llm_unavailable_env_falls_back(self):
        import os

        self._sign_roe()
        old = os.environ.get("INKBLADE_LLM_BASE_URL")
        os.environ["INKBLADE_LLM_BASE_URL"] = "http://127.0.0.1:1/v1"  # 不可达
        try:
            p = self._explorer().propose(_session(), use_llm=True)
            self.assertEqual(p["mode"], "rules")
            self.assertIn("LLM 降级", p.get("llm_note", ""))
        finally:
            if old is None:
                os.environ.pop("INKBLADE_LLM_BASE_URL", None)
            else:
                os.environ["INKBLADE_LLM_BASE_URL"] = old


class TestLlmAvailable(unittest.TestCase):
    def test_default_false_without_env(self):
        import os

        saved = os.environ.pop("INKBLADE_LLM_BASE_URL", None)
        try:
            from inkblade.core.explorer import llm_available

            self.assertFalse(llm_available())
        finally:
            if saved:
                os.environ["INKBLADE_LLM_BASE_URL"] = saved


class TestPreauthorizedApproval(unittest.TestCase):
    """L3：lead 预授权 token 已验签后，explorer 仍做白名单/写权限的防御性复核。"""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = EvidenceStore(root, workspace="local-lab")
        AssetInventory(self.store).ingest(SEEDS, source="seed")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})

    def tearDown(self):
        self.tmp.cleanup()

    def _grant(self, allowlist, allow_writes=False):
        class Grant:
            id = "grant-unit"
            token_hint = "abcdef123456"

            def __init__(self):
                self.allowlist = list(allowlist)
                self.allow_writes = bool(allow_writes)

        return Grant()

    def test_preauthorized_approval_records_mode_and_audit(self):
        ex = Explorer(self.store, modules_dir=MODULES_DIR)
        p = ex.propose(_session("tester"))
        modules = [a["module"] for a in p["actions"]]
        approved = ex.approve_preauthorized(p["id"], grant=self._grant(modules,
                                                                      allow_writes=True))
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approval"]["mode"], "preauth")
        self.assertEqual(approved["approval"]["approved_by"], "preauth:grant-unit")
        audit = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("explorer.approve", audit)
        self.assertIn("preauth:grant-unit", audit)

    def test_preauthorized_denies_action_outside_allowlist(self):
        ex = Explorer(self.store, modules_dir=MODULES_DIR)
        p = ex.propose(_session("tester"))
        with self.assertRaises(ApprovalDenied):
            ex.approve_preauthorized(p["id"], grant=self._grant([]))
        self.assertEqual(ex.list_proposals()[0]["status"], "pending_approval")


if __name__ == "__main__":
    unittest.main()
