# -*- coding: utf-8 -*-
"""LLM 多模型池：默认关闭/权重/失败切换/配额/健康/角色闸门/explorer 集成。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inkblade.core import llmpool
from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import Explorer
from inkblade.core.llmpool import (LLMPool, NoHealthyEndpoint, PoolDisabled)
from inkblade.core.roe import init_roe
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


def _ok_poster(ep, messages, timeout):
    return {"choices": [{"message": {"content": ep["id"]}}],
            "usage": {"total_tokens": 1}}


class TestPoolBasics(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        self.pool = LLMPool(self.store, clock=lambda: 1000.0, poster=_ok_poster)

    def tearDown(self):
        self.tmp.cleanup()

    def test_disabled_by_default(self):
        self.assertFalse(self.pool.enabled)
        self.assertEqual(self.pool.status()["endpoints"], [])
        with self.assertRaises(PoolDisabled):
            self.pool.complete([{"role": "user", "content": "x"}])

    def test_role_gate_and_masking(self):
        with self.assertRaises(PermissionError):
            self.pool.add_endpoint(_session("tester"), base_url="http://x/v1", model="m")
        ep = self.pool.add_endpoint(_session("lead"), base_url="http://x/v1", model="m",
                                    api_key="sk-secret-1234")
        self.assertTrue(ep["api_key_set"])
        self.assertNotIn("api_key", ep)
        self.assertEqual(self.pool.status()["endpoints"][0].get("api_key"), None)
        with self.assertRaises(PermissionError):
            self.pool.set_enabled(_session("tester"), True)

    def test_weighted_round_robin(self):
        self.pool.add_endpoint(_session(), base_url="http://a/v1", model="m", weight=3,
                               endpoint_id="a")
        self.pool.add_endpoint(_session(), base_url="http://b/v1", model="m", weight=1,
                               endpoint_id="b")
        self.pool.set_enabled(_session(), True)
        seq = [self.pool.complete_text("hi")["endpoint"] for _ in range(4)]
        self.assertEqual(seq, ["a", "a", "b", "a"])

    def test_failover_and_cooldown(self):
        self.pool.add_endpoint(_session(), base_url="http://a/v1", model="m", endpoint_id="a")
        self.pool.add_endpoint(_session(), base_url="http://b/v1", model="m", endpoint_id="b")
        self.pool.set_enabled(_session(), True)

        def poster(ep, messages, timeout):
            if ep["id"] == "a":
                raise OSError("boom")
            return _ok_poster(ep, messages, timeout)

        self.pool._poster = poster
        res = self.pool.complete_text("hi")
        self.assertEqual(res["endpoint"], "b")
        self.assertEqual(len(res["attempts"]), 2)
        status = {e["id"]: e for e in self.pool.status()["endpoints"]}
        self.assertEqual(status["a"]["failures"], 1)
        self.assertFalse(status["a"]["healthy"])
        # 冷却期内只选 b
        self.assertEqual(self.pool.complete_text("hi")["endpoint"], "b")

    def test_quota_exhaustion(self):
        self.pool.add_endpoint(_session(), base_url="http://a/v1", model="m",
                               quota_requests=1, endpoint_id="a")
        self.pool.set_enabled(_session(), True)
        self.pool.complete_text("hi")
        with self.assertRaises(NoHealthyEndpoint):
            self.pool.complete_text("hi")

    def test_health_check_marks_cooldown(self):
        self.pool.add_endpoint(_session(), base_url="http://a/v1", model="m", endpoint_id="a")
        self.pool.set_enabled(_session(), True)
        out = self.pool.health_check(_session(), probe=lambda ep, timeout: False)
        self.assertFalse(out["results"]["a"]["ok"])
        self.assertFalse(self.pool.status()["endpoints"][0]["healthy"])
        with self.assertRaises(PoolDisabled):
            self.pool.set_enabled(_session(), False)
            self.pool.health_check(_session(), probe=lambda ep, timeout: True)

    def test_records_and_token_stats(self):
        self.pool.add_endpoint(_session(), base_url="http://a/v1", model="m", endpoint_id="a")
        self.pool.set_enabled(_session(), True)
        self.pool.complete_text("hi", purpose="test")
        self.pool.complete_text("hi", purpose="test")
        recs = self.pool.records()
        self.assertEqual(len(recs), 2)
        self.assertNotIn("text", recs[0])
        self.assertEqual(recs[0]["tokens"], 1)
        self.assertEqual(self.pool.records_by_model()["by_model"][0]["calls"], 2)
        stats = self.pool.token_stats()
        self.assertEqual(stats["totals"]["tokens"], 2)
        self.assertEqual(self.pool.models()[0]["model"], "m")
        with self.assertRaises(PermissionError):
            self.pool.clear_records(_session("tester"))
        self.assertEqual(self.pool.clear_records(_session())["cleared"], 2)

    def test_narrate_deterministic_default(self):
        out = llmpool.narrate(self.store, {"runs": 2, "findings": 3, "critical": 1,
                                           "chains": 1})
        self.assertEqual(out["mode"], "deterministic")
        self.assertIn("3", out["text"])


class TestExplorerPoolIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        AssetInventory(self.store).ingest({"services": [
            {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
             "port": 30000, "labels": {"app": "sglang"}}]})
        pool = LLMPool(self.store)
        pool.add_endpoint(_session(), base_url="http://a/v1", model="m", endpoint_id="a")
        pool.set_enabled(_session(), True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_propose_uses_pool_when_enabled(self):
        ex = Explorer(self.store, modules_dir=MODULES_DIR)
        with patch("inkblade.core.explorer.rank_candidates",
                   return_value=["sglang-admin-failopen"]):
            p = ex.propose(_session("tester"), use_llm=True)
        self.assertEqual(p["mode"], "llm")
        self.assertEqual(p["actions"][0]["module"], "sglang-admin-failopen")

    def test_pool_failure_falls_back_to_rules(self):
        ex = Explorer(self.store, modules_dir=MODULES_DIR)
        with patch("inkblade.core.explorer.rank_candidates", side_effect=OSError("no route")):
            p = ex.propose(_session("tester"), use_llm=True)
        self.assertEqual(p["mode"], "rules")
        self.assertIn("LLM 降级", p.get("llm_note", ""))


if __name__ == "__main__":
    unittest.main()
