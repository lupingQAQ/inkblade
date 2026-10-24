"""实效验证测试：调 trident/verify-effects.py::run_verification 断言 7 项全 PASS。

覆盖（本机真实进程 + 127.0.0.1 真实 HTTP）：
a) 管理面未授权利用（200 + 服务端状态文件变更）
b) 权重投毒对权重文件副本真实写入（sha256 前后不同 + benign marker）
c) 备份回滚（sha256 与原始完全一致）
d) RCE 链在 mock 侧真实落地 marker 文件（内容含 run 标记）
e) 训练数据泄露读取 fixture 假密钥，报告仅尾4位
f) 规则引擎对本次靶场重放 ≥1 条规则命中
g) 端到端链 dry-run → execute（备份 + 三层证据完整）
"""

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "trident" / "verify-effects.py"
FAKE_TOKEN = "hf_FAKEtokenDoNotUseSampleABCD1234wxyz"

EXPECTED_IDS = {
    "admin-plane-failopen",
    "weight-poison-write",
    "backup-rollback",
    "rce-marker",
    "data-leak-redaction",
    "rules-detection",
    "chain-e2e",
}


def load_verify():
    spec = importlib.util.spec_from_file_location("trident_verify_effects", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestVerifyEffects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "effects"
        cls.result = load_verify().run_verification(cls.out, write_docs=False)
        cls.by_id = {c["id"]: c for c in cls.result["checks"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_checks_pass(self):
        self.assertEqual(self.result["summary"]["failed"], 0, self.by_id)
        self.assertEqual(self.result["summary"]["passed"], 7)
        self.assertEqual(set(self.by_id), EXPECTED_IDS)

    def test_json_and_md_written(self):
        data = json.loads((self.out / "effects.json").read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["passed"], 7)
        md = (self.out / "effects.md").read_text(encoding="utf-8")
        self.assertIn("PASS", md)
        for cid in EXPECTED_IDS:
            self.assertIn(cid, md)
        self.assertIn("非 live K8s", data["scope"])
        self.assertIn("非 live K8s", md)

    def test_admin_plane_real_http_and_state_change(self):
        ev = self.by_id["admin-plane-failopen"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertEqual(ev["state_applied"], True)
        self.assertNotEqual(ev["state_sha256_before"], ev["state_sha256_after"])

    def test_weight_poison_file_mutation(self):
        ev = self.by_id["weight-poison-write"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertNotEqual(ev["sha256_before"], ev["sha256_after"])
        self.assertTrue(ev["marker_present"])
        self.assertIn("TRIDENT-", ev["marker"])

    def test_rollback_restores_exact_bytes(self):
        ev = self.by_id["backup-rollback"]["evidence"]
        self.assertEqual(ev["rollback_rows"], 1)
        self.assertEqual(ev["sha256_after_rollback"], ev["sha256_original"])
        self.assertTrue(ev["exact_restore"])

    def test_rce_marker_file(self):
        ev = self.by_id["rce-marker"]["evidence"]
        self.assertEqual(ev["http_statuses"], {"set_env": 200, "create_engine": 200, "call": 200})
        self.assertTrue(ev["marker_present"])
        self.assertIn("TRIDENT-", ev["marker"])

    def test_data_leak_only_tail4_in_report(self):
        ev = self.by_id["data-leak-redaction"]["evidence"]
        self.assertEqual(ev["tail4"], FAKE_TOKEN[-4:])
        self.assertIn("****" + FAKE_TOKEN[-4:], ev["redacted_sample"])
        self.assertTrue(ev["full_token_absent"])
        self.assertTrue(ev["report_full_token_absent"])
        self.assertIn("****" + FAKE_TOKEN[-4:], ev["report_redacted_sample"])
        self.assertNotIn(FAKE_TOKEN, json.dumps(self.result, ensure_ascii=False))

    def test_rules_engine_hits(self):
        ev = self.by_id["rules-detection"]["evidence"]
        self.assertGreaterEqual(ev["hits"], 1)
        self.assertGreaterEqual(ev["rules_detected"] + ev["rules_blocked"], 1)
        self.assertTrue(ev["sample_hit"])

    def test_chain_completed_with_three_layer_evidence(self):
        ev = self.by_id["chain-e2e"]["evidence"]
        self.assertTrue(ev["ok"])
        self.assertEqual(ev["steps"]["admin-failopen-probe"], "success")
        self.assertEqual(ev["steps"]["weight-pull-poison"], "success")
        self.assertGreaterEqual(ev["backup_receipts"], 1)
        self.assertTrue(ev["layers"]["context"])
        self.assertTrue(ev["layers"]["database"])
        self.assertGreaterEqual(ev["layers"]["archives"], 1)
        self.assertTrue(ev["layers"]["manifest"])


if __name__ == "__main__":
    unittest.main()
