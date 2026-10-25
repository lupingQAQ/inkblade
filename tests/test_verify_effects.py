"""实效验证测试：调 trident/verify-effects.py::run_verification 断言 20 项全 PASS。

覆盖（本机真实进程 + 127.0.0.1 真实 HTTP）：
a) 管理面未授权利用（200 + 服务端状态文件变更）
b) 权重投毒对权重文件副本真实写入（sha256 前后不同 + benign marker）
c) 备份回滚（sha256 与原始完全一致）
d) RCE 链在 mock 侧真实落地 marker 文件（内容含 run 标记）
e) 训练数据泄露读取 fixture 假密钥，报告仅尾4位
f) 规则引擎对本次靶场重放 ≥1 条规则命中
g) 端到端链 dry-run → execute（备份 + 三层证据完整）
h) 长上下文超窗请求被接受且 queue_depth 增长
i) prefix cache 跨租户复用（cached_tokens>0）
j) PD KV 通道 benign marker 写入并读回（sha256 一致）
k) checkpoint 分片投毒后 rollback 的 sha256 精确复原
l) GPU 跨租户残留 benign marker 分配→释放→读回（含释放后）+ sha256 一致
m) 通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏）
n) 公共桶策略 + 跨租户列目录证据
o) AI 网关默认 master key 读到上游 MOCK key，报告仅尾4位
p) 伪造 X-Forwarded-User 越权（admin 全局 key 视图 + 全租户日志）
q) 语义缓存跨租户命中（共享前缀键 cache_key 一致）
r) SHARP 在网聚合投毒（入组 + reduce 前后差分 + tampered_reduces 计数）
s) PFC 暂停风暴（pfc_pause_frames 计数暴增）
t) 慢 rank 注入步时劣化（计时差分 ≥2×）
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
    "longctx-window-overflow",
    "longctx-prefix-reuse",
    "longctx-kv-channel-write",
    "longctx-checkpoint-rollback",
    "gpu-tenant-residue-marker",
    "cloud-assume-role-cross-account",
    "cloud-bucket-public-listing",
    "gateway-default-master-key-exfil",
    "gateway-forwarded-user-impersonation",
    "gateway-semantic-cache-cross-tenant",
    "fabric-sharp-reduce-tamper",
    "fabric-pfc-storm-counter",
    "fabric-straggler-step-slowdown",
    "trainstack-optimizer-state-marker",
    "trainstack-data-tamper-detect",
    "trainstack-template-injection-detect",
    "ray-job-rce-marker",
    "gateway-default-key-exfil",
    "ipmi-cipher-zero-bypass",
    "redfish-default-credentials",
    "runc-surface-detection",
    "privesc-escalate",
    "privesc-bind",
    "privesc-sa-token",
    "privesc-webhook",
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
        self.assertGreaterEqual(self.result["summary"]["passed"], len(EXPECTED_IDS))
        # ????????????????????? 25 ???????
        self.assertFalse(set(EXPECTED_IDS) - set(self.by_id), "????????")

    def test_json_and_md_written(self):
        data = json.loads((self.out / "effects.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(data["summary"]["passed"], len(EXPECTED_IDS))
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

    def test_longctx_window_overflow_accepted_and_queue_grows(self):
        ev = self.by_id["longctx-window-overflow"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertGreater(ev["prefill_tokens"], ev["context_window_tokens"])
        self.assertEqual(ev["queue_depth_delta"], 1)
        self.assertGreater(ev["queue_depth_after"], ev["queue_depth_before"])

    def test_longctx_prefix_cache_cross_tenant_cached_tokens(self):
        ev = self.by_id["longctx-prefix-reuse"]["evidence"]
        self.assertEqual(ev["prime_status"], 200)
        self.assertEqual(ev["reuse_status"], 200)
        self.assertGreater(ev["cached_tokens"], 0)
        self.assertTrue(ev["cross_tenant"])

    def test_longctx_kv_channel_write_readback(self):
        ev = self.by_id["longctx-kv-channel-write"]["evidence"]
        self.assertEqual(ev["write_status"], 200)
        self.assertEqual(ev["readback_status"], 200)
        self.assertTrue(ev["readback_marker_present"])
        self.assertEqual(ev["readback_sha256"], ev["write_sha256"])

    def test_longctx_checkpoint_shard_rollback_exact(self):
        ev = self.by_id["longctx-checkpoint-rollback"]["evidence"]
        self.assertEqual(ev["write_status"], 200)
        self.assertNotEqual(ev["sha256_before"], ev["sha256_after"])
        self.assertGreaterEqual(ev["rollback_rows"], 1)
        self.assertEqual(ev["sha256_after_rollback"], ev["sha256_before"])
        self.assertTrue(ev["exact_restore"])

    def test_gpu_tenant_residue_marker_readback_after_release(self):
        ev = self.by_id["gpu-tenant-residue-marker"]["evidence"]
        self.assertEqual(ev["allocate_status"], 200)
        self.assertEqual(ev["release_status"], 200)
        self.assertEqual(ev["readback_status"], 200)
        self.assertEqual(ev["victim_read_status"], 200)
        self.assertTrue(ev["readback_after_release"])
        self.assertTrue(ev["marker"].startswith("TRIDENT-BENIGN-"))
        self.assertEqual(ev["marker_sha256"], ev["expected_marker_sha256"])
        self.assertEqual(ev["readback_file_sha256"], ev["residue_file_sha256"])
        self.assertEqual(ev["readback_file_sha256"], ev["actual_file_sha256"])
        self.assertEqual(ev["victim_tenant"], "tenant-b")

    def test_cloud_assume_role_cross_account_success(self):
        ev = self.by_id["cloud-assume-role-cross-account"]["evidence"]
        self.assertEqual(ev["identity_status"], 200)
        self.assertEqual(ev["assume_role_status"], 200)
        self.assertTrue(ev["cross_account"])
        self.assertTrue(ev["wildcard_principal"])
        self.assertEqual(ev["trust_policy_principal"], "*")
        self.assertEqual(ev["source_account"], "999999999999")
        self.assertTrue(ev["full_credential_absent"])
        self.assertIn("MOCK****", ev["masked_credentials"]["AccessKeyId"])
        self.assertNotIn("MOCKAKIACROSSTENANT0001", json.dumps(self.result, ensure_ascii=False))

    def test_cloud_bucket_public_cross_tenant_listing(self):
        ev = self.by_id["cloud-bucket-public-listing"]["evidence"]
        self.assertEqual(ev["policy_status"], 200)
        self.assertEqual(ev["list_status"], 200)
        self.assertTrue(ev["public"])
        self.assertTrue(ev["cross_tenant"])
        self.assertEqual(ev["bucket_owner"], "tenant-b")
        self.assertEqual(ev["policy_principal"], "*")
        self.assertGreaterEqual(ev["object_count"], 1)
        self.assertTrue(any(str(k).startswith("tenant-b/") for k in ev["objects"]))


    def test_gateway_default_master_key_exfil_masked_in_report(self):
        ev = self.by_id["gateway-default-master-key-exfil"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertEqual(ev["master_key_class"], "default")
        self.assertGreaterEqual(ev["upstream_key_count"], 1)
        self.assertEqual(ev["upstream_key_masked"], "MOCK****" + ev["upstream_key_tail4"])
        self.assertFalse(ev["full_key_in_finding"])
        self.assertTrue(ev["report_full_key_absent"])
        self.assertIn(ev["upstream_key_masked"], ev["report_redacted_sample"])

    def test_gateway_forwarded_user_impersonation(self):
        ev = self.by_id["gateway-forwarded-user-impersonation"]["evidence"]
        self.assertEqual(ev["key_info_status"], 200)
        self.assertEqual(ev["scope"], "global")
        self.assertEqual(ev["impersonated_user"], "admin")
        self.assertIn("tenant-b", ev["visible_tenants"])
        self.assertEqual(ev["logs_status"], 200)
        self.assertGreaterEqual(len(ev["logs_tenants"]), 2)
        self.assertGreaterEqual(ev["finding_count"], 1)

    def test_gateway_semantic_cache_cross_tenant(self):
        ev = self.by_id["gateway-semantic-cache-cross-tenant"]["evidence"]
        self.assertEqual(ev["requester_status"], 200)
        self.assertEqual(ev["victim_status"], 200)
        self.assertTrue(ev["hit"])
        self.assertEqual(ev["requester_tenant"], "tenant-a")
        self.assertEqual(ev["entry_tenant"], "tenant-b")
        self.assertEqual(ev["cache_key"], ev["victim_cache_key"])
        self.assertTrue(ev["shared_key"])
        self.assertTrue(ev["cross_tenant"])
        self.assertGreaterEqual(ev["finding_count"], 1)

    def test_fabric_sharp_reduce_tamper_diff(self):
        ev = self.by_id["fabric-sharp-reduce-tamper"]["evidence"]
        self.assertEqual(ev["join_status"], 200)
        self.assertEqual(ev["baseline_status"], 200)
        self.assertEqual(ev["tamper_status"], 200)
        self.assertNotEqual(ev["tampered_result"], ev["baseline_result"])
        self.assertTrue(ev["results_differ"])
        self.assertTrue(ev["silent"])
        self.assertGreaterEqual(ev["tampered_reduces"], 1)

    def test_fabric_pfc_storm_counter(self):
        ev = self.by_id["fabric-pfc-storm-counter"]["evidence"]
        self.assertEqual(ev["read_status"], 200)
        self.assertGreaterEqual(ev["pfc_pause_frames_delta"], 50000)
        self.assertGreater(ev["pfc_pause_frames_after"], ev["pfc_pause_frames_before"])
        self.assertTrue(ev["storm_active"])

    def test_fabric_straggler_step_slowdown(self):
        ev = self.by_id["fabric-straggler-step-slowdown"]["evidence"]
        self.assertEqual(ev["inject_status"], 200)
        self.assertGreater(ev["slowed_step_ms"], ev["baseline_step_ms"])
        self.assertGreaterEqual(ev["step_time_ratio"], 2.0)

    def test_ray_job_rce_marker(self):
        ev = self.by_id["ray-job-rce-marker"]["evidence"]
        self.assertEqual(ev["submit_status"], 200)
        self.assertTrue(ev["marker_present"])
        self.assertIn("TRIDENT-", ev["marker"])
        self.assertTrue(ev["cleanup_deleted"])
        self.assertEqual(ev["cve"], "CVE-2023-48022")

    def test_gateway_default_key_exfil(self):
        ev = self.by_id["gateway-default-key-exfil"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertEqual(ev["key_class"], "default")
        self.assertGreaterEqual(ev["upstream_key_count"], 1)
        self.assertTrue(ev["masked_only"])
        self.assertFalse(ev["full_key_in_finding"])

    def test_ipmi_cipher_zero_bypass(self):
        ev = self.by_id["ipmi-cipher-zero-bypass"]["evidence"]
        self.assertEqual(ev["auth_status"], 200)
        self.assertEqual(ev["cipher"], 0)
        self.assertEqual(ev["privilege"], "admin")
        self.assertTrue(ev["session_established"])

    def test_redfish_default_credentials(self):
        ev = self.by_id["redfish-default-credentials"]["evidence"]
        self.assertEqual(ev["session_status"], 201)
        self.assertEqual(ev["accepted_username"], "admin")
        self.assertEqual(ev["systems_status"], 200)
        self.assertTrue(ev["token_issued"])

    def test_runc_surface_detection(self):
        ev = self.by_id["runc-surface-detection"]["evidence"]
        self.assertIn("CVE-2024-21626", ev["cves"])
        self.assertIn("CVE-2025-31133", ev["cves"])
        self.assertGreaterEqual(ev["findings"], 1)
        self.assertFalse(ev["writes"])

    def test_trainstack_optimizer_state_marker(self):
        ev = self.by_id["trainstack-optimizer-state-marker"]["evidence"]
        self.assertEqual(ev["http_statuses"], {"write": 200, "read": 200})
        self.assertTrue(ev["marker_present"])
        self.assertIn("TRIDENT-", ev["marker"])
        self.assertTrue(ev["optimizer_state"])
        self.assertNotEqual(ev["sha256_before"], ev["sha256_after"])
        self.assertEqual(ev["readback_sha256"], ev["sha256_after"])
        self.assertEqual(ev["sha256_after_rollback"], ev["sha256_before"])
        self.assertTrue(ev["exact_restore"])

    def test_trainstack_data_tamper_detect(self):
        ev = self.by_id["trainstack-data-tamper-detect"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertGreaterEqual(ev["appended"], 3)
        self.assertTrue(ev["tamper_detected"])
        self.assertNotEqual(ev["expected_sha256"], ev["actual_sha256"])
        self.assertGreaterEqual(ev["duplicate_ids"], 1)
        self.assertGreaterEqual(ev["unknown_ids"], 1)
        self.assertTrue(ev["order_changed"])
        self.assertEqual(ev["sha256_after_rollback"], ev["expected_sha256"])

    def test_trainstack_template_injection_detect(self):
        ev = self.by_id["trainstack-template-injection-detect"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertTrue(ev["template_modified"])
        self.assertTrue(ev["injected_directive"])
        self.assertFalse(ev["sanitized"])
        self.assertTrue(ev["marker_in_system_block"])
        self.assertNotEqual(ev["sha256_before"], ev["sha256_after"])
        self.assertEqual(ev["sha256_after_rollback"], ev["sha256_before"])
        self.assertTrue(ev["exact_restore"])


if __name__ == "__main__":
    unittest.main()
