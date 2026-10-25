# -*- coding: utf-8 -*-
"""tests/test_trainstack_modules.py — 预训练/SFT/RL 训练栈 10 模块契约与双态差分。

覆盖：
- 注册表契约：10 个纯小写键、系列/级别/writes、requires 为空、produces 非空；
- 模块源码不得 import 仿真器（lab.trainstack_sim）；
- vulnerable：10 个模块各产出 high finding，证据来自 HTTP 状态/读回 sha256/marker；
- fixed：同一批模块无 high/critical（读面 401 / 写面 401/403 / 奖励指标健康）；
- 写类闸门：backup-write 缺 backup_targets → BackupGateRefused（退出码语义 91）；
- 备份回滚：optimizer state 文件快照 → 投毒 → rollback 精确复原；
- 奖励作弊多指标：signals ≥3 且含 reward-up-pass-flat，不允许单点结论；
- 无 target：全部模块返回空 findings。
"""
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.trainstack_sim import (
    data_shard_path,
    jobs_path,
    optimizer_state_path,
    rollout_buffer_path,
    sft_jobs_path,
    start_all,
    template_path,
)
from trident.core.backup import BackupManager
from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import init_roe
from trident.core.runner import BackupGateRefused, run_module
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"

MODULE_SPECS = {
    "megatron-deepspeed-config-surface": {"series": "侦察", "min_level": "主动探测",
                                          "writes": False},
    "torchrun-elastic-surface": {"series": "网络架构", "min_level": "主动探测",
                                 "writes": False},
    "checkpoint-optimizer-state-poison": {"series": "横向利用", "min_level": "利用验证",
                                          "writes": True},
    "data-pipeline-poison": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "tokenizer-template-injection": {"series": "横向利用", "min_level": "利用验证",
                                     "writes": True},
    "experiment-tracker-exposure": {"series": "窃取与数据泄露", "min_level": "主动探测",
                                    "writes": False},
    "sft-framework-surface": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "rl-rollout-buffer-poison": {"series": "横向利用", "min_level": "利用验证",
                                 "writes": True},
    "reward-hacking-detect": {"series": "情报", "min_level": "主动探测", "writes": False},
    "pretrain-job-escape": {"series": "权限链", "min_level": "利用验证", "writes": True},
}

WRITE_KEYS = {k for k, spec in MODULE_SPECS.items() if spec["writes"]}
FULL_TOKEN = "MOCK-wandb-runner-3d21"


def _detail(finding):
    try:
        return json.loads(finding["detail"])
    except (ValueError, TypeError):
        return {}


class RegistryContractTest(unittest.TestCase):
    def test_ten_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key, spec in MODULE_SPECS.items():
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertEqual(meta.series, spec["series"], key)
            self.assertEqual(meta.min_level, spec["min_level"], key)
            self.assertEqual(meta.writes, spec["writes"], key)
            self.assertEqual(meta.requires, [], key)
            self.assertTrue(meta.description, key)
            self.assertTrue(meta.produces, key)
            self.assertTrue(meta.combo_signature, key)

    def test_keys_are_lowercase_words(self):
        for key in MODULE_SPECS:
            self.assertRegex(key, r"^[a-z][a-z-]*$")

    def test_modules_do_not_import_simulator(self):
        for key in MODULE_SPECS:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("trainstack_sim", source, f"{key} 不得依赖仿真器内部实现")
            self.assertNotIn("lab.trainstack", source, f"{key} 不得依赖仿真器内部实现")


class _Base(unittest.TestCase):
    mode = "vulnerable"

    def setUp(self):
        self.sim_tmp = TemporaryDirectory()
        self.server = start_all(mode=self.mode, root=Path(self.sim_tmp.name) / "sim")
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="trainstack-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("trainstack-tester", "x", "tester", ["trainstack-lab"])
        self.session = users.verify("trainstack-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8"],
            "window": "trainstack-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.server.shutdown()
        self.sim_tmp.cleanup()
        self.tmp.cleanup()

    def _backup_targets(self):
        return [
            {"kind": "file", "path": str(optimizer_state_path(self.server.root, "ckpt-optim-smoke"))},
            {"kind": "file", "path": str(data_shard_path(self.server.root, "shard-0001"))},
            {"kind": "file", "path": str(template_path(self.server.root))},
            {"kind": "file", "path": str(sft_jobs_path(self.server.root))},
            {"kind": "file", "path": str(rollout_buffer_path(self.server.root))},
            {"kind": "file", "path": str(jobs_path(self.server.root))},
        ]

    def _params(self, key, extra=None):
        params = {"target": self.server.url("")}
        if key in WRITE_KEYS:
            params["mode"] = "backup-write"
            params["backup_targets"] = self._backup_targets()
        params.update(extra or {})
        return params

    def _run(self, key, extra=None):
        self._seq += 1
        run = self.store.create_run(f"trainstack-{key}-{self._seq}")
        result = run_module(self.store, self.session, key, self._params(key, extra),
                            modules_dir=MODULES_DIR, run=run)
        findings = [f for f in run.findings if f["step_key"] == key]
        return result, findings, run


class VulnerableDetectionTest(_Base):
    mode = "vulnerable"

    def test_every_module_hits_and_honours_contract(self):
        for key in MODULE_SPECS:
            with self.subTest(module=key):
                result, findings, run = self._run(key)
                self.assertEqual(result["step"], key)
                self.assertTrue((run.dir / "traces" / f"{key}.json").is_file(),
                                f"{key} 缺 trace artifact")
                self.assertTrue((run.dir / "artifacts" / f"{key}.json").is_file(),
                                f"{key} 缺 artifact")
                high = [f for f in findings if f["severity"] == "high"]
                self.assertEqual(len(high), 1, f"{key}: {findings}")
                detail = _detail(high[0])
                self.assertTrue(detail, key)
                self.assertIn("route", detail, key)

    def test_config_surface_detail(self):
        _, findings, _ = self._run("megatron-deepspeed-config-surface")
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["config_status"], 200)
        self.assertEqual(detail["env_status"], 200)
        self.assertEqual(detail["world_size"], 512)
        self.assertEqual(set(detail["parallelism"]), {"tp", "pp", "ep", "cp", "sp"})
        self.assertTrue(detail["trust_remote_code"])
        self.assertIn("HF_TOKEN", detail["secret_names"])
        self.assertIn("WANDB_API_KEY", detail["secret_names"])
        self.assertTrue(detail["checkpoint_shared_path"])

    def test_elastic_detail(self):
        _, findings, _ = self._run("torchrun-elastic-surface")
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["rdzv_backend"], "etcd")
        self.assertEqual(detail["etcd_auth"], "none")
        self.assertFalse(detail["tls"])
        self.assertGreaterEqual(detail["member_count"], 2)

    def test_checkpoint_optimizer_write_readback(self):
        shard = "ckpt-optim-smoke"
        path = optimizer_state_path(self.server.root, shard)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        _, findings, run = self._run("checkpoint-optimizer-state-poison", {
            "mode": "backup-write", "shard_id": shard, "marker": "TRIDENT-OPT"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["write_status"], 200)
        self.assertEqual(detail["readback_status"], 200)
        self.assertTrue(detail["readback_matches"])
        self.assertTrue(detail["optimizer_state"])
        self.assertTrue(detail["changed_from_prior"])
        self.assertNotEqual(detail["readback_sha256"], before)
        self.assertIn("TRIDENT-OPT", path.read_text(encoding="utf-8"))
        receipt = BackupManager(self.store, run).rollback("checkpoint-optimizer-state-poison")
        self.assertGreaterEqual(receipt["restored"], 1)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_data_pipeline_tamper_detected(self):
        _, findings, _ = self._run("data-pipeline-poison",
                                   {"mode": "backup-write", "shard_id": "shard-0001"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["write_status"], 200)
        self.assertTrue(detail["tamper_detected"])
        self.assertNotEqual(detail["expected_sha256"], detail["actual_sha256"])
        self.assertGreaterEqual(detail["duplicate_ids"], 1)
        self.assertGreaterEqual(detail["unknown_ids"], 1)
        self.assertTrue(detail["order_changed"])

    def test_tokenizer_template_injection(self):
        _, findings, _ = self._run("tokenizer-template-injection",
                                   {"mode": "backup-write", "marker": "TRIDENT-TPL"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["write_status"], 200)
        self.assertTrue(detail["template_modified"])
        self.assertTrue(detail["injected_directive"])
        self.assertTrue(detail["marker_in_system_block"])
        self.assertFalse(detail["sanitized"])
        self.assertNotEqual(detail["template_sha256_after"], detail["template_sha256_before"])

    def test_tracker_exposure_masks_credentials(self):
        _, findings, _ = self._run("experiment-tracker-exposure")
        high = [f for f in findings if f["severity"] == "high"][0]
        detail = _detail(high)
        self.assertEqual(detail["runs_status"], 200)
        self.assertGreaterEqual(detail["other_tenant_runs"], 1)
        self.assertEqual(detail["auth"], "none")
        self.assertGreaterEqual(detail["key_count"], 2)
        self.assertTrue(all(k["value"].startswith("MOCK****") for k in detail["keys_masked"]))
        self.assertNotIn(FULL_TOKEN, high["detail"])

    def test_sft_framework_surface(self):
        _, findings, _ = self._run("sft-framework-surface",
                                   {"mode": "backup-write", "marker": "TRIDENT-SFT"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["status_status"], 200)
        self.assertEqual(detail["bind"], "0.0.0.0:7860")
        self.assertFalse(detail["auth"])
        self.assertTrue(detail["trust_remote_code"])
        self.assertTrue(detail["allow_file_scheme"])
        self.assertEqual(detail["submit_status"], 200)
        self.assertTrue(detail["accepted"])
        self.assertEqual(detail["data_path_scheme"], "file")
        self.assertTrue(detail["other_tenant_datasets"])
        self.assertTrue(detail["trl_dev_mode"])

    def test_rollout_buffer_cross_tenant(self):
        _, findings, _ = self._run("rl-rollout-buffer-poison",
                                   {"mode": "backup-write", "tenant": "tenant-a",
                                    "victim_tenant": "tenant-b", "marker": "TRIDENT-RL"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["victim_write_status"], 200)
        self.assertTrue(detail["cross_tenant"])
        self.assertEqual(detail["readback_status"], 200)
        self.assertTrue(detail["marker_present"])
        self.assertTrue(detail["shared_buffer"])

    def test_reward_hacking_multi_signal_not_single_point(self):
        _, findings, _ = self._run("reward-hacking-detect")
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["signal_count"], 3)
        self.assertEqual(detail["signal_count"], len(detail["signals"]))
        self.assertIn("reward-up-pass-flat", detail["signals"])
        self.assertIn("response-length-inflation", detail["signals"])
        self.assertIn("kl-collapse", detail["signals"])
        self.assertIn("多指标", detail["note"])

    def test_pretrain_job_escape(self):
        _, findings, _ = self._run("pretrain-job-escape",
                                   {"mode": "backup-write", "marker": "TRIDENT-JOB"})
        detail = _detail([f for f in findings if f["severity"] == "high"][0])
        self.assertEqual(detail["cluster_status"], 200)
        self.assertEqual(detail["shared_service_account"], "trainer-admin")
        self.assertTrue(detail["host_network"])
        self.assertEqual(detail["submit_status"], 200)
        self.assertEqual(detail["escape_primitives"], 3)
        self.assertTrue(detail["readback_privileged"])
        self.assertEqual(detail["readback_host_path"], "/")


class FixedHardeningTest(_Base):
    mode = "fixed"

    def test_no_high_findings_under_fixed(self):
        for key in MODULE_SPECS:
            with self.subTest(module=key):
                _, findings, _ = self._run(key)
                high = [f for f in findings if f["severity"] in ("high", "critical")]
                self.assertEqual(high, [], f"{key} 在 fixed 姿态仍报 high: {high}")
                self.assertTrue(findings, f"{key} 无任何 finding")

    def test_reward_metrics_healthy_under_fixed(self):
        _, findings, _ = self._run("reward-hacking-detect")
        detail = _detail(findings[0])
        self.assertEqual(findings[0]["severity"], "info")
        self.assertLess(detail["signal_count"], 3)


class WriteGateTest(_Base):
    mode = "vulnerable"

    def test_write_modules_refused_without_backup_targets(self):
        for key in sorted(WRITE_KEYS):
            with self.subTest(module=key):
                self._seq += 1
                run = self.store.create_run(f"trainstack-gate-{key}-{self._seq}")
                with self.assertRaises(BackupGateRefused):
                    run_module(self.store, self.session, key,
                               {"target": self.server.url(""), "mode": "backup-write"},
                               modules_dir=MODULES_DIR, run=run)


class NoTargetTest(unittest.TestCase):
    def test_missing_target_returns_empty(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="trainstack-lab")
            users = UserStore(root / "users.json")
            users.create_user("t", "x", "tester", ["trainstack-lab"])
            session = users.verify("t", "x")
            init_roe(store, fields={"level": "全影响演示", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            run = store.create_run("trainstack-no-target")
            backup_file = root / "no-target.backup.json"
            backup_file.write_text("{}", encoding="utf-8")
            for key, spec in MODULE_SPECS.items():
                params = {"backup_targets": [{"kind": "file", "path": str(backup_file)}]} \
                    if spec["writes"] else {}
                result = run_module(store, session, key, params,
                                    modules_dir=MODULES_DIR, run=run)
                self.assertEqual(result["step"], key)
                self.assertEqual([f for f in run.findings if f["step_key"] == key], [])


if __name__ == "__main__":
    unittest.main()
