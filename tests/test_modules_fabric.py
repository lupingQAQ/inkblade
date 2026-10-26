"""tests/test_modules_fabric.py — 万卡 fabric 破坏面 12 模块（真实 HTTP 差分证据）。

覆盖：
- 注册表契约：12 个纯小写键、系列/级别/writes、requires 为空；
- vulnerable 靶场下 5 个只读模块 + 7 个写类模块产出 high finding，证据来自
  HTTP 状态、/metrics 计数器差分、读回内容与计时差分；
- fixed 靶场下同一模块无 high finding（写面 401 / 超限 400 / 配额 429）；
- 写类闸门：backup-write 无 backup_targets → BackupGateRefused（退出码语义 91）；
- 两条 fabric 链：前置判定成立 + dry-run 写面/备份动作齐备；
- 模块源码不得引用仿真器答案（不 import lab.fabric_dos_sim）。
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.fabric_dos_sim import start_all
from inkblade.core.chains import dry_run, evaluate_preconditions, load_chains
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
CHAINS_DIR = REPO / "inkblade" / "chains"

NEW_MODULES = {
    "sharp-in-network-poison": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "ib-subnet-manager-hijack": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "roce-pfc-storm": {"series": "网络架构", "min_level": "利用验证", "writes": True},
    "nccl-straggler-injection": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "nccl-port-exhaustion": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "checkpoint-io-storm": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "api-server-flood-surface": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "kv-oom-bomb": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "training-silent-corruption": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "gang-scheduler-abuse": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "driver-reset-trigger": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "rail-mismatch-forcing": {"series": "网络架构", "min_level": "利用验证", "writes": True},
}

WRITE_MODULES = {k for k, v in NEW_MODULES.items() if v["writes"]}


def _detail(finding):
    try:
        return json.loads(finding["detail"])
    except (ValueError, TypeError):
        return {}


class FabricModuleTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="fabric-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("fabric-tester", "x", "tester", ["fabric-lab"])
        self.session = users.verify("fabric-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8"],
            "window": "fabric-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        self._seq += 1
        run = self.store.create_run(f"fabric-{key}-{self._seq}")
        result = run_module(self.store, self.session, key, params,
                            modules_dir=MODULES_DIR, run=run)
        findings = [f for f in run.findings if f["step_key"] == key]
        return result, findings, run

    def _backup(self, server, path):
        return [{"kind": "http", "url": server.url(path), "state": {}}]


class RegistryContractTest(unittest.TestCase):
    def test_twelve_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key, spec in NEW_MODULES.items():
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertEqual(meta.series, spec["series"], key)
            self.assertEqual(meta.min_level, spec["min_level"], key)
            self.assertEqual(meta.writes, spec["writes"], key)
            self.assertEqual(meta.requires, [], key)

    def test_modules_do_not_import_simulator(self):
        for key in NEW_MODULES:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("fabric_dos_sim", source, f"{key} 不得依赖仿真器内部答案")
            self.assertNotIn("lab.fabric", source, f"{key} 不得依赖仿真器内部答案")


class VulnerableDetectionTest(FabricModuleTestBase):
    def _high(self, findings):
        return [f for f in findings if f["severity"] == "high"]

    def test_sharp_in_network_poison(self):
        _, findings, _ = self._run("sharp-in-network-poison", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "backup_targets": self._backup(self.vulnerable, "/sharp/sessions"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["join_status"], 200)
        self.assertEqual(detail["baseline_result"], 36.0)
        self.assertNotEqual(detail["tampered_result"], detail["baseline_result"])
        self.assertGreaterEqual(detail["tampered_reduces_delta"], 1)

    def test_ib_subnet_manager_hijack(self):
        _, findings, _ = self._run("ib-subnet-manager-hijack", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "backup_targets": self._backup(self.vulnerable, "/ib/sm/partition"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["write_status"], 200)
        self.assertTrue(detail["member_in_partition"])
        self.assertGreaterEqual(detail["membership_changes_delta"], 1)

    def test_roce_pfc_storm(self):
        _, findings, _ = self._run("roce-pfc-storm", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "rounds": 3,
            "backup_targets": self._backup(self.vulnerable, "/roce/pfc"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["pfc_pause_frames_delta"], 50000)
        self.assertTrue(detail["storm_active"])

    def test_nccl_straggler_injection(self):
        _, findings, _ = self._run("nccl-straggler-injection", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "straggler_ms": 5000,
            "backup_targets": self._backup(self.vulnerable, "/nccl/rank"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["step_time_ratio"], 2.0)

    def test_nccl_port_exhaustion(self):
        _, findings, _ = self._run("nccl-port-exhaustion", {
            "target": self.vulnerable.url(""),
            "job": "inkblade-test",
            "max_allocs": 30,
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["victim_status"], 503)
        self.assertTrue(detail["victim_refused"])
        self.assertEqual(detail["ports_remaining"], 0)

    def test_checkpoint_io_storm(self):
        _, findings, _ = self._run("checkpoint-io-storm", {
            "target": self.vulnerable.url(""),
            "bytes_mb": 4096, "burst": 4, "rounds": 5,
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["io_bytes_mb_delta"], 40960)
        self.assertFalse(detail["rate_limited"])

    def test_api_server_flood_surface(self):
        _, findings, _ = self._run("api-server-flood-surface", {
            "target": self.vulnerable.url(""),
            "count": 250, "rounds": 4, "imds_rounds": 2,
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["requests_delta"] + detail["imds_requests_delta"], 500)
        self.assertFalse(detail["quota_enforced"])

    def test_kv_oom_bomb(self):
        _, findings, _ = self._run("kv-oom-bomb", {
            "target": self.vulnerable.url(""),
            "context_tokens": 4000000, "declared_context_tokens": 8192,
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["http_status"], 200)
        self.assertTrue(detail["oom"])
        self.assertGreater(detail["kv_bytes"], detail["capacity_bytes"])

    def test_training_silent_corruption(self):
        _, findings, _ = self._run("training-silent-corruption", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "scale": 3.0,
            "backup_targets": self._backup(self.vulnerable, "/train/gradient"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreaterEqual(detail["loss_ratio"], 2.0)
        self.assertTrue(detail["silent"])
        self.assertGreaterEqual(detail["corruption_events"], 1)

    def test_gang_scheduler_abuse(self):
        _, findings, _ = self._run("gang-scheduler-abuse", {
            "target": self.vulnerable.url(""),
            "gang_size": 8, "rounds": 5,
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreater(detail["pending_gpus"], detail["capacity"])
        self.assertTrue(detail["clogged"])

    def test_driver_reset_trigger(self):
        _, findings, _ = self._run("driver-reset-trigger", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "xid_code": 79,
            "backup_targets": self._backup(self.vulnerable, "/gpu/health"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertTrue(detail["reset_triggered"])
        self.assertFalse(detail["healthy_after"])
        self.assertGreaterEqual(detail["driver_resets_after"]
                                - detail["driver_resets_before"], 1)

    def test_rail_mismatch_forcing(self):
        _, findings, _ = self._run("rail-mismatch-forcing", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "rank": "rank-7", "force_rail": "rail-0",
            "backup_targets": self._backup(self.vulnerable, "/nccl/rail"),
        })
        high = self._high(findings)
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertTrue(detail["mismatch"])
        self.assertGreaterEqual(detail["cross_rail_flows"], 1)
        self.assertNotEqual(detail["original_rail"], detail["forced_rail"])


class FixedHardeningTest(FabricModuleTestBase):
    def test_no_high_findings_under_fixed(self):
        cases = [
            ("sharp-in-network-poison", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/sharp/sessions")}),
            ("ib-subnet-manager-hijack", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/ib/sm/partition")}),
            ("roce-pfc-storm", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/roce/pfc")}),
            ("nccl-straggler-injection", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/nccl/rank")}),
            ("training-silent-corruption", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/train/gradient")}),
            ("driver-reset-trigger", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/gpu/health")}),
            ("rail-mismatch-forcing", {
                "mode": "backup-write",
                "backup_targets": self._backup(self.fixed, "/nccl/rail")}),
            ("nccl-port-exhaustion", {}),
            ("checkpoint-io-storm", {}),
            ("api-server-flood-surface", {}),
            ("kv-oom-bomb", {}),
            ("gang-scheduler-abuse", {}),
        ]
        for key, extra in cases:
            with self.subTest(module=key):
                _, findings, _ = self._run(key, {"target": self.fixed.url(""), **extra})
                high = [f for f in findings if f["severity"] in ("high", "critical")]
                self.assertEqual(high, [], f"{key} 在 fixed 姿态仍报 high: {high}")


class WriteGateTest(FabricModuleTestBase):
    def test_write_modules_refused_without_backup_targets(self):
        for key in sorted(WRITE_MODULES):
            with self.subTest(module=key):
                with self.assertRaises(BackupGateRefused):
                    self._run(key, {"target": self.vulnerable.url(""),
                                    "mode": "backup-write"})


class ChainIntegrationTest(unittest.TestCase):
    """新增 2 条 fabric 链：前置判定可成立 + dry-run 写面/备份动作可读。"""

    def test_fabric_chains_preconditions_and_dry_run(self):
        chains = load_chains(CHAINS_DIR)
        findings = [
            {"step_key": "sharp-in-network-poison", "severity": "high",
             "title": "sharp", "detail": "{}"},
            {"step_key": "nccl-port-exhaustion", "severity": "high",
             "title": "ports", "detail": "{}"},
        ]
        for cid in ("fabric-silent-corruption-chain", "fabric-exhaustion-chain"):
            with self.subTest(chain=cid):
                self.assertIn(cid, chains)
                verdict, missing = evaluate_preconditions(chains[cid], findings)
                self.assertEqual(verdict, "成立", missing)
                plan = dry_run(chains[cid], findings, modules_dir=MODULES_DIR)
                self.assertEqual(plan["verdict"], "成立")
                write_steps = [s for s in plan["steps"] if s["writes"]]
                if cid == "fabric-silent-corruption-chain":
                    self.assertTrue(write_steps, f"{cid} 缺少写类步骤")
                    for step in write_steps:
                        self.assertTrue(step["backup_targets"], f"{cid} 写类步骤缺备份目标")
                        self.assertTrue(step["backup_actions"], f"{cid} 写类步骤缺备份动作")
                else:
                    self.assertEqual(write_steps, [], f"{cid} 应为只读链")


class NoTargetTest(unittest.TestCase):
    def test_missing_target_returns_empty(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="fabric-lab")
            users = UserStore(root / "users.json")
            users.create_user("t", "x", "tester", ["fabric-lab"])
            session = users.verify("t", "x")
            init_roe(store, fields={"level": "全影响演示", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            run = store.create_run("fabric-no-target")
            backup_file = root / "no-target.backup.json"
            backup_file.write_text("{}", encoding="utf-8")
            for key, spec in NEW_MODULES.items():
                params = {"backup_targets": [{"kind": "file", "path": str(backup_file)}]} \
                    if spec["writes"] else {}
                result = run_module(store, session, key, params,
                                    modules_dir=MODULES_DIR, run=run)
                self.assertEqual(result["step"], key)
                self.assertEqual([f for f in run.findings if f["step_key"] == key], [])


if __name__ == "__main__":
    unittest.main()
