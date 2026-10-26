"""tests/test_modules_longctx.py — 长上下文/大规模训练 8 模块（真实 HTTP 差分证据）。

覆盖：
- 注册表契约：8 个纯小写键、系列/级别/writes、requires 为空；
- vulnerable 靶场下 6 个只读模块 + 2 个写类模块产出 high finding，且证据来自 HTTP 状态/计数器/读回 sha256；
- fixed 靶场下同一模块无 high finding（超窗 400 / metrics 401 / cache_salt 403 / 写面 401）；
- 写类闸门：backup-write 无 backup_targets → BackupGateRefused（退出码语义 91）；
- checkpoint 分片：写后 sha256 变化 + marker 落地，rollback 后 sha256 精确复原；
- 模块源码不得引用仿真器答案（不 import lab.longctx_sim）。
"""
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.longctx_sim import checkpoint_shard_path, start_all
from inkblade.core.backup import BackupManager
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
    "long-context-window-exhaustion": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "prefix-cache-cross-tenant-leak": {"series": "窃取与数据泄露", "min_level": "主动探测", "writes": False},
    "kv-cache-integrity-poison": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "prefill-decode-kv-channel-unauth": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "long-context-training-collective-surface": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "checkpoint-shard-poison": {"series": "横向利用", "min_level": "利用验证", "writes": True},
    "long-context-memory-amplification": {"series": "网络架构", "min_level": "主动探测", "writes": False},
    "context-limit-bypass": {"series": "网络架构", "min_level": "主动探测", "writes": False},
}


def _detail(finding):
    try:
        return json.loads(finding["detail"])
    except (ValueError, TypeError):
        return {}


class LongctxModuleTestBase(unittest.TestCase):
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
        self.store = EvidenceStore(self.root, workspace="longctx-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("longctx-tester", "x", "tester", ["longctx-lab"])
        self.session = users.verify("longctx-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8"],
            "window": "longctx-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        self._seq += 1
        run = self.store.create_run(f"longctx-{key}-{self._seq}")
        result = run_module(self.store, self.session, key, params,
                            modules_dir=MODULES_DIR, run=run)
        findings = [f for f in run.findings if f["step_key"] == key]
        return result, findings, run


class RegistryContractTest(unittest.TestCase):
    def test_eight_modules_registered(self):
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
            self.assertNotIn("longctx_sim", source, f"{key} 不得依赖仿真器内部答案")
            self.assertNotIn("lab.longctx", source, f"{key} 不得依赖仿真器内部答案")


class VulnerableDetectionTest(LongctxModuleTestBase):
    def test_window_exhaustion(self):
        _, findings, _ = self._run("long-context-window-exhaustion",
                                   {"target": self.vulnerable.url("")})
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["http_status"], 200)
        self.assertGreater(detail["prefill_tokens"], detail["context_window_tokens"])
        self.assertGreaterEqual(detail["queue_depth_delta"], 1)

    def test_prefix_cache_cross_tenant(self):
        _, findings, _ = self._run("prefix-cache-cross-tenant-leak",
                                   {"target": self.vulnerable.url("")})
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreater(detail["cached_tokens"], 0)
        self.assertTrue(detail["cross_tenant"])
        self.assertEqual(detail["reuse_status"], 200)

    def test_kv_cache_integrity_poison_write_readback(self):
        _, findings, run = self._run("kv-cache-integrity-poison", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "block_id": "kv-test-block",
            "backup_targets": [{"kind": "http",
                                "url": self.vulnerable.url("/kv/transfer"),
                                "state": {}}],
        })
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["write_status"], 200)
        self.assertEqual(detail["readback_status"], 200)
        self.assertTrue(detail["readback_matches"])
        trace = json.loads((run.dir / "traces" / "kv-cache-integrity-poison.json")
                           .read_text(encoding="utf-8"))
        get = [e for e in trace["entries"] if e["method"] == "GET" and e["url"].endswith("/kv/transfer?block_id=kv-test-block")]
        self.assertEqual(len(get), 1)
        self.assertTrue(get[0]["response"]["found"])

    def test_prefill_decode_kv_channel_unauth(self):
        _, findings, _ = self._run("prefill-decode-kv-channel-unauth",
                                   {"target": self.vulnerable.url("")})
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["read_status"], 200)
        self.assertEqual(detail["metrics_status"], 200)

    def test_training_collective_surface(self):
        _, findings, _ = self._run("long-context-training-collective-surface",
                                   {"target": self.vulnerable.url("")})
        hits = [f for f in findings if f["severity"] in ("high", "medium")]
        self.assertEqual(len(hits), 1, findings)
        detail = _detail(hits[0])
        self.assertGreaterEqual(detail["world_size"], 64)
        self.assertTrue(detail["ring_attention"])
        self.assertTrue(detail["hierarchical_all_reduce"])
        self.assertTrue(detail["collective_ports"])

    def test_checkpoint_shard_poison_and_rollback(self):
        shard_id = "inkblade-shard-test"
        path = checkpoint_shard_path(self.vulnerable.root, shard_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        original = b"INKBLADE-CHECKPOINT-ORIGINAL\nshard=test\n"
        path.write_bytes(original)
        before = hashlib.sha256(original).hexdigest()
        _, findings, run = self._run("checkpoint-shard-poison", {
            "target": self.vulnerable.url(""),
            "mode": "backup-write",
            "shard_id": shard_id,
            "marker": "INKBLADE-MARKER-SHARD",
            "backup_targets": [{"kind": "file", "path": str(path)}],
        })
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        after = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertNotEqual(after, before)
        content = path.read_text(encoding="utf-8", errors="replace")
        self.assertIn("INKBLADE-MARKER-SHARD", content)
        detail = _detail(high[0])
        self.assertEqual(detail["readback_sha256"], after)
        receipt = BackupManager(self.store, run).rollback("checkpoint-shard-poison")
        self.assertGreaterEqual(receipt["restored"], 1)
        self.assertEqual(receipt["failed"], 0, receipt["items"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        self.assertEqual(path.read_bytes(), original)

    def test_long_context_memory_amplification(self):
        _, findings, _ = self._run("long-context-memory-amplification",
                                   {"target": self.vulnerable.url("")})
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertGreater(detail["amplification_ratio"], 64)
        self.assertGreater(detail["kv_cache_bytes_delta"], 0)

    def test_context_limit_bypass(self):
        _, findings, _ = self._run("context-limit-bypass",
                                   {"target": self.vulnerable.url("")})
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, findings)
        detail = _detail(high[0])
        self.assertEqual(detail["baseline_status"], 200)
        self.assertEqual(detail["bypass_status"], 200)
        self.assertGreater(detail["prefill_tokens"], detail["context_window_tokens"])


class FixedHardeningTest(LongctxModuleTestBase):
    def test_no_high_findings_under_fixed(self):
        cases = [
            ("long-context-window-exhaustion", {}),
            ("prefix-cache-cross-tenant-leak", {}),
            ("prefill-decode-kv-channel-unauth", {}),
            ("long-context-training-collective-surface", {}),
            ("long-context-memory-amplification", {}),
            ("context-limit-bypass", {}),
            ("kv-cache-integrity-poison", {
                "mode": "backup-write",
                "backup_targets": [{"kind": "http",
                                    "url": self.fixed.url("/kv/transfer"),
                                    "state": {}}],
            }),
            ("checkpoint-shard-poison", {
                "mode": "backup-write",
                "shard_id": "shard-fixed",
                "backup_targets": [{"kind": "http",
                                    "url": self.fixed.url("/checkpoint/shards"),
                                    "state": {}}],
            }),
        ]
        for key, extra in cases:
            with self.subTest(module=key):
                _, findings, _ = self._run(key, {"target": self.fixed.url(""), **extra})
                high = [f for f in findings if f["severity"] in ("high", "critical")]
                self.assertEqual(high, [], f"{key} 在 fixed 姿态仍报 high: {high}")


class WriteGateTest(LongctxModuleTestBase):
    def test_kv_poison_refused_without_backup_targets(self):
        with self.assertRaises(BackupGateRefused):
            self._run("kv-cache-integrity-poison", {
                "target": self.vulnerable.url(""),
                "mode": "backup-write",
            })

    def test_checkpoint_poison_refused_without_backup_targets(self):
        with self.assertRaises(BackupGateRefused):
            self._run("checkpoint-shard-poison", {
                "target": self.vulnerable.url(""),
                "mode": "backup-write",
                "shard_id": "shard-gate",
            })


class ChainIntegrationTest(unittest.TestCase):
    """新增 2 条链：前置判定可成立 + dry-run 写面/备份动作可读。"""

    def test_new_chains_preconditions_and_dry_run(self):
        chains = load_chains(CHAINS_DIR)
        findings = [
            {"step_key": "long-context-window-exhaustion", "severity": "high",
             "title": "window", "detail": "{}"},
            {"step_key": "prefill-decode-kv-channel-unauth", "severity": "high",
             "title": "kv", "detail": "{}"},
        ]
        for cid in ("long-context-cache-leak", "pd-kv-poison"):
            with self.subTest(chain=cid):
                self.assertIn(cid, chains)
                verdict, missing = evaluate_preconditions(chains[cid], findings)
                self.assertEqual(verdict, "成立", missing)
                plan = dry_run(chains[cid], findings, modules_dir=MODULES_DIR)
                self.assertEqual(plan["verdict"], "成立")
                write_steps = [s for s in plan["steps"] if s["writes"]]
                if cid == "pd-kv-poison":
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
            store = EvidenceStore(root, workspace="longctx-lab")
            users = UserStore(root / "users.json")
            users.create_user("t", "x", "tester", ["longctx-lab"])
            session = users.verify("t", "x")
            init_roe(store, fields={"level": "全影响演示", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            run = store.create_run("longctx-no-target")
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
