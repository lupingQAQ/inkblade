"""tests/test_modules_cache.py — 多租户缓存安全 7 模块（真实 HTTP 差分 + 备份闸门）。

覆盖：
- 注册表契约：7 个模块键/系列/级别/writes，requires 为空，模块源码不 import 仿真器；
- vulnerable 靶场：每模块产出 high finding，证据来自真实 HTTP trace（状态码/usage/
  ttft_ms/逐出计数/sha256/KV 块读回），而非仿真器内部状态；
- 实效 4 项：近似缓存误命中读回 tenant-b marker、TTFT 差分显著（N=60≥50）、
  逐出残留跨租户可读、KV 池命名空间绕过读回 tenant-b 块；
- 写类模块 cache-poison-persistence：probe-only 前置条件 + backup-write 毒化块
  pinned 存续（sha256 读回一致）；无 backup_targets 时 runner 抛 BackupGateRefused(91)；
- fixed 靶场：同一批模块无 high/medium（仅 info 收敛结论），池读 403/残留 404。
"""
import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.cache_sim import start_all
from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"

MODULE_CASES = [
    {"key": "cache-salt-policy-audit", "series": "网络架构",
     "min_level": "主动探测", "writes": False},
    {"key": "similarity-cache-false-hit", "series": "窃取与数据泄露",
     "min_level": "主动探测", "writes": False},
    {"key": "cache-timing-sidechannel", "series": "窃取与数据泄露",
     "min_level": "主动探测", "writes": False},
    {"key": "cache-eviction-residue", "series": "窃取与数据泄露",
     "min_level": "主动探测", "writes": False},
    {"key": "remote-kv-pool-isolation", "series": "横向利用",
     "min_level": "主动探测", "writes": False},
    {"key": "router-cache-metrics-leak", "series": "网络架构",
     "min_level": "主动探测", "writes": False},
    {"key": "cache-poison-persistence", "series": "横向利用",
     "min_level": "利用验证", "writes": True},
]
KEYS = [case["key"] for case in MODULE_CASES]
HIGH_MODULES = [
    "cache-salt-policy-audit", "similarity-cache-false-hit",
    "cache-timing-sidechannel", "cache-eviction-residue",
    "remote-kv-pool-isolation", "router-cache-metrics-leak",
    "cache-poison-persistence",
]


def load_run(key: str):
    spec = importlib.util.spec_from_file_location(
        f"inkblade_cache_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_ctx(key: str, tmp_root: Path) -> dict:
    store = EvidenceStore(tmp_root, workspace="cache-lab")
    run = store.create_run(f"selftest-{key}")
    return {"store": store, "run": run, "marker": "INKBLADE-cache-selftest",
            "backup": BackupManager(store, run), "actor": "tester",
            "meta": {"key": key, "writes": True}}


def build_params(base: str, *, mode: str = "probe-only") -> dict:
    params = {
        "target": base,
        "mode": mode,
        "tenant": "tenant-a",
        "victim_tenant": "tenant-b",
        "admin_key": "cache-admin-key",
    }
    if mode == "backup-write":
        params["backup_targets"] = [{"kind": "http", "url": base + "/", "state": {}}]
    return params


def run_direct(key: str, params: dict, tmp_root: Path) -> dict:
    return load_run(key).run(make_ctx(key, tmp_root), params)


def detail_of(result: dict) -> dict:
    for finding in result.get("findings", []):
        if finding.get("sev") == "high":
            try:
                return json.loads(finding.get("detail") or "{}")
            except (TypeError, ValueError):
                return {}
    return {}


class RegistryContractTest(unittest.TestCase):
    def test_seven_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for case in MODULE_CASES:
            key = case["key"]
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertRegex(meta.key, r"^[a-z][a-z0-9-]*$")
            self.assertEqual(meta.key, meta.path.name, key)
            self.assertEqual(meta.series, case["series"], key)
            self.assertEqual(meta.min_level, case["min_level"], key)
            self.assertEqual(meta.writes, case["writes"], key)
            self.assertEqual(meta.requires, [], key)

    def test_modules_do_not_import_simulator(self):
        for key in KEYS:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("cache_sim", source, f"{key} 不得依赖仿真器内部答案")
            self.assertNotIn("lab.cache", source, f"{key} 不得依赖仿真器内部答案")


class VulnerableDetectionTest(unittest.TestCase):
    def test_each_module_produces_high_finding(self):
        for key in HIGH_MODULES:
            with self.subTest(key=key):
                with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
                    result = run_direct(key, build_params(lab.url("")), Path(tmp))
                    high = [f for f in result["findings"] if f["sev"] == "high"]
                    self.assertTrue(high, f"{key} vulnerable 必须 high: {result['summary']}")
                    self.assertTrue(result["artifacts"])
                    trace = json.loads(
                        Path(result["artifacts"][0]).read_text(encoding="utf-8"))
                    self.assertEqual(trace["module"], key)
                    self.assertTrue(trace["entries"])

    def test_false_hit_reads_victim_marker(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("similarity-cache-false-hit",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertTrue(detail["cross_tenant_hit"])
        self.assertEqual(detail["entry_tenant"], "tenant-b")
        self.assertTrue(detail["victim_marker_present"])
        self.assertIn("INKBLADE-BENIGN-APPROX-VICTIM", detail["response_excerpt"])

    def test_timing_delta_significant_n_ge_50(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("cache-timing-sidechannel",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertGreaterEqual(detail["n_total"], 50)
        self.assertTrue(detail["n_total_ge_50"])
        self.assertGreaterEqual(detail["delta_ms"], 30)
        self.assertLess(detail["p_value"], 0.05)
        self.assertTrue(detail["significant"])
        self.assertGreater(detail["extraction_rate"], 0.9)

    def test_eviction_residue_cross_tenant(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("cache-eviction-residue",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertGreaterEqual(detail["evictions_delta"], 1)
        self.assertTrue(detail["cross_tenant_residue"])
        self.assertEqual(detail["residue_tenant"], "tenant-b")
        self.assertTrue(detail["marker_present"])

    def test_kv_pool_namespace_bypass_reads_victim_block(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("remote-kv-pool-isolation",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertTrue(detail["cross_tenant_read"])
        self.assertEqual(detail["block_tenant"], "tenant-b")
        self.assertTrue(detail["marker_present"])
        self.assertEqual(detail["control_status"], 200)

    def test_salt_policy_cross_tenant_cached_tokens(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("cache-salt-policy-audit",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertTrue(detail["weak_config"])
        self.assertTrue(detail["cross_tenant_hit"])
        self.assertGreater(detail["cross_tenant_cached_tokens"], 0)

    def test_router_metrics_exposes_victim_tenant(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct("router-cache-metrics-leak",
                                build_params(lab.url("")), Path(tmp))
        detail = detail_of(result)
        self.assertTrue(detail["cross_tenant_visible"])
        self.assertIn("tenant-b", detail["visible_tenants"])
        self.assertIsNotNone(detail["victim_metrics"])

    def test_poison_write_persists_with_pinned_policy(self):
        with TemporaryDirectory() as tmp, start_all(mode="vulnerable") as lab:
            result = run_direct(
                "cache-poison-persistence",
                build_params(lab.url(""), mode="backup-write"), Path(tmp))
        detail = detail_of(result)
        self.assertEqual(detail["mode"], "backup-write")
        self.assertTrue(detail["pinned_applied"])
        self.assertGreaterEqual(detail["evictions_delta"], 1)
        self.assertTrue(detail["readback_matches"])
        self.assertTrue(detail["survived_eviction_pressure"])
        self.assertEqual(detail["readback_status"], 200)


class FixedDetectionTest(unittest.TestCase):
    def test_fixed_reports_no_high_or_medium(self):
        for key in HIGH_MODULES:
            with self.subTest(key=key):
                with TemporaryDirectory() as tmp, start_all(mode="fixed") as lab:
                    result = run_direct(key, build_params(lab.url("")), Path(tmp))
                    severe = [f for f in result["findings"]
                              if f["sev"] in ("high", "medium")]
                    self.assertEqual(severe, [],
                                     f"fixed 不得 high/medium: {result['summary']}")
                    self.assertTrue(result["findings"], "fixed 仍应给出 info 收敛结论")

    def test_fixed_pool_and_residue_statuses(self):
        with TemporaryDirectory() as tmp, start_all(mode="fixed") as lab:
            pool = run_direct("remote-kv-pool-isolation",
                              build_params(lab.url("")), Path(tmp))
            residue = run_direct("cache-eviction-residue",
                                 build_params(lab.url("")), Path(tmp))
        pool_detail = json.loads(pool["findings"][0]["detail"])
        residue_detail = json.loads(residue["findings"][0]["detail"])
        self.assertEqual(pool_detail["victim_status"], 403)
        self.assertEqual(residue_detail["residue_status"], 404)
        self.assertFalse(residue_detail["residue_found"])

    def test_fixed_pinning_denied_for_tenant(self):
        with TemporaryDirectory() as tmp, start_all(mode="fixed") as lab:
            result = run_direct(
                "cache-poison-persistence",
                build_params(lab.url(""), mode="backup-write"), Path(tmp))
        detail = json.loads(result["findings"][0]["detail"])
        self.assertFalse(detail["pinned_applied"])
        self.assertTrue(detail["pinning_denied"])
        self.assertEqual(detail["readback_status"], 404)


class BackupGateTest(unittest.TestCase):
    def test_write_module_refused_without_backup_targets(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="cache-lab")
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["cache-lab"])
            session = users.verify("tester", "x")
            init_roe(store, fields={"level": "全影响演示",
                                    "namespaces": ["default"],
                                    "cidrs": ["127.0.0.0/8"]})
            with start_all(mode="vulnerable") as lab:
                with self.assertRaises(BackupGateRefused) as ctx:
                    run_module(store, session, "cache-poison-persistence",
                               {"target": lab.url(""), "mode": "backup-write"},
                               modules_dir=MODULES_DIR)
                self.assertEqual(ctx.exception.exit_code, 91)

    def test_write_module_runs_with_backup_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="cache-lab")
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["cache-lab"])
            session = users.verify("tester", "x")
            init_roe(store, fields={"level": "全影响演示",
                                    "namespaces": ["default"],
                                    "cidrs": ["127.0.0.0/8"]})
            with start_all(mode="vulnerable") as lab:
                result = run_module(
                    store, session, "cache-poison-persistence",
                    {"target": lab.url(""), "mode": "backup-write",
                     "backup_targets": [{"kind": "http", "url": lab.url("/"),
                                         "state": {}}]},
                    modules_dir=MODULES_DIR)
                self.assertEqual(result["step"], "cache-poison-persistence")
                run = store.open_run(result["run"])
                self.assertTrue(any(f.get("severity") == "high" for f in run.findings),
                                "带备份回执的写类执行应产出 high finding")


if __name__ == "__main__":
    unittest.main()
