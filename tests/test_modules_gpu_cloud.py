"""tests/test_modules_gpu_cloud.py — GPU 池化/云跨租户 10 模块（真实 HTTP 差分证据）。

覆盖：
- 注册表契约：10 个纯小写键、系列/级别/writes、requires 为空；
- vulnerable 靶场下每模块产出 finding，且证据来自真实 HTTP 状态/计数器/sha256；
- fixed 靶场下同一模块 0 finding（含租户令牌路径：tenant-a 看不到 tenant-b）；
- 写类闸门：backup-write 无 backup_targets → BackupGateRefused（退出码语义 91）；
- 残留 marker 写读回 + 释放后仍可读 + sha256 一致；fixed 释放后 404；
- 通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏）；公共桶跨租户列目录。
- 模块源码不得 import 仿真器（不依赖靶场内部答案）。
"""
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.gpu_cloud_sim import ADMIN_TOKEN, TENANT_TOKENS, start_all
from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"

MODULE_CASES = [
    {"key": "gpu-pool-scheduler-unauth", "series": "网络架构", "min_level": "利用验证", "writes": True, "mode": "backup-write"},
    {"key": "gpu-tenant-residue", "series": "网络架构", "min_level": "利用验证", "writes": True, "mode": "backup-write"},
    {"key": "mig-profile-mismatch", "series": "网络架构", "min_level": "主动探测", "writes": True, "mode": "backup-write"},
    {"key": "mps-context-shared", "series": "网络架构", "min_level": "主动探测", "writes": False, "mode": "probe-only"},
    {"key": "gpu-metrics-tenant-leak", "series": "网络架构", "min_level": "主动探测", "writes": False, "mode": "probe-only"},
    {"key": "gpu-device-cross-namespace", "series": "网络架构", "min_level": "主动探测", "writes": False, "mode": "probe-only"},
    {"key": "cloud-irsa-trust-wildcard", "series": "混合云", "min_level": "利用验证", "writes": False, "mode": "probe-only"},
    {"key": "cloud-bucket-cross-tenant", "series": "混合云", "min_level": "利用验证", "writes": False, "mode": "probe-only"},
    {"key": "cloud-snapshot-share", "series": "混合云", "min_level": "利用验证", "writes": True, "mode": "backup-write"},
    {"key": "cloud-sg-imds-exposure", "series": "混合云", "min_level": "主动探测", "writes": False, "mode": "probe-only"},
]


def load_run(key: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        f"inkblade_gpu_cloud_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_ctx(key: str, tmp_root: Path) -> dict:
    store = EvidenceStore(tmp_root, workspace="gpu-cloud-lab")
    run = store.create_run(f"selftest-{key}")
    return {"store": store, "run": run, "marker": "INKBLADE-selftest",
            "backup": BackupManager(store, run), "actor": "tester",
            "meta": {"key": key, "writes": True}}


def build_params(case: dict, base: str, *, fixed: bool = False) -> dict:
    params = {
        "target": base,
        "mode": case["mode"],
        "tenant": "tenant-a",
        "victim_tenant": "tenant-b",
        "token": TENANT_TOKENS["tenant-a"],
        "admin_token": ADMIN_TOKEN,
    }
    if case["mode"] == "backup-write":
        params["backup_targets"] = [{"kind": "http", "url": base + "/", "state": {}}]
    return params


def run_direct(key: str, params: dict, tmp_root: Path) -> dict:
    return load_run(key).run(make_ctx(key, tmp_root), params)


def _detail(finding: dict) -> dict:
    try:
        return json.loads(finding.get("detail") or "{}")
    except (ValueError, TypeError):
        return {}


class RegistryContractTest(unittest.TestCase):
    def test_ten_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for case in MODULE_CASES:
            key = case["key"]
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertRegex(meta.key, r"^[a-z][a-z-]*$")
            self.assertEqual(meta.key, meta.path.name, key)
            self.assertEqual(meta.series, case["series"], key)
            self.assertEqual(meta.min_level, case["min_level"], key)
            self.assertEqual(meta.writes, case["writes"], key)
            self.assertEqual(meta.requires, [], key)

    def test_modules_do_not_import_simulator(self):
        for case in MODULE_CASES:
            source = (MODULES_DIR / case["key"] / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("gpu_cloud_sim", source, f"{case['key']} 不得依赖仿真器内部答案")
            self.assertNotIn("lab.gpu_cloud", source, f"{case['key']} 不得依赖仿真器内部答案")


class VulnerableDetectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_each_module_produces_findings(self):
        with TemporaryDirectory() as tmp:
            for case in MODULE_CASES:
                with self.subTest(key=case["key"]):
                    result = run_direct(case["key"], build_params(case, self.lab.url("")), Path(tmp))
                    self.assertTrue(result["findings"], "vulnerable 必须检出 ≥1 finding")
                    for f in result["findings"]:
                        self.assertIn(f["sev"], ("high", "medium", "low", "info"))
                        self.assertIsInstance(f["detail"], str)
                    self.assertTrue(result["artifacts"])
                    doc = json.loads(Path(result["artifacts"][0]).read_text(encoding="utf-8"))
                    self.assertEqual(doc["module"], case["key"])
                    self.assertTrue(doc["entries"])

    def test_residue_marker_write_readback_after_release(self):
        with TemporaryDirectory() as tmp:
            result = run_direct("gpu-tenant-residue",
                                build_params(MODULE_CASES[1], self.lab.url("")), Path(tmp))
        details = [_detail(f) for f in result["findings"]]
        readback = next(d for d in details if d.get("readback_after_release"))
        expected = hashlib.sha256(readback["marker"].encode("utf-8")).hexdigest()
        self.assertEqual(readback["marker_sha256"], expected)
        self.assertEqual(readback["readback_file_sha256"], readback["residue_file_sha256"])
        self.assertEqual(readback["victim_tenant"], "tenant-b")
        self.assertIn("INKBLADE-BENIGN-", readback["marker"])

    def test_cross_account_assume_role_success_and_masking(self):
        with TemporaryDirectory() as tmp:
            result = run_direct("cloud-irsa-trust-wildcard",
                                build_params(MODULE_CASES[6], self.lab.url("")), Path(tmp))
        text = result["summary"] + json.dumps(result["findings"], ensure_ascii=False)
        self.assertIn("MOCK****", text)
        for secret in ("MOCKAKIACROSSTENANT", "MOCKSECRETCROSSTENANT", "MOCKSESSIONCROSSTENANT"):
            self.assertNotIn(secret, text)
        details = [_detail(f) for f in result["findings"]]
        assumed = next(d for d in details if d.get("assume_role_status") == 200)
        self.assertTrue(assumed["cross_account"])
        self.assertEqual(assumed["source_account"], "999999999999")
        self.assertTrue(assumed["trust_policy_wildcard"])

    def test_public_bucket_cross_tenant_listing(self):
        with TemporaryDirectory() as tmp:
            result = run_direct("cloud-bucket-cross-tenant",
                                build_params(MODULE_CASES[7], self.lab.url("")), Path(tmp))
        details = [_detail(f) for f in result["findings"]]
        listing = next(d for d in details if d.get("objects"))
        self.assertGreaterEqual(listing["object_count"], 1)
        self.assertTrue(any(k.startswith("tenant-b/") for k in listing["objects"]))
        self.assertTrue(listing["cross_tenant"])
        self.assertEqual(listing["bucket_owner"], "tenant-b")


class FixedDetectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_fixed_reports_zero_findings_with_tenant_token(self):
        with TemporaryDirectory() as tmp:
            for case in MODULE_CASES:
                with self.subTest(key=case["key"]):
                    result = run_direct(case["key"], build_params(case, self.lab.url(""), fixed=True), Path(tmp))
                    self.assertEqual(result["findings"], [], f"fixed 必须为 0 finding: {result['summary']}")

    def test_fixed_residue_cleanup_after_own_release(self):
        with TemporaryDirectory() as tmp:
            result = run_direct("gpu-tenant-residue",
                                build_params(MODULE_CASES[1], self.lab.url(""), fixed=True), Path(tmp))
        self.assertEqual(result["findings"], [])
        self.assertIn("residue_cleanup", result["summary"])


class BackupGateTest(unittest.TestCase):
    def test_write_module_refused_without_backup_targets(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="gpu-cloud-lab")
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["gpu-cloud-lab"])
            session = users.verify("tester", "x")
            init_roe(store, fields={"level": "全影响演示", "namespaces": ["ns-a-infer"],
                                    "cidrs": ["127.0.0.0/8"]})
            with start_all(mode="vulnerable") as lab:
                with self.assertRaises(BackupGateRefused) as ctx:
                    run_module(store, session, "gpu-pool-scheduler-unauth",
                               {"target": lab.url(""), "mode": "backup-write"},
                               modules_dir=MODULES_DIR)
                self.assertEqual(ctx.exception.exit_code, 91)


if __name__ == "__main__":
    unittest.main()
