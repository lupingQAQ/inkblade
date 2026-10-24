"""tests/test_modules_lateral.py — 横向利用模块族（19 模块）表驱动自测。

契约：trident/core/runner.py（run(ctx, params) -> {summary, artifacts, findings}；writes=true 的
写动作仅可在 backup-write 模式且 params.backup_targets 提供时执行）；靶场：lab/mock_targets.py。

Ruling（实验室同构承载：单端口 25 路由对 19 模块的映射，module.json description 同步记载）：
- 直达：vllm /plugins/*、djev /v1/*、sglang 管理面、slime /pull_weights、areal 三步链、ray /api/jobs/、
  /mock-imds/aws/*（ssrf-imds-credential）。
- 同构（漏洞类级映射）：
  /pull_weights 承载「未鉴权权重拉取/加载通道」（skyrl /fetch_weights、areal /load 与 /save、LoRA 运行时加载）；
  areal /create_engine 承载「无鉴权训练控制面」（skyrl tinker 建模型/删检查点）；
  areal /call 承载「无鉴权对象通道」（verl recv_pyobj 检查点）与 NCCL rendezvous 入组回显；
  ray POST /api/jobs/ 承载「未鉴权命令/路径提交执行」（verl HDFS 路径拼入 os.system）；
  djev /v1/* 承载「无 key 推理/打分服务面」（trl vllm-serve dev-mode、serve_rm 奖励打分滥用）；
  vllm /plugins/invoke 承载「外部代码加载执行」（trust_remote_code 供应链投毒）；
  sglang /update_weights_from_disk 承载「管理面放行的磁盘路径写」（sglang-omni profiler 事件目录写）。
- 探针安全边界：probe-only 仅打靶场 ROUTE_TABLE 中 writes=False 路由；writes=True 路由
  （slime /pull_weights、ray POST /api/jobs/）只在 backup-write（backup_targets 已提供）下触碰。
- 检测依据 = 实际 HTTP 响应差分（vulnerable 200 vs fixed 401/403），不读取 /__routes__ 的姿态答案。
"""
import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.mock_targets import start_all
from trident.core.backup import BackupManager
from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import init_roe
from trident.core.runner import BackupGateRefused, run_module
from trident.core.users import UserStore

MODULES_DIR = Path(__file__).resolve().parents[1] / "trident" / "modules"

# 表驱动：key / 自测模式 / 是否需要 backup_targets / module.json writes / 是否需要 collective_snapshot
LATERAL_CASES = [
    {"key": "vllm-plugin-auth-bypass", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "djev-open-proxy", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "sglang-admin-failopen", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "slime-weight-pull-poison", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "sglang-omni-profiler-write", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "skyrl-dev-pickle-rce", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "skyrl-tinker-hijack", "mode": "probe-only", "backup": False, "writes": True, "snapshot": False},
    {"key": "trl-serve-dev-mode", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "areal-setenv-engine-rce", "mode": "probe-only", "backup": False, "writes": True, "snapshot": False},
    {"key": "areal-load-pickle", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "areal-awex-nccl-injection", "mode": "probe-only", "backup": False, "writes": True, "snapshot": False},
    {"key": "verl-checkpoint-pickle", "mode": "probe-only", "backup": False, "writes": True, "snapshot": False},
    {"key": "verl-hdfs-command-injection", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "ray-dashboard-job", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "ssrf-imds-credential", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "trust-remote-code-supply-chain", "mode": "probe-only", "backup": False, "writes": True, "snapshot": False},
    {"key": "lora-adapter-injection", "mode": "backup-write", "backup": True, "writes": True, "snapshot": False},
    {"key": "reward-model-abuse", "mode": "probe-only", "backup": False, "writes": False, "snapshot": False},
    {"key": "nccl-collective-join", "mode": "probe-only", "backup": False, "writes": True, "snapshot": True},
]

# 检测面即靶场 writes=True 路由的模块：probe-only 必须 0 finding 且不触发靶场写盘
PROBE_ZERO_KEYS = {
    "slime-weight-pull-poison", "skyrl-dev-pickle-rce", "areal-load-pickle",
    "verl-hdfs-command-injection", "ray-dashboard-job", "lora-adapter-injection",
}

MOCK_SECRETS = ("MOCKAKIATRIDENTLAB", "MOCKSECRETTRIDENTLAB", "MOCKSESSIONTRIDENTLAB")


def load_run(key: str):
    """按 runner 同款方式加载模块 run.py。"""
    spec = importlib.util.spec_from_file_location(
        f"trident_selftest_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_ctx(key: str, tmp_root: Path) -> dict:
    store = EvidenceStore(tmp_root, workspace="local-lab")
    run = store.create_run(f"selftest-{key}")
    return {"store": store, "run": run, "marker": "TRIDENT-selftest",
            "backup": BackupManager(store, run), "actor": "tester",
            "meta": {"key": key, "writes": True}}


def build_params(case: dict, base: str) -> dict:
    params = {"target": base, "mode": case["mode"]}
    if case["backup"]:
        params["backup_targets"] = [{"kind": "http", "url": base + "/", "state": {}}]
    if case["snapshot"]:
        params["collective_snapshot"] = {
            "reachable": True, "auth": "none",
            "bootstrap_url": base + "/call", "world_size": 8,
        }
    return params


def run_direct(key: str, params: dict, tmp_root: Path) -> dict:
    return load_run(key).run(make_ctx(key, tmp_root), params)


class CatalogTest(unittest.TestCase):
    def test_catalog_registered_and_contract(self):
        """19 个横向模块全部注册，键纯小写单词、系列/writes/级别与规格一致。"""
        mods = load_modules(MODULES_DIR)
        self.assertTrue(mods, "模块目录未加载出任何模块")
        for case in LATERAL_CASES:
            key = case["key"]
            self.assertIn(key, mods, f"缺少模块 {key}")
            m = mods[key]
            self.assertRegex(m.key, r"^[a-z][a-z-]*$", "机器键禁数字/非小写")
            self.assertEqual(m.key, m.path.name, "机器键必须与目录同名")
            self.assertEqual(m.series, "横向利用", key)
            self.assertEqual(m.writes, case["writes"], f"{key} writes 标志不符")
            self.assertEqual(m.min_level, "利用验证", key)
            self.assertTrue((m.path / "run.py").is_file(), key)
        lateral = [k for k, m in mods.items() if m.series == "横向利用"]
        self.assertGreaterEqual(len(lateral), len(LATERAL_CASES))


class VulnerableSelftestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_vulnerable_detects_at_least_one_finding(self):
        """vulnerable 姿态：每模块 ≥1 finding，trace 落盘且结构完整。"""
        with TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            for case in LATERAL_CASES:
                with self.subTest(key=case["key"]):
                    result = run_direct(case["key"], build_params(case, self.lab.url("")), tmp_root)
                    self.assertIsInstance(result["summary"], str)
                    self.assertTrue(result["summary"], "summary 非空")
                    self.assertTrue(result["findings"], "vulnerable 必须检出 ≥1 finding")
                    for f in result["findings"]:
                        self.assertIn(f["sev"], ("high", "medium", "low", "info"))
                        self.assertIsInstance(f["title"], str)
                        self.assertIsInstance(f["detail"], str, "detail 必须是字符串（数据库层可入库）")
                    self.assertTrue(result["artifacts"], "必须返回 trace artifact")
                    for art in result["artifacts"]:
                        self.assertTrue(Path(art).is_file(), f"artifact 未落盘: {art}")
                    doc = json.loads(Path(result["artifacts"][0]).read_text(encoding="utf-8"))
                    self.assertEqual(doc["module"], case["key"])
                    self.assertTrue(doc["entries"], "trace 必须含全部请求条目")


class FixedSelftestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_fixed_reports_zero_findings(self):
        """fixed 姿态：每模块 0 finding（trace 仍完整落盘）。"""
        with TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            for case in LATERAL_CASES:
                with self.subTest(key=case["key"]):
                    result = run_direct(case["key"], build_params(case, self.lab.url("")), tmp_root)
                    self.assertEqual(result["findings"], [], "fixed 必须为 0 finding")
                    self.assertTrue(all(Path(a).is_file() for a in result["artifacts"]))


class ProbeSafetyTest(unittest.TestCase):
    def test_probe_only_never_touches_write_face(self):
        """probe-only：检测面为靶场 writes=True 路由的模块必须 0 finding 且靶场零写盘。"""
        with TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            lab_root = tmp_root / "labroot"
            lab_root.mkdir()
            with start_all(mode="vulnerable", root=lab_root) as lab:
                for key in sorted(PROBE_ZERO_KEYS):
                    with self.subTest(key=key):
                        result = run_direct(key, {"target": lab.url(""), "mode": "probe-only"}, tmp_root)
                        self.assertEqual(result["findings"], [], "probe-only 不得产生写面检测结论")
            self.assertEqual(list(lab_root.glob("**/*")), [], "probe-only 不得触发靶场任何写盘")


class ModeGateTest(unittest.TestCase):
    def test_backup_write_without_targets_downgrades(self):
        """backup-write 缺 backup_targets：降级 probe-only，0 finding，无写动作。"""
        with TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            lab_root = tmp_root / "labroot"
            lab_root.mkdir()
            with start_all(mode="vulnerable", root=lab_root) as lab:
                result = run_direct("slime-weight-pull-poison",
                                    {"target": lab.url(""), "mode": "backup-write"}, tmp_root)
            self.assertEqual(result["findings"], [])
            self.assertIn("降级", result["summary"])
            self.assertEqual(list(lab_root.glob("**/*")), [])


class MaskingTest(unittest.TestCase):
    def test_credentials_masked_in_outputs_raw_in_trace(self):
        """凭据输出 MOCK 前缀脱敏（尾 4 位）；全文仅存在于证据 trace。"""
        with TemporaryDirectory() as tmp:
            with start_all(mode="vulnerable") as lab:
                result = run_direct("ssrf-imds-credential",
                                    {"target": lab.url(""), "mode": "probe-only"}, Path(tmp))
                doc = json.loads(Path(result["artifacts"][0]).read_text(encoding="utf-8"))
        text = result["summary"] + json.dumps(result["findings"], ensure_ascii=False)
        self.assertIn("MOCK****", text)
        for secret in MOCK_SECRETS:
            self.assertNotIn(secret, text, "凭据全文不得出现在输出")
        self.assertIn("MOCKAKIATRIDENTLAB", json.dumps(doc), "trace 证据层保留原始响应")


class NcclSnapshotTest(unittest.TestCase):
    def test_negative_snapshot_yields_no_findings(self):
        """collective_snapshot 判定不可达/已认证 → 联动前置不成立 → 0 finding（即便靶场 vulnerable）。"""
        with TemporaryDirectory() as tmp:
            with start_all(mode="vulnerable") as lab:
                result = run_direct("nccl-collective-join", {
                    "target": lab.url(""), "mode": "probe-only",
                    "collective_snapshot": {"reachable": False, "auth": "none",
                                            "bootstrap_url": lab.url("/call"), "world_size": 8},
                }, Path(tmp))
                self.assertEqual(result["findings"], [])
                result2 = run_direct("nccl-collective-join", {
                    "target": lab.url(""), "mode": "probe-only",
                    "collective_snapshot": {"reachable": True, "auth": "token",
                                            "bootstrap_url": lab.url("/call"), "world_size": 8},
                }, Path(tmp))
                self.assertEqual(result2["findings"], [])


class RunnerEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def _session(self, root: Path):
        users = UserStore(root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        return users.verify("tester", "x")

    def test_slime_via_runner_with_backup(self):
        """经 run_module 全链路：备份闸门放行 + 发现入库 + trace 归档。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="local-lab")
            init_roe(store, fields={"level": "利用验证", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            params = {
                "target": self.lab.url(""),
                "mode": "backup-write",
                "backup_targets": [{"kind": "http", "url": self.lab.url("/pull_weights"), "state": {}}],
            }
            result = run_module(store, self._session(root), "slime-weight-pull-poison",
                                params=params, modules_dir=MODULES_DIR)
            run = store.open_run(result["run"])
            self.assertTrue(run.findings, "发现必须入数据库层")
            self.assertIn("slime-weight-pull-poison", result["step"])

    def test_runner_gate_refuses_without_backup_targets(self):
        """写类模块经 runner 缺 backup_targets：退出码 91 拒绝，模块体不执行。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="local-lab")
            init_roe(store, fields={"level": "利用验证", "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            with self.assertRaises(BackupGateRefused) as cm:
                run_module(store, self._session(root), "slime-weight-pull-poison",
                           params={"target": self.lab.url(""), "mode": "backup-write"},
                           modules_dir=MODULES_DIR)
            self.assertEqual(cm.exception.exit_code, 91)


if __name__ == "__main__":
    unittest.main()
