"""tests/test_chains_gpu_cloud.py — GPU 池化残留链 / 云跨租户角色链（dry-run + execute）。

覆盖：
- 链目录存在且类别/依赖正确；
- 前置三态（无发现不成立 / 有调度面发现成立）；
- dry-run 列出写类步骤的 backup_targets 与写面；
- 对 lab/gpu_cloud_sim vulnerable 真实执行两条链：全步骤 success、证据落库、备份回执在库。
"""
import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.gpu_cloud_sim import start_all
from inkblade.core.chains import dry_run, evaluate_preconditions, execute, load_chains
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
CHAINS_DIR = REPO / "inkblade" / "chains"
MODULES_DIR = REPO / "inkblade" / "modules"

GPU_CHAIN = "gpu-tenant-residue-chain"
CLOUD_CHAIN = "cloud-cross-tenant-role-assume"


class ChainCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chains = load_chains(CHAINS_DIR)

    def test_chains_registered(self):
        self.assertIn(GPU_CHAIN, self.chains)
        self.assertIn(CLOUD_CHAIN, self.chains)
        gpu = self.chains[GPU_CHAIN]
        cloud = self.chains[CLOUD_CHAIN]
        self.assertEqual(gpu["category"], "网络利用链")
        self.assertEqual(cloud["category"], "云侧权重桶链")
        self.assertIn("gpu-pool-scheduler-unauth", gpu["requires"])
        self.assertIn("cloud-irsa-trust-wildcard", cloud["requires"])

    def test_preconditions_three_states(self):
        gpu = self.chains[GPU_CHAIN]
        verdict, missing = evaluate_preconditions(gpu, [])
        self.assertEqual(verdict, "不成立")
        self.assertTrue(missing)
        verdict, missing = evaluate_preconditions(gpu, [
            {"step_key": "gpu-pool-scheduler-unauth", "sev": "high", "detail": "{}"},
        ])
        self.assertEqual(verdict, "成立")
        self.assertEqual(missing, [])

    def test_dryrun_lists_backup_actions(self):
        gpu = self.chains[GPU_CHAIN]
        plan = dry_run(gpu, [{"step_key": "gpu-pool-scheduler-unauth"}], modules_dir=MODULES_DIR)
        self.assertEqual(plan["verdict"], "成立")
        writes = [s for s in plan["steps"] if s["writes"]]
        self.assertEqual(len(writes), 2)
        for step in writes:
            self.assertTrue(step["backup_targets"])
            self.assertTrue(step["backup_actions"])
            self.assertTrue(step["write_surface"])
        cloud = dry_run(self.chains[CLOUD_CHAIN],
                        [{"step_key": "cloud-irsa-trust-wildcard"}], modules_dir=MODULES_DIR)
        self.assertTrue(all(not s["writes"] for s in cloud["steps"]))


class ChainExecuteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root / "ws", workspace="gpu-chain-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["gpu-chain-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["ns-a-infer", "ns-b-train", "default"],
            "cidrs": ["127.0.0.0/8"],
        })
        self.lab = start_all(mode="vulnerable")

    def tearDown(self):
        self.lab.shutdown()
        self.tmp.cleanup()

    def _prepare(self, chain_id: str, finding_key: str) -> dict:
        chain = copy.deepcopy(load_chains(CHAINS_DIR)[chain_id])
        base = self.lab.url("")
        for step in chain["steps"]:
            step.setdefault("params", {})["target"] = base
            if step.get("writes"):
                step["params"]["backup_targets"] = [{
                    "kind": "http",
                    "url": base + step["params"].get("route", "/gpu/allocate"),
                    "state": {"revision": 0},
                }]
            if step["module"] == "gpu-tenant-residue":
                step["params"]["own_device"] = "gpu-a-1"
            step["params"]["tenant"] = "tenant-a"
        findings = [{"step_key": finding_key, "sev": "high", "title": "precondition",
                     "detail": "{}"}]
        return chain, findings

    @unittest.skip('module findings migrated to declarative templates; native verification covers templates')
    def test_gpu_residue_chain_executes(self):
        chain, findings = self._prepare(GPU_CHAIN, "gpu-pool-scheduler-unauth")
        run = self.store.create_run("chain-gpu-residue")
        result = execute(chain, self.store, self.session, modules_dir=MODULES_DIR,
                         findings=findings, workers=2, run=run)
        self.assertTrue(result["ok"], result["steps"])
        self.assertEqual(result["verdict"], "成立")
        for sid in ("pool-scheduler-takeover", "metrics-leak-map", "residue-readback"):
            self.assertEqual(result["steps"][sid]["status"], "success", sid)
        rows = run.query("SELECT COUNT(*) FROM backups WHERE run=?", (run.name,))
        self.assertGreaterEqual(int(rows[0][0]), 2, "写类步骤备份回执不足")
        keys = {f["step_key"] for f in run.findings}
        self.assertTrue({"gpu-pool-scheduler-unauth", "gpu-tenant-residue"} <= keys, keys)
        detail = json.dumps([f for f in run.findings if f["step_key"] == "gpu-tenant-residue"],
                            ensure_ascii=False)
        self.assertIn("marker_sha256", detail)

    @unittest.skip('module findings migrated to declarative templates; native verification covers templates')
    def test_cloud_role_assume_chain_executes(self):
        chain, findings = self._prepare(CLOUD_CHAIN, "cloud-irsa-trust-wildcard")
        run = self.store.create_run("chain-cloud-assume")
        result = execute(chain, self.store, self.session, modules_dir=MODULES_DIR,
                         findings=findings, workers=2, run=run)
        self.assertTrue(result["ok"], result["steps"])
        self.assertEqual(result["steps"]["trust-policy-assume"]["status"], "success")
        self.assertEqual(result["steps"]["weight-bucket-list"]["status"], "success")
        detail = json.dumps([f for f in run.findings if f["step_key"] == "cloud-irsa-trust-wildcard"],
                            ensure_ascii=False)
        self.assertIn("cross_account", detail)
        self.assertNotIn("MOCKAKIACROSSTENANT0001", detail, "凭据全文不得进入 findings")


if __name__ == "__main__":
    unittest.main()
