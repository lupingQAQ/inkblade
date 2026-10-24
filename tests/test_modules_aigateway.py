"""tests/test_modules_aigateway.py — AI 网关与配套基建模块族测试（TDD 先行）。

覆盖：
- 注册表契约：10 模块纯小写键 / 系列 / 级别 / writes 标志（隔离目录加载，免受并行任务干扰）；
- vulnerable 靶场：每模块真实 HTTP 差分命中并产出 findings（severity 合法、detail 可解析）；
- fixed 靶场：每模块 0 finding（加固后不可检出）；
- 敏感值：上游 provider key 在 finding 中仅尾 4 位（MOCK****xxxx），全文只存在于归档 trace；
- 写类闸门：route-hijack 无 backup_targets → BackupGateRefused(91) 且服务端别名未变；
- 链：ai-gateway-key-exfil dry-run 判定 + execute 全步骤成功 + 别名劫持 + 备份回执。
"""

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.ai_gateway_sim import (
    MASTER_KEY,
    TENANT_KEYS,
    VICTIM_CACHE_PROMPT,
    start_all,
)
from trident.core.chains import dry_run, execute, load_chains
from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe
from trident.core.runner import BackupGateRefused, run_module
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"
CHAINS_DIR = REPO / "trident" / "chains"

MODULE_KEYS = [
    "aigateway-fingerprint",
    "aigateway-auth-bypass",
    "aigateway-upstream-key-exfil",
    "aigateway-route-hijack",
    "aigateway-cache-cross-tenant",
    "aigateway-quota-bypass",
    "aigateway-log-pii-leak",
    "aigateway-guardrail-bypass",
    "model-registry-exposure",
    "vector-db-exposure",
]
WRITE_KEYS = {"aigateway-route-hijack"}
DEFAULT_TENANT_KEY = TENANT_KEYS["tenant-a"]
TARGET_BACKEND = "http://attacker.invalid/v1"


def _params(key: str, base: str, mode: str = "probe-only") -> dict:
    """每模块的最小参数集（fixed 模式需要合法租户 key 才能做同租户对照）。"""
    common = {"target": base, "mode": mode, "tenant_key": DEFAULT_TENANT_KEY,
              "master_key": MASTER_KEY, "spoof_user": "admin"}
    if key == "aigateway-route-hijack":
        common["alias"] = "gpt-4o-mini"
        common["backend"] = TARGET_BACKEND
        common["tenant"] = "tenant-a"
        # 写类模块（writes=true）始终需要备份回执；probe-only 仍不触碰写面
        common["backup_targets"] = [{"kind": "http", "url": f"{base}/ai/route", "state": {}}]
    if key == "aigateway-cache-cross-tenant":
        common["requester_tenant"] = "tenant-a"
        common["victim_tenant"] = "tenant-b"
        common["victim_prompt"] = VICTIM_CACHE_PROMPT
    if key in ("model-registry-exposure", "vector-db-exposure", "aigateway-quota-bypass",
               "aigateway-log-pii-leak", "aigateway-guardrail-bypass"):
        common["tenant"] = "tenant-a"
    return common


class _Base(unittest.TestCase):
    mode = "vulnerable"

    @classmethod
    def setUpClass(cls):
        cls.server = start_all(mode=cls.mode)
        cls.base = cls.server.url("")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示", "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8", "10.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params=None, run=None):
        return run_module(self.store, self.session, key, params or _params(key, self.base),
                          modules_dir=MODULES_DIR, run=run)

    def _findings(self, run, key):
        return [f for f in run.findings if f["step_key"] == key]


class RegistryContractTest(unittest.TestCase):
    def test_ten_modules_registered(self):
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "modules"
            dest.mkdir()
            shutil.copy(MODULES_DIR / "_aigateway-common.py", dest / "_aigateway-common.py")
            for key in MODULE_KEYS:
                shutil.copytree(MODULES_DIR / key, dest / key)
            mods = __import__("trident.core.registry", fromlist=["load_modules"]).load_modules(dest)
        self.assertEqual(len(mods), 10)
        for key in MODULE_KEYS:
            meta = mods[key]
            self.assertEqual(meta.key, key)
            self.assertEqual(meta.writes, key in WRITE_KEYS, key)
            self.assertIn(meta.series, ("侦察", "横向利用", "窃取与数据泄露"), key)
            self.assertIn(meta.min_level, ("只读侦察", "主动探测", "利用验证"), key)
            self.assertTrue(meta.description, key)
            self.assertTrue(meta.produces, key)


class VulnerableDetectionTest(_Base):
    mode = "vulnerable"

    def test_every_module_hits_and_honours_contract(self):
        for key in MODULE_KEYS:
            with self.subTest(module=key):
                result = self._run(key)
                self.assertIn("run", result)
                run = self.store.open_run(result["run"])
                self.assertTrue((run.dir / "traces" / f"{key}.json").is_file(),
                                f"{key} 缺 trace artifact")
                rows = self._findings(run, key)
                self.assertGreaterEqual(len(rows), 1, f"{key} 未产出 finding")
                for row in rows:
                    self.assertIn(row["severity"], ("critical", "high", "medium", "low", "info"))
                    self.assertTrue(row["title"])
                    json.loads(row["detail"])  # detail 必须是合法 JSON

    def test_upstream_key_masked_in_finding_but_full_in_archive(self):
        result = self._run("aigateway-upstream-key-exfil")
        run = self.store.open_run(result["run"])
        rows = self._findings(run, "aigateway-upstream-key-exfil")
        joined = json.dumps(rows, ensure_ascii=False)
        self.assertIn("MOCK****9f3c", joined)
        self.assertNotIn("MOCK-openai-upstream-key-9f3c", joined)
        trace = json.loads((run.dir / "traces" / "aigateway-upstream-key-exfil.json")
                           .read_text(encoding="utf-8"))
        self.assertIn("MOCK-openai-upstream-key-9f3c", json.dumps(trace))

    def test_route_hijack_mutates_alias_table(self):
        result = self._run("aigateway-route-hijack", _params(
            "aigateway-route-hijack", self.base, mode="backup-write"))
        run = self.store.open_run(result["run"])
        rows = self._findings(run, "aigateway-route-hijack")
        self.assertGreaterEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "critical")
        table = json.loads(self._get_json("/ai/route"))
        self.assertEqual(table["aliases"]["gpt-4o-mini"]["backend"], TARGET_BACKEND)

    def test_cache_finding_proves_cross_tenant_reuse(self):
        result = self._run("aigateway-cache-cross-tenant")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "aigateway-cache-cross-tenant")[0]["detail"])
        self.assertTrue(detail["hit"])
        self.assertEqual(detail["entry_tenant"], "tenant-b")
        self.assertEqual(detail["requester_tenant"], "tenant-a")
        self.assertTrue(detail["shared_key"])

    def test_quota_finding_reports_xff_rotation(self):
        result = self._run("aigateway-quota-bypass")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "aigateway-quota-bypass")[0]["detail"])
        self.assertFalse(detail["enforced"])
        self.assertEqual(detail["blocked_count"], 0)
        self.assertGreaterEqual(detail["distinct_buckets"], 3)

    def test_logs_finding_reports_plaintext_pii(self):
        result = self._run("aigateway-log-pii-leak")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "aigateway-log-pii-leak")[0]["detail"])
        self.assertGreaterEqual(detail["email_count"], 1)
        self.assertGreaterEqual(detail["card_count"], 1)
        self.assertTrue(detail["authorization_plaintext"])

    def test_guardrail_finding_reports_canary(self):
        result = self._run("aigateway-guardrail-bypass")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "aigateway-guardrail-bypass")[0]["detail"])
        self.assertTrue(detail["canary_present"])
        self.assertEqual(detail["inspected_messages"], 1)

    def test_vector_finding_reports_cross_tenant_docs(self):
        result = self._run("vector-db-exposure")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "vector-db-exposure")[0]["detail"])
        self.assertIn("tenant-b-docs", detail["other_tenant_collections"])
        self.assertGreaterEqual(detail["match_count"], 1)

    def test_model_registry_finding_lists_private_models(self):
        result = self._run("model-registry-exposure")
        run = self.store.open_run(result["run"])
        detail = json.loads(self._findings(run, "model-registry-exposure")[0]["detail"])
        self.assertIn("tenant-b-finetune", detail["private_models"])
        self.assertTrue(detail["backend_exposed"])

    def _get_json(self, path):
        import urllib.request

        with urllib.request.urlopen(self.server.url(path), timeout=10) as resp:
            return resp.read().decode("utf-8")


class FixedDetectionTest(_Base):
    mode = "fixed"

    def test_every_module_is_clean_on_hardened_gateway(self):
        for key in MODULE_KEYS:
            with self.subTest(module=key):
                result = self._run(key)
                run = self.store.open_run(result["run"])
                rows = self._findings(run, key)
                self.assertEqual(rows, [], f"{key} 在 fixed 模式仍有 finding: {rows}")


class WriteGateTest(_Base):
    mode = "vulnerable"

    def test_route_hijack_refused_without_backup(self):
        with self.assertRaises(BackupGateRefused) as ctx:
            self._run("aigateway-route-hijack", _params(
                "aigateway-route-hijack", self.base, mode="backup-write")
                | {"backup_targets": []})
        self.assertEqual(ctx.exception.exit_code, 91)
        import urllib.request

        with urllib.request.urlopen(self.server.url("/ai/route"), timeout=10) as resp:
            table = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(table["aliases"]["gpt-4o-mini"]["backend"], "http://upstream-openai.mock/v1")

    def test_route_hijack_probe_only_does_not_mutate(self):
        self._run("aigateway-route-hijack", _params("aigateway-route-hijack", self.base))
        import urllib.request

        with urllib.request.urlopen(self.server.url("/ai/route"), timeout=10) as resp:
            table = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(table["aliases"]["gpt-4o-mini"]["backend"], "http://upstream-openai.mock/v1")


class ChainExecutionTest(_Base):
    mode = "vulnerable"

    def test_chain_dryrun_and_execute(self):
        chain = load_chains(CHAINS_DIR)["ai-gateway-key-exfil"]
        findings = [{"step_key": "aigateway-fingerprint", "severity": "high"}]
        plan = dry_run(chain, findings, modules_dir=MODULES_DIR)
        self.assertEqual(plan["verdict"], "成立")
        write_steps = [s for s in plan["steps"] if s["writes"]]
        self.assertEqual([s["module"] for s in write_steps], ["aigateway-route-hijack"])
        self.assertTrue(write_steps[0]["backup_actions"])

        steps = []
        for step in chain["steps"]:
            step = json.loads(json.dumps(step))
            step.setdefault("params", {})["target"] = self.base
            if step["module"] == "aigateway-route-hijack":
                step["params"]["mode"] = "backup-write"
                step["params"]["backup_targets"] = [
                    {"kind": "http", "url": self.server.url("/ai/route"), "state": {}}]
            steps.append(step)
        executed = dict(chain, steps=steps)
        result = execute(executed, self.store, self.session, modules_dir=MODULES_DIR,
                         findings=findings, workers=3)
        self.assertTrue(result["ok"], result["steps"])
        for sid, row in result["steps"].items():
            self.assertEqual(row["status"], "success", sid)
        receipts = result["run"]
        rows = self.store.open_run(receipts).query(
            "SELECT COUNT(*) FROM backups WHERE run=? AND step_key='aigateway-route-hijack'",
            (receipts,))
        self.assertGreaterEqual(int(rows[0][0]), 1)


if __name__ == "__main__":
    unittest.main()
