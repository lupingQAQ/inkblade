"""窃取与数据泄露模块族测试：凭据脱敏 + FS fixture 枚举存证 + 数据泄露面检出。"""

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import redact
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
FIXTURES = REPO / "lab" / "fixtures" / "theft"

THEFT_KEYS = [
    "unlimited-query-distillation",
    "supply-chain-credential-theft",
    "shared-volume-weight-copy",
    "training-data-leak",
]

FAKE_HF_TOKEN = "hf_FAKEtokenDoNotUseSampleABCD1234wxyz"


class TestTheftModules(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "主动探测", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        return run_module(self.store, self.session, key, params, modules_dir=MODULES_DIR)

    def _run_findings(self, result, key):
        run = self.store.open_run(result["run"])
        return [f for f in run.findings if f["step_key"] == key]

    def test_theft_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key in THEFT_KEYS:
            self.assertIn(key, mods, f"缺少窃取模块 {key}")
            self.assertEqual(mods[key].series, "窃取与数据泄露")

    def test_credential_redaction(self):
        self.assertEqual(redact.cred("AKIAIOSFODNN7EXAMPLE"), "MPLE")
        self.assertEqual(redact.cred(FAKE_HF_TOKEN), FAKE_HF_TOKEN[-4:])
        self.assertEqual(redact.cred("abc"), "***")  # 短值全遮蔽

    def test_shared_volume_weight_copy_inventory(self):
        result = self._run("shared-volume-weight-copy", {
            "volume_root": str(FIXTURES / "shared-volume"),
        })
        findings = self._run_findings(result, "shared-volume-weight-copy")
        self.assertGreaterEqual(len(findings), 1, "权重直读未产出 finding")
        # 产物清单作为 artifacts 归档
        artifacts = list((self.root / "evidence" / "local-lab" / result["run"] / "steps").glob("*"))
        self.assertTrue(artifacts, "未归档产物")
        # 直接读模块写入的产物文件
        inv_paths = list((self.root / "evidence" / "local-lab" / result["run"] / "artifacts").glob("*.json"))
        self.assertTrue(inv_paths, "缺少枚举清单产物")
        data = json.loads(inv_paths[0].read_text(encoding="utf-8"))
        files = [e["file"] for e in data["entries"]]
        self.assertTrue(any(f.endswith(".pt") for f in files), "假权重 .pt 未入清单")
        self.assertTrue(any(f.endswith(".safetensors") for f in files), "假权重 .safetensors 未入清单")
        for entry in data["entries"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")

    def test_supply_chain_credential_theft_redacted(self):
        result = self._run("supply-chain-credential-theft", {
            "scan_root": str(FIXTURES / "credentials"),
        })
        findings = self._run_findings(result, "supply-chain-credential-theft")
        self.assertGreaterEqual(len(findings), 1, "凭据扫描未产出 finding")
        run_dir = self.root / "evidence" / "local-lab" / result["run"]
        blobs = [p.read_bytes().decode("utf-8", errors="ignore")
                 for p in run_dir.rglob("*") if p.is_file()]
        for blob in blobs:
            self.assertNotIn(FAKE_HF_TOKEN, blob, "完整凭据不得出现在任何证据/产物中")
        joined = json.dumps(findings, ensure_ascii=False)
        self.assertIn(FAKE_HF_TOKEN[-4:], joined, "finding 需保留尾4位指纹")

    def test_training_data_leak_categories(self):
        result = self._run("training-data-leak", {
            "data_root": str(FIXTURES),
        })
        findings = self._run_findings(result, "training-data-leak")
        joined = json.dumps(findings, ensure_ascii=False)
        for category in ("数据集", "缓存", "日志", "轨迹", "凭据"):
            self.assertIn(category, joined, f"训练数据泄露未覆盖类别: {category}")
        self.assertIn(FAKE_HF_TOKEN[-4:], joined, "假密钥需保留尾4位指纹")
        self.assertNotIn(FAKE_HF_TOKEN, joined, "完整假密钥不得进入 finding")
        # 样张必须脱敏
        run_dir = self.root / "evidence" / "local-lab" / result["run"]
        for p in run_dir.rglob("*"):
            if p.is_file() and p.suffix in (".json", ".jsonl", ".gz", ".tar", ".zst"):
                continue
        samples = [p for p in (run_dir / "artifacts").glob("*.json")]
        self.assertTrue(samples, "缺少脱敏样张产物")
        content = samples[0].read_text(encoding="utf-8")
        self.assertNotIn("zhangsan", content, "PII 样张未脱敏")
        self.assertNotIn(FAKE_HF_TOKEN, content, "凭据样张未脱敏")

    def test_unlimited_query_distillation(self):
        result = self._run("unlimited-query-distillation", {
            "access_log": str(FIXTURES / "access" / "query-log.json"),
        })
        findings = self._run_findings(result, "unlimited-query-distillation")
        self.assertGreaterEqual(len(findings), 1, "蒸馏面未产出 finding")
        joined = json.dumps(findings, ensure_ascii=False)
        self.assertIn("配额", joined)
        self.assertTrue(re.search(r"鉴权|认证", joined), "finding 必须指出无鉴权")


if __name__ == "__main__":
    unittest.main()
