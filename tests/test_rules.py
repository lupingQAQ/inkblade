"""tests/test_rules.py — 规则转化引擎 + 紫队验证测试（TDD 先行）。

覆盖四项主断言：
- test_every_chain_covered：18 条链每条 ≥1 规则（mapping.json blocks_chains 矩阵）；
- test_per_cni_variants：native/Calico/Cilium 三变体 + VPC 安全组补充 + RDMA/SR-IOV 不覆盖声明与 IB Partition 建议；
- test_zeroday_rule_no_detail_leak：零日行为化签名规则文本不含利用细节特征串；
- test_purple_coverage_matrix：mock 靶场重放 + 内置简化匹配器 → 覆盖率矩阵含拦截/检测态、零漏过。

另含 monitor 模式注解与调参建议字段断言。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.mock_targets import start_all
from trident.core.chains import load_chains
from trident.rules.generate import generate_all
from trident.rules.validate import validate

CHAINS_DIR = Path(__file__).resolve().parents[1] / "trident" / "chains"

# 零日规则文本禁止出现的利用细节特征串（产品名/根因术语/具体端点，小写比较）
ZERODAY_DETAIL_TOKENS = [
    "dify",
    "open-webui",
    "openwebui",
    "open webui",
    "jwe",
    "stub-token",
    "stub token",
    "root-key",
    "hardcoded",
    "/api/v1/bindings",
    "/v1/jobs/run",
    "code/execute",
]

CNI_FILES = [
    ("native", "network/native/network-policy-default-deny.yaml",
     ["networking.k8s.io/v1", "kind: NetworkPolicy"]),
    ("calico", "network/calico/global-network-policy-default-deny.yaml",
     ["projectcalico.org/v3", "kind: GlobalNetworkPolicy"]),
    ("cilium", "network/cilium/cilium-network-policy-default-deny.yaml",
     ["cilium.io/v2", "kind: CiliumNetworkPolicy"]),
]


def _load_mapping(pack_dir: str) -> dict:
    return json.loads((Path(pack_dir) / "mapping.json").read_text(encoding="utf-8"))


class RuleGenerationTest(unittest.TestCase):
    """规则包生成：链覆盖矩阵 + per-CNI 变体 + 零日级行为化签名 + monitor 注解。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = TemporaryDirectory()
        cls.pack = generate_all(CHAINS_DIR, findings=[], cni="native", out_dir=cls._tmp.name)
        cls.pack_dir = Path(cls.pack.out_dir)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_every_chain_covered(self):
        """18 条链全部在 mapping blocks_chains 中（0 规则即败）。"""
        chains = load_chains(CHAINS_DIR)
        self.assertEqual(len(chains), 18, "链目录应恰为 18 条")
        mapping = _load_mapping(self.pack_dir)
        covered: dict[str, list[str]] = {}
        for rule in mapping["rules"]:
            self.assertTrue(rule["blocks_chains"], f"规则 {rule['id']} 未映射任何链")
            for cid in rule["blocks_chains"]:
                self.assertIn(cid, chains, f"规则映射到不存在的链 {cid}")
                covered.setdefault(cid, []).append(rule["id"])
        for cid in chains:
            self.assertIn(cid, covered, f"链 {cid} 没有任何规则覆盖")
            self.assertGreaterEqual(len(covered[cid]), 1, f"链 {cid} 规则数为 0")
        # mapping 侧 chains 视图与规则侧一致
        for cid in chains:
            self.assertIn(cid, mapping["chains"])
            self.assertTrue(mapping["chains"][cid]["rules"])

    def test_per_cni_variants(self):
        """三 CNI 变体文件存在且含各自 apiVersion/kind；VPC 安全组补充与 RDMA 声明齐备。"""
        for name, rel, markers in CNI_FILES:
            path = self.pack_dir / rel
            self.assertTrue(path.is_file(), f"缺少 {name} 变体文件 {rel}")
            text = path.read_text(encoding="utf-8")
            for marker in markers:
                self.assertIn(marker, text, f"{rel} 缺 {marker}")
        vpc = (self.pack_dir / "network/vpc-native/security-group-supplement.yaml").read_text(encoding="utf-8")
        self.assertIn("SecurityGroupPolicy", vpc)
        self.assertIn("vpcresources.k8s.aws", vpc)
        rdma_md = (self.pack_dir / "network/rdma-sriov-uncovered.md").read_text(encoding="utf-8")
        for token in ("RDMA", "SR-IOV", "NetworkPolicy", "IB"):
            self.assertIn(token, rdma_md)
        self.assertIn("Partition", rdma_md)
        self.assertTrue((self.pack_dir / "network/ib-partition-advice.yaml").is_file())
        # 三变体 + VPC 补充均登记在 mapping
        mapping = _load_mapping(self.pack_dir)
        net_rule = next(r for r in mapping["rules"] if r["id"] == "netpol-default-deny-partition")
        variants = {Path(f).parent.name for f in net_rule["files"]}
        self.assertTrue({"native", "calico", "cilium"} <= variants)
        self.assertEqual(mapping["cni_active"], "native")
        self.assertTrue(mapping["rdma_declaration"]["files"])

    def test_zeroday_rule_no_detail_leak(self):
        """零日行为化签名：规则文本不得含利用细节特征串。"""
        mapping = _load_mapping(self.pack_dir)
        self.assertTrue(mapping["zeroday"], "缺少零日行为化签名条目")
        for entry in mapping["zeroday"]:
            self.assertTrue(entry["behavioral"])
            self.assertTrue(entry["files"], f"零日规则 {entry['id']} 未产出文件")
            for rel in entry["files"]:
                text = (self.pack_dir / rel).read_text(encoding="utf-8").lower()
                for token in ZERODAY_DETAIL_TOKENS:
                    self.assertNotIn(token, text, f"零日规则文件 {rel} 泄漏细节特征串 {token!r}")

    def test_monitor_mode_and_tuning(self):
        """默认 monitor 模式注解 + 调参建议字段全覆盖。"""
        mapping = _load_mapping(self.pack_dir)
        self.assertGreaterEqual(len(mapping["rules"]), 15)
        for rule in mapping["rules"]:
            self.assertEqual(rule["mode"], "monitor", f"{rule['id']} 应默认 monitor")
            tuning = rule["tuning"]
            self.assertTrue(tuning.get("zh") and tuning.get("en"), f"{rule['id']} 缺调参建议")
            for rel in rule["files"]:
                self.assertTrue((self.pack_dir / rel).is_file(), f"{rule['id']} 文件缺失 {rel}")
        kyverno = "\n".join(
            p.read_text(encoding="utf-8") for p in sorted((self.pack_dir / "kyverno").glob("*.yaml"))
        )
        self.assertIn("trident.io/mode", kyverno)
        self.assertIn("Audit", kyverno)
        gatekeeper = "\n".join(
            p.read_text(encoding="utf-8") for p in sorted((self.pack_dir / "gatekeeper").glob("constraints/*.yaml"))
        )
        self.assertIn("dryrun", gatekeeper)
        sigma = "\n".join(
            p.read_text(encoding="utf-8") for p in sorted((self.pack_dir / "sigma").glob("*.yaml"))
        )
        self.assertIn("trident-mode", sigma)
        falco = (self.pack_dir / "falco" / "trident-rules.yaml").read_text(encoding="utf-8")
        self.assertIn("monitor", falco)
        suricata = (self.pack_dir / "suricata" / "trident.rules").read_text(encoding="utf-8")
        self.assertIn("trident.mode=monitor", suricata)
        for uri in ("/pull_weights", "/set_env", "/create_engine", "/fetch_weights", "/awex"):
            self.assertIn(uri, suricata)


class PurpleValidationTest(unittest.TestCase):
    """紫队验证：mock vulnerable 靶场重放 + 简化 sigma/falco/suricata 匹配器 → 覆盖率矩阵。"""

    @classmethod
    def setUpClass(cls):
        cls.server = start_all(mode="vulnerable")
        cls._tmp = TemporaryDirectory()
        cls.pack = generate_all(CHAINS_DIR, findings=[], cni="native", out_dir=cls._tmp.name)
        cls.matrix = validate(cls.pack.out_dir, cls.server.url("/"))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls._tmp.cleanup()

    def test_purple_coverage_matrix(self):
        """每链含拦截/检测态、零漏过，矩阵 JSON+MD 落盘且内容完整。"""
        chains = load_chains(CHAINS_DIR)
        self.assertEqual(set(self.matrix["chains"]), set(chains), "矩阵必须覆盖全部 18 条链")
        for cid, row in self.matrix["chains"].items():
            self.assertIn(
                row["state"],
                ("拦截", "检测", "拦截+检测"),
                f"链 {cid} 状态为 {row['state']!r}（存在漏过）",
            )
            statuses = {cell["status"] for cell in row["rules"]}
            self.assertNotIn("漏过", statuses, f"链 {cid} 存在漏过规则")
            self.assertTrue(statuses & {"拦截", "检测"}, f"链 {cid} 无任何拦截/检测命中")
        self.assertEqual(self.matrix["summary"]["chains"], 18)
        self.assertEqual(self.matrix["summary"]["missed"], 0)
        self.assertTrue(self.matrix["ok"])
        # 矩阵文件落盘
        matrix_json = Path(self.pack.out_dir) / "coverage-matrix.json"
        matrix_md = Path(self.pack.out_dir) / "coverage-matrix.md"
        self.assertTrue(matrix_json.is_file())
        self.assertTrue(matrix_md.is_file())
        saved = json.loads(matrix_json.read_text(encoding="utf-8"))
        self.assertEqual(set(saved["chains"]), set(chains))
        md = matrix_md.read_text(encoding="utf-8")
        self.assertIn("拦截", md)
        self.assertIn("检测", md)
        for cid in chains:
            self.assertIn(cid, md)
        # 重放确有 HTTP 探针命中 vulnerable 姿态
        http_rows = [row for row in self.matrix["chains"].values() for p in row["probe"] if p["kind"] == "http"]
        self.assertGreaterEqual(len(http_rows), 10, "mock 靶场 HTTP 重放数量异常")


if __name__ == "__main__":
    unittest.main()
