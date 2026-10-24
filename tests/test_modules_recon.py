"""tests/test_modules_recon.py — 侦察模块族（11 模块）fixture 命中断言 + TSV 直通 + 注册表族完整性。

fixture（lab/fixtures/recon/，自建）：
- cluster-snapshot.json：同构暴露面/策略缺口/Ray 控制面/特权/RBAC/存储/观测端口/漏洞端口/元数据出网/逃逸原语/云指纹要素样本
- cluster-clean.json：加固基线（默认拒绝 + 无特权 + 最小 RBAC）→ 全族期望零发现
- cloud-providers.json：多云指纹要素（EKS/AKS/GKE/TCE providerID、IRSA/Workload Identity 注解、云存储类、混合互联）

模块免 bash 依赖：run.py 读 params.snapshot（dict 或 fixture 路径），测试完全封闭。
"""
import json
import shutil
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.registry import load_modules

ROOT = Path(__file__).resolve().parents[1]
MODULES_DIR = ROOT / "trident" / "modules"
FIX_DIR = ROOT / "lab" / "fixtures" / "recon"

RECON_KEYS = (
    "cloud-integration-fingerprint",
    "escape-primitives",
    "exposure-mapping",
    "framework-port-matching",
    "metadata-egress",
    "network-policy-coverage",
    "observability-exposure",
    "privileged-workloads",
    "rbac-mapping",
    "ray-control-plane",
    "storage-sharing",
)
ZERODAY_KEYS = (
    "dify-control-plane-failopen",
    "dify-stub-token-forgery",
    "dify-snapshot-cross-tenant-theft",
    "dify-local-sandbox-unauth-rce",
    "open-webui-code-execute-rce",
    "open-webui-indirect-injection-exec",
)


def load_run(key):
    spec = spec_from_file_location(f"reconmod_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ReconFixtureHitTest(unittest.TestCase):
    """每个侦察模块在 cluster-snapshot 上必须命中其家族发现（按模块逻辑逐一断言）。"""

    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads((FIX_DIR / "cluster-snapshot.json").read_text(encoding="utf-8"))
        cls.clean = json.loads((FIX_DIR / "cluster-clean.json").read_text(encoding="utf-8"))

    def run_mod(self, key, snapshot):
        result = load_run(key).run(
            {"marker": "TRIDENT-recon-test", "meta": {"key": key}}, {"snapshot": snapshot}
        )
        for field in ("summary", "findings", "artifacts"):
            self.assertIn(field, result, f"{key} 结果缺 {field}")
        return result

    @staticmethod
    def titles(findings):
        return [f["title"] for f in findings]

    # -- 暴露面测绘 ----------------------------------------------------------
    def test_exposure_mapping_hits(self):
        findings = self.run_mod("exposure-mapping", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("ray-dashboard" in t and "LoadBalancer" in t for t in titles), titles)
        self.assertTrue(any("grafana" in t and "LoadBalancer" in t for t in titles), titles)
        self.assertTrue(any("vllm-plugins" in t and "NodePort" in t for t in titles), titles)
        self.assertTrue(any("Ingress" in t and "mlflow" in t for t in titles), titles)
        self.assertTrue(any("HTTPRoute" in t for t in titles), titles)
        self.assertTrue(any("FailOpen" in t for t in titles), titles)

    # -- 网络策略覆盖分析 ----------------------------------------------------
    def test_network_policy_coverage_gaps(self):
        findings = self.run_mod("network-policy-coverage", self.snapshot)["findings"]
        titles = self.titles(findings)
        for ns in ("infer", "ray-system", "default"):
            self.assertTrue(any(ns in t for t in titles), f"{ns} 覆盖缺口未报: {titles}")
        self.assertFalse(any("train" in t for t in titles), "train 有默认拒绝策略，不应报缺口")

    # -- Ray 控制面侦察 ------------------------------------------------------
    def test_ray_control_plane(self):
        findings = self.run_mod("ray-control-plane", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("rl-train" in t and "8265" in t for t in titles), titles)
        self.assertTrue(any("autoscaler" in t or "ray-operator" in t for t in titles), titles)
        dash = next(f for f in findings if "rl-train" in f["title"])
        self.assertEqual(dash["sev"], "critical")  # auth=none × LoadBalancer

    # -- 特权工作负载盘点 ----------------------------------------------------
    def test_privileged_workloads(self):
        findings = self.run_mod("privileged-workloads", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("privileged" in t and "sglang-server-0" in t for t in titles), titles)
        self.assertTrue(any("SYS_ADMIN" in t for t in titles), titles)
        self.assertTrue(any("docker.sock" in t for t in titles), titles)
        self.assertTrue(any("seccomp" in t.lower() for t in titles), titles)
        self.assertTrue(any("hostPID" in t for t in titles), titles)

    # -- RBAC 权限测绘 -------------------------------------------------------
    def test_rbac_mapping(self):
        findings = self.run_mod("rbac-mapping", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("通配符" in t and "ray-operator-role" in t for t in titles), titles)
        self.assertTrue(any("cluster-admin" in t for t in titles), titles)
        self.assertTrue(any("roles/rolebindings" in t or "rolebindings" in t for t in titles), titles)
        self.assertTrue(any("exec" in t for t in titles), titles)
        self.assertTrue(any("Secret 名称盘点" in t for t in titles), titles)
        wildcard = next(f for f in findings if "通配符" in f["title"])
        self.assertEqual(wildcard["sev"], "critical")

    # -- 存储共享面测绘 ------------------------------------------------------
    def test_storage_sharing(self):
        findings = self.run_mod("storage-sharing", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("RWX" in t and "shared-weights" in t for t in titles), titles)
        self.assertTrue(any("RWX" in t and "datasets" in t for t in titles), titles)
        self.assertTrue(any("juicefs" in t.lower() for t in titles), titles)
        self.assertTrue(any("NFS" in t and "pv-weights" in t for t in titles), titles)
        self.assertTrue(any("hf-cache" in t for t in titles), titles)

    # -- 观测面暴露测绘 ------------------------------------------------------
    def test_observability_exposure(self):
        findings = self.run_mod("observability-exposure", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("Grafana" in t for t in titles), titles)
        self.assertTrue(any("Prometheus" in t for t in titles), titles)
        self.assertTrue(any("DCGM" in t for t in titles), titles)
        self.assertTrue(any("TensorBoard" in t for t in titles), titles)
        grafana = next(f for f in findings if "Grafana" in f["title"])
        self.assertEqual(grafana["sev"], "high")  # LoadBalancer 直接对外
        dcgm = next(f for f in findings if "DCGM" in f["title"])
        self.assertEqual(dcgm["sev"], "info")  # ClusterIP 集群内可达

    # -- 框架漏洞端口匹配 ----------------------------------------------------
    def test_framework_port_matching(self):
        findings = self.run_mod("framework-port-matching", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("30000" in t and "sglang" in t.lower() for t in titles), titles)
        self.assertTrue(any("8265" in t and "ray" in t.lower() for t in titles), titles)
        self.assertTrue(any("8000" in t and "vllm" in t.lower() for t in titles), titles)
        self.assertTrue(any("5000" in t and "openrlhf" in t.lower() for t in titles), titles)
        # mlflow 同为 5000 端口但非漏洞框架：名称提示不匹配 → 不得误报
        self.assertFalse(any("mlflow" in t.lower() for t in titles), titles)
        sglang = next(f for f in findings if "30000" in f["title"])
        self.assertEqual(sglang["sev"], "high")

    # -- 元数据与出网面 ------------------------------------------------------
    def test_metadata_egress(self):
        findings = self.run_mod("metadata-egress", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("凭据环境变量" in t and "gpu-trainer-0" in t for t in titles), titles)
        self.assertTrue(any("token 自动挂载" in t for t in titles), titles)
        self.assertTrue(any("出网不受限" in t and "infer" in t for t in titles), titles)
        self.assertTrue(any("hostNetwork" in t and "ray-head-0" in t for t in titles), titles)
        # train 有 Egress 默认拒绝 → gpu-trainer 不应报出网缺口
        self.assertFalse(any("gpu-trainer-0" in t and "出网" in t for t in titles), titles)
        creds = next(f for f in findings if "凭据环境变量" in f["title"])
        self.assertEqual(creds["sev"], "high")
        self.assertNotIn("MOCKSECRET", json.dumps(creds, ensure_ascii=False))  # 凭据值不得入证据

    # -- 逃逸原语检查 --------------------------------------------------------
    def test_escape_primitives(self):
        findings = self.run_mod("escape-primitives", self.snapshot)["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("socket" in t and "gpu-trainer-0" in t for t in titles), titles)
        self.assertTrue(any("逃逸矩阵" in t and "可创建" in t for t in titles), titles)
        sock = next(f for f in findings if "socket" in f["title"] and "gpu-trainer-0" in f["title"])
        self.assertEqual(sock["sev"], "critical")
        matrix = [f for f in findings if "逃逸矩阵" in f["title"] and "可创建" in f["title"]]
        self.assertTrue(matrix, titles)
        self.assertEqual(matrix[0]["sev"], "critical")  # 可建 Pod × 特权先例成立

    # -- 云集成指纹 ----------------------------------------------------------
    def test_cloud_fingerprint_snapshot(self):
        result = self.run_mod("cloud-integration-fingerprint", self.snapshot)
        findings = result["findings"]
        titles = self.titles(findings)
        self.assertTrue(any("ACK" in t or "阿里云" in t for t in titles), titles)
        self.assertTrue(any("云存储类" in t and "alicloud-ssd" in t for t in titles), titles)
        self.assertTrue(any("混合互联" in t and "cen" in t.lower() for t in titles), titles)

    def test_cloud_fingerprint_multi_provider(self):
        multi = json.loads((FIX_DIR / "cloud-providers.json").read_text(encoding="utf-8"))
        findings = self.run_mod("cloud-integration-fingerprint", multi)["findings"]
        titles = self.titles(findings)
        for provider in ("EKS", "AKS", "GKE", "TKE"):
            self.assertTrue(any(provider in t for t in titles), f"{provider} 未识别: {titles}")
        self.assertTrue(any("IRSA" in t for t in titles), titles)
        self.assertTrue(any("Workload Identity" in t and "Azure" in t for t in titles), titles)
        irsa = next(f for f in findings if "IRSA" in f["title"])
        self.assertEqual(irsa["sev"], "medium")

    # -- 加固基线：全族零发现 ------------------------------------------------
    def test_clean_baseline_zero_findings(self):
        for key in RECON_KEYS:
            with self.subTest(module=key):
                result = self.run_mod(key, self.clean)
                self.assertEqual(
                    result["findings"], [], f"加固基线不应产生发现: {self.titles(result['findings'])}"
                )

    # -- 快照路径形态 --------------------------------------------------------
    def test_snapshot_path_form(self):
        result = load_run("exposure-mapping").run(
            {}, {"snapshot": str(FIX_DIR / "cluster-snapshot.json")}
        )
        self.assertTrue(result["findings"])

    def test_missing_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            load_run("exposure-mapping").run({}, {})


class ReconTsvPassthroughTest(unittest.TestCase):
    """findings_tsv 直通：转换既有 recon 输出（severity/id/title/evidence/mapping/fix）。"""

    TSV = (
        "severity\tid\ttitle\tevidence\tmapping\tfix\n"
        "high\texp-nodeport\tNodePort 暴露\tinfer/vllm-plugins:31000\texposure-mapping\t收敛 NodePort 范围并限源\n"
        "info\tnote-item\t备注行\t-\t-\t-\n"
    )

    def test_tsv_with_header(self):
        result = load_run("exposure-mapping").run({}, {"findings_tsv": self.TSV})
        self.assertIn("直通", result["summary"])
        findings = result["findings"]
        self.assertEqual(len(findings), 2)
        first = findings[0]
        self.assertEqual(first["sev"], "high")
        self.assertEqual(first["id"], "exp-nodeport")
        self.assertIn("NodePort", first["title"])
        self.assertEqual(first["detail"], "infer/vllm-plugins:31000")
        self.assertEqual(first["mapping"], "exposure-mapping")
        self.assertIn("收敛", first["fix"])

    def test_tsv_without_header(self):
        result = load_run("rbac-mapping").run({}, {"findings_tsv": "medium\trb-wild\t通配符角色\tclusterrole *\trbac-mapping\t去通配符\n"})
        findings = result["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sev"], "medium")
        self.assertIn("通配符", findings[0]["title"])


class ModuleFamilyRegistryTest(unittest.TestCase):
    """注册表族完整性：本任务 17 模块（复制到隔离目录加载，免受并行任务在途模块干扰）。"""

    def test_seventeen_modules_registered(self):
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "modules"
            dest.mkdir()
            shutil.copy(MODULES_DIR / "_recon-common.py", dest / "_recon-common.py")
            for key in RECON_KEYS + ZERODAY_KEYS:
                shutil.copytree(MODULES_DIR / key, dest / key)
            mods = load_modules(dest)
        self.assertEqual(len(mods), 17)
        for key in RECON_KEYS:
            meta = mods[key]
            self.assertEqual(meta.series, "侦察", key)
            self.assertEqual(meta.min_level, "只读侦察", key)
            self.assertFalse(meta.writes, key)
            self.assertFalse(meta.private, key)
        for key in ZERODAY_KEYS:
            meta = mods[key]
            self.assertEqual(meta.min_level, "利用验证", key)
            self.assertTrue(meta.private, f"{key} 必须标记 private（零日闸门依赖）")


if __name__ == "__main__":
    unittest.main()
