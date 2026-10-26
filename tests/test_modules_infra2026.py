"""tests/test_modules_infra2026.py — 2026 会议 infra 缺口模块（16 个）。

契约：纯小写键、只读（writes=false）、requires 为空、不得依赖仿真器答案。
行为：vulnerable 靶场产出预期 high/medium；fixed 靶场无 high；fixture/快照类模块
      用最小快照验证“干净即无发现”。
"""

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.infra2026_sim import start_all
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"

NEW_MODULES = {
    "confidential-containers-attestation": {
        "series": "核心代码", "min_level": "主动探测"},
    "sandbox-runtime-surface": {
        "series": "权限链", "min_level": "只读侦察"},
    "spiffe-spire-surface": {
        "series": "权限链", "min_level": "主动探测"},
    "cert-manager-webhook-tls": {
        "series": "网络架构", "min_level": "主动探测"},
    "gateway-api-ambient-mesh": {
        "series": "网络架构", "min_level": "只读侦察"},
    "wasm-workload-surface": {
        "series": "核心代码", "min_level": "主动探测"},
    "gitops-supply-chain": {
        "series": "核心代码", "min_level": "只读侦察"},
    "multi-cluster-federation": {
        "series": "混合云", "min_level": "只读侦察"},
    "dpu-ipu-offload": {
        "series": "网络架构", "min_level": "主动探测"},
    "pcie-iommu-dma": {
        "series": "网络架构", "min_level": "只读侦察"},
    "tpm-measured-boot": {
        "series": "侦察", "min_level": "只读侦察"},
    "post-quantum-tls-posture": {
        "series": "网络架构", "min_level": "主动探测"},
    "model-watermark-backdoor-detect": {
        "series": "情报", "min_level": "主动探测"},
    "rag-vector-injection": {
        "series": "窃取与数据泄露", "min_level": "主动探测"},
    "federated-learning-surface": {
        "series": "情报", "min_level": "只读侦察"},
    "data-provenance-audit": {
        "series": "情报", "min_level": "主动探测"},
}

EXPECTED_TITLES = {
    "confidential-containers-attestation": (
        "CoCo 证明测量值不匹配", "CoCo 未强制证明或允许任意镜像"),
    "sandbox-runtime-surface": (
        "Agent Pod 使用非沙箱运行时", "Pod 关闭 seccomp 或持有 SYS_ADMIN",
        "hostPID/hostNetwork 旁路沙箱边界"),
    "spiffe-spire-surface": (
        "SPIRE 通配 SPIFFE ID 条目", "SPIRE 条目缺少选择器或 TTL 异常",
        "SPIRE 管理接口无 ACL 或监听 0.0.0.0"),
    "cert-manager-webhook-tls": (
        "Webhook 证书已过期", "Webhook 证书 SAN 与 Service 不匹配",
        "Webhook CA bundle 不匹配或跳过校验"),
    "gateway-api-ambient-mesh": (
        "Gateway 监听器明文 HTTP 或通配主机",
        "HTTPRoute 跨命名空间或全来源放行", "Ambient waypoint 未强制 L7 授权"),
    "wasm-workload-surface": (
        "WASM 模块获得宿主文件系统或网络能力", "WASM 模块未签名",
        "WASM 启用 WASI unstable 或继承环境变量"),
    "gitops-supply-chain": (
        "GitOps 仓库存在明文密钥", "GitOps 漂移未阻断或自动同步未签名",
        "GitOps 未启用 prune 或签名提交"),
    "multi-cluster-federation": (
        "Karmada 通配传播到全部集群", "多集群 kubeconfig 共享或无审批",
        "多集群无自动故障转移或命名空间未隔离"),
    "dpu-ipu-offload": (
        "DPU 未接管基础设施服务", "DPU 未启用 IOMMU/switchdev 隔离",
        "DPU 固件未验证"),
    "pcie-iommu-dma": (
        "IOMMU 未启用（DMA 直通风险）", "PCIe 设备共享 IOMMU 组且启用 passthrough",
        "ACS 未启用或 ATS 无保护"),
    "tpm-measured-boot": (
        "Secure Boot/Measured Boot 未启用", "TPM PCR 测量值不匹配",
        "TPM 使用 SHA-1 PCR bank 或证明密钥未保护"),
    "post-quantum-tls-posture": (
        "TLS 使用 RSA 密钥交换或低于 TLS 1.3", "未配置混合后量子密钥交换",
        "证书或签名算法非后量子", "存在 harvest-now-decrypt-later 暴露"),
    "model-watermark-backdoor-detect": (
        "模型未嵌入可验证水印", "未执行后门或触发器扫描", "模型来源未签名"),
    "rag-vector-injection": (
        "RAG 知识库存在未签名注入文档", "检索未按租户过滤",
        "检索内容未清洗或文档数无上限"),
    "federated-learning-surface": (
        "联邦更新未签名或未验证", "未启用安全聚合",
        "未启用差分隐私或拜占庭过滤"),
    "data-provenance-audit": (
        "制品证明签名无效", "缺少 SBOM 或来源材料", "SLSA 等级不足或未接入 Rekor"),
}

SUMMARY_FIELDS = {
    "confidential-containers-attestation": {
        "measurement_matches": False, "policy_enforced": False, "debug": True},
    "spiffe-spire-surface": {"wildcard_entries": 2, "admin_acl": False},
    "cert-manager-webhook-tls": {"expired": True, "san_match": False},
    "gateway-api-ambient-mesh": {
        "plaintext_listeners": 1, "cross_namespace_routes": 1},
    "wasm-workload-surface": {"overprivileged_modules": 1, "unsigned_modules": 1},
    "gitops-supply-chain": {"plaintext_secrets": 3, "drift_entries": 2},
    "multi-cluster-federation": {"wildcard_propagation": True},
    "dpu-ipu-offload": {"host_offload": False, "iommu_enabled": False},
    "pcie-iommu-dma": {"iommu_enabled": False, "passthrough_groups": 1},
    "tpm-measured-boot": {"measured_boot": False, "pcr_mismatches": 2},
    "post-quantum-tls-posture": {"min_version": "TLS1.2", "hybrid_group": ""},
    "model-watermark-backdoor-detect": {"watermark_present": False},
    "rag-vector-injection": {"injected_docs": 1, "tenant_filter": False},
    "federated-learning-surface": {"unverified_updates": 2},
    "data-provenance-audit": {"signature_valid": False},
}


def _isolated_modules(root: Path) -> Path:
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULES_DIR / "_infra2026-common.py", dest / "_infra2026-common.py")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for key in NEW_MODULES:
        shutil.copytree(MODULES_DIR / key, dest / key, ignore=ignore)
    return dest


def _titles(findings):
    return " | ".join(f.get("title", "") for f in findings)


class Infra2026RegistryTest(unittest.TestCase):
    def test_sixteen_modules_read_only_lowercase(self):
        with TemporaryDirectory() as tmp:
            mods = load_modules(_isolated_modules(Path(tmp)))
        self.assertEqual(len(mods), len(NEW_MODULES))
        for key, spec in NEW_MODULES.items():
            self.assertIn(key, mods, key)
            meta = mods[key]
            self.assertEqual(meta.series, spec["series"], key)
            self.assertEqual(meta.min_level, spec["min_level"], key)
            self.assertFalse(meta.writes, key)
            self.assertEqual(meta.requires, [], key)
            self.assertRegex(key, r"^[a-z][a-z0-9-]*$")

    def test_modules_do_not_import_simulator(self):
        for key in NEW_MODULES:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("infra2026_sim", source, key)
            self.assertNotIn("lab.infra2026", source, key)


class Infra2026ModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules_tmp = TemporaryDirectory()
        cls.modules_dir = _isolated_modules(Path(cls.modules_tmp.name))
        cls.vuln = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.fixed.shutdown()
        cls.modules_tmp.cleanup()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="infra2026-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("infra-tester", "x", "tester", ["infra2026-lab"])
        self.session = users.verify("infra-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["default", "infer", "train"],
            "cidrs": ["127.0.0.0/8"],
            "window": "infra2026-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, target):
        self._seq += 1
        run = self.store.create_run(f"infra2026-{key}-{self._seq}")
        run_module(self.store, self.session, key, {"target": target},
                   modules_dir=self.modules_dir, run=run)
        findings = [f for f in run.findings if f["step_key"] == key]
        row = run.query(
            "SELECT result_summary FROM steps WHERE run=? AND step_key=? ORDER BY id DESC LIMIT 1",
            (run.name, key),
        )
        summary = json.loads(row[0][0]) if row else {}
        return summary, findings

    def test_all_modules_vulnerable_and_fixed(self):
        for key, expected in EXPECTED_TITLES.items():
            with self.subTest(module=key):
                summary, findings = self._run(key, self.vuln.url(""))
                titles = _titles(findings)
                for title in expected:
                    self.assertIn(title, titles, f"{key}: {titles}")
                high = [f for f in findings if f["severity"] == "high"]
                self.assertTrue(high, f"{key} 缺少 high: {titles}")
                fields = SUMMARY_FIELDS.get(key, {})
                for field, value in fields.items():
                    self.assertEqual(summary.get(field), value,
                                     f"{key}.{field}={summary.get(field)!r}")
                _, fixed = self._run(key, self.fixed.url(""))
                self.assertEqual(
                    [f for f in fixed if f["severity"] == "high"], [],
                    f"{key} fixed 仍有 high: {_titles(fixed)}",
                )

    def test_core_six_fixed_clean(self):
        for key in (
            "confidential-containers-attestation", "spiffe-spire-surface",
            "cert-manager-webhook-tls", "gateway-api-ambient-mesh",
            "wasm-workload-surface", "post-quantum-tls-posture",
        ):
            with self.subTest(module=key):
                _, findings = self._run(key, self.fixed.url(""))
                self.assertEqual(findings, [], f"{key}: {_titles(findings)}")

    def test_no_target_is_noop(self):
        for key in NEW_MODULES:
            with self.subTest(module=key):
                summary, findings = self._run(key, "")
                self.assertEqual(summary, {"summary": "no-target"})
                self.assertEqual(findings, [])

    def test_findings_do_not_echo_secret_values(self):
        _, findings = self._run("gitops-supply-chain", self.vuln.url(""))
        blob = json.dumps(findings, ensure_ascii=False).lower()
        self.assertNotIn("db-password-value", blob)
        self.assertNotIn("registry-token-value", blob)


if __name__ == "__main__":
    unittest.main()
