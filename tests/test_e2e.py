"""tests/test_e2e.py — 端到端验收测试：调 trident/e2e-check.py::main() 断言全 PASS 与样张落盘。

对应计划任务「端到端验收 + RUNBOOK + 样张」与 设计基线第 18 节验收标准中可本机闭环的条目：
授权锁（runner+API）/ 备份闸 91 / 零日级模块（已公开，无需闸门）/ 三层证据+manifest / 链 dry-run+execute /
report 双语默认展示 + 可选脱敏 / rules generate_all 每链≥1+紫队矩阵 / export_static 兜底 / 角色与工作区隔离 / 样张清单。

e2e-check.py 文件名含连字符（计划口径），经 importlib 按路径装载。
"""

import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
E2E_SCRIPT = REPO / "trident" / "e2e-check.py"
SAMPLES = REPO / "reports" / "samples"

# 必须出现的验收检查项（对应 spec 18 节可本机闭环条目）
REQUIRED_CHECK_IDS = {
    "lab-mock-vulnerable",
    "consent-lock-runner",
    "consent-lock-api",
    "backup-gate-exit-code-91",
    "module-family-subset",
    "chain-catalog-dryrun",
    "chain-execute-weight-poison",
    "evidence-three-layers-manifest",
    "zeroday-public-no-gate",
    "report-bilingual-public-details",
    "rules-pack-coverage",
    "purple-coverage-matrix",
    "export-static-offline",
    "roles-and-workspace-isolation",
    "samples-written",
}

# 样张清单（入库交付物）
REQUIRED_SAMPLES = [
    "e2e/e2e-check.json",
    "e2e/e2e-check.md",
    "pentest-report-bi.md",
    "pentest-report-bi-redacted.md",
    "remediation-report-bi.md",
    "rules-pack/mapping.json",
    "rules-pack/coverage-matrix.json",
    "rules-pack/coverage-matrix.md",
    "rules-pack/network/native/network-policy-default-deny.yaml",
    "rules-pack/network/calico/global-network-policy-default-deny.yaml",
    "rules-pack/network/cilium/cilium-network-policy-default-deny.yaml",
    "static-export/index.html",
]


def load_e2e():
    spec = importlib.util.spec_from_file_location("trident_e2e_check", E2E_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestE2EAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_e2e()
        cls.rc = cls.mod.main([])

    def test_main_exit_zero(self):
        self.assertEqual(self.rc, 0, "e2e-check.main() 有失败项时必须非 0")

    def test_all_checks_pass(self):
        data = json.loads((SAMPLES / "e2e" / "e2e-check.json").read_text(encoding="utf-8"))
        self.assertEqual(data["failed"], 0, f"失败项: {[c for c in data['checks'] if c['status'] != 'PASS']}")
        self.assertEqual(data["passed"], data["total"])
        self.assertTrue(data["ok"])

    def test_required_check_ids_present(self):
        data = json.loads((SAMPLES / "e2e" / "e2e-check.json").read_text(encoding="utf-8"))
        ids = {c["id"] for c in data["checks"]}
        self.assertTrue(REQUIRED_CHECK_IDS <= ids, f"缺少检查项: {sorted(REQUIRED_CHECK_IDS - ids)}")

    def test_nine_module_families_covered(self):
        data = json.loads((SAMPLES / "e2e" / "e2e-check.json").read_text(encoding="utf-8"))
        families = set(data["families"])
        self.assertGreaterEqual(
            len(families & {"侦察", "网络架构", "权限链", "横向利用", "混合云",
                            "窃取与数据泄露", "核心代码", "防护绕过", "零日"}),
            9,
            f"九族代表性子集未全覆盖: {sorted(families)}",
        )

    def test_sample_files_exist(self):
        for rel in REQUIRED_SAMPLES:
            p = SAMPLES / rel
            self.assertTrue(p.exists(), f"样张缺失: {rel}")
        for engine_dir in ("sigma", "falco", "suricata"):
            d = SAMPLES / "rules-pack" / engine_dir
            self.assertTrue(d.is_dir() and any(d.iterdir()), f"规则包缺 {engine_dir} 产物")

    def test_pentest_sample_bilingual_and_public_details(self):
        text = (SAMPLES / "pentest-report-bi.md").read_text(encoding="utf-8")
        self.assertIn("渗透测试报告", text)
        self.assertIn("Penetration Test Report", text)
        self.assertIn("中英对照 / Bilingual (CN/EN)", text)
        self.assertIn("无 Authorization 凭据即可创建/销毁 binding", text)  # 已公开零日级细节默认展示
        self.assertNotIn("影响已验证 + 证据哈希", text)
        self.assertIn("sha256:", text)  # 证据锚
        redacted = (SAMPLES / "pentest-report-bi-redacted.md").read_text(encoding="utf-8")
        self.assertIn("影响已验证 + 证据哈希", redacted)  # 可选脱敏开关样例
        self.assertNotIn("无 Authorization 凭据即可创建/销毁 binding", redacted)

    def test_remediation_sample_structure(self):
        text = (SAMPLES / "remediation-report-bi.md").read_text(encoding="utf-8")
        self.assertIn("修复报告", text)
        self.assertIn("Remediation Report", text)
        self.assertIn("复测计划", text)

    def test_e2e_md_checklist_readable(self):
        md = (SAMPLES / "e2e" / "e2e-check.md").read_text(encoding="utf-8")
        self.assertIn("PASS", md)
        self.assertIn("验收", md)
        for cid in REQUIRED_CHECK_IDS:
            self.assertIn(cid, md, f"MD 清单缺检查项 {cid}")


if __name__ == "__main__":
    unittest.main()
