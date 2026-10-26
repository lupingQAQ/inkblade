"""报告引擎测试：CVSS 3.1 精确值 / PTES 七段双语 / 专节 / 证据锚 / 标准映射 / 深度默认展示与可选脱敏 / 修复基线。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.reports import cvss
from inkblade.reports.render import render_pentest, render_remediation

# CVSS 3.1 官方示例向量（FIRST example-vectors / 规范附录）→ 精确基础分
CVSS_CASES = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # CVE-2015-8252
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),   # CVE-2008-1447
    ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
]

PTES_SECTIONS = [
    ("范围与约定", "Scope and Rules of Engagement"),
    ("情报收集", "Intelligence Gathering"),
    ("威胁建模", "Threat Modeling"),
    ("漏洞分析", "Vulnerability Analysis"),
    ("利用", "Exploitation"),
    ("后利用", "Post-Exploitation"),
    ("风险评级与修复", "Risk Rating and Remediation"),
]

SPECIAL_SECTIONS = [
    ("组合层风险", "Combination-Layer Risks"),
    ("训练数据泄露", "Training Data Exposure Surface"),
    ("核心代码问题", "Core Code Issues"),
    ("网络分层威胁模型", "Layered Network Threat Model"),
    ("混合云边界", "Hybrid Cloud Boundary"),
]

ZD_SECRET = "SECRET-ZD-POC-payload-91f3"


def _manifest_map(run_dir: Path) -> dict:
    out = {}
    for line in (run_dir / "manifest.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip():
            sha, _, rel = line.partition("  ")
            out[rel.strip()] = sha.strip()
    return out


def _seed_run(store: EvidenceStore, name: str = "run-report"):
    run = store.create_run(name)
    art = store.root / "art.txt"
    art.write_text("evidence-body", encoding="utf-8")
    run.add_step("rbac-escape", "kubectl auth can-i --list", {"actor": "tester"},
                 "vLLM Operator SA 可创建 RoleBinding 指向 cluster-admin", artifacts=[art])
    run.add_step("mgmt-port", "curl 127.0.0.1:30000/pull_weights", {},
                 "SGLang 管理面无鉴权拉取权重", artifacts=[art])
    archives = {r[0]: r[1] for r in run.query("SELECT step_key, archive FROM steps")}
    run.add_finding("rbac-escape", "high", "vLLM Operator 集群级 RBAC 越权",
                    "cluster-admin RoleBinding 可被该 SA 创建",
                    evidence_path=archives["rbac-escape"])
    run.add_finding("mgmt-port", "critical", "SGLang 管理面 fail-open 拉取权重",
                    f"无 key 放行 {ZD_SECRET}",
                    evidence_path=archives["mgmt-port"], is_novel=True)
    run.query(
        "INSERT INTO combos(run, signature, detail) VALUES(?,?,?)",
        (name, "weights-write-endpoint+patch-image",
         "组合命中：权重写端点与补丁栈镜像共存于同一命名空间"),
    )
    run.finalize_run()
    return run


class TestCvss(unittest.TestCase):
    def test_cvss_known_vectors(self):
        for vector, expected in CVSS_CASES:
            with self.subTest(vector=vector):
                self.assertEqual(cvss.base_score(vector), expected)

    def test_cvss_prefix_and_invalid(self):
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 7.5)
        with self.assertRaises(ValueError):
            cvss.base_score("AV:N/AC:L/PR:N/UI:X/S:U/C:H/I:H/A:H")
        with self.assertRaises(ValueError):
            cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # 缺 A
        with self.assertRaises(ValueError):
            cvss.base_score("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_cn_grade_bands(self):
        self.assertEqual(cvss.cn_grade(9.8), "超危")
        self.assertEqual(cvss.cn_grade(7.5), "高危")
        self.assertEqual(cvss.cn_grade(5.3), "中危")
        self.assertEqual(cvss.cn_grade(2.1), "低危")
        self.assertEqual(cvss.cn_grade(0.0), "无风险")
        self.assertEqual(cvss.severity_band(10.0), "critical")


class TestRenderPentest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        self.run = _seed_run(self.store)
        self.md = render_pentest(self.store, "run-report")

    def tearDown(self):
        self.tmp.cleanup()

    def test_bilingual_sections_present(self):
        for zh, en in PTES_SECTIONS:
            self.assertIn(zh, self.md, f"PTES 中文段缺失: {zh}")
            self.assertIn(en, self.md, f"PTES 英文段缺失: {en}")
        for zh, en in SPECIAL_SECTIONS:
            self.assertIn(zh, self.md, f"专节中文缺失: {zh}")
            self.assertIn(en, self.md, f"专节英文缺失: {en}")
        self.assertGreaterEqual(self.md.count("\n## "), 12)

    def test_combo_section_rows(self):
        self.assertIn("weights-write-endpoint+patch-image", self.md)
        self.assertIn("组合命中", self.md)

    def test_novel_details_public_by_default(self):
        """深度漏洞模块（已公开）细节默认展示，不再默认脱敏。"""
        self.assertIn(ZD_SECRET, self.md)
        self.assertNotIn("影响已验证 + 证据哈希", self.md)
        rem = render_remediation(self.store, "run-report")
        self.assertIn(ZD_SECRET, rem)
        self.assertNotIn("影响已验证 + 证据哈希", rem)

    def test_novel_redaction_opt_in(self):
        """可选脱敏开关：供未来真私有发现使用；disclosed 可逐条解除。"""
        md = render_pentest(self.store, "run-report", redact_novel=True)
        self.assertNotIn(ZD_SECRET, md)
        self.assertIn("影响已验证", md)
        self.assertIn("细节按合同分级", md)
        rem = render_remediation(self.store, "run-report", redact_novel=True)
        self.assertNotIn(ZD_SECRET, rem)
        self.assertIn("影响已验证", rem)
        disclosed = render_pentest(
            self.store, "run-report", redact_novel=True,
            disclosed=("SGLang 管理面 fail-open 拉取权重",))
        self.assertIn(ZD_SECRET, disclosed, "disclosed 内的已公开发现应恢复细节")

    def test_evidence_anchor_sha16(self):
        m = _manifest_map(self.run.dir)
        for step in ("rbac-escape", "mgmt-port"):
            sha = m[f"steps/{step}.tar.gz"]
            self.assertIn(f"sha256:{sha[:16]}", self.md)

    def test_standards_mapping_injected(self):
        self.assertIn("NIST SP 800-115", self.md)
        self.assertIn("§5", self.md)
        self.assertIn("§8", self.md)
        self.assertIn("GB/T 22239-2019", self.md)
        self.assertIn("8.1.3.2", self.md)
        self.assertIn("GB/T 20984", self.md)
        self.assertIn("计划", self.md)  # NIST 计划-执行-后置三阶段
        self.assertIn("Post-Testing", self.md)

    def test_tamper_evident_declaration(self):
        self.assertIn("manifest.sha256", self.md)
        self.assertIn("通过", self.md)  # 生成时校验通过

    def test_glossary_present(self):
        self.assertIn("术语表", self.md)
        self.assertIn("Glossary", self.md)
        self.assertIn("权重投毒", self.md)
        self.assertIn("Weight Poisoning", self.md)

    def test_lang_zh_and_en(self):
        zh = render_pentest(self.store, "run-report", lang="zh")
        self.assertIn("威胁建模", zh)
        self.assertNotIn("Threat Modeling", zh)
        en = render_pentest(self.store, "run-report", lang="en")
        self.assertIn("Threat Modeling", en)
        self.assertNotIn("威胁建模", en)
        with self.assertRaises(ValueError):
            render_pentest(self.store, "run-report", lang="fr")


class TestRenderRemediation(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        _seed_run(self.store)
        self.rem = render_remediation(self.store, "run-report")

    def tearDown(self):
        self.tmp.cleanup()

    def test_baseline_priorities_present(self):
        for p in ("立即", "短期", "中期"):
            self.assertIn(p, self.rem)
        self.assertIn("RBAC", self.rem)  # RBAC 越权发现命中立即级基线
        self.assertIn("复测", self.rem)   # 复测计划
        self.assertIn("规则", self.rem)   # 规则包引用

    def test_baseline_json_structure(self):
        data = json.loads(
            (Path(__file__).parent.parent / "inkblade" / "reports" / "baseline.json").read_text(encoding="utf-8")
        )
        prios = {p["key"] for p in data["priorities"]}
        self.assertEqual(prios, {"immediate", "short", "mid"})
        by_prio = {}
        for e in data["entries"]:
            self.assertIn(e["priority"], prios)
            self.assertTrue(e["title"]["zh"] and e["title"]["en"])
            self.assertTrue(e["remediation"]["zh"] and e["remediation"]["en"])
            by_prio.setdefault(e["priority"], []).append(e)
        for p in prios:
            self.assertGreaterEqual(len(by_prio.get(p, [])), 2, f"基线 {p} 项数不足")

    def test_remediation_meta(self):
        self.assertIn("run-report", self.rem)
        self.assertIn("manifest.sha256", self.rem)


class TestEdgeCases(unittest.TestCase):
    def test_unknown_run_raises(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="local-lab")
            with self.assertRaises(KeyError):
                render_pentest(store, "no-such-run")


if __name__ == "__main__":
    unittest.main()
