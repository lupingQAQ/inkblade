# -*- coding: utf-8 -*-
"""2026-10 合规映射测试：七框架标准库 / 每发现每框架至少 1 条款 / 报告「合规映射」节。

覆盖：OWASP LLM Top 10（2025/2026）、OWASP Agentic AI Top 10（ASI01–ASI10）、
MITRE ATLAS、NIST AI RMF、ISO/IEC 42001、EU AI Act GPAI、TC260/生成式AI管理办法。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.reports import compliance
from inkblade.reports.render import render_pentest, render_remediation

STANDARDS_PATH = Path(__file__).resolve().parents[1] / "inkblade" / "reports" / "standards.json"

FRAMEWORK_KEYS = {
    "owasp_llm", "owasp_agentic", "atlas", "nist_ai_rmf", "iso_42001", "eu_ai_act", "tc260",
}

SAMPLES = [
    {"step_key": "rbac-mapping", "severity": "high", "title": "vLLM Operator 集群级 RBAC 越权",
     "detail": "cluster-admin RoleBinding 可被该 SA 创建"},
    {"step_key": "pickle-channel-unauth-execution", "severity": "critical",
     "title": "pickle 反序列化未授权 RCE", "detail": "推理服务加载恶意 pickle 触发命令执行"},
    {"step_key": "shared-volume-weight-copy", "severity": "high", "title": "共享卷权重投毒",
     "detail": "训练 Job 可改写共享 PVC 内 checkpoint 权重"},
    {"step_key": "training-data-leak", "severity": "high", "title": "训练数据泄露",
     "detail": "数据集挂载越权导致样本外泄"},
    {"step_key": "open-webui-indirect-injection-exec", "severity": "high",
     "title": "间接提示词注入导致工具误调用", "detail": "网页内容注入 agent 工具链"},
    {"step_key": "system-prompt-leak", "severity": "medium", "title": "系统提示词泄露",
     "detail": "system prompt 经错误回显外泄"},
    {"step_key": "supply-chain-pinning", "severity": "medium", "title": "模型供应链镜像未固定",
     "detail": "信任远端代码且未固定 digest"},
    {"step_key": "unlimited-query-distillation", "severity": "medium", "title": "无限查询蒸馏",
     "detail": "配额缺失导致模型能力被批量抽取"},
    {"step_key": "totally-unknown-module", "severity": "low", "title": "未分类观察",
     "detail": "新出现的平台面异常"},
]


def _seed_run(store: EvidenceStore, name: str = "run-compliance"):
    run = store.create_run(name)
    art = store.root / "art.txt"
    art.write_text("evidence-body", encoding="utf-8")
    run.add_step("rbac-mapping", "kubectl auth can-i --list", {}, "RBAC 越权", artifacts=[art])
    archive = run.query("SELECT archive FROM steps")[0][0]
    run.add_finding("rbac-mapping", "high", SAMPLES[0]["title"], SAMPLES[0]["detail"],
                    evidence_path=archive)
    run.add_finding("pickle-channel-unauth-execution", "critical", SAMPLES[1]["title"],
                    SAMPLES[1]["detail"], evidence_path=archive, is_novel=True)
    run.finalize_run()
    return run


class TestStandardsData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(STANDARDS_PATH.read_text(encoding="utf-8"))
        cls.comp = cls.data["compliance"]
        cls.frameworks = {f["key"]: f for f in cls.comp["frameworks"]}

    def test_seven_frameworks_present(self):
        self.assertEqual(set(self.frameworks), FRAMEWORK_KEYS)

    def test_owasp_llm_ids(self):
        ids = [c["id"] for c in self.frameworks["owasp_llm"]["clauses"]]
        self.assertEqual(ids, [f"LLM{i:02d}" for i in range(1, 11)])

    def test_owasp_llm_2026_reorder_and_crosswalk(self):
        fw = self.frameworks["owasp_llm"]
        self.assertEqual(fw["version"], "2026")
        clauses = {c["id"]: c for c in fw["clauses"]}
        expected = {
            "LLM03": ("Excessive Agency", "LLM06"),
            "LLM04": ("Supply Chain", "LLM03"),
            "LLM05": ("Data and Model Poisoning", "LLM04"),
            "LLM06": ("Unbounded Consumption", "LLM10"),
            "LLM07": ("Misinformation", "LLM09"),
            "LLM08": ("Hidden Context Exposure", "LLM07"),
            "LLM09": ("Vector and Embedding Weaknesses", "LLM08"),
            "LLM10": ("Improper Output Handling", "LLM05"),
        }
        for cid, (name, legacy) in expected.items():
            self.assertEqual(clauses[cid]["en"], name, cid)
            self.assertEqual(clauses[cid]["legacy_2025"], legacy, cid)

    def test_agentic_2026_names(self):
        fw = self.frameworks["owasp_agentic"]
        self.assertEqual(fw["version"], "2026")
        names = {c["id"]: c["en"] for c in fw["clauses"]}
        self.assertEqual(names["ASI05"], "Unexpected Code Execution (RCE)")
        self.assertEqual(names["ASI06"], "Memory and Context Poisoning")

    def test_owasp_agentic_ids(self):
        ids = [c["id"] for c in self.frameworks["owasp_agentic"]["clauses"]]
        self.assertEqual(ids, [f"ASI{i:02d}" for i in range(1, 11)])

    def test_atlas_ids(self):
        ids = [c["id"] for c in self.frameworks["atlas"]["clauses"]]
        self.assertGreaterEqual(len(ids), 15)
        self.assertTrue(all(i.startswith("AML.T") and i[5:].isdigit() for i in ids), ids)

    def test_nist_rmf_four_functions(self):
        ids = [c["id"] for c in self.frameworks["nist_ai_rmf"]["clauses"]]
        self.assertTrue(any(i.startswith("GV") for i in ids))
        self.assertTrue(any(i.startswith("MP") for i in ids))
        self.assertTrue(any(i.startswith("MS") for i in ids))
        self.assertTrue(any(i.startswith("MG") for i in ids))

    def test_iso_42001_controls(self):
        ids = [c["id"] for c in self.frameworks["iso_42001"]["clauses"]]
        self.assertEqual(ids, [f"A.{i}" for i in range(2, 11)])

    def test_eu_gpai_articles(self):
        ids = [c["id"] for c in self.frameworks["eu_ai_act"]["clauses"]]
        self.assertIn("Art. 53(1)(a)", ids)
        self.assertIn("Art. 53(1)(d)", ids)
        self.assertIn("Art. 55(1)(b)", ids)
        self.assertIn("Art. 55(1)(d)", ids)

    def test_tc260_and_genai_rules(self):
        ids = [c["id"] for c in self.frameworks["tc260"]["clauses"]]
        self.assertTrue(any("TC260-003" in i for i in ids))
        self.assertTrue(any("暂行办法" in i for i in ids))
        self.assertGreaterEqual(len(ids), 6)

    def test_clause_bilingual_and_unique(self):
        for key, fw in self.frameworks.items():
            self.assertTrue(fw.get("name_zh") and fw.get("name_en"), key)
            self.assertTrue(fw.get("url", "").startswith("http"), key)
            ids = [c["id"] for c in fw["clauses"]]
            self.assertEqual(len(ids), len(set(ids)), key)
            for c in fw["clauses"]:
                self.assertTrue(c.get("zh") and c.get("en"), f"{key}/{c['id']}")

    def test_mapping_covers_every_framework(self):
        mapping = self.comp["mapping"]
        self.assertIn(self.comp["fallback"], mapping)
        for cat, per in mapping.items():
            self.assertEqual(set(per), FRAMEWORK_KEYS, cat)
            for key, ids in per.items():
                ids_in_fw = {c["id"] for c in self.frameworks[key]["clauses"]}
                self.assertTrue(ids, f"{cat}/{key} 为空")
                self.assertTrue(set(ids) <= ids_in_fw, f"{cat}/{key} 引用未知条款 {set(ids) - ids_in_fw}")

    def test_categories_have_keywords(self):
        for cat in self.comp["categories"]:
            self.assertTrue(cat.get("zh") and cat.get("en"), cat)
            self.assertTrue(cat.get("keywords"), cat["key"])
        self.assertIn(self.comp["fallback"], {c["key"] for c in self.comp["categories"]})


class TestMapping(unittest.TestCase):
    def test_every_sample_maps_each_framework(self):
        for finding in SAMPLES:
            mapped = compliance.map_finding(finding)
            self.assertEqual(set(mapped), FRAMEWORK_KEYS, finding["title"])
            for key, ids in mapped.items():
                self.assertTrue(ids, f"{finding['title']} 未映射 {key}")

    def test_unknown_falls_back(self):
        finding = {"step_key": "brand-new", "title": "totally novel observation",
                   "detail": "nothing familiar", "severity": "low"}
        self.assertEqual(compliance.classify(finding), [compliance.fallback_category()])
        mapped = compliance.map_finding(finding)
        for key, ids in mapped.items():
            self.assertTrue(ids, key)

    def test_classification_specificity(self):
        cases = {
            "model-poisoning": {"step_key": "x", "title": "权重投毒 / weight poison", "detail": ""},
            "prompt-injection": {"step_key": "x", "title": "间接提示词注入", "detail": "prompt injection"},
            "unsafe-code-exec": {"step_key": "x", "title": "pickle 反序列化 RCE", "detail": ""},
            "data-leak": {"step_key": "x", "title": "训练数据泄露", "detail": "exfil"},
            "supply-chain": {"step_key": "x", "title": "模型供应链投毒", "detail": "trust remote code"},
            "system-prompt": {"step_key": "x", "title": "系统提示词泄露", "detail": ""},
        }
        for expected, finding in cases.items():
            self.assertIn(expected, compliance.classify(finding), finding["title"])

    def test_rbac_maps_agentic_privilege(self):
        mapped = compliance.map_finding(SAMPLES[0])
        self.assertIn("ASI03", mapped["owasp_agentic"])
        self.assertIn("AML.T0055", mapped["atlas"])

    def test_2026_owasp_mapping_reorder(self):
        poison = compliance.map_finding(SAMPLES[2])
        self.assertIn("LLM05", poison["owasp_llm"])
        agency = compliance.map_finding({"step_key": "x", "title": "agent tool 过度代理", "detail": ""})
        self.assertIn("LLM03", agency["owasp_llm"])
        prompt = compliance.map_finding(SAMPLES[4])
        self.assertIn("LLM01", prompt["owasp_llm"])
        self.assertIn("ASI01", prompt["owasp_agentic"])

    def test_coverage_summary(self):
        summary = compliance.coverage_summary(SAMPLES)
        self.assertEqual(summary["findings"], len(SAMPLES))
        for key in FRAMEWORK_KEYS:
            self.assertGreater(summary["frameworks"][key]["clauses"], 0, key)
            self.assertEqual(summary["frameworks"][key]["findings"], len(SAMPLES), key)
        self.assertTrue(summary["ok"])

    def test_exportable_matrix(self):
        rows = compliance.matrix_rows(SAMPLES)
        self.assertEqual(len(rows), len(SAMPLES))
        for row in rows:
            self.assertEqual(set(row["clauses"]), FRAMEWORK_KEYS)
            self.assertTrue(all(row["clauses"].values()))
            self.assertTrue(row["title"])


class TestRenderedComplianceSection(unittest.TestCase):
    def test_section_bi(self):
        text = compliance.render_compliance_section(SAMPLES, "bi")
        self.assertIn("合规映射", text)
        self.assertIn("Compliance Mapping", text)
        for label in ("OWASP LLM", "OWASP Agentic", "MITRE ATLAS", "NIST AI RMF",
                      "ISO/IEC 42001", "EU AI Act", "TC260"):
            self.assertIn(label, text)
        for finding in SAMPLES:
            self.assertIn(finding["title"], text)
        self.assertIn("LLM01", text)
        self.assertIn("ASI03", text)
        self.assertIn("AML.T0055", text)
        self.assertIn("Art. 53", text)
        self.assertIn("TC260", text)

    def test_section_zh_and_en(self):
        zh = compliance.render_compliance_section(SAMPLES, "zh")
        en = compliance.render_compliance_section(SAMPLES, "en")
        self.assertIn("合规映射", zh)
        self.assertNotIn("Compliance Mapping", zh)
        self.assertIn("Compliance Mapping", en)
        self.assertNotIn("合规映射", en)

    def test_row_count_and_no_empty_cells(self):
        rows = compliance.matrix_rows(SAMPLES)
        for row in rows:
            self.assertEqual(len(row["clauses"]), 7)

    def test_bad_lang(self):
        with self.assertRaises(ValueError):
            compliance.render_compliance_section(SAMPLES, "fr")


class TestReportIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        _seed_run(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pentest_has_compliance_section_and_rows(self):
        md = render_pentest(self.store, "run-compliance")
        self.assertIn("合规映射", md)
        self.assertIn("Compliance Mapping", md)
        self.assertIn("OWASP LLM", md)
        self.assertIn("ASI01", md)
        self.assertIn("MITRE ATLAS", md)
        self.assertIn("NIST AI RMF", md)
        self.assertIn("ISO/IEC 42001", md)
        self.assertIn("EU AI Act", md)
        self.assertIn("TC260", md)
        self.assertIn(SAMPLES[0]["title"], md)
        self.assertIn(SAMPLES[1]["title"], md)

    def test_every_finding_row_has_clause_per_framework(self):
        md = render_pentest(self.store, "run-compliance")
        section = md.split("合规映射", 1)[1]
        for title in (SAMPLES[0]["title"], SAMPLES[1]["title"]):
            line = next(l for l in section.splitlines() if title in l)
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            self.assertGreaterEqual(len(cells), 8, line)
            for cell in cells[1:8]:
                self.assertNotIn(cell, ("", "—", "-"), f"{title} 存在空条款: {line}")

    def test_remediation_has_compliance_section(self):
        md = render_remediation(self.store, "run-compliance")
        self.assertIn("合规映射", md)
        self.assertIn("Compliance Mapping", md)

    def test_redacted_report_keeps_compliance_titles_only(self):
        md = render_pentest(self.store, "run-compliance", redact_novel=True)
        self.assertIn("合规映射", md)
        self.assertIn(SAMPLES[1]["title"], md)


if __name__ == "__main__":
    unittest.main()
