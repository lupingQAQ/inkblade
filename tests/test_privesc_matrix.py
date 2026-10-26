"""全量提权矩阵：字段完整性、覆盖清单、文档与紫队检测规则一致性。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.privesc import (
    CATEGORY_REQUIRED,
    REQUIRED_VECTOR_FIELDS,
    load_matrix,
    render_matrix_md,
    validate_matrix,
)
from inkblade.core.registry import load_modules
from inkblade.rules.privesc import (
    PrivescCoverageError,
    purple_replay,
    render_rule_pack,
    write_rule_pack,
)

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
DOC = REPO / "docs" / "PRIVESC-MATRIX.md"


class TestPrivescMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load_matrix()

    def test_vector_count_and_required_categories(self):
        vectors = self.matrix["vectors"]
        self.assertGreaterEqual(len(vectors), 30, "提权向量必须 >= 30")
        by_cat: dict[str, set[str]] = {}
        for v in vectors:
            by_cat.setdefault(v["category"], set()).add(v["id"])
        for cat, required in CATEGORY_REQUIRED.items():
            self.assertIn(cat, by_cat, f"缺少类别 {cat}")
            missing = set(required) - by_cat[cat]
            self.assertFalse(missing, f"{cat} 缺少必需向量: {sorted(missing)}")

    def test_every_vector_has_required_fields(self):
        for v in self.matrix["vectors"]:
            for field in REQUIRED_VECTOR_FIELDS:
                self.assertIn(field, v, f"{v.get('id')} 缺少字段 {field}")
            self.assertTrue(v["subject"].strip(), v["id"])
            self.assertTrue(v["requires"], v["id"])
            self.assertTrue(v["primitive"].strip(), v["id"])
            for scope in ("node", "cluster", "cloud"):
                self.assertIn(scope, v["impact"], f"{v['id']} impact 缺 {scope}")
                self.assertTrue(str(v["impact"][scope]).strip(), f"{v['id']} impact.{scope} 为空")
            self.assertTrue(v["sources"], f"{v['id']} 缺来源")
            for src in v["sources"]:
                self.assertTrue(src.get("type") and src.get("ref"), f"{v['id']} 来源字段不完整")
            detect = v["detect"]
            self.assertIn(detect["engine"], ("sigma", "falco"), v["id"])
            self.assertTrue(detect["point"].strip(), v["id"])
            self.assertTrue(v["edges"], f"{v['id']} 缺图边")
            for edge in v["edges"]:
                self.assertTrue(edge["from"].startswith(("principal:", "cap:")), edge)
                self.assertTrue(edge["to"].startswith(("cap:", "target:", "cloud:")), edge)

    def test_module_keys_exist(self):
        mods = load_modules(MODULES_DIR)
        for v in self.matrix["vectors"]:
            self.assertIn(v["module"], mods, f"{v['id']} 引用不存在的模块 {v['module']}")

    def test_validate_matrix_reports_clean(self):
        report = validate_matrix(self.matrix, modules=load_modules(MODULES_DIR))
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["vectors"], len(self.matrix["vectors"]))
        self.assertEqual(report["rules"], len(self.matrix["vectors"]))
        self.assertGreater(report["edges"], report["vectors"])

    def test_doc_matches_generated_and_contains_all_vectors(self):
        self.assertTrue(DOC.is_file(), f"缺少 {DOC}")
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("提权面", text)
        self.assertIn("选择依据", text)
        for v in self.matrix["vectors"]:
            self.assertIn(v["id"], text, f"文档缺少向量 {v['id']}")
        self.assertEqual(text, render_matrix_md(self.matrix), "文档必须由矩阵确定性生成")

    def test_purple_replay_all_vectors(self):
        result = purple_replay(self.matrix)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["vectors"], len(self.matrix["vectors"]))
        self.assertEqual(result["missed"], [])
        for item in result["items"]:
            self.assertTrue(item["fired"], item)

    def test_rule_pack_has_one_rule_per_vector(self):
        with TemporaryDirectory() as tmp:
            summary = write_rule_pack(self.matrix, tmp)
            self.assertTrue(summary["ok"], summary)
            self.assertEqual(summary["vectors"], len(self.matrix["vectors"]))
            pack = Path(tmp)
            coverage = json.loads((pack / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(len(coverage["items"]), len(self.matrix["vectors"]))
            self.assertTrue((pack / "README.md").is_file())
            self.assertTrue(any((pack / "sigma").glob("*.yaml")))
            # 每个向量至少 1 条规则文件，且规则 id 全局唯一
            rule_ids = [item["rule"] for item in coverage["items"]]
            self.assertEqual(len(rule_ids), len(set(rule_ids)))
            rendered = render_rule_pack(self.matrix)
            self.assertEqual(len(rendered["documents"]), len(self.matrix["vectors"]))
            self.assertTrue(rendered["documents"])

    def test_coverage_error_lists_missing_vector(self):
        broken = json.loads(json.dumps(self.matrix))
        broken["vectors"][0]["detect"]["event"] = {"kind": "sigma", "verb": "list"}
        with self.assertRaises(PrivescCoverageError):
            purple_replay(broken)


if __name__ == "__main__":
    unittest.main()
