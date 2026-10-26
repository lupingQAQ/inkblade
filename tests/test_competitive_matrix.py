# -*- coding: utf-8 -*-
"""竞品对比矩阵测试：核心逻辑（fixture 注入）+ docs/COMPETITIVE-MATRIX.md 结构/来源/维度覆盖断言。

核心校验逻辑在 inkblade/arch-intel/competitive.py（verify 接受任意文本 → fixture 注入测试）；
真实文档断言：23 工具 / 18 维度 / 5 分类表 / 每工具一行启示 / 33 项 backlog（S/M/L）/
gen-27 重叠标注 / SOTA-2026-10.md 挂链。工作区模式（存在 .slim/clonedeps/clonedeps.json）时
附加克隆登记断言；独立发布模式自动跳过（不依赖仓外文件）。
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "COMPETITIVE-MATRIX.md"
SOTA = REPO / "docs" / "SOTA-2026-10.md"
CLONEDEPS = REPO.parents[1] / ".slim" / "clonedeps" / "clonedeps.json"

# arch-intel 目录名含连字符，按路径加载模块（与 tests/test_archintel.py 同法）
ARCH_INTEL = REPO / "inkblade" / "arch-intel"
_spec = importlib.util.spec_from_file_location("inkblade_arch_intel_competitive", ARCH_INTEL / "competitive.py")
ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci)

# ---------------------------------------------------------------------------
# fixture：最小合成矩阵（注入核心逻辑，验证 verify() 的判定而非真实文档）
# ---------------------------------------------------------------------------

FIXTURE = """# fixture 竞品矩阵

| 工具 | 类别 | 形态与许可 | 版本/核验锚点 | 来源 | 核验日期 |
|---|---|---|---|---|---|
| ToolA | 自主渗透 | x | y | https://example.com/a | 2026-10-25 |
| ToolB | K8s 攻防 | x | y | .slim/clonedeps/repos/ToolB | 2026-10-25 |

| 维度 | InkBlade | ToolA | ToolB |
|---|---|---|---|
| D1 资产发现 | ✓ | ✓ | ◐ |
| D2 自主规划 | ◐ | ? | ○ |
| D3 攻击链编排 | ✓ | ✓ | — |

| 工具 | 类别 | 对我们启示：补齐项（映射模块/功能键） |
|---|---|---|---|
| ToolA | 自主渗透 | 补齐：X（→ a/b.py，CM-01） |
| ToolB | K8s 攻防 | 已对齐：无补齐项 |

| ID | 一句话 | 对应维度 | 工作量 | 重叠标注 | 来源工具 |
|---|---|---|---|---|---|
| CM-01 | 做 X | D1 资产发现 | S | - | ToolA |
| CM-02 | 做 Y | D2 自主规划 | M | gen-27（XBow 派生） | ToolB |
"""


def _mutate(old: str, new: str) -> str:
    text = FIXTURE.replace(old, new)
    assert text != FIXTURE, f"fixture 注入替换失败: {old!r}"
    return text


class TestCoreLogicFixture(unittest.TestCase):
    """fixture 注入核心逻辑：合法通过 + 各类破坏必被捕获。"""

    def test_fixture_ok(self):
        result = ci.verify(FIXTURE, min_tools=2, min_dims=3)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["stats"]["tools"], 2)
        self.assertEqual(result["stats"]["dimensions"], 3)
        self.assertEqual(result["stats"]["backlog_total"], 2)
        self.assertEqual(result["stats"]["backlog_overlap_gen27"], 1)

    def test_illegal_mark_rejected(self):
        result = ci.verify(_mutate("| D1 资产发现 | ✓ | ✓ | ◐ |", "| D1 资产发现 | ✓ | ✓✗ | ◐ |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("非法判定标记" in e for e in result["errors"]), result["errors"])

    def test_missing_source_rejected(self):
        result = ci.verify(_mutate("https://example.com/a", "内部手册"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("来源字段" in e for e in result["errors"]), result["errors"])

    def test_missing_verified_date_rejected(self):
        result = ci.verify(_mutate("| ToolA | 自主渗透 | x | y | https://example.com/a | 2026-10-25 |",
                                   "| ToolA | 自主渗透 | x | y | https://example.com/a | 未核验 |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("核验日期" in e for e in result["errors"]), result["errors"])

    def test_bad_effort_rejected(self):
        result = ci.verify(_mutate("| CM-01 | 做 X | D1 资产发现 | S |", "| CM-01 | 做 X | D1 资产发现 | XL |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("工作量" in e for e in result["errors"]), result["errors"])

    def test_duplicate_backlog_id_rejected(self):
        result = ci.verify(_mutate("| CM-02 | 做 Y | D2 自主规划 | M |", "| CM-01 | 做 Y | D2 自主规划 | M |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("重复 ID" in e for e in result["errors"]), result["errors"])

    def test_unknown_backlog_dimension_rejected(self):
        result = ci.verify(_mutate("| CM-02 | 做 Y | D2 自主规划 | M |", "| CM-02 | 做 Y | D99 不存在 | M |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("未出现在矩阵维度" in e for e in result["errors"]), result["errors"])

    def test_tool_without_matrix_column_rejected(self):
        result = ci.verify(_mutate("| 维度 | InkBlade | ToolA | ToolB |\n|---|---|---|---|\n| D1 资产发现 | ✓ | ✓ | ◐ |",
                                   "| 维度 | InkBlade | ToolA |\n|---|---|---|\n| D1 资产发现 | ✓ | ✓ |"), min_tools=2, min_dims=3)
        self.assertFalse(result["ok"])
        self.assertTrue(any("无列" in e for e in result["errors"]), result["errors"])

    def test_dimension_coverage_threshold(self):
        result = ci.verify(FIXTURE, min_tools=2, min_dims=4)
        self.assertFalse(result["ok"])
        self.assertTrue(any("维度数" in e for e in result["errors"]), result["errors"])

    def test_parse_units(self):
        self.assertEqual(len(ci.parse_registry(FIXTURE)), 2)
        self.assertEqual(ci.parse_registry(FIXTURE)[0]["来源"], "https://example.com/a")
        self.assertEqual(len(ci.parse_matrix(FIXTURE)), 1)
        self.assertEqual(len(ci.parse_insights(FIXTURE)), 2)
        self.assertEqual(len(ci.parse_backlog(FIXTURE)), 2)
        # 未知格式单元（○/—/? 之外的词）不会通过 MARKS
        self.assertNotIn("部分", ci.MARKS)


class TestRealDoc(unittest.TestCase):
    """真实 docs/COMPETITIVE-MATRIX.md 断言（结构/来源/维度覆盖/启示/backlog/SOTA 挂链）。"""

    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")
        cls.result = ci.verify(cls.text)

    def test_doc_exists_and_verified_ok(self):
        self.assertTrue(DOC.is_file(), "缺少 docs/COMPETITIVE-MATRIX.md")
        self.assertTrue(self.result["ok"], self.result["errors"])

    def test_tool_count_and_registry_sources(self):
        stats = self.result["stats"]
        self.assertGreaterEqual(stats["tools"], 23)
        self.assertEqual(stats["categories"], 5, "应按 5 类分表")
        rows = ci.parse_registry(self.text)
        cats = {r["类别"] for r in rows}
        self.assertEqual(cats, {"自主渗透", "K8s 攻防", "运行时/准入", "AI/LLM 安全", "其他"}, cats)
        for r in rows:
            self.assertTrue(r["来源"].startswith("http") or ".slim/clonedeps" in r["来源"], r)
            self.assertRegex(r["核验日期"], r"\d{4}-\d{2}-\d{2}", r)

    def test_dimension_coverage(self):
        self.assertGreaterEqual(self.result["stats"]["dimensions"], 18)
        matrix = ci.parse_matrix(self.text)
        dims = matrix[0]["dimensions"]
        for m in matrix[1:]:
            self.assertEqual(set(m["dimensions"]), set(dims), "每张分类表都应覆盖全部 18 维")
        keys = [d.split()[0] for d in dims]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(k.startswith("D") for k in keys))

    def test_every_tool_has_insight_row(self):
        self.assertEqual(self.result["stats"]["insights"], self.result["stats"]["tools"])
        reg = {r["工具"] for r in ci.parse_registry(self.text)}
        ins = {r["工具"] for r in ci.parse_insights(self.text)}
        self.assertEqual(reg, ins, "启示表必须每工具一行，与登记表一致")

    def test_backlog_shape_and_effort_counts(self):
        backlog = ci.parse_backlog(self.text)
        self.assertGreaterEqual(len(backlog), 30)
        efforts = {"S": 0, "M": 0, "L": 0}
        for b in backlog:
            self.assertIn(b["工作量"], efforts, b)
            self.assertRegex(b["ID"], r"^CM-\d{2,}$", b)
            self.assertTrue(b["一句话"].strip(), b)
            self.assertTrue(b["对应维度"].split()[0].startswith("D"), b)
            efforts[b["工作量"]] += 1
        self.assertGreater(efforts["S"], 0)
        self.assertGreater(efforts["M"], 0)
        self.assertGreater(efforts["L"], 0)

    def test_gen27_overlap_marked(self):
        overlap = [b for b in ci.parse_backlog(self.text) if "gen-27" in b["重叠标注"]]
        self.assertGreaterEqual(len(overlap), 3, "gen-27（XBow 对标）重叠项必须显式标注")
        for b in overlap:
            self.assertTrue(b["重叠标注"].strip(), b)

    def test_marks_documented_and_used(self):
        for mark in ci.MARKS:
            self.assertIn(mark, self.text, f"标记 {mark} 未在文档中出现")
        self.assertIn("官方文档可证", self.text, "口径声明（官方文档为准，不臆断）应存在")

    def test_honest_unknowns_not_invented(self):
        # 商业产品 K8s/ML 未声明面必须保守标 ?（抽样断言：XBow 列存在 ?）
        matrix = ci.parse_matrix(self.text)
        cols = matrix[0]["columns"]
        self.assertIn("XBow", cols)
        xbow = [m["cells"][d]["XBow"] for m in [matrix[0]] for d in m["dimensions"]]
        self.assertIn("?", xbow, "XBow 官网未声明处应标 ?，不得臆断")

    def test_sota_links_matrix_and_backlog(self):
        sota = SOTA.read_text(encoding="utf-8")
        self.assertIn("COMPETITIVE-MATRIX.md", sota, "SOTA 文档应链接竞品矩阵")
        self.assertIn("竞品对比", sota)
        # 矩阵文档回链 SOTA（InkBlade 列锚点）
        self.assertIn("SOTA-2026-10.md", self.text)


@unittest.skipUnless(CLONEDEPS.is_file(), "独立发布模式：仓外 clonedeps.json 不存在时跳过")
class TestClonedepsRegistration(unittest.TestCase):
    """工作区模式：新增克隆登记 clonedeps.json（≤6 个新克隆约束 + 来源登记）。"""

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(CLONEDEPS.read_text(encoding="utf-8"))

    def test_new_clones_registered(self):
        names = {r["name"] for r in self.data["repos"]}
        expected_new = {
            "DataDog__KubeHound", "NVIDIA__garak", "microsoft__PyRIT",
            "promptfoo__promptfoo", "aquasecurity__kube-hunter", "ethz-spylab__agentdojo",
        }
        self.assertTrue(expected_new.issubset(names), f"新增克隆缺登记: {expected_new - names}")

    def test_new_clone_budget_respected(self):
        new = [r for r in self.data["repos"] if "competitive-matrix" in r.get("registered_by", "")]
        self.assertLessEqual(len(new), 6, "任务约束：新增克隆 ≤6")

    def test_registry_covers_all_cloned_sources_in_doc(self):
        names = {r["name"] for r in self.data["repos"]}
        for row in ci.parse_registry(DOC.read_text(encoding="utf-8")):
            src = row["来源"]
            if ".slim/clonedeps" in src:
                self.assertIn(Path(src).name, names, f"文档引用的本地克隆未登记: {src}")


if __name__ == "__main__":
    unittest.main()
