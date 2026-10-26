# -*- coding: utf-8 -*-
"""arch-intel 万卡语料重收门槛校验测试（2026-10-25 推倒重收批次）。

硬门槛（任务口径）：
- corpus 重组为 official-cn / official-en / paper 三类目录
- official-cn ≥ 12、official-en ≥ 12（verified 源计数）
- 万卡证据源（wanka_evidence=true 且 verified）≥ 20
- 网络要素 8 项全覆盖：rail / multi-plane / in-network-computing /
  congestion-control / optical-switching / multi-tenancy / isolation /
  ops-fault-surface
- 本轮新增源 ≥ 30 且新增中 official（official-cn|official-en）占比 ≥ 70%

先于 check.py 改写（TDD）：fixture 注入校验门槛函数语义，不依赖真实语料。
"""

import importlib.util
import json
import unittest
from pathlib import Path

ARCH_INTEL = Path(__file__).resolve().parent.parent / "inkblade" / "arch-intel"

# arch-intel 目录名含连字符，按路径加载模块
_spec = importlib.util.spec_from_file_location(
    "inkblade_arch_intel_check", ARCH_INTEL / "check.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CLASSES = _mod.CLASSES
NETWORK_ELEMENTS = _mod.NETWORK_ELEMENTS
REQUIRED = _mod.REQUIRED
verify = _mod.verify


def make_source(sid, cls="official-en", org="org", status="verified",
                wanka=False, elements=(), added=False):
    return {
        "id": sid,
        "file": f"inkblade/arch-intel/corpus/{cls}/{sid}.md",
        "class": cls,
        "organization": org,
        "system": sid,
        "urls": ["https://example.invalid/" + sid],
        "verification": {"date": "2026-10-25", "status": status, "method": "websearch"},
        "wanka_evidence": wanka,
        "wanka_quote": "≥10,000 GPUs（fixture 证据）" if wanka else "",
        "network_elements": list(elements),
        "added_this_round": added,
    }


def make_matrix(cn=12, en=12, wanka=20, elements=None, extra_new=0,
                new_official_share=1.0, new_official_cls="official-en",
                extra=None):
    """构造恰在门槛之上的最小矩阵 fixture。"""
    elements = elements if elements is not None else list(NETWORK_ELEMENTS)
    sources = []
    # 已有源承担 element 覆盖与 wanka 计数
    per_element = {e: 0 for e in elements}
    for i in range(wanka):
        e = elements[i % len(elements)]
        per_element[e] += 1
        sources.append(make_source(f"old-w{i}", cls="paper", wanka=True,
                                   elements=[e]))
    for e, n in per_element.items():
        for j in range(n, 2):
            sources.append(make_source(f"old-e-{e}-{j}", cls="paper",
                                       elements=[e]))
    # 类门槛
    for i in range(cn):
        sources.append(make_source(f"old-cn{i}", cls="official-cn"))
    for i in range(en):
        sources.append(make_source(f"old-en{i}", cls="official-en"))
    # 本轮新增：wanka 个 official 新增 + 补足非 official 新增
    new_total = REQUIRED["new-this-round"] + extra_new
    new_official = int(new_total * new_official_share)
    for i in range(new_official):
        sources.append(make_source(f"new-a{i}", cls=new_official_cls, added=True))
    for i in range(new_total - new_official):
        sources.append(make_source(f"new-p{i}", cls="paper", added=True))
    if extra:
        sources.extend(extra)
    return {"schema": "test-fixture", "sources": sources}


class TestThresholdsFixture(unittest.TestCase):
    """门槛函数语义：fixture 注入，覆盖达标/不达标边界。"""

    def test_minimum_matrix_all_ok(self):
        r = verify(make_matrix())
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["classes"]["official-cn"]["ok"])
        self.assertTrue(r["classes"]["official-en"]["ok"])
        self.assertTrue(r["wanka-evidence"]["ok"])
        self.assertTrue(r["network-elements"]["ok"])
        self.assertTrue(r["new-this-round"]["ok"])

    def test_official_cn_below_threshold(self):
        r = verify(make_matrix(cn=11))
        self.assertFalse(r["classes"]["official-cn"]["ok"])
        self.assertEqual(r["classes"]["official-cn"]["required"], 12)
        self.assertFalse(r["ok"])

    def test_official_en_below_threshold(self):
        # 新增 official 源全部落 official-cn，避免垫高 en 计数
        r = verify(make_matrix(en=11, new_official_cls="official-cn"))
        self.assertFalse(r["classes"]["official-en"]["ok"])
        self.assertFalse(r["ok"])

    def test_wanka_below_threshold(self):
        r = verify(make_matrix(wanka=19))
        self.assertFalse(r["wanka-evidence"]["ok"])
        self.assertEqual(r["wanka-evidence"]["required"], 20)
        self.assertFalse(r["ok"])

    def test_unverified_wanka_not_counted(self):
        extra = [make_source("fake-wanka", cls="paper", status="verified-partial",
                             wanka=True)]
        r = verify(make_matrix(wanka=19, extra=extra))
        self.assertEqual(r["wanka-evidence"]["count"], 19)
        self.assertFalse(r["wanka-evidence"]["ok"])

    def test_missing_element_fails(self):
        elements = [e for e in NETWORK_ELEMENTS if e != "optical-switching"]
        r = verify(make_matrix(elements=elements))
        self.assertFalse(r["network-elements"]["ok"])
        self.assertFalse(
            r["network-elements"]["elements"]["optical-switching"]["ok"]
        )

    def test_new_count_below_threshold(self):
        # 显式构造：仅 29 个新增（其余门槛全达标）
        sources = [
            make_source(f"old-cn{i}", cls="official-cn") for i in range(12)
        ] + [
            make_source(f"old-en{i}", cls="official-en") for i in range(12)
        ] + [
            make_source(f"old-w{i}", cls="paper", wanka=True,
                        elements=[NETWORK_ELEMENTS[i % len(NETWORK_ELEMENTS)]])
            for i in range(20)
        ]
        for e in NETWORK_ELEMENTS:
            sources.append(make_source(f"old-e-{e}", cls="paper", elements=[e]))
        sources += [make_source(f"n{i}", cls="official-en", added=True)
                    for i in range(REQUIRED["new-this-round"] - 1)]
        r = verify({"schema": "x", "sources": sources})
        self.assertFalse(r["new-this-round"]["count"]["ok"])
        self.assertFalse(r["new-this-round"]["ok"])
        self.assertFalse(r["ok"])

    def test_new_official_ratio_below_threshold_fails(self):
        # 30 新增中仅 20 official（66.7% < 70%）
        sources = [
            make_source(f"old-cn{i}", cls="official-cn") for i in range(12)
        ] + [
            make_source(f"old-en{i}", cls="official-en") for i in range(12)
        ] + [
            make_source(f"old-w{i}", cls="paper", wanka=True,
                        elements=[NETWORK_ELEMENTS[i % len(NETWORK_ELEMENTS)]])
            for i in range(20)
        ]
        for e in NETWORK_ELEMENTS:  # element 全覆盖兜底
            sources.append(make_source(f"old-e-{e}", cls="paper", elements=[e]))
        sources += [make_source("new-o", cls="official-en", added=True) for _ in range(20)]
        sources += [make_source("new-p", cls="paper", added=True) for _ in range(10)]
        r = verify({"schema": "x", "sources": sources})
        self.assertTrue(r["new-this-round"]["count"]["ok"])
        self.assertFalse(r["new-this-round"]["ratio"]["ok"])
        self.assertFalse(r["ok"])

    def test_empty_matrix_all_fail(self):
        r = verify({"schema": "x", "sources": []})
        self.assertFalse(r["ok"])
        self.assertFalse(r["classes"]["ok"])
        self.assertFalse(r["wanka-evidence"]["ok"])
        self.assertFalse(r["network-elements"]["ok"])
        self.assertFalse(r["new-this-round"]["ok"])

    def test_unknown_class_rejected(self):
        extra = [make_source("weird", cls="official-xx")]
        r = verify(make_matrix(extra=extra))
        self.assertEqual(r["classes"]["counts"].get("official-xx", 0), 0)
        # 非法分类不进任何门槛，也不应让 verify 抛异常
        self.assertIsInstance(r, dict)


class TestRealMatrix(unittest.TestCase):
    """真实语料矩阵：达标且与 corpus 三目录文件一一对应。"""

    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(
            (ARCH_INTEL / "coverage-matrix.json").read_text(encoding="utf-8")
        )
        cls.result = verify(cls.matrix)

    def test_all_gates_pass(self):
        self.assertTrue(self.result["ok"], f"门槛未达标：{self.result}")

    def test_gates_meet_hard_thresholds(self):
        self.assertGreaterEqual(
            self.result["classes"]["official-cn"]["count"], 12)
        self.assertGreaterEqual(
            self.result["classes"]["official-en"]["count"], 12)
        self.assertGreaterEqual(self.result["wanka-evidence"]["count"], 20)
        self.assertGreaterEqual(self.result["new-this-round"]["count"]["count"], 30)
        ratio = self.result["new-this-round"]["ratio"]
        self.assertGreaterEqual(ratio["ratio"], 0.70)
        for elem, r in self.result["network-elements"]["elements"].items():
            self.assertTrue(r["ok"], f"网络要素缺口：{elem}")

    def test_every_source_has_corpus_file_in_class_dir(self):
        root = Path(__file__).resolve().parent.parent
        for s in self.matrix["sources"]:
            p = root / s["file"]
            self.assertTrue(p.exists(), f"corpus 文件缺失：{s['file']}")
            self.assertEqual(p.read_text(encoding="utf-8")[:2], "# ",
                             f"corpus 首行应为标题：{p.name}")
            self.assertIn(f"corpus/{s['class']}/", s["file"].replace("\\", "/"),
                          f"file 路径未落在声明的 class 目录：{s['id']}")

    def test_every_corpus_file_listed(self):
        for cls in CLASSES:
            listed = {s["id"] for s in self.matrix["sources"]
                      if s["class"] == cls}
            d = ARCH_INTEL / "corpus" / cls
            self.assertTrue(d.is_dir(), f"缺少分类目录：{cls}")
            for f in d.glob("*.md"):
                self.assertIn(f.stem, listed,
                              f"corpus 文件未入矩阵：{cls}/{f.name}")

    def test_no_stray_files_in_corpus_root(self):
        strays = list((ARCH_INTEL / "corpus").glob("*.md"))
        self.assertEqual(strays, [], "corpus 根目录不应残留扁平 md 文件")

    def test_every_corpus_file_annotated(self):
        for s in self.matrix["sources"]:
            text = (Path(__file__).resolve().parent.parent
                    / s["file"]).read_text(encoding="utf-8")
            self.assertIn("万卡证据", text, f"缺万卡证据标注：{s['id']}")
            self.assertIn("网络要素", text, f"缺网络要素标注：{s['id']}")

    def test_wanka_sources_carry_quote(self):
        for s in self.matrix["sources"]:
            if s.get("wanka_evidence"):
                self.assertTrue(
                    s.get("wanka_quote", "").strip(),
                    f"wanka_evidence=true 但缺原文摘录：{s['id']}")

    def test_unreachable_sources_flagged(self):
        for s in self.matrix["sources"]:
            status = s["verification"]["status"]
            if status != "verified":
                note = (s["verification"].get("summary", "")
                        + s["verification"].get("method", ""))
                self.assertTrue(
                    any(k in note for k in ("不可达", "拒连", "403", "404",
                                            "超时", "快照", "JS")),
                    f"非 verified 源必须显式标注不可达/快照原因：{s['id']}")


if __name__ == "__main__":
    unittest.main()
