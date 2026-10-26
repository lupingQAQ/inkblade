"""tests/test_llm_probes.py — LLM 探针库（trident/probes）测试（TDD 先行）。

覆盖：
- 库契约：≥80 探针 / ≥13 类 / 纯小写键与文件名一一对应 / 判定器与请求模板结构合法；
- 分类学：每类映射 OWASP LLM Top 10 2026（LLM01–LLM10）与 ASI01–ASI10，id 合法且一致；
- 规则联动：每探针类 ≥1 检测规则键，且全部存在于 sigma 规则目录并可被规则引擎生成；
- 运行器差分：对 lab/ai_gateway_sim、lab/mock_targets、lab/longctx_sim 两态真实 HTTP 差分
  ——攻击探针 vulnerable 命中且 fixed 不命中（confirmed），对照探针两态均不命中（不误报）；
- 逐类 ≥1 命中断言 + 逐类 ≥1 不误报断言；
- 矩阵产物：JSON/MD 结构、类别行、规则键、判定分布；
- 报告集成：渗透测试报告渲染「LLM 探针矩阵」节（有产物=矩阵表，无产物=显式占位不臆造）；
- 对比文档：docs/PROBE-PARITY.md 引用 garak/PyRIT/promptfoo 计数并标注独有/未覆盖项。
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.probes import (
    CATEGORIES,
    DETECTOR_KINDS,
    FACES,
    SEVERITIES,
    DetectorError,
    evaluate_detector,
    load_probes,
)
from trident.probes.run import run_matrix
from trident.reports.render import render_pentest

REPO = Path(__file__).resolve().parents[1]
PARITY_DOC = REPO / "docs" / "PROBE-PARITY.md"

# 对照（不误报）类探针：期望 vulnerable=miss 且 fixed=miss
EXPECT_CONTROL_MISS = ("jailbreak-benign-baseline", "pi-benign-later-question",
                       "sp-benign-capability-question", "td-benign-paraphrase-question",
                       "ua-benign-security-hardening-question", "mm-benign-image-caption",
                       "gb-benign-first-message", "di-benign-downstream-summary",
                       "ta-benign-tool-echo", "pii-benign-greeting",
                       "lc-benign-within-window", "cp-benign-unknown-lookup",
                       "ga-benign-health-secret-scan")


class TestLibraryContract(unittest.TestCase):
    """探针库静态契约（无需靶场）。"""

    @classmethod
    def setUpClass(cls):
        cls.probes = load_probes()

    def test_size_at_least_80(self):
        self.assertGreaterEqual(len(self.probes), 80, f"探针数 {len(self.probes)} < 80")

    def test_keys_pure_lowercase_and_match_files(self):
        library = REPO / "trident" / "probes" / "library"
        files = sorted(p.name for p in library.rglob("*.json"))
        self.assertEqual(len(files), len(self.probes), "库文件数与探针数不一致")
        for key, probe in self.probes.items():
            with self.subTest(key=key):
                self.assertRegex(key, r"^[a-z0-9]+(-[a-z0-9]+)*$",
                                 "键必须为纯小写-连字符")
                self.assertEqual(probe["key"], key)
                rel = probe["_source"]
                self.assertTrue(rel.is_file(), f"源文件缺失 {rel}")
                self.assertEqual(rel.stem, key, "文件名必须等于探针键")

    def test_unique_keys(self):
        self.assertEqual(len(set(self.probes)), len(self.probes))

    def test_categories_at_least_13(self):
        self.assertGreaterEqual(len(CATEGORIES), 13)
        by_cat: dict[str, list[str]] = {}
        for probe in self.probes.values():
            by_cat.setdefault(probe["category"], []).append(probe["key"])
        for cat, spec in CATEGORIES.items():
            with self.subTest(category=cat):
                self.assertGreaterEqual(len(by_cat.get(cat, [])), 4,
                                        f"类别 {cat} 探针数 {len(by_cat.get(cat, []))} < 4")
                self.assertTrue(spec["owasp"], f"{cat} 缺 OWASP 映射")
        for probe in self.probes.values():
            self.assertIn(probe["category"], CATEGORIES)

    def test_taxonomy_ids_valid(self):
        valid_owasp = {f"LLM{i:02d}" for i in range(1, 11)}
        valid_asi = {f"ASI{i:02d}" for i in range(1, 11)}
        for cat, spec in CATEGORIES.items():
            with self.subTest(category=cat):
                self.assertTrue(spec["owasp"], f"{cat} 缺 OWASP LLM 2026 映射")
                self.assertTrue(spec["asi"], f"{cat} 缺 ASI 映射")
                self.assertTrue(set(spec["owasp"]) <= valid_owasp, f"{cat} OWASP id 非法")
                self.assertTrue(set(spec["asi"]) <= valid_asi, f"{cat} ASI id 非法")

    def test_taxonomy_covers_all_2026_ids(self):
        """OWASP LLM 2026 全 10 条 + ASI01–10 均有类别映射，且编号语义与 2026 版一致。"""
        owasp = set().union(*(set(spec["owasp"]) for spec in CATEGORIES.values()))
        asi = set().union(*(set(spec["asi"]) for spec in CATEGORIES.values()))
        self.assertEqual(owasp, {f"LLM{i:02d}" for i in range(1, 11)},
                         f"OWASP LLM 2026 未全覆盖，缺 {sorted({f'LLM{i:02d}' for i in range(1, 11)} - owasp)}")
        self.assertEqual(asi, {f"ASI{i:02d}" for i in range(1, 11)},
                         f"ASI01–10 未全覆盖，缺 {sorted({f'ASI{i:02d}' for i in range(1, 11)} - asi)}")
        # 2026 重排锚点：LLM03=过度代理 / LLM04=供应链 / LLM05=数据与模型投毒 /
        # LLM06=无界消耗 / LLM08=隐藏上下文暴露 / LLM10=不当输出处理
        anchors = {
            "tool-abuse": ({"LLM03"}, {"ASI04", "ASI10"}),
            "gateway-abuse": ({"LLM04"}, set()),
            "cache-poison": ({"LLM05", "LLM09"}, set()),
            "longctx-attack": ({"LLM06"}, set()),
            "sysprompt-leak": ({"LLM08"}, set()),
            "downstream-injection": ({"LLM10"}, set()),
        }
        for cat, (want_owasp, want_asi) in anchors.items():
            with self.subTest(category=cat):
                self.assertTrue(want_owasp <= set(CATEGORIES[cat]["owasp"]),
                                f"{cat} 缺 OWASP 2026 锚点 {sorted(want_owasp)}")
                self.assertTrue(want_asi <= set(CATEGORIES[cat]["asi"]),
                                f"{cat} 缺 ASI 锚点 {sorted(want_asi)}")

    def test_probe_schema(self):
        for key, probe in self.probes.items():
            with self.subTest(key=key):
                self.assertIn(probe["severity"], SEVERITIES)
                self.assertIn(probe["face"], FACES)
                self.assertTrue(probe["title"].get("zh") and probe["title"].get("en"))
                self.assertIsInstance(probe["preconditions"], list)
                self.assertGreaterEqual(len(probe["preconditions"]), 1)
                req = probe["request"]
                self.assertIsInstance(req, list)
                self.assertGreaterEqual(len(req), 1)
                for step in req:
                    self.assertIn(step["method"], ("GET", "POST", "PUT"))
                    self.assertTrue(str(step["path"]).startswith("/"))
                    self.assertIn(step.get("auth", "none"),
                                  ("none", "tenant", "admin", "victim-tenant", "vllm"))
                det = probe["detector"]
                self.assertIn(det["kind"], DETECTOR_KINDS)
                self.assertIn(probe["expect"]["vulnerable"], ("hit", "miss"))
                self.assertIn(probe["expect"]["fixed"], ("hit", "miss"))
                self.assertTrue(probe["rule_key"])

    def test_required_categories_present(self):
        required = {
            "jailbreak", "prompt-injection", "sysprompt-leak", "traindata-extraction",
            "pii-leak", "unsafe-advice", "tool-abuse", "multimodal-injection",
            "longctx-attack", "cache-poison", "downstream-injection",
        }
        self.assertTrue(required <= set(CATEGORIES), f"缺类别: {required - set(CATEGORIES)}")


class TestRuleLinkage(unittest.TestCase):
    """每探针类 ≥1 检测规则 + 规则可被规则引擎产出。"""

    @classmethod
    def setUpClass(cls):
        cls.probes = load_probes()

    def test_every_category_has_rule(self):
        by_cat: dict[str, set[str]] = {}
        for probe in self.probes.values():
            by_cat.setdefault(probe["category"], set()).add(probe["rule_key"])
        for cat, rules in by_cat.items():
            with self.subTest(category=cat):
                self.assertGreaterEqual(len(rules), 1, f"{cat} 无检测规则键")

    def test_rule_keys_exist_in_sigma_catalog(self):
        from trident.rules.generate import load_catalog

        catalog = load_catalog()
        sigma_ids = {spec["id"] for spec in catalog["sigma"]}
        for probe in self.probes.values():
            with self.subTest(key=probe["key"]):
                self.assertIn(probe["rule_key"], sigma_ids,
                              f"{probe['key']} 的规则键 {probe['rule_key']} 不在 sigma 目录")

    def test_rules_generated_into_pack(self):
        import shutil

        from trident.core.chains import load_chains
        from trident.rules import generate_all

        # 受控链子集（并行任务可能向链目录投放无规则覆盖的在途新链，全局生成对其红——与本库无关）
        with TemporaryDirectory() as tmp:
            chains_tmp = Path(tmp) / "chains"
            chains_tmp.mkdir()
            source = REPO / "trident" / "chains"
            wanted = [cid for cid in ("long-context-cache-leak", "ai-gateway-key-exfil")
                      if (source / f"{cid}.json").is_file()]
            self.assertGreaterEqual(len(wanted), 1)
            for cid in wanted:
                shutil.copy(source / f"{cid}.json", chains_tmp / f"{cid}.json")
            self.assertTrue(load_chains(chains_tmp))
            pack = generate_all(chains_tmp, findings=[], cni="native",
                                out_dir=str(Path(tmp) / "pack"))
            ids = {rule["id"] for rule in pack.rules}
            files = {Path(rel).name for rel in pack.files}
            for cat in CATEGORIES:
                with self.subTest(category=cat):
                    self.assertIn(f"sigma-llm-probe-{cat}", ids,
                                  f"类别 {cat} 的 sigma 规则未生成")
                    self.assertIn(f"sigma-llm-probe-{cat}.yaml", files,
                                  f"类别 {cat} 的规则 YAML 未落盘")


class TestDetectorEngine(unittest.TestCase):
    """判定器引擎纯函数行为。"""

    def _entry(self, status=200, payload=None):
        text = json.dumps(payload, ensure_ascii=False) if payload is not None else ""
        return {"status": status, "payload": payload, "text": text}

    def test_regex(self):
        det = {"kind": "regex", "patterns": ["CANARY"]}
        self.assertTrue(evaluate_detector(det, [self._entry(payload={"content": "x CANARY y"})]))
        self.assertFalse(evaluate_detector(det, [self._entry(payload={"content": "clean"})]))

    def test_keywords(self):
        det = {"kind": "keywords", "any_of": ["tenant-b confidential", "policy check skipped"]}
        self.assertTrue(evaluate_detector(det, [self._entry(payload={"entry": {"response": "tenant-b confidential: 42.7M"}})]))
        self.assertFalse(evaluate_detector(det, [self._entry(payload={"entry": None})]))

    def test_length(self):
        det = {"kind": "length", "min": 100}
        self.assertTrue(evaluate_detector(det, [self._entry(payload={"x": "a" * 200})]))
        self.assertFalse(evaluate_detector(det, [self._entry(payload={"x": "ab"})]))

    def test_refusal_and_not_refusal(self):
        refusal = {"kind": "refusal"}
        self.assertTrue(evaluate_detector(refusal, [self._entry(payload={"content": "I cannot assist with that"})]))
        self.assertFalse(evaluate_detector(refusal, [self._entry(payload={"content": "here you go"})]))
        not_refusal = {"kind": "not_refusal"}
        self.assertTrue(evaluate_detector(not_refusal, [self._entry(payload={"content": "here you go"})]))
        self.assertFalse(evaluate_detector(not_refusal, [self._entry(status=400, payload={"error": "guardrail_blocked"})]))
        self.assertFalse(evaluate_detector(not_refusal, [self._entry(payload={"content": "I cannot assist with that"})]))

    def test_status(self):
        det = {"kind": "status", "equals": 200}
        self.assertTrue(evaluate_detector(det, [self._entry(status=200)]))
        self.assertFalse(evaluate_detector(det, [self._entry(status=401)]))

    def test_json_path(self):
        det = {"kind": "json_path", "path": "guardrail.bypass_suspected", "equals": True}
        self.assertTrue(evaluate_detector(det, [self._entry(payload={"guardrail": {"bypass_suspected": True}})]))
        self.assertFalse(evaluate_detector(det, [self._entry(payload={"guardrail": {"bypass_suspected": False}})]))
        gt = {"kind": "json_path", "path": "usage.cached_tokens", "op": "gt", "value": 0}
        self.assertTrue(evaluate_detector(gt, [self._entry(payload={"usage": {"cached_tokens": 4096}})]))
        self.assertFalse(evaluate_detector(gt, [self._entry(payload={"usage": {"cached_tokens": 0}})]))

    def test_target_any_over_sequence(self):
        det = {"kind": "regex", "patterns": ["MARKER"], "target": "any"}
        entries = [self._entry(payload={"a": 1}), self._entry(payload={"b": "MARKER"})]
        self.assertTrue(evaluate_detector(det, entries))
        det_last = {"kind": "regex", "patterns": ["MARKER"]}
        entries_rev = [self._entry(payload={"b": "MARKER"}), self._entry(payload={"a": 1})]
        self.assertFalse(evaluate_detector(det_last, entries_rev), "默认只看最后一步")

    def test_unknown_kind_raises(self):
        with self.assertRaises(DetectorError):
            evaluate_detector({"kind": "nonexistent"}, [self._entry()])


class _MatrixBase(unittest.TestCase):
    """两态差分运行器测试基类（一次拉起全部 face，供子类共享）。"""

    @classmethod
    def setUpClass(cls):
        cls.matrix = run_matrix()

    def category_keys(self, cat: str) -> list[str]:
        return [k for k, p in self.matrix["probes"].items() if p["category"] == cat]


class TestRunnerDifferential(_MatrixBase):
    """运行器对 lab 两态靶场的真实 HTTP 差分。"""

    def test_all_attack_probes_confirmed(self):
        attacks = {k: p for k, p in self.matrix["probes"].items()
                   if p["expect"]["vulnerable"] == "hit"}
        self.assertGreaterEqual(len(attacks), 60)
        bad = {k: p["verdict"] for k, p in attacks.items() if p["verdict"] != "confirmed"}
        self.assertEqual(bad, {}, f"攻击探针未全部 confirmed: {bad}")

    def test_controls_never_fire(self):
        probes = self.matrix["probes"]
        for key in EXPECT_CONTROL_MISS:
            with self.subTest(key=key):
                self.assertIn(key, probes, "对照探针缺失")
                p = probes[key]
                self.assertFalse(p["vulnerable"]["hit"], "对照探针在 vulnerable 误报")
                self.assertFalse(p["fixed"]["hit"], "对照探针在 fixed 误报")

    def test_every_category_confirmed_hit(self):
        for cat in CATEGORIES:
            with self.subTest(category=cat):
                keys = self.category_keys(cat)
                hits = [k for k in keys if self.matrix["probes"][k]["vulnerable"]["hit"]]
                self.assertGreaterEqual(len(hits), 1, f"{cat} 无任何 vulnerable 命中")
                confirmed = [k for k in keys
                             if self.matrix["probes"][k]["verdict"] == "confirmed"]
                self.assertGreaterEqual(len(confirmed), 1, f"{cat} 无 confirmed 探针")

    def test_every_category_control_no_false_positive(self):
        for cat in CATEGORIES:
            with self.subTest(category=cat):
                keys = self.category_keys(cat)
                clean = [k for k in keys
                         if self.matrix["probes"][k]["expect"]["vulnerable"] == "miss"
                         and not self.matrix["probes"][k]["vulnerable"]["hit"]
                         and not self.matrix["probes"][k]["fixed"]["hit"]]
                self.assertGreaterEqual(
                    len(clean), 1,
                    f"{cat} 无「两态均不命中」的对照/防误报证据（clean={clean}）")

    def test_verdict_distribution(self):
        dist = self.matrix["summary"]["verdicts"]
        self.assertGreaterEqual(dist.get("confirmed", 0), 60)
        self.assertEqual(dist.get("unexpected", 0), 0, "出现 fixed 命中而 vulnerable 未命中的反向差分")

    def test_faces_covered(self):
        faces = {p["face"] for p in self.matrix["probes"].values()}
        self.assertTrue({"gateway", "longctx", "relay"} <= faces)

    def test_response_evidence_recorded(self):
        for key, p in self.matrix["probes"].items():
            with self.subTest(key=key):
                self.assertIn("statuses", p["vulnerable"])
                self.assertIn("statuses", p["fixed"])
                self.assertTrue(p["vulnerable"]["statuses"], "缺 vulnerable 状态码证据")


class TestMatrixArtifacts(_MatrixBase):
    """矩阵 JSON/MD 产物与报告节。"""

    def test_summary_counts(self):
        s = self.matrix["summary"]
        self.assertEqual(s["total"], len(self.matrix["probes"]))
        self.assertEqual(s["categories"], len(CATEGORIES))
        self.assertGreaterEqual(s["rules_linked"], 13)

    def test_matrix_markdown(self):
        from trident.probes.matrix import render_matrix_doc, render_matrix_section

        doc = render_matrix_doc(self.matrix, "bi")
        self.assertIn("LLM 探针矩阵", doc)
        md = render_matrix_section(self.matrix, "bi")
        for cat in CATEGORIES:
            self.assertIn(cat, md)
        self.assertIn("sigma-llm-probe-jailbreak", md)
        self.assertIn("confirmed", md)
        self.assertIn("garak", md.lower(), "矩阵节应引用对比口径来源")

    def test_matrix_markdown_table_columns_aligned(self):
        from trident.probes.matrix import render_matrix_section

        md = render_matrix_section(self.matrix, "bi")
        rows = [ln for ln in md.splitlines() if ln.startswith("|")]
        self.assertGreaterEqual(len(rows), 15)
        widths = {ln.count("|") for ln in rows}
        self.assertEqual(len(widths), 1, f"表格列数不一致（竖线数 {sorted(widths)}）")

    def test_report_section_with_artifact(self):
        from trident.probes.matrix import MATRIX_FILENAME

        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="local-lab")
            run = store.create_run("run-probes")
            run.add_step("probe-sweep", "trident probes run", {},
                         "LLM 探针矩阵两态差分", artifacts=[])
            (Path(run.dir) / MATRIX_FILENAME).write_text(
                json.dumps(self.matrix, ensure_ascii=False), encoding="utf-8")
            run.finalize_run()
            text = render_pentest(store, "run-probes", lang="zh")
            self.assertIn("LLM 探针矩阵", text)
            self.assertIn("jailbreak", text)

    def test_report_section_placeholder_without_artifact(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="local-lab")
            run = store.create_run("run-noprobe")
            run.add_step("recon", "kubectl get pods", {}, "无探针产物", artifacts=[])
            run.finalize_run()
            text = render_pentest(store, "run-noprobe", lang="zh")
            self.assertIn("LLM 探针矩阵", text)
            self.assertIn("未执行", text, "无产物时必须显式声明，不得臆造")


class TestParityDoc(unittest.TestCase):
    """docs/PROBE-PARITY.md 对比口径。"""

    def test_doc_exists_and_cites_counts(self):
        text = PARITY_DOC.read_text(encoding="utf-8")
        self.assertIn("garak", text.lower())
        self.assertIn("PyRIT", text)
        self.assertIn("promptfoo", text)
        self.assertIn("87", text, "应标注本库探针总数")
        self.assertIn("13", text, "应标注本库类别数")

    def test_doc_marks_unique_and_gaps(self):
        text = PARITY_DOC.read_text(encoding="utf-8")
        self.assertIn("独有", text)
        self.assertIn("未覆盖", text)
        for kw in ("长上下文", "KV", "缓存", "网关"):
            self.assertIn(kw, text, f"独有面声明缺 {kw}")
        # 官方文档引用（URL 或明确计数口径）
        self.assertRegex(text, r"https?://", "应引用官方文档/仓库来源")

    def test_doc_declares_verification_date(self):
        text = PARITY_DOC.read_text(encoding="utf-8")
        self.assertIn("2026-10", text)


if __name__ == "__main__":
    unittest.main()
