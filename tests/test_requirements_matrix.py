# -*- coding: utf-8 -*-
"""Requirements matrix contract: source, status, numbers, and open gaps.

The matrix (`docs/REQUIREMENTS-MATRIX.md`) is the single source of truth for
*what was asked*. These tests keep it honest in three ways:

1. every requirement row has a source anchor, a legal status, evidence and an
   owner line, and the published status counts equal the rows;
2. the numbers in §1 are recomputed from the registries / directories / git and
   must match, so a stale document cannot silently disagree with the data;
3. the README / SOTA / MASTER summaries are checked against the same numbers, so
   the old wording (275 modules, 93 static-only, 47/47 effects, 35 corpus
   sources, 42 version rows) cannot come back.
"""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MATRIX = REPO / "docs" / "REQUIREMENTS-MATRIX.md"
SOTA = REPO / "docs" / "SOTA-2026-10.md"
MASTER = REPO / "docs" / "MASTER-REPORT.md"
README = REPO / "README.md"
README_CN = REPO / "README.zh-CN.md"

STATUSES = {"done", "partial", "not-done", "blocked-resource"}
OWNERS = {"probe", "migration", "agent", "defense", "docs", "enterprise"}
GROUPS = {"INIT", "ADD", "CMP"}

ROW_RE = re.compile(r"^\| (INIT|ADD|CMP)-(\d{2}) \|")


def _rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 7:
            raise AssertionError(f"{m.group(0)}: expected 7 columns, got {len(cells)}: {line[:120]}")
        rows.append({
            "id": f"{m.group(1)}-{m.group(2)}",
            "group": m.group(1),
            "requirement": cells[1],
            "source": cells[2],
            "status": cells[3],
            "evidence": cells[4],
            "gap": cells[5],
            "owner": cells[6],
        })
    return rows


def _section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _module_keys() -> list[str]:
    return sorted(p.parent.name for p in (REPO / "inkblade" / "modules").glob("*/module.json"))


def _git_ls(pattern: str) -> list[str]:
    try:
        out = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD", "--", pattern],
                             cwd=REPO, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git missing
        return []
    if out.returncode != 0:
        return []
    return [l for l in out.stdout.splitlines() if l.strip()]


class MatrixShapeTest(unittest.TestCase):
    def test_matrix_exists_and_has_enough_requirements(self):
        self.assertTrue(MATRIX.is_file())
        rows = _rows()
        self.assertGreaterEqual(len(rows), 80, "需求条目必须 >= 80")
        self.assertEqual({r["group"] for r in rows}, GROUPS)

    def test_ids_unique_and_sequential(self):
        rows = _rows()
        ids = [r["id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)), "重复 ID")
        for group in GROUPS:
            nums = sorted(int(r["id"][-2:]) for r in rows if r["group"] == group)
            self.assertEqual(nums, list(range(1, len(nums) + 1)), f"{group} 编号不连续")

    def test_every_row_has_source_status_evidence_gap_owner(self):
        for row in _rows():
            with self.subTest(row=row["id"]):
                self.assertTrue(row["requirement"], row["id"])
                self.assertGreaterEqual(len(row["source"]), 3, f"{row['id']} 缺来源锚点")
                self.assertIn(row["status"], STATUSES, f"{row['id']} 状态非法: {row['status']}")
                self.assertTrue(row["evidence"], f"{row['id']} 缺证据路径")
                self.assertTrue(row["gap"], f"{row['id']} 缺缺口说明")
                self.assertIn(row["owner"], OWNERS, f"{row['id']} 责任线非法: {row['owner']}")

    def test_published_status_counts_match_rows(self):
        text = MATRIX.read_text(encoding="utf-8")
        block = _section(text, "### 2.4 状态统计", "> `not-done`")
        published: dict[str, int] = {}
        for line in block.splitlines():
            m = re.match(r"^\| (done|partial|not-done|blocked-resource) \|", line)
            if not m:
                continue
            cells = [c.strip().strip("*") for c in line.strip().strip("|").split("|")]
            published[cells[0]] = int(cells[-1])
        actual = Counter(r["status"] for r in _rows())
        self.assertEqual(published, {s: actual.get(s, 0) for s in STATUSES})

    def test_every_group_has_unfinished_items_or_is_explained(self):
        rows = _rows()
        for group in GROUPS:
            unfinished = [r for r in rows if r["group"] == group and r["status"] != "done"]
            self.assertTrue(unfinished, f"{group} 没有任何未完成项，统计口径可疑")


class AuthoritativeNumbersTest(unittest.TestCase):
    """§1 of the matrix must equal what the repository actually contains."""

    @classmethod
    def setUpClass(cls):
        cls.text = MATRIX.read_text(encoding="utf-8")
        cls.rows = {}
        for line in cls.text.splitlines():
            if not line.startswith("| ") or not line.rstrip().endswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 5 and re.match(r"^\d+$", cells[0]):
                cls.rows[cells[1]] = line

    def _row(self, needle: str) -> str:
        for label, line in self.rows.items():
            if needle in label:
                return line
        self.fail(f"§1 缺少指标行: {needle}")

    def test_modules_templates_and_chains(self):
        keys = _module_keys()
        self.assertIn(f"**{len(keys)}**", self._row("模块目录"))
        mods = [_load(REPO / "inkblade" / "modules" / k / "module.json") for k in keys]
        enabled = sum(1 for m in mods if m.get("default_enabled") is not False)
        disabled = len(mods) - enabled
        self.assertIn(f"**{enabled} / {disabled}**", self._row("默认启用/隔离"))
        templates = sum(1 for k in keys if (REPO / "inkblade" / "modules" / k / "template.json").is_file())
        bootstrap = sum(1 for m in mods if m.get("execution") == "bootstrap")
        self.assertIn(f"**{templates} / {bootstrap}**", self._row("模板 / bootstrap"))
        chains = len(list((REPO / "inkblade" / "chains").glob("*.json")))
        self.assertIn(f"**{chains}**", self._row("攻击链"))
        writes = sum(1 for m in mods if m.get("writes"))
        self.assertIn(f"**{writes}**", self._row("写类模块"))
        line = self._row("旧 `run.py`")
        self.assertIn(f"**{len(list((REPO / 'inkblade' / 'modules').glob('*/run.py')))}（工作树）", line)
        head = [p for p in _git_ls("inkblade/modules") if p.endswith("/run.py")]
        if head:  # git worktree available
            self.assertIn(f"{len(head)}（HEAD）", line)

    def test_corpus_counts_match_generated_matrix(self):
        corpus = _load(REPO / "inkblade" / "arch-intel" / "coverage-matrix.json")
        sources = corpus["sources"]
        classes = Counter(s["class"] for s in sources)
        line = self._row("架构语料")
        self.assertIn(f"**{len(sources)} 源**", line)
        for cls in ("official-cn", "official-en", "paper"):
            self.assertIn(f"{cls} {classes[cls]}", line)
        verified = sum(1 for s in sources if s["verification"]["status"] == "verified")
        partial = len(sources) - verified
        self.assertIn(f"verified {verified} + partial {partial}", line)

    def test_exploit_registry_counts(self):
        reg = _load(REPO / "inkblade" / "core" / "exploit-registry.json")
        s = reg["summary"]["total"]
        line = self._row("可利用性核验")
        self.assertIn(f"**{s['total']} = {s['verified']} verified + "
                      f"{s['exposure_verified']} exposure-verified + "
                      f"{s['static_only']} static-only + {s['unsupported']} unsupported**", line)
        dep = reg["deployment"]["counts"]
        dep_line = self._row("部署面分类")
        for key in ("default-exposed", "needs-config", "function-level", "hardware-only"):
            self.assertIn(f"{dep[key]} {key}", dep_line)

    def test_zeroday_and_weapon_counts(self):
        zd = _load(REPO / "inkblade" / "core" / "zeroday-registry.json")
        entries = zd["entries"]
        states = Counter(e.get("state") for e in entries)
        inv_line = self._row("零日清单")
        self.assertIn(f"**{len(entries)}**", inv_line)
        for state in ("candidate", "novelty-checked", "public"):
            self.assertIn(f"{state} {states[state]}", inv_line)
        summary = zd["summary"]
        res_line = self._row("零日储备")
        self.assertIn(f"**reserve-eligible {summary['reserve']}", res_line)
        self.assertIn(f"去重 {summary['reserve_unique']}", res_line)
        packs = _load(REPO / "inkblade" / "core" / "data" / "weapon-packs.json")
        modules = {p.get("module") for p in packs["packs"]}
        variants = sum(len(p.get("variants") or []) for p in packs["packs"])
        wp_line = self._row("武器包")
        self.assertIn(f"**{packs['total']} 包 / {len(modules)} 模块 / {variants} 变体**", wp_line)

    def test_rules_and_purple_counts(self):
        mapping = _load(REPO / "reports" / "samples" / "rules-pack" / "mapping.json")
        engines = Counter()
        for rule in mapping["rules"]:
            engines[tuple(sorted(rule["engines"]))] += 1
        text = self._row("规则")
        self.assertIn(f"**{len(mapping['rules'])}**", text)
        self.assertIn(f"Sigma {engines[('sigma',)]}", text)
        self.assertIn(f"Falco {engines[('falco',)]}", text)
        self.assertIn(f"Suricata {engines[('suricata',)]}", text)
        cov = _load(REPO / "reports" / "samples" / "rules-pack" / "coverage-matrix.json")
        summary = cov["summary"]
        purple = self._row("紫队覆盖")
        self.assertIn(f"**{summary['chains']}/{len(list((REPO / 'inkblade' / 'chains').glob('*.json')))} 链·"
                      f"{summary['missed']} 漏过**", purple)

    def test_effects_probes_cis_version_matrix(self):
        effects = _load(REPO / "reports" / "samples" / "effects" / "effects.json")
        checks = effects["checks"]
        passed = sum(1 for c in checks if str(c.get("status", "")).upper() == "PASS")
        self.assertIn(f"**{passed}/{len(checks)} PASS**", self._row("实效验证"))
        probes = list((REPO / "inkblade" / "probes" / "library").rglob("*.json"))
        self.assertIn(f"**{len(probes)} 探针", self._row("LLM 探针"))
        cis = _load(REPO / "inkblade" / "cis" / "catalog.json") if (REPO / "inkblade" / "cis" / "catalog.json").is_file() else None
        line = self._row("CIS / LPE")
        if cis is not None:
            self.assertIn(f"CIS {len(cis.get('items') or cis)}", line)
        vm = _load(REPO / "inkblade" / "core" / "data" / "version-matrix.json")
        self.assertIn(f"**{len(vm['entries'])} 条**", self._row("版本矩阵"))

    def test_profile_coverage_matches_computed_matrix(self):
        import sys
        sys.path.insert(0, str(REPO))
        from inkblade.core.registry import load_modules
        from inkblade.core.surface import matrix, profile_names

        mods = load_modules(REPO / "inkblade" / "modules")
        line = self._row("画像覆盖（production）")
        for name in profile_names():
            pct = matrix(name, modules=mods)["summary"]["coverage_pct"]
            self.assertIn(f"{pct:.2f}%", line, f"{name} 覆盖率与矩阵不一致")
        reg = _load(REPO / "inkblade" / "core" / "exploit-registry.json")
        by_profile = reg["deployment"]["by_profile"]
        poc_line = self._row("默认可利用 PoC/画像")
        expected = " / ".join(str(by_profile[k]["default_exposed"])
                              for k in profile_names())
        self.assertIn(f"**{expected}**", poc_line)
        no_surface = set()
        verdicts: dict[str, list[str]] = {}
        for name in profile_names():
            for row in matrix(name, modules=mods)["modules"]:
                verdicts.setdefault(row["module"], []).append(row["verdict"])
        no_surface = {k for k, v in verdicts.items() if v and all(x == "no-surface" for x in v)}
        self.assertIn(f"**{len(no_surface)}**", self._row("全画像无面"))

    def test_comparison_tool_counts(self):
        gap = _load(REPO / "docs" / "gap-matrix.json")
        self.assertEqual(len(gap["tools"]), 31)
        rows = sum(len(v[k]) for v in gap["tools"].values()
                   for k in ("features", "surfaces", "payloads"))
        self.assertIn("**260", self._row("缺口行数"))
        self.assertIn(str(rows), self._row("缺口行数"))
        oss = _load(REPO / "docs" / "oss-ml-cluster-tools.json")
        compare = self._row("对比工具数")
        self.assertIn(str(len(oss["tools"])), compare)
        self.assertIn("23", compare)
        self.assertIn("8", compare)


class OpenItemsTest(unittest.TestCase):
    def test_unfinished_section_has_dependency_and_acceptance(self):
        text = MATRIX.read_text(encoding="utf-8")
        block = _section(text, "### 3.1 阻断项", "### 3.2")
        rows = [l for l in block.splitlines() if re.match(r"^\| \d+ \|", l)]
        self.assertGreaterEqual(len(rows), 8, "阻断项少于 8 条")
        for line in rows:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            self.assertGreaterEqual(len(cells), 6, line)
            self.assertTrue(cells[3], f"缺依赖: {line[:80]}")
            self.assertTrue(cells[5], f"缺验收标准: {line[:80]}")

    def test_every_blocked_requirement_is_in_the_dependency_section(self):
        text = MATRIX.read_text(encoding="utf-8")
        blocked = [r["id"] for r in _rows() if r["status"] == "blocked-resource"]
        self.assertGreaterEqual(len(blocked), 4)
        tail = text[text.index("### 3.1"):]
        for rid in blocked:
            self.assertIn(rid, tail, f"{rid} 未在未完成清单里出现")

    def test_suite_evidence_matches_matrix(self):
        summary = (REPO / "reports" / "samples" / "requirements" / "suite-summary.txt").read_text(encoding="utf-8")
        m = re.search(r"Ran (\d+) tests", summary)
        self.assertIsNotNone(m)
        text = MATRIX.read_text(encoding="utf-8")
        self.assertIn(f"**Ran {m.group(1)} tests", text)
        outcome = re.search(r"^(OK(?: \(.*\))?|FAILED \(.*\))$", summary, re.M)
        self.assertIsNotNone(outcome, "suite summary has no outcome line")
        self.assertIn(outcome.group(1), text)
        self.assertIn("python -m unittest discover", summary)

    def test_migration_in_flight_section_lists_red_tests(self):
        text = MATRIX.read_text(encoding="utf-8")
        block = _section(text, "### 3.2 迁移收口记录", "### 3.3")
        self.assertIn("run.py", block)
        self.assertIn("unittest", block)

    def test_only_documented_reason_for_not_done(self):
        note = MATRIX.read_text(encoding="utf-8")
        for row in _rows():
            if row["status"] == "not-done":
                self.assertIn(row["id"], note, "not-done 需在正文说明原因")
                self.assertTrue(row["gap"])


class DocConsistencyTest(unittest.TestCase):
    """The three summary documents must not resurrect the old numbers."""

    @classmethod
    def setUpClass(cls):
        cls.matrix = MATRIX.read_text(encoding="utf-8")
        cls.sota = SOTA.read_text(encoding="utf-8")
        cls.master = MASTER.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")
        cls.readme_cn = README_CN.read_text(encoding="utf-8")

    def test_all_four_documents_point_at_the_matrix(self):
        for name, text in (("SOTA", self.sota), ("MASTER", self.master), ("README", self.readme)):
            self.assertIn("REQUIREMENTS-MATRIX.md", text, f"{name} 没有指向唯一事实源")

    def test_sota_counts_match_matrix(self):
        self.assertIn("287", self.sota)
        self.assertIn("276", self.sota)
        self.assertIn("70.65%", self.sota)
        self.assertIn("25.00%", self.sota)
        self.assertIn("80 源", self.sota)
        self.assertIn("39 项", self.sota)
        self.assertNotIn("275（", self.sota)
        self.assertNotIn("93 static-only", self.sota)
        self.assertNotIn("35 源", self.sota)
        self.assertNotIn("Ran 2003", self.sota)

    def test_master_counts_match_matrix(self):
        self.assertIn("53/53", self.master)
        self.assertIn("103 条版本矩阵", self.master)
        self.assertIn("19", self.master)
        self.assertNotIn("落盘 **47/47", self.master)
        self.assertNotIn("42 条版本矩阵", self.master)
        self.assertNotIn("93 static-only", self.master)

    def test_readme_states_the_real_command_surface(self):
        self.assertIn("not implemented", self.readme)
        self.assertIn("session run", self.readme)
        self.assertIn("287 module directories", self.readme)
        self.assertIn("gone from both the working tree", self.readme)
        self.assertIn("未实现", self.readme_cn)
        self.assertIn("287", self.readme_cn)

    def test_old_layer_wording_is_gone(self):
        detection = (REPO / "docs" / "DETECTION-LAYERS.md").read_text(encoding="utf-8")
        architecture = (REPO / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertNotIn("按九层组织", detection)
        self.assertIn("十层", detection)
        self.assertNotIn("采用七层架构", architecture)
        self.assertIn("七个组件", architecture)

    def test_no_special_case_zero_day_wording(self):
        self.assertIn("口径已更正", self.matrix)
        self.assertNotIn("首批 6 条未披露", self.master)


if __name__ == "__main__":
    unittest.main()
