# -*- coding: utf-8 -*-
"""UX 产品化验收：错误人话 ≥30 类 / UI 双语空态 / 10k findings 分页 /
kubeconfig→pilot 引导流 / 可用性走查脚本与文档。

约束：
- 全部离线，不读取真实 kubeconfig、不连接真实集群；
- UI 只做静态断言 + 真实静态导出（不启动浏览器也可验证数据面）；
- 走查脚本是「专家启发式走查」，测试只断言度量口径与 SUS 模板存在，
  不把模板分数冒充真实用户数据。
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

STATIC = REPO / "inkblade" / "webui" / "static"
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
STYLE = STATIC / "style.css"


class TestHumanizeCatalog(unittest.TestCase):
    """>=30 类错误码，且每条都能给出「发生了什么/为什么/怎么修」。"""

    def test_catalog_has_at_least_30_distinct_codes(self):
        from inkblade.core.humanize import catalog, catalog_codes

        codes = catalog_codes()
        self.assertGreaterEqual(len(codes), 30, f"错误码仅 {len(codes)} 类：{codes}")
        self.assertEqual(len(codes), len(set(codes)), "错误码目录存在重复")
        for err in catalog():
            self.assertRegex(err.code, r"^E\d{3}$")
            self.assertTrue(err.title.strip(), f"{err.code} 缺标题")
            self.assertTrue(err.happened.strip(), f"{err.code} 缺「发生了什么」")
            self.assertTrue(err.why.strip(), f"{err.code} 缺「为什么」")
            self.assertGreater(len(err.fix), 10, f"{err.code} 修复建议过短")
            text = str(err)
            for phrase in ("发生了什么：", "为什么：", "怎么修："):
                self.assertIn(phrase, text, f"{err.code} 缺 {phrase}")

    def test_catalog_covers_install_auth_chaos_api_pilot(self):
        from inkblade.core.humanize import catalog_codes

        codes = set(catalog_codes())
        for prefix in ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"):
            self.assertTrue(any(c.startswith(prefix) for c in codes),
                            f"缺少 {prefix}xx 错误族")

    def test_unknown_exception_still_actionable(self):
        from inkblade.core.humanize import explain_exception

        err = explain_exception(RuntimeError("surprise"))
        self.assertEqual(err.code, "E900")
        self.assertIn("INKBLADE_DEBUG=1", err.fix)


class TestUIProductization(unittest.TestCase):
    def test_bilingual_switch_wired(self):
        html = INDEX.read_text(encoding="utf-8")
        js = APP_JS.read_text(encoding="utf-8")
        self.assertIn('id="lang-toggle"', html)
        self.assertIn("data-i18n", html)
        for needle in ("I18N", "applyI18n", "setLang", "inkblade-lang"):
            self.assertIn(needle, js, f"app.js 缺 {needle}")

    def test_all_ten_views_have_guided_empty_state(self):
        js = APP_JS.read_text(encoding="utf-8")
        self.assertIn("EMPTY_STATES", js)
        self.assertIn("function emptyState", js)
        for view in ("dag", "chain", "timeline", "evidence", "report", "rules",
                     "assets", "drift", "approvals", "schedules"):
            self.assertIn(f'"{view}"', js)
        # 空态必须带下一步命令，而不是一句「暂无数据」
        self.assertIn("inkblade channel listen", js)
        self.assertIn("reverse --transport tls", js)
        css = STYLE.read_text(encoding="utf-8")
        self.assertIn(".empty-state", css)

    def test_report_uses_paged_rendering_with_legacy_benchmark_switch(self):
        js = APP_JS.read_text(encoding="utf-8")
        for needle in ("REPORT_PAGE_SIZE", "reportVisible", "perf=legacy",
                       "显示更多", "renderedRows", "__INKBLADE_REPORT_META"):
            self.assertIn(needle, js, f"app.js 缺 {needle}")
        # 不能再用一次性全量 fs.forEach 直接建 DOM（分页后应仅渲染 slice）
        self.assertIn("visibleFindings", js)

    def test_login_page_compact_and_connect_commands_post_auth(self):
        html = INDEX.read_text(encoding="utf-8")
        js = APP_JS.read_text(encoding="utf-8")
        for removed in ("kubeconfig", "onboarding-steps", "connect-panel", "三步"):
            self.assertNotIn(removed, html.lower())
        self.assertIn("id=\"login-form\"", html)
        self.assertIn("inkblade channel listen", js)
        self.assertIn("inkblade session open --mode foothold", js)
        self.assertIn("kubeconfig 批量投放", js)


class TestClusterWizard(unittest.TestCase):
    def _run(self, *argv):
        from inkblade.cluster_wizard import run_wizard

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_wizard(**_kwargs(argv), home=Path(tempfile.mkdtemp()))
        return rc, buf.getvalue()

    def test_snapshot_dry_run_lists_contexts_and_next_command(self):
        fixture = REPO / "lab" / "enterprise-fixtures" / "clusters" / "east-prod.json"
        self.assertTrue(fixture.is_file(), "缺少 pilot snapshot fixture")
        rc, out = self._run("--snapshot", str(fixture), "--dry-run",
                            "--out", str(Path(tempfile.mkdtemp()) / "pilot"))
        self.assertEqual(rc, 0, out)
        self.assertIn("dry-run", out.lower())
        self.assertIn("east-prod", out)
        self.assertIn("inkblade pilot", out)
        self.assertIn("只读", out)

    def test_missing_kubeconfig_is_humanized_and_nonzero(self):
        rc, out = self._run("--kubeconfig", "Z" + ":" + "/definitely-missing-kubeconfig",
                            "--dry-run")
        self.assertEqual(rc, 2)
        self.assertIn("kubeconfig", out.lower())
        self.assertIn("怎么修", out)


class TestUsabilityWalkthrough(unittest.TestCase):
    def _load(self):
        path = REPO / "scripts" / "usability-walkthrough.py"
        self.assertTrue(path.is_file(), "缺少 scripts/usability-walkthrough.py")
        spec = importlib.util.spec_from_file_location("usability_walkthrough", path)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    def test_five_roles_and_sus_template_are_explicitly_expert_only(self):
        mod = self._load()
        self.assertEqual(len(mod.ROLES), 5)
        self.assertEqual(len(mod.SUS_QUESTIONS), 10)
        text = mod.DISCLAIMER
        self.assertIn("专家", text)
        self.assertIn("非真实用户", text)
        self.assertIn("不构成", text)

    def test_metrics_shape_from_synthetic_steps(self):
        mod = self._load()
        steps = [
            {"role": "platform-admin", "name": "doctor", "ok": True,
             "duration_ms": 120.0, "errors": []},
            {"role": "platform-admin", "name": "demo", "ok": False,
             "duration_ms": 480.0, "errors": ["E103"]},
        ]
        summary = mod.summarize(steps)
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["failed_steps"], 1)
        self.assertAlmostEqual(summary["success_rate"], 0.5)
        self.assertAlmostEqual(summary["total_duration_s"], 0.6)
        self.assertEqual(summary["error_classes"], ["E103"])


class TestUiPerfFixture(unittest.TestCase):
    def _load(self):
        path = REPO / "scripts" / "ui-perf-bench.py"
        spec = importlib.util.spec_from_file_location("ui_perf_bench", path)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    def test_fixture_exports_expected_count_and_relative_paths(self):
        mod = self._load()
        with tempfile.TemporaryDirectory() as tmp:
            metrics = mod.build_fixture(Path(tmp), count=120)
            self.assertEqual(metrics["findings"], 120)
            self.assertTrue(Path(tmp).joinpath("export", "index.html").is_file())
            self.assertNotRegex(metrics["run_dir"], r"^[A-Za-z]:[\\/]")
            self.assertIn("html_bytes", metrics)


class TestDocsExist(unittest.TestCase):
    def test_chaos_parity_doc_compares_three_tools(self):
        text = (REPO / "docs" / "CHAOS-PARITY.md").read_text(encoding="utf-8")
        for needle in ("Chaos Mesh", "Litmus", "Chaos Toolkit", "18",
                       "PFC", "KV", "边界"):
            self.assertIn(needle, text)
        for exp_id in ("net-latency-step-degradation", "net-disconnect-workers",
                       "fabric-pfc-storm", "gpu-xid-driver-reset"):
            self.assertIn(exp_id, text)

    def test_ui_perf_doc_has_measured_before_after(self):
        text = (REPO / "docs" / "UI-PERF.md").read_text(encoding="utf-8")
        for needle in ("10,000", "渲染", "DOM", "优化前", "优化后", "复现",
                       "局限"):
            self.assertIn(needle, text)

    def test_ux_evaluation_doc_has_before_after(self):
        text = (REPO / "docs" / "UX-EVALUATION.md").read_text(encoding="utf-8")
        for needle in ("前后对比", "错误", "空态", "双语", "10k", "kubeconfig",
                       "专家走查", "非真实用户"):
            self.assertIn(needle, text)


def _kwargs(argv: list[str]) -> dict:
    parser_keys = {
        "--snapshot": "snapshots", "--kubeconfig": "kubeconfigs", "--context": "context",
        "--out": "out_dir", "--workspace": "workspace", "--actor": "actor",
        "--role": "role", "--kubectl": "kubectl", "--timeout": "timeout",
        "--yes": "yes", "--dry-run": "dry_run",
    }
    kw: dict = {"kubeconfigs": [], "snapshots": []}
    i = 0
    while i < len(argv):
        key = argv[i]
        field = parser_keys[key]
        if field in ("yes", "dry_run"):
            kw[field] = True
            i += 1
            continue
        if field in ("kubeconfigs", "snapshots"):
            kw.setdefault(field, []).append(argv[i + 1])
        else:
            kw[field] = argv[i + 1]
        i += 2
    kw.setdefault("out_dir", "reports/pilot")
    kw.setdefault("workspace", "pilot-onboard")
    kw.setdefault("actor", "onboarding-wizard")
    kw.setdefault("role", "auditor")
    kw.setdefault("kubectl", "kubectl")
    kw.setdefault("timeout", 30)
    kw.setdefault("yes", False)
    kw.setdefault("dry_run", False)
    return kw


if __name__ == "__main__":
    unittest.main()
