"""SPA 六视图静态前端：离线资产 / 视图齐全 / 静态导出内嵌 run 数据。"""

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.webui.export_static import export_static

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "inkblade" / "webui" / "static"

VIEW_IDS = ("dag", "chain", "timeline", "evidence", "report", "rules")


def _make_run(root: Path):
    """用 EvidenceStore 造一个含步骤/发现/图数据的 run，返回 run 目录。"""
    store = EvidenceStore(root, workspace="local-lab")
    run = store.create_run("run-spa-demo")
    art = root / "artifact.txt"
    art.write_text("inkblade-demo", encoding="utf-8")
    run.add_step(
        "exposure-mapping", "inkblade recon exposure-mapping",
        {"host": "lab", "user": "tester"}, "12 services exposed",
        artifacts=[art],
    )
    run.add_step(
        "sglang-admin-failopen", "curl 127.0.0.1:30000/health",
        {"host": "lab"}, "fail-open confirmed on 30000",
        artifacts=[art],
    )
    run.add_finding(
        "sglang-admin-failopen", sev="high", title="SGLang 管理面 fail-open",
        detail="30000 无 key 放行", evidence_path="steps/sglang-admin-failopen.tar.gz",
    )
    run.add_finding(
        "sglang-admin-failopen", sev="critical", title="已公开深度样例",
        detail="公开细节：未鉴权管理面动作成功",
        evidence_path="steps/sglang-admin-failopen.tar.gz", is_novel=True,
    )
    run.upsert_node("workload-pod", "pod", "pod", {"namespace": "train"})
    run.upsert_node("svc/sglang-admin", "service", "service", {"port": 30000})
    run.add_edge("workload-pod", "svc/sglang-admin", "reachable", "probed",
                 chain="flat-network-admin-plane-weight-poison")
    run.finalize_run()
    return root / "evidence" / "local-lab" / "run-spa-demo"


class TestOfflineAssets(unittest.TestCase):
    def test_index_exists_and_fully_offline(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        # 禁止任何 http(s) 外链（源引用 / 超链接 / 内联引用）
        self.assertNotRegex(html, re.compile(r'https?://', re.I))
        # 引用必须是相对路径
        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html):
            self.assertFalse(m.group(1).startswith("/"), f"非相对引用: {m.group(1)}")

    def test_vendor_assets_present(self):
        react = STATIC / "vendor" / "react.production.min.js"
        dom = STATIC / "vendor" / "react-dom.production.min.js"
        self.assertTrue(react.exists() and react.stat().st_size > 5_000, "React UMD 缺失")
        self.assertTrue(dom.exists() and dom.stat().st_size > 50_000, "ReactDOM UMD 缺失")
        for p in (react, dom):
            text = p.read_text(encoding="utf-8", errors="replace")
            self.assertIn("React", text[:400])

    def test_dag_engine_available(self):
        """React Flow UMD 入库；若下载失败必须有自绘引擎兜底（Ruling 见 progress.md）。"""
        rf = STATIC / "vendor" / "reactflow.umd.min.js"
        app_js = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertTrue(
            rf.exists() or "DagCanvas" in app_js,
            "既无 React Flow UMD 也无自绘 DagCanvas 兜底",
        )

    def test_app_js_declares_six_views(self):
        app_js = (STATIC / "app.js").read_text(encoding="utf-8")
        for vid in VIEW_IDS:
            self.assertIn(f"view-{vid}", app_js)
        # 步骤状态五色语义
        for status in ("pending", "running", "success", "degraded", "blocked"):
            self.assertIn(status, app_js)

    def test_style_css_exists(self):
        css = (STATIC / "style.css").read_text(encoding="utf-8")
        self.assertIn("--status-success", css)

    def test_index_nav_has_six_views(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        for vid in VIEW_IDS:
            self.assertIn(f'"{vid}"', html)


class TestExportStatic(unittest.TestCase):
    def test_export_static_embeds_run(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            run_dir = _make_run(root)
            out = root / "export"
            html_path = export_static(run_dir, out)
            self.assertTrue(html_path.exists(), "导出 index.html 缺失")
            html = html_path.read_text(encoding="utf-8")
            # 内嵌 run 步骤名与发现
            self.assertIn("exposure-mapping", html)
            self.assertIn("SGLang 管理面 fail-open", html)
            # 图数据
            self.assertIn("svc/sglang-admin", html)
            # 导出物同样全离线
            self.assertNotRegex(html, re.compile(r'https?://', re.I))
            # 免服务打开：静态资产随行 + 数据内嵌（无需 /api）
            self.assertTrue((out / "app.js").exists())
            self.assertTrue((out / "style.css").exists())
            self.assertTrue((out / "vendor" / "react.production.min.js").exists())
            self.assertNotIn('fetch("/api/runs")', html)  # app.js 用相对路径而非绝对

    def test_export_static_optional_novel_redaction(self):
        """静态导出可选脱敏开关：默认展示已公开细节；开启后仅保留证据引用。"""
        with TemporaryDirectory() as td:
            root = Path(td)
            run_dir = _make_run(root)
            html_path = export_static(run_dir, root / "export", redact_novel=True)
            html = html_path.read_text(encoding="utf-8")
            m = re.search(
                r"window\.INKBLADE_DATA\s*=\s*(\{.*?\})\s*;?\s*</script>",
                html, re.S,
            )
            self.assertIsNotNone(m)
            data = json.loads(m.group(1))
            zd = [f for f in data["findings"] if f["is_novel"]]
            self.assertTrue(zd, "fixture 缺深度发现")
            self.assertIn("【脱敏】", zd[0]["title"])
            self.assertEqual(zd[0]["detail"], "")
            self.assertTrue(zd[0]["evidence_path"])

    def test_export_static_data_json_parses(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            run_dir = _make_run(root)
            html_path = export_static(run_dir, root / "export")
            html = html_path.read_text(encoding="utf-8")
            m = re.search(
                r"window\.INKBLADE_DATA\s*=\s*(\{.*?\})\s*;?\s*</script>",
                html, re.S,
            )
            self.assertIsNotNone(m, "未找到 window.INKBLADE_DATA 注入")
            data = json.loads(m.group(1))
            self.assertEqual(data["run"]["name"], "run-spa-demo")
            keys = [s["step_key"] for s in data["steps"]]
            self.assertIn("exposure-mapping", keys)
            self.assertEqual(data["findings"][0]["severity"], "high")
            self.assertEqual(data["edges"][0]["chain"], "flat-network-admin-plane-weight-poison")


if __name__ == "__main__":
    unittest.main()
