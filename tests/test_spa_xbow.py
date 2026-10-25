# -*- coding: utf-8 -*-
"""SPA 十视图（XBow 对标 ⑦）测试：新视图 nav/section/渲染 + 静态导出内嵌新数据。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.discovery import AssetInventory
from trident.core.evidence import EvidenceStore
from trident.webui.export_static import export_static, load_run_data

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "trident" / "webui" / "static"
NEW_VIEWS = ("assets", "drift", "approvals", "schedules")


class TestNewViews(unittest.TestCase):
    def test_index_nav_and_sections(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        for vid in NEW_VIEWS:
            self.assertIn(f'"{vid}"', html)
            self.assertIn(f'id="view-{vid}"', html)
            self.assertIn(f'id="{vid}-body"', html)
        # 零外链红线不破
        self.assertNotIn("http://", html.replace("http://127.0.0.1", ""))

    def test_app_js_render_functions(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        for fn in ("renderAssets", "renderDrift", "renderApprovals", "renderSchedules"):
            self.assertIn(f"function {fn}", js)
        for vid in NEW_VIEWS:
            self.assertIn(f'case "{vid}":', js)  # 视图路由分派
            self.assertIn(f'"{vid}-body"', js)   # 渲染宿主

    def test_style_covers_new_components(self):
        css = (STATIC / "style.css").read_text(encoding="utf-8")
        for cls in ("rules-matrix", "node-missing", "sev-card"):
            self.assertIn(cls, css)


class TestStaticExportEmbeds(unittest.TestCase):
    def test_export_embeds_assets_drift(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            store = EvidenceStore(root, workspace="local-lab")
            AssetInventory(store).ingest({
                "namespaces": ["ml"],
                "services": [{"name": "sglang-admin", "namespace": "ml",
                              "addr": "10.0.0.1", "port": 30000}],
            }, source="seed")
            run = store.create_run("run-xbow")
            art = root / "a.txt"
            art.write_text("x", encoding="utf-8")
            run.add_step("demo", "cmd", {}, "ok", artifacts=[art])
            (Path(run.dir) / "drift.json").write_text(
                json.dumps({"schedule": "s1", "counts": {"new": 1, "fixed": 0, "unchanged": 0}}),
                encoding="utf-8")
            data = load_run_data(run.dir)
            self.assertIn("assets", data)
            self.assertEqual(len(data["assets"]["nodes"]), 2)
            self.assertIn("drift", data)
            self.assertEqual(data["drift"]["counts"]["new"], 1)
            out = export_static(run.dir, root / "out")
            html = Path(out).read_text(encoding="utf-8")
            self.assertIn("window.TRIDENT_DATA", html)

    def test_old_run_export_unchanged(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            store = EvidenceStore(root, workspace="local-lab")
            run = store.create_run("run-old")
            art = root / "a.txt"
            art.write_text("x", encoding="utf-8")
            run.add_step("demo", "cmd", {}, "ok", artifacts=[art])
            data = load_run_data(run.dir)
            self.assertNotIn("drift", data)
            self.assertNotIn("assets", data)  # 无 assets.db 时内嵌省略
            self.assertIn("steps", data)


if __name__ == "__main__":
    unittest.main()
