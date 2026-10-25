"""终审 Minor#13：UI 资产图/差异视图接真实 API 数据（已有视图补齐数据绑定）。

- 后端新增只读 `/api/v1/drift`（run 目录 drift.json；缺 run 时取最新含 drift 的 run）；
- 前端 app.js：差异视图服务模式必须实际请求 `api/v1/drift`（不再只读内嵌数据）；
  资产图必须按 kind 过滤并重新请求 `api/v1/assets`；
- 静态导出仍内嵌 drift/assets（离线可看），与 API 数据同源。
"""

import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.users import UserStore
from trident.webui.export_static import export_static
from trident.webui.server import make_server

REPO = Path(__file__).resolve().parents[1]
APP_JS = REPO / "trident" / "webui" / "static" / "app.js"


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


class TestUiDataBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        cls.users = users
        cls.store = EvidenceStore(cls.root, workspace="local-lab")
        run = cls.store.create_run("ui-run")
        run.add_step("s1", "probe", {"actor": "tester"}, "summary")
        drift = {
            "run": run.name,
            "generated_at": "2026-10-25T00:00:00Z",
            "counts": {"new": 2, "fixed": 1, "unchanged": 7},
            "new": [{"step_key": "s1", "title": "新增发现", "severity": "high"},
                    {"step_key": "s1", "title": "另一个新增", "severity": "medium"}],
            "fixed": [{"step_key": "s0", "title": "已修复发现", "severity": "low"}],
        }
        (run.dir / "drift.json").write_text(json.dumps(drift, ensure_ascii=False), encoding="utf-8")
        # 工作区资产库（assets.db，供静态导出与资产视图）
        from trident.core.discovery import AssetInventory

        inv = AssetInventory(cls.store)
        inv.ingest({"namespaces": ["train"], "services": [
            {"namespace": "train", "name": "sglang", "port": 30000, "product": "sglang"}]},
            source="ui-test")
        cls.run_name = run.name
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def _token(self):
        code, body = _req("POST", self.base + "/api/login",
                          body={"name": "tester", "password": "x"})
        self.assertEqual(code, 200, body)
        return body["token"]

    def test_drift_endpoint_requires_run_or_picks_latest(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/drift?run=ui-run", token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["run"], "ui-run")
        self.assertEqual(body["counts"], {"new": 2, "fixed": 1, "unchanged": 7})
        self.assertEqual(len(body["new"]), 2)
        self.assertEqual(body["drift"]["counts"]["fixed"], 1)

        code, latest = _req("GET", self.base + "/api/v1/drift", token=token)
        self.assertEqual(code, 200, latest)
        self.assertEqual(latest["run"], "ui-run")

    def test_drift_endpoint_404_and_401(self):
        code, _ = _req("GET", self.base + "/api/v1/drift")
        self.assertEqual(code, 401)
        token = self._token()
        code, _ = _req("GET", self.base + "/api/v1/drift?run=ghost", token=token)
        self.assertEqual(code, 404)

    def test_assets_endpoint_filtered_by_kind(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/assets?kind=service", token=token)
        self.assertEqual(code, 200, body)
        self.assertTrue(body["assets"])
        self.assertTrue(all(a["kind"] == "service" for a in body["assets"]))
        code, ns = _req("GET", self.base + "/api/v1/assets?kind=namespace", token=token)
        self.assertEqual(code, 200)
        self.assertTrue(all(a["kind"] == "namespace" for a in ns["assets"]))

    def test_app_js_binds_real_api_for_assets_and_drift(self):
        js = APP_JS.read_text(encoding="utf-8")
        # 差异视图确实请求后端（服务模式）
        self.assertIn("api/v1/drift", js)
        self.assertNotIn("此处展示内嵌数据", js)
        # 资产视图按 kind 过滤并重新请求
        self.assertIn("api/v1/assets?workspace=", js)
        self.assertIn("kind=", js)
        self.assertIn("product=", js)
        # 错误路径有可见提示（不是静默空白）
        self.assertIn("差异数据加载失败", js)

    def test_static_export_embeds_drift_and_assets(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "export"
            html = export_static(self.store.ws_dir / self.run_name, out).read_text(encoding="utf-8")
            start = html.index("window.TRIDENT_DATA = ") + len("window.TRIDENT_DATA = ")
            end = html.index(";</script>", start)
            data = json.loads(html[start:end])
            self.assertEqual(data["drift"]["counts"]["new"], 2)
            self.assertTrue(data["assets"]["nodes"])
            kinds = {n["kind"] for n in data["assets"]["nodes"]}
            self.assertIn("service", kinds)


if __name__ == "__main__":
    unittest.main()
