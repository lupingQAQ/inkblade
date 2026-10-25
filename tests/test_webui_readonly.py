"""终审 Minor#8：Web API 只读端点补全（steps/evidence/graph/report/rules/consent/workspaces）+ openapi.json。

约定：
- 全部业务端点须登录且受工作区隔离（401/403）；
- 未知 run → 404；缺 run 参数 → 400；
- openapi.json 公开可取，3.1.0 版本，逐路径含操作与 Bearer 安全方案；
- graph 端点返回 graph_nodes/graph_edges（层级 + 判定方式原样透出）。
"""

import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe
from trident.core.users import UserStore
from trident.webui.server import make_server


def _req(method, url, token=None, body=None, timeout=10):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


class TestReadOnlyApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        cls.users = users
        cls.store = EvidenceStore(cls.root, workspace="local-lab")
        init_roe(cls.store, fields={
            "level": "利用验证", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"],
            "client": "api-readonly-test",
        })
        run = cls.store.create_run("api-run")
        run.add_step("s1", "probe /__routes__", {"actor": "tester"}, "ok summary")
        run.add_step("s2", "probe /pause", {"actor": "tester"}, "ok summary 2")
        run.add_finding("s1", "high", "管理面无鉴权", "detail body", is_zeroday=False)
        run.upsert_node("svc/sglang", "service", "工作负载层", {"ns": "train", "port": 30000})
        run.upsert_node("ns/train", "namespace", "命名空间层", {"ns": "train"})
        run.add_edge("ns/train", "svc/sglang", "reachable", "CNI 语义推演", "admin-plane")
        run.finalize_run()
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

    def test_all_endpoints_require_login(self):
        for path in ("/api/v1/steps?run=api-run", "/api/v1/evidence?run=api-run",
                     "/api/v1/graph?run=api-run", "/api/v1/report?run=api-run",
                     "/api/v1/rules", "/api/v1/consent", "/api/v1/workspaces"):
            with self.subTest(path=path):
                code, _ = _req("GET", self.base + path)
                self.assertEqual(code, 401)

    def test_steps_endpoint(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/steps?run=api-run", token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["run"], "api-run")
        self.assertEqual(body["count"], 2)
        keys = [s["step_key"] for s in body["steps"]]
        self.assertEqual(keys, ["s1", "s2"])
        self.assertTrue(body["steps"][0]["prompts"])
        self.assertTrue(body["steps"][0]["evidence"])

    def test_steps_missing_run_param_and_unknown_run(self):
        token = self._token()
        code, _ = _req("GET", self.base + "/api/v1/steps", token=token)
        self.assertEqual(code, 400)
        code, _ = _req("GET", self.base + "/api/v1/steps?run=ghost", token=token)
        self.assertEqual(code, 404)

    def test_evidence_endpoint_verifies_manifest(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/evidence?run=api-run", token=token)
        self.assertEqual(code, 200, body)
        self.assertTrue(body["manifest_verified"])
        self.assertGreaterEqual(body["count"], 2)
        row = body["evidence"][0]
        for key in ("step_key", "path", "sha256", "kind"):
            self.assertIn(key, row)
        self.assertEqual(len(row["sha256"]), 64)
        # 步骤过滤
        code, filtered = _req("GET", self.base + "/api/v1/evidence?run=api-run&step=s1",
                              token=token)
        self.assertEqual(code, 200)
        self.assertEqual({r["step_key"] for r in filtered["evidence"]}, {"s1"})

    def test_graph_endpoint(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/graph?run=api-run", token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["node_count"], 2)
        self.assertEqual(body["edge_count"], 1)
        layers = {n["node_id"]: n["layer"] for n in body["nodes"]}
        self.assertEqual(layers["svc/sglang"], "工作负载层")
        edge = body["edges"][0]
        self.assertEqual((edge["src"], edge["dst"], edge["verdict"], edge["method"]),
                         ("ns/train", "svc/sglang", "reachable", "CNI 语义推演"))
        self.assertEqual(body["by_layer"], {"工作负载层": 1, "命名空间层": 1})

    def test_report_endpoint(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/report?run=api-run&kind=pentest&lang=zh",
                          token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["kind"], "pentest")
        self.assertIn("渗透测试报告", body["markdown"])
        self.assertIn("管理面无鉴权", body["markdown"])
        code, rem = _req("GET",
                         self.base + "/api/v1/report?run=api-run&kind=remediation&lang=en",
                         token=token)
        self.assertEqual(code, 200, rem)
        self.assertIn("Remediation Report", rem["markdown"])
        code, _ = _req("GET", self.base + "/api/v1/report?run=api-run&kind=bogus", token=token)
        self.assertEqual(code, 400)

    def test_rules_and_consent_endpoints(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/rules", token=token)
        self.assertEqual(code, 200)
        self.assertIn("ok", body)
        code, consent = _req("GET", self.base + "/api/v1/consent", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(consent["status"], "complete")
        self.assertEqual(consent["fields"]["client"], "api-readonly-test")

    def test_workspaces_endpoint(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/workspaces", token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["current"], "local-lab")
        self.assertIn("local-lab", body["workspaces"])

    def test_cross_workspace_denied(self):
        token = self._token()
        code, _ = _req("GET", self.base + "/api/v1/steps?workspace=other&run=api-run",
                       token=token)
        self.assertEqual(code, 403)

    def test_server_backlog_supports_concurrency(self):
        """性能网格发现：默认 backlog=5 在 16+ 并发下吞吐断崖，已提升到 256。"""
        self.assertGreaterEqual(self.httpd.request_queue_size, 128)

    def test_openapi_is_public_and_complete(self):
        code, doc = _req("GET", self.base + "/api/v1/openapi.json")
        self.assertEqual(code, 200, doc)
        self.assertEqual(doc["openapi"], "3.1.0")
        schemes = doc["components"]["securitySchemes"]
        self.assertTrue(any(s.get("type") == "http" and s.get("scheme") == "bearer"
                            for s in schemes.values()), schemes)
        paths = doc["paths"]
        for required in ("/api/v1/steps", "/api/v1/evidence", "/api/v1/graph",
                         "/api/v1/report", "/api/v1/rules", "/api/v1/consent",
                         "/api/v1/workspaces", "/api/login", "/api/execute"):
            self.assertIn(required, paths, f"openapi 缺路径 {required}")
        for path, ops in paths.items():
            self.assertTrue(ops, f"{path} 无操作定义")
            for method, op in ops.items():
                self.assertIn(method, ("get", "post", "put", "patch", "delete", "head"))
                self.assertIn("summary", op, f"{path}.{method} 缺 summary")
        # 别名同样可访问
        code, doc2 = _req("GET", self.base + "/openapi.json")
        self.assertEqual(code, 200)
        self.assertEqual(doc2["info"]["title"], doc["info"]["title"])


if __name__ == "__main__":
    unittest.main()
