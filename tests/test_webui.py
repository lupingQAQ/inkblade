import json
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.users import UserStore
from inkblade.webui.server import make_server


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


class TestWebUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        cls.users = users
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def test_api_requires_login(self):
        code, _ = _req("GET", self.base + "/api/runs?workspace=local-lab")
        self.assertEqual(code, 401)

    def test_login_and_list_runs(self):
        code, body = _req("POST", self.base + "/api/login", body={"name": "tester", "password": "x"})
        self.assertEqual(code, 200)
        token = body["token"]
        code, body = _req("GET", self.base + "/api/runs?workspace=local-lab", token=token)
        self.assertEqual(code, 200)
        self.assertIn("runs", body)

    def test_locked_workspace_rejects_execution(self):
        _, body = _req("POST", self.base + "/api/login", body={"name": "tester", "password": "x"})
        token = body["token"]
        code, body = _req(
            "POST", self.base + "/api/execute", token=token,
            body={"workspace": "local-lab", "module": "any-probe", "params": {}},
        )
        self.assertEqual(code, 423)  # 授权未完成 → 全执行路径锁定

    def test_cross_workspace_denied(self):
        _, body = _req("POST", self.base + "/api/login", body={"name": "tester", "password": "x"})
        token = body["token"]
        code, _ = _req("GET", self.base + "/api/runs?workspace=other-secret", token=token)
        self.assertEqual(code, 403)

    def test_static_offline_no_external_refs(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertNotIn('src="http', html)
        self.assertNotIn('href="http', html)


if __name__ == "__main__":
    unittest.main()
