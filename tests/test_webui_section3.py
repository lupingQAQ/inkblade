# -*- coding: utf-8 -*-
"""只读视图接口：/api/v1/agent/{policy,observations,cost}（不新增写路由）。"""

import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import Explorer
from inkblade.core.roe import init_roe
from inkblade.core.users import Session, UserStore
from inkblade.webui.server import make_server

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


class TestAgentViewAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("lead", "x", "lead", ["local-lab"])
        cls.store = EvidenceStore(cls.root, workspace="local-lab")
        init_roe(cls.store, {"level": "利用验证", "namespaces": ["ml"],
                            "cidrs": ["10.0.0.0/8"]})
        AssetInventory(cls.store).ingest({"services": [
            {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
             "port": 30000, "labels": {"app": "sglang"}}]}, source="seed")
        Explorer(cls.store, modules_dir=MODULES_DIR).propose(
            Session(None, "lead", "lead", ["local-lab"], "t"))
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"
        code, body = _req("POST", cls.base + "/api/login",
                          body={"name": "lead", "password": "x"})
        assert code == 200, body
        cls.token = body["token"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def test_policy_catalog(self):
        code, body = _req("GET", self.base + "/api/v1/agent/policy?workspace=local-lab",
                          token=self.token)
        self.assertEqual(code, 200)
        self.assertEqual([x["key"] for x in body["levels"]], ["L0", "L1", "L2", "L3"])
        self.assertTrue(body["strategies"])
        self.assertTrue(body["readonly"])

    def test_observations_readonly_view(self):
        code, body = _req("GET",
                          self.base + "/api/v1/agent/observations?workspace=local-lab&limit=10",
                          token=self.token)
        self.assertEqual(code, 200)
        self.assertTrue(body["observations"])
        for obs in body["observations"]:
            self.assertIn("evidence", obs)
            self.assertIn("next", obs)
            self.assertIn("action", obs)
            self.assertIn("result", obs)

    def test_cost_view(self):
        code, body = _req("GET", self.base + "/api/v1/agent/cost?workspace=local-lab",
                          token=self.token)
        self.assertEqual(code, 200)
        self.assertIn("budget", body)
        self.assertIn("proposal", body)
        self.assertGreater(body["budget"]["tokens"], 0)

    def test_requires_auth(self):
        code, body = _req("GET", self.base + "/api/v1/agent/policy?workspace=local-lab")
        self.assertEqual(code, 401)

    def test_unknown_agent_subpath_404(self):
        code, body = _req("GET", self.base + "/api/v1/agent/unknown?workspace=local-lab",
                          token=self.token)
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
