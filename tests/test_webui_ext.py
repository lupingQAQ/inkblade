# -*- coding: utf-8 -*-
"""Web API 扩展：LLM 池/通知/模板/日历/侧问/图/黑板/情报/检索 + 闸门。"""

import json
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.users import UserStore
from inkblade.webui.server import make_server


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


class TestWebUIExt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("lead", "x", "lead", ["local-lab", "locked"])
        users.create_user("tester", "x", "tester", ["local-lab"])
        users.create_user("auditor", "x", "auditor", ["local-lab"])
        cls.users = users
        for ws in ("local-lab", "locked"):
            store = EvidenceStore(cls.root, workspace=ws)
            if ws == "local-lab":
                init_roe(store, {"level": "利用验证", "namespaces": ["ml"],
                                 "cidrs": ["10.0.0.0/8"]})
                AssetInventory(store).ingest({"services": [
                    {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
                     "port": 30000, "labels": {"app": "sglang"}}]})
                run = store.create_run("r1")
                run.add_step("sglang-admin-failopen", "needle prompt", {}, "needle")
                run.add_finding("sglang-admin-failopen", "high", "needle admin unauth",
                                "needle detail", evidence_path="steps/a.tar.gz")
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"
        cls.lead = cls._login("lead")
        cls.tester = cls._login("tester")
        cls.auditor = cls._login("auditor")

    @classmethod
    def _login(cls, name):
        code, body = _req("POST", cls.base + "/api/login",
                          body={"name": name, "password": "x"})
        assert code == 200, body
        return body["token"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def test_health_stats_and_search(self):
        code, body = _req("GET", self.base + "/api/v1/health?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        code, body = _req("GET", self.base + "/api/v1/stats?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(body["runs"], 1)
        self.assertEqual(body["findings"], 1)
        code, body = _req("GET", self.base + "/api/v1/search?workspace=local-lab&q=needle",
                          token=self.tester)
        self.assertGreaterEqual(body["result"]["count"], 2)
        code, body = _req("GET", self.base + "/api/v1/logs?workspace=local-lab",
                          token=self.tester)
        self.assertIn("lines", body)

    def test_notify_channel_lifecycle(self):
        code, body = _req("GET", self.base + "/api/v1/notify/meta?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(code, 200)
        self.assertFalse(body["meta"]["enabled"])
        payload = {"kind": "email", "name": "ops", "config": {"to": "ops@example.invalid"}}
        code, body = _req("POST", self.base + "/api/v1/notify/channels", token=self.tester,
                          body={"workspace": "local-lab", **payload})
        self.assertEqual(code, 403)
        code, body = _req("POST", self.base + "/api/v1/notify/channels", token=self.lead,
                          body={"workspace": "local-lab", **payload, "id": "ch-mail"})
        self.assertEqual(code, 200)
        _req("POST", self.base + "/api/v1/notify/enable", token=self.lead,
             body={"workspace": "local-lab", "enabled": True})
        code, body = _req("POST", self.base + "/api/v1/notify/channels/ch-mail/test",
                          token=self.lead, body={"workspace": "local-lab"})
        self.assertEqual(body["delivery"]["status"], "delivered")
        code, body = _req("PATCH", self.base + "/api/v1/notify/channels/ch-mail",
                          token=self.lead, body={"name": "renamed"})
        self.assertEqual(body["channel"]["name"], "renamed")
        code, body = _req("GET", self.base + "/api/v1/notify/channels?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(body["channels"][0]["id"], "ch-mail")
        code, _ = _req("DELETE", self.base + "/api/v1/notify/channels/ch-mail",
                       token=self.lead, body={})
        self.assertEqual(code, 200)

    def test_templates_calendar_threads(self):
        code, body = _req("POST", self.base + "/api/v1/templates/add", token=self.lead,
                          body={"workspace": "local-lab", "name": "t",
                                "chains": ["flat-network-admin-plane-weight-poison"],
                                "id": "tpl-api"})
        self.assertEqual(code, 200)
        code, body = _req("GET", self.base + "/api/v1/templates?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(body["templates"][0]["id"], "tpl-api")
        code, body = _req("POST", self.base + "/api/v1/templates/instantiate", token=self.tester,
                          body={"workspace": "local-lab", "id": "tpl-api"})
        self.assertFalse(body["plan"]["execution"]["performed"])
        code, body = _req("POST", self.base + "/api/v1/calendar/add", token=self.lead,
                          body={"workspace": "local-lab", "name": "w",
                                "start": time.time() - 1, "end": time.time() + 100,
                                "chains": ["no-such-chain"], "id": "w-api"})
        self.assertEqual(code, 200)
        code, body = _req("POST", self.base + "/api/v1/calendar/pause", token=self.lead,
                          body={"workspace": "local-lab", "id": "w-api"})
        self.assertTrue(body["window"]["paused"])
        code, body = _req("POST", self.base + "/api/v1/calendar/run-due", token=self.lead,
                          body={"workspace": "locked"})
        self.assertEqual(code, 423, body)
        code, body = _req("POST", self.base + "/api/v1/threads/ask", token=self.tester,
                          body={"workspace": "local-lab", "run": "r1",
                                "subject": "why", "body": "check auth"})
        self.assertEqual(code, 200)
        tid = body["thread"]["id"]
        code, body = _req("POST", self.base + "/api/v1/threads/reply", token=self.lead,
                          body={"workspace": "local-lab", "run": "r1", "id": tid,
                                "body": "because exposed"})
        self.assertEqual(body["thread"]["status"], "answered")
        code, body = _req("GET", self.base + f"/api/v1/threads/{tid}/events?workspace=local-lab&run=r1",
                          token=self.auditor)
        self.assertEqual(len(body["thread"]["events"]), 2)

    def test_graph_blackboard_intel_and_workers(self):
        code, body = _req("POST", self.base + "/api/v1/graph/snapshot", token=self.lead,
                          body={"workspace": "local-lab", "run": "r1", "label": "api"})
        self.assertEqual(code, 200)
        sid = body["snapshot"]["id"]
        code, body = _req("GET", self.base + f"/api/v1/graph/ui?workspace=local-lab&id={sid}",
                          token=self.tester)
        self.assertTrue(body["graph"]["nodes"])
        code, body = _req("POST", self.base + "/api/v1/blackboard/pin", token=self.lead,
                          body={"workspace": "local-lab", "kind": "note",
                                "text": "focus sglang", "ref": "api-note"})
        self.assertEqual(code, 200)
        code, body = _req("GET", self.base + "/api/v1/blackboard/context?workspace=local-lab",
                          token=self.tester)
        self.assertGreaterEqual(body["context"]["count"], 1)
        code, body = _req("POST", self.base + "/api/v1/intel/add", token=self.tester,
                          body={"workspace": "local-lab", "kind": "clue", "label": "c1",
                                "value": "seen in logs", "mode": "metadata"})
        self.assertEqual(code, 200)
        code, body = _req("GET", self.base + "/api/v1/intel?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(len(body["intel"]), 1)
        code, body = _req("POST", self.base + "/api/v1/explorer/execute", token=self.lead,
                          body={"workspace": "local-lab", "id": "ghost", "workers": 99})
        self.assertEqual(code, 409)
        self.assertIn("workers", body.get("error", ""))


    def test_llm_pool_api(self):
        code, body = _req("GET", self.base + "/api/v1/llm/pool?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(code, 200)
        self.assertFalse(body["pool"]["enabled"])
        code, _ = _req("POST", self.base + "/api/v1/llm/pool/add", token=self.tester,
                       body={"workspace": "local-lab", "base_url": "http://127.0.0.1:9/v1",
                             "model": "m"})
        self.assertEqual(code, 403)
        code, body = _req("POST", self.base + "/api/v1/llm/pool/add", token=self.lead,
                          body={"workspace": "local-lab", "id": "ep-api",
                                "base_url": "http://127.0.0.1:9/v1", "model": "m",
                                "weight": 1})
        self.assertEqual(code, 200)
        code, body = _req("POST", self.base + "/api/v1/llm/pool/enable", token=self.lead,
                          body={"workspace": "local-lab", "enabled": True})
        self.assertTrue(body["enabled"])
        code, body = _req("GET", self.base + "/api/v1/llm/pool?workspace=local-lab",
                          token=self.tester)
        self.assertTrue(body["pool"]["enabled"])
        code, body = _req("GET", self.base + "/api/v1/llm/records?workspace=local-lab",
                          token=self.tester)
        self.assertEqual(body["records"], [])
        code, body = _req("GET", self.base + "/api/v1/tokens/daily?workspace=local-lab",
                          token=self.tester)
        self.assertIn("days", body)


if __name__ == "__main__":
    unittest.main()
