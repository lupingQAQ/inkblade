# -*- coding: utf-8 -*-
"""流量录制与回放（XBow 对标 ④）测试：ingest/traffic 表/dry 计划/live 重放断言。"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import traffic as traffic_mod
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.users import Session


def _session(role="tester"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class _MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/probe"):
            self._send(200, {"ok": True})
        else:
            self._send(404, {})

    def do_POST(self):
        self._send(200, {"applied": True})


class TestTraffic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        self.run = self.store.create_run("run-traffic")
        # 造模块 trace 文件（与模块 Trace 落盘格式一致）
        traces = Path(self.run.dir) / "traces"
        traces.mkdir(parents=True, exist_ok=True)
        (traces / "demo-probe.json").write_text(json.dumps({
            "module": "demo-probe",
            "entries": [
                {"ts": 1.0, "method": "GET", "url": f"http://127.0.0.1:{self.port}/probe",
                 "body": None, "headers": {}, "status": 200, "response": {"ok": True}},
                {"ts": 1.1, "method": "POST", "url": f"http://127.0.0.1:{self.port}/probe",
                 "body": {"x": 1}, "headers": {"Authorization": "Bearer t"},
                 "status": 200, "response": {"applied": True}},
            ],
        }, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ingest_run(self):
        counts = traffic_mod.ingest_run(self.run)
        self.assertEqual(counts, {"demo-probe": 2})
        entries = traffic_mod.list_traffic(self.store, "run-traffic")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["method"], "GET")
        self.assertTrue(entries[0]["sha256"])
        # 幂等：重复 ingest 不翻倍
        traffic_mod.ingest_run(self.run)
        self.assertEqual(len(traffic_mod.list_traffic(self.store, "run-traffic")), 2)

    def test_module_filter(self):
        traffic_mod.ingest_run(self.run)
        self.assertEqual(len(traffic_mod.list_traffic(self.store, "run-traffic",
                                                      module="demo-probe")), 2)
        self.assertEqual(traffic_mod.list_traffic(self.store, "run-traffic",
                                                  module="other"), [])

    def test_replay_dry_plan(self):
        traffic_mod.ingest_run(self.run)
        plan = traffic_mod.replay_plan(self.store, "run-traffic")
        self.assertEqual(plan["mode"], "dry")
        self.assertEqual(plan["count"], 2)
        self.assertEqual(plan["assertions"][0]["expect_status"], 200)

    def test_replay_dry_requires_traffic(self):
        empty = self.store.create_run("run-empty")
        with self.assertRaises(traffic_mod.TrafficError):
            traffic_mod.replay_plan(self.store, "run-empty")

    def test_replay_live_requires_roe_and_permission(self):
        traffic_mod.ingest_run(self.run)
        with self.assertRaises(traffic_mod.ReplayLocked):
            traffic_mod.replay(self.store, _session(), "run-traffic", live=True)  # ROE 未签
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["127.0.0.0/8"]})
        with self.assertRaises(traffic_mod.ReplayLocked):
            traffic_mod.replay(self.store, Session(None, "a", "auditor", ["local-lab"], "t"),
                               "run-traffic", live=True)  # auditor 无 execute

    def test_replay_live_assertions_and_audit(self):
        traffic_mod.ingest_run(self.run)
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["127.0.0.0/8"]})
        out = traffic_mod.replay(self.store, _session(), "run-traffic", live=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 2)
        self.assertTrue(all(r["actual_status"] == 200 for r in out["results"]))
        # 审计落库
        rows = self.run.query("SELECT action, target, result FROM actions WHERE action='replay'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], "ok")

    def test_ingest_store_sweeps_all_runs(self):
        traffic_mod.ingest_run(self.run)
        swept = traffic_mod.ingest_store(self.store)
        self.assertIn("run-traffic", swept)


if __name__ == "__main__":
    unittest.main()
