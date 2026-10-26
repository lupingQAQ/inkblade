# -*- coding: utf-8 -*-
"""模块 payload 变体接线（弹药 B②落地）测试：两代表模块 finding 携带变体命中记录。"""

import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


class _VariantHandler(BaseHTTPRequestHandler):
    """sglang/vllm 双面靶场：主路由 200 + 变体路由（路径变形）部分放行。"""

    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path in ("/pause", "/pause/", "/Pause", "/pau%73e", "/pau%2573e"):
            self._send(200, {"applied": True})
        elif self.path == "/resume":
            self._send(200, {"resumed": True})
        else:
            self._send(404, {})

    def do_GET(self):
        if self.path.startswith("/plugins/list"):
            self._send(200, {"plugins": [{"name": "mock-plugin"}]})
        elif self.path.startswith("/v1/models"):
            self._send(401, {"error": "api key required"})
        else:
            self._send(404, {})

    def do_PUT(self):
        self._send(405, {})


def _load(key: str):
    spec = importlib.util.spec_from_file_location(
        f"variant_selftest_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ctx(key: str, tmp: Path):
    store = EvidenceStore(tmp, workspace="local-lab")
    run = store.create_run(f"variant-{key}")
    return {"store": store, "run": run, "marker": "INKBLADE-variant",
            "backup": BackupManager(store, run), "actor": "tester",
            "meta": {"key": key, "writes": False}}


class TestModuleVariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _VariantHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _run(self, key: str) -> dict:
        with TemporaryDirectory() as td:
            result = _load(key).run(_ctx(key, Path(td)),
                                    {"target": f"http://127.0.0.1:{self.port}",
                                     "mode": "probe-only"})
        return result

    def test_sglang_finding_has_payload_variants(self):
        result = self._run("sglang-admin-failopen")
        self.assertTrue(result["findings"], "sglang 主探针应命中")
        detail = json.loads(result["findings"][0]["detail"])
        self.assertIn("payload_variants", detail)
        variants = detail["payload_variants"]
        self.assertGreaterEqual(len(variants), 2)
        # 变体命中差分：trailing-slash/case/pct 靶场放行 → 200；PUT → 405
        statuses = {v["variant"]: v["status"] for v in variants}
        self.assertIn(200, set(statuses.values()))
        self.assertIn("variants=", result["summary"])

    def test_vllm_finding_has_payload_variants(self):
        result = self._run("vllm-plugin-auth-bypass")
        self.assertTrue(result["findings"], "vllm 主探针应命中")
        detail = json.loads(result["findings"][0]["detail"])
        self.assertIn("payload_variants", detail)
        self.assertGreaterEqual(len(detail["payload_variants"]), 2)

    def test_no_target_short_circuits(self):
        with TemporaryDirectory() as td:
            result = _load("sglang-admin-failopen").run(
                _ctx("sglang-admin-failopen", Path(td)), {"mode": "probe-only"})
        self.assertEqual(result["summary"], "no-target")


if __name__ == "__main__":
    unittest.main()
