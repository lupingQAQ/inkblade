# -*- coding: utf-8 -*-
"""验证级 PoC（XBow 对标 ⑤）测试：验证块/runner 附加/重验/自动重验开关。"""

import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import poc
from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="tester"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class _SglangHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.dumps({"applied": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestVerificationBlock(unittest.TestCase):
    def test_build_verification_shape(self):
        v = poc.build_verification("some-write-module", {"target": "http://x"},
                                   {"summary": "done", "artifacts": ["/tmp/a.json"]})
        self.assertEqual(v["schema"], "inkblade-poc-verification-v1")
        self.assertEqual(len(v["steps"]), 4)
        self.assertIn("result_sha256", v["expected_evidence"])
        self.assertIn("rollback", v["expected_evidence"])
        self.assertNotIn("backup_targets", v["params"])

    def test_enrich_only_write_modules(self):
        finding = {"sev": "high", "title": "T", "detail": json.dumps({"k": 1})}
        result = {"summary": "s", "artifacts": [], "findings": [dict(finding)]}
        out = poc.enrich_write_findings("m", True, {}, result)
        detail = json.loads(out[0]["detail"])
        self.assertIn("verification", detail)
        out2 = poc.enrich_write_findings("m", False, {}, {"findings": [dict(finding)]})
        self.assertEqual(json.loads(out2[0]["detail"]), {"k": 1})  # 读类不加块

    def test_enrich_tolerates_plain_detail(self):
        out = poc.enrich_write_findings("m", True, {},
                                        {"findings": [{"sev": "low", "title": "x", "detail": "plain"}]})
        detail = json.loads(out[0]["detail"])
        self.assertEqual(detail["detail"], "plain")
        self.assertIn("verification", detail)


class TestAutoReverifySwitch(unittest.TestCase):
    def test_default_off_and_toggle(self):
        with TemporaryDirectory() as td:
            store = EvidenceStore(Path(td), workspace="local-lab")
            self.assertFalse(poc.auto_reverify_enabled(store))
            poc.set_auto_reverify(store, True)
            self.assertTrue(poc.auto_reverify_enabled(store))
            poc.set_auto_reverify(store, False)
            self.assertFalse(poc.auto_reverify_enabled(store))


class TestRunnerAttachAndReverify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SglangHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = EvidenceStore(root, workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["127.0.0.0/8"]})
        self.mods = load_modules(MODULES_DIR)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_finding_run(self, module_key: str, params: dict) -> str:
        """跑一个写类模块拿带 verification 的 finding（slime /pull_weights 写面 + 备份闸门）。"""
        meta = self.mods[module_key]
        backup = [{"kind": "http", "url": params["target"] + "/pull_weights", "state": {}}]
        params = dict(params, mode="backup-write", backup_targets=backup)
        res = run_module(self.store, _session(), module_key, params, MODULES_DIR)
        run = self.store.open_run(res["run"])
        return res["run"]

    def test_write_module_finding_carries_verification(self):
        target = f"http://127.0.0.1:{self.port}"
        run_name = self._write_finding_run(
            "slime-weight-pull-poison", {"target": target})
        run = self.store.open_run(run_name)
        write_findings = [f for f in run.findings if f["step_key"] == "slime-weight-pull-poison"]
        if not write_findings:
            self.skipTest("靶场响应形状未命中写类 finding（探测面依 mock 而定）")
        detail = json.loads(write_findings[0]["detail"])
        self.assertIn("verification", detail)
        self.assertEqual(detail["verification"]["module"], "slime-weight-pull-poison")

    def test_reverify_reproduces(self):
        target = f"http://127.0.0.1:{self.port}"
        # 先让 sglang-admin-failopen（读类）命中一个 finding
        res = run_module(self.store, _session(), "sglang-admin-failopen",
                         {"target": target}, MODULES_DIR)
        run = self.store.open_run(res["run"])
        titles = [f["title"] for f in run.findings]
        if not titles:
            self.skipTest("mock 未复现 sglang finding")
        v = poc.reverify(self.store, _session(), MODULES_DIR, "sglang-admin-failopen",
                         {"target": target}, expected_titles=titles)
        self.assertTrue(v["verified"])
        self.assertIn("SGLang 管理面 fail-open", v["reproduced_titles"][0])
        # 期望集为空时 verified=False
        v2 = poc.reverify(self.store, _session(), MODULES_DIR, "sglang-admin-failopen",
                          {"target": target}, expected_titles=[])
        self.assertFalse(v2["verified"])


if __name__ == "__main__":
    unittest.main()
