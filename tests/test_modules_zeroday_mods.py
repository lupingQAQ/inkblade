"""tests/test_modules_zeroday_mods.py — 零日级漏洞模块族（6 模块，已公开）对 mock 靶场的两态断言。

- vulnerable：fingerprint（GET /__routes__）命中 dify-agent / open-webui 路由 + 无凭据（或伪造凭据）动作成功
  → finding(is_zeroday=True)
- fixed：目标存在但动作被拒（401/403）→ 零发现
- 6 模块均为公开模块（private=false）：零日闸门不再作为门槛；通用 private 闸门由
  tests/test_runner_zeroday.py 覆盖，此处只测模块自身两态与公开标记。
"""
import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from lab.mock_targets import start_all
from inkblade.core.registry import load_modules

ROOT = Path(__file__).resolve().parents[1]
MODULES_DIR = ROOT / "inkblade" / "modules"

ZERODAY_KEYS = (
    "dify-control-plane-failopen",
    "dify-stub-token-forgery",
    "dify-snapshot-cross-tenant-theft",
    "dify-local-sandbox-unauth-rce",
    "open-webui-code-execute-rce",
    "open-webui-indirect-injection-exec",
)


def load_run(key):
    spec = spec_from_file_location(f"zdmod_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _NotFoundHandler(BaseHTTPRequestHandler):
    """无 /__routes__ 的裸目标：一切请求 404（fingerprint 必须失败 → 不进入动作分支）。"""

    def log_message(self, fmt, *args):
        return

    def _reply(self):
        body = b'{"error": "not found"}'
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self._reply()


@contextmanager
def bare_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _NotFoundHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


class ZerodayTwoStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def test_vulnerable_state_detected(self):
        for key in ZERODAY_KEYS:
            with self.subTest(module=key):
                result = load_run(key).run(
                    {"marker": "INKBLADE-zd-test"}, {"base_url": self.vulnerable.url("/")}
                )
                self.assertTrue(result["findings"], "vulnerable 态必须检出")
                finding = result["findings"][0]
                self.assertTrue(finding.get("is_zeroday"), "零日发现必须带 is_zeroday")
                self.assertIn(finding["sev"], ("critical", "high"))
                for field in ("title", "detail", "evidence", "fix"):
                    self.assertTrue(finding.get(field), f"{key} finding 缺 {field}")

    def test_fixed_state_clean(self):
        for key in ZERODAY_KEYS:
            with self.subTest(module=key):
                result = load_run(key).run(
                    {"marker": "INKBLADE-zd-test"}, {"base_url": self.fixed.url("/")}
                )
                self.assertEqual(result["findings"], [])

    def test_fingerprint_gate_requires_routes_manifest(self):
        """无 /__routes__（非实验室语义目标）：fingerprint 失败 → 零发现、不发动作。"""
        with bare_server() as url:
            result = load_run("dify-control-plane-failopen").run(
                {"marker": "INKBLADE-zd-test"}, {"base_url": url}
            )
        self.assertEqual(result["findings"], [])
        self.assertIn("fingerprint", result["summary"])

    def test_missing_base_url_rejected(self):
        with self.assertRaises(ValueError):
            load_run("dify-local-sandbox-unauth-rce").run({}, {})

    def test_public_class_modules_are_not_private(self):
        """6 个零日级模块已公开：不得标记 private（否则会被零日闸门错误隐藏）。"""
        mods = load_modules(MODULES_DIR)
        for key in ZERODAY_KEYS:
            with self.subTest(module=key):
                self.assertIn(key, mods)
                self.assertFalse(mods[key].private, f"{key} 已公开，必须 private=false/缺省")

    def test_module_specific_evidence(self):
        # dify 控制面：证据锚定路由
        result = load_run("dify-control-plane-failopen").run(
            {"marker": "INKBLADE-zd-test"}, {"base_url": self.vulnerable.url("/")}
        )
        self.assertIn("/api/v1/bindings", json.dumps(result["findings"], ensure_ascii=False))
        # open-webui 共享沙箱：证据含 mock stdout 标记
        result = load_run("open-webui-code-execute-rce").run(
            {"marker": "INKBLADE-zd-test"}, {"base_url": self.vulnerable.url("/")}
        )
        self.assertIn("B-was-here", result["findings"][0]["evidence"])
        # dify 存根令牌伪造：语义锚定「伪造」
        result = load_run("dify-stub-token-forgery").run(
            {"marker": "INKBLADE-zd-test"}, {"base_url": self.vulnerable.url("/")}
        )
        head = result["findings"][0]
        self.assertIn("伪造", head["title"] + head["detail"])


if __name__ == "__main__":
    unittest.main()
