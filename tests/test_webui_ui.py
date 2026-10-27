"""Web UI first screen and static asset contract.

Covers the real-environment onboarding surface:
- no demo/mock/trial copy in the shipped page, script or stylesheet;
- login form plus all ten views are present and served;
- static assets are served by the webui server with correct content types;
- a workspace login lists runs and the steps endpoint feeds the DAG.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.users import UserStore
from inkblade.webui.server import make_server

REPO = Path(__file__).resolve().parents[1]
STATIC = REPO / "inkblade" / "webui" / "static"
FORBIDDEN = ("demo", "mock", "trial")


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, payload, ctype
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("Content-Type", "")


def _json(method, url, token=None, body=None):
    code, payload, _ = _req(method, url, token=token, body=body)
    return code, json.loads(payload.decode("utf-8") or "{}")


class TestWebuiUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("demo-lead", "demo-pass", "lead", ["demo-lab"])
        store = EvidenceStore(cls.root, workspace="demo-lab")
        run = store.create_run("demo-20261027-203000")
        run.add_step("recon-phase", "probe --collect", {"actor": "demo-lead"},
                     "probe[reference] recon-phase: 2 finding(s), 1 artifact(s)")
        run.add_step("exposure-check", "probe --http", {"actor": "demo-lead"},
                     "probe[reference] exposure-check: 1 finding(s), 1 artifact(s)")
        run.add_finding("recon-phase", "high", "管理面未鉴权",
                        "授权范围内只读探测确认管理面可访问。", "steps/recon-phase.tar.gz")
        run.add_finding("exposure-check", "medium", "调试端口暴露",
                        "只读探测发现调试端口。", "steps/exposure-check.tar.gz")
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
        code, body = _json("POST", self.base + "/api/login",
                           body={"name": "demo-lead", "password": "demo-pass"})
        self.assertEqual(code, 200, body)
        return body["token"]

    def test_root_is_served_and_has_login_plus_views(self):
        code, payload, ctype = _req("GET", self.base + "/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", ctype)
        html = payload.decode("utf-8")
        for marker in ('id="login-form"', 'id="onboarding"', 'id="dashboard"',
                       'id="views"', 'data-view="dag"', 'data-view="schedules"',
                       'class="login-subtitle"'):
            self.assertIn(marker, html)
        for view in ("dag", "chain", "timeline", "evidence", "report",
                     "rules", "assets", "drift", "approvals", "schedules"):
            self.assertIn(f'id="view-{view}"', html)
        # 登录页只保留品牌 + 登录卡 + 一行副标题
        for removed in ('id="onboarding-steps"', 'id="kube-file"', 'id="kube-path"',
                        'id="connect-panel"', '三步接入', 'CONNECT A REAL CLUSTER'):
            self.assertNotIn(removed, html)
        self.assertNotIn("kubeconfig", html.lower())
        self.assertNotIn("demo-guide", html)
        lowered = html.lower()
        for word in FORBIDDEN:
            self.assertNotIn(word, lowered, f"首屏仍包含禁用词 {word!r}")

    def test_static_assets_served_with_content_types(self):
        expected = {
            "/style.css": "text/css",
            "/app.js": "text/javascript",
            "/vendor/react.production.min.js": "text/javascript",
            "/vendor/react-dom.production.min.js": "text/javascript",
            "/vendor/reactflow.umd.min.js": "text/javascript",
            "/vendor/reactflow.style.css": "text/css",
        }
        for path, ctype in expected.items():
            with self.subTest(path=path):
                code, payload, served = _req("GET", self.base + path)
                self.assertEqual(code, 200, path)
                self.assertIn(ctype, served, path)
                self.assertGreater(len(payload), 1000, path)

    def test_static_sources_have_no_forbidden_copy(self):
        for name in ("index.html", "app.js", "style.css"):
            text = (STATIC / name).read_text(encoding="utf-8")
            lowered = text.lower()
            for word in FORBIDDEN:
                self.assertNotIn(word, lowered, f"{name} still contains {word!r}")
            self.assertNotIn("demo-guide", lowered, name)

    def test_app_js_has_no_external_refs_and_parses(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertNotRegex(js, re.compile(r"(?:fetch|src)\s*\(\s*['\"]https?://", re.I))
        self.assertIn("renderDag", js)
        self.assertIn("api/v1/steps", js)
        self.assertIn("api/v1/report", js)
        node = shutil.which("node")
        if node:
            proc = subprocess.run([node, "--check", str(STATIC / "app.js")],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_login_lists_runs_and_steps_for_dag(self):
        token = self._token()
        code, body = _json("GET", self.base + "/api/runs?workspace=demo-lab", token=token)
        self.assertEqual(code, 200, body)
        self.assertIn(self.run_name, body["runs"])
        code, steps = _json("GET", self.base + "/api/v1/steps?workspace=demo-lab&run="
                            + self.run_name, token=token)
        self.assertEqual(code, 200, steps)
        self.assertGreaterEqual(steps["count"], 2)
        keys = {s["step_key"] for s in steps["steps"]}
        self.assertEqual(keys, {"recon-phase", "exposure-check"})
        self.assertTrue(all(s.get("started_at") for s in steps["steps"]))

    def test_probe_first_connect_panel_commands(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        for command in (
            "inkblade channel listen --host 0.0.0.0 --port 8443",
            "./inkblade-probe reverse --host <controller-host> --port 8443",
            "inkblade probe list --workspace ./work",
            "inkblade session open --mode foothold --target <target> --pod <pod>",
            "inkblade probe deploy --session <id> --via rce --binary ./inkblade-probe-linux-amd64",
            "inkblade probe deploy --session <id> --via sa-token --binary ./inkblade-probe-linux-amd64",
            "inkblade session open --mode kubeconfig --workspace ./work --kubeconfig ~/.kube/config",
        ):
            self.assertIn(command, js)
        for label in ("已有探针", "首次投放", "kubeconfig 批量投放", "connect-panel"):
            self.assertIn(label, js)
        self.assertIn("function cmdRow", js)
        self.assertIn("copyText", js)

    def test_unknown_static_asset_is_404(self):
        code, _, _ = _req("GET", self.base + "/vendor/missing.js")
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
