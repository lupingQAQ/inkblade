# -*- coding: utf-8 -*-
"""XBow 对标 REST API（A⑥）测试：/api/v1/* 全量端点 + 授权/审批语义。"""

import json
import time
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.discovery import AssetInventory
from trident.core.evidence import EvidenceStore
from trident.core.users import UserStore
from trident.webui.server import make_server

MODULES_DIR = Path(__file__).resolve().parents[1] / "trident" / "modules"
SEEDS = {"services": [{"name": "sglang-admin", "namespace": "ml", "addr": "127.0.0.1", "port": 30000,
                       "labels": {"app": "sglang"}}]}

_FIXTURE_MODULE_JSON = {
    "key": "sglang-admin-failopen", "name": {"zh": "SGLang 管理面 fail-open（API 测试件）",
                                             "en": "SGLang Admin Fail-open (API fixture)"},
    "series": "横向利用",
    "description": "API 测试件：与真实模块同键，探测不可达靶场返回 no-target。",
    "min_level": "利用验证", "writes": False, "requires": [],
    "params_schema": {"target": "目标基址"},
}
_FIXTURE_RUN_PY = (
    "def run(ctx, params):\n"
    "    if not params.get('target'):\n"
    "        return {'summary': 'no-target', 'artifacts': [], 'findings': []}\n"
    "    return {'summary': 'fixture-probe-unreachable', 'artifacts': [], 'findings': []}\n"
)


def _make_fixture_modules(root: Path):
    d = root / "modules" / "sglang-admin-failopen"
    d.mkdir(parents=True, exist_ok=True)
    (d / "module.json").write_text(json.dumps(_FIXTURE_MODULE_JSON, ensure_ascii=False),
                                   encoding="utf-8")
    (d / "run.py").write_text(_FIXTURE_RUN_PY, encoding="utf-8")


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


class TestApiV1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        _make_fixture_modules(cls.root)  # explorer 候选需要根目录 modules/
        users = UserStore(cls.root / "users.json")
        users.create_user("lead1", "x", "lead", ["local-lab"])
        users.create_user("tester1", "x", "tester", ["local-lab"])
        cls.users = users
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def _login(self, name="lead1", pw="x"):
        _, body = _req("POST", self.base + "/api/login", body={"name": name, "password": pw})
        return body["token"]

    # ---------- assets ----------
    def test_assets_discover_and_list(self):
        tok = self._login()
        code, body = _req("POST", self.base + "/api/v1/assets/discover", token=tok,
                          body={"workspace": "local-lab", "seeds": SEEDS, "source": "api-test"})
        self.assertEqual(code, 200)
        self.assertEqual(len(body["diff"]["added"]), 1)
        code, body = _req("GET", self.base + "/api/v1/assets?workspace=local-lab&kind=service",
                          token=tok)
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["assets"][0]["product"], "sglang")
        self.assertEqual(len(body["graph"]["nodes"]), 1)

    def test_assets_discover_bad_seeds(self):
        tok = self._login()
        code, body = _req("POST", self.base + "/api/v1/assets/discover", token=tok,
                          body={"workspace": "local-lab", "seeds": {}})
        self.assertEqual(code, 400)

    def test_assets_requires_login(self):
        code, _ = _req("GET", self.base + "/api/v1/assets?workspace=local-lab")
        self.assertEqual(code, 401)

    # ---------- explorer ----------
    def test_explorer_full_lifecycle(self):
        lead = self._login()
        tester = self._login("tester1")
        _req("POST", self.base + "/api/v1/assets/discover", token=lead,
             body={"workspace": "local-lab", "seeds": SEEDS})
        # 候选受模块级别闸门约束：先签 ROE（lead 签署）
        code, _ = _req("POST", self.base + "/api/v1/consent/sign", token=lead,
                       body={"workspace": "local-lab",
                             "fields": {"level": "利用验证", "namespaces": ["ml"],
                                        "cidrs": ["127.0.0.0/8"]}})
        self.assertEqual(code, 200)
        code, body = _req("POST", self.base + "/api/v1/explorer/propose", token=lead,
                          body={"workspace": "local-lab"})
        self.assertEqual(code, 200)
        pid = body["proposal"]["id"]
        self.assertEqual(body["proposal"]["status"], "pending_approval")
        code, body = _req("GET", self.base + "/api/v1/explorer?workspace=local-lab", token=lead)
        self.assertEqual(len(body["proposals"]), 1)
        self.assertIn("llm_available", body)
        # tester 不可批准
        code, _ = _req("POST", self.base + "/api/v1/explorer/approve", token=tester,
                       body={"workspace": "local-lab", "id": pid})
        self.assertEqual(code, 403)
        # lead 批准后执行：撤销 ROE → 423（与 /api/execute 同一把锁）
        code, _ = _req("POST", self.base + "/api/v1/explorer/approve", token=lead,
                       body={"workspace": "local-lab", "id": pid})
        self.assertEqual(code, 200)
        (EvidenceStore(self.root, workspace="local-lab").ws_dir / "consent.json").unlink()
        code, _ = _req("POST", self.base + "/api/v1/explorer/execute", token=tester,
                       body={"workspace": "local-lab", "id": pid})
        self.assertEqual(code, 423)
        # 重签 ROE 后执行可用（靶场不通也须逐动作记录 failed 而非 5xx）
        code, _ = _req("POST", self.base + "/api/v1/consent/sign", token=lead,
                       body={"workspace": "local-lab",
                             "fields": {"level": "利用验证", "namespaces": ["ml"],
                                        "cidrs": ["127.0.0.0/8"]}})
        self.assertEqual(code, 200)
        code, body = _req("POST", self.base + "/api/v1/explorer/execute", token=tester,
                          body={"workspace": "local-lab", "id": pid})
        self.assertEqual(code, 200)
        self.assertIn("results", body)

    # ---------- scheduler ----------
    def test_scheduler_add_list_run_due(self):
        lead = self._login()
        # run-due 须 ROE：先签署（该工作区独立于 explorer 用例）
        code, _ = _req("POST", self.base + "/api/v1/consent/sign", token=lead,
                       body={"workspace": "local-lab",
                             "fields": {"level": "利用验证", "namespaces": ["ml"],
                                        "cidrs": ["127.0.0.0/8"]}})
        self.assertEqual(code, 200)
        code, body = _req("POST", self.base + "/api/v1/scheduler/add", token=lead,
                          body={"workspace": "local-lab", "interval_seconds": 1,
                                "chains": ["no-such-chain"]})
        self.assertEqual(code, 200)
        sid = body["schedule"]["id"]
        code, body = _req("GET", self.base + "/api/v1/scheduler?workspace=local-lab", token=lead)
        self.assertEqual(len(body["schedules"]), 1)
        time.sleep(1.2)  # interval=1s：确保到期
        code, body = _req("POST", self.base + "/api/v1/scheduler/run-due", token=lead,
                          body={"workspace": "local-lab"})
        self.assertEqual(code, 200)
        self.assertIn(sid, body["due"])
        code, _ = _req("POST", self.base + "/api/v1/scheduler/remove", token=lead,
                       body={"workspace": "local-lab", "id": sid})
        self.assertEqual(code, 200)

    def test_scheduler_add_requires_lead(self):
        tester = self._login("tester1")
        code, _ = _req("POST", self.base + "/api/v1/scheduler/add", token=tester,
                       body={"workspace": "local-lab", "interval_seconds": 60, "chains": ["x"]})
        self.assertEqual(code, 403)

    def test_scheduler_add_bad_cron(self):
        lead = self._login()
        code, _ = _req("POST", self.base + "/api/v1/scheduler/add", token=lead,
                       body={"workspace": "local-lab", "cron": "bad", "chains": ["x"]})
        self.assertEqual(code, 400)

    # ---------- traffic / consent / zeroday / rules ----------
    def test_consent_sign_requires_lead_and_level(self):
        tester = self._login("tester1")
        code, _ = _req("POST", self.base + "/api/v1/consent/sign", token=tester,
                       body={"workspace": "local-lab", "fields": {"level": "只读侦察"}})
        self.assertEqual(code, 403)
        lead = self._login()
        code, _ = _req("POST", self.base + "/api/v1/consent/sign", token=lead,
                       body={"workspace": "local-lab", "fields": {}})
        self.assertEqual(code, 400)  # level 缺失（不落任何状态）

    def test_consent_status(self):
        tok = self._login()
        code, body = _req("GET", self.base + "/api/v1/consent?workspace=local-lab", token=tok)
        self.assertEqual(code, 200)
        self.assertIn(body["status"], ("absent", "complete"))

    def test_zeroday_status_and_enable_gate(self):
        lead = self._login()
        tester = self._login("tester1")
        code, body = _req("GET", self.base + "/api/v1/zeroday?workspace=local-lab", token=lead)
        self.assertEqual(code, 200)
        self.assertIn("enabled", body)
        code, _ = _req("POST", self.base + "/api/v1/zeroday/enable", token=tester,
                       body={"workspace": "local-lab"})
        self.assertEqual(code, 403)
        code, _ = _req("POST", self.base + "/api/v1/zeroday/enable", token=lead,
                       body={"workspace": "local-lab"})
        self.assertEqual(code, 200)

    def test_traffic_replay_dry_and_missing(self):
        tok = self._login()
        # 无录制流量 → 404
        store = EvidenceStore(self.root, workspace="local-lab")
        store.create_run("api-run-empty")
        code, _ = _req("POST", self.base + "/api/v1/traffic/replay", token=tok,
                       body={"workspace": "local-lab", "run": "api-run-empty"})
        self.assertEqual(code, 404)
        # run 缺失参数 → 400
        code, _ = _req("POST", self.base + "/api/v1/traffic/replay", token=tok,
                       body={"workspace": "local-lab"})
        self.assertEqual(code, 400)
        # 造一条录制流量 → dry 200
        run = store.open_run("api-run-empty")
        run.record_traffic("m", [{"method": "GET", "url": "http://127.0.0.1:1/x",
                                  "headers": {}, "status": 200, "ts": 1.0}])
        code, body = _req("POST", self.base + "/api/v1/traffic/replay", token=tok,
                          body={"workspace": "local-lab", "run": "api-run-empty"})
        self.assertEqual(code, 200)
        self.assertEqual(body["mode"], "dry")
        # GET /api/v1/traffic
        code, body = _req("GET", self.base + "/api/v1/traffic?workspace=local-lab&run=api-run-empty",
                          token=tok)
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 1)

    def test_rules_endpoint(self):
        tok = self._login()
        code, body = _req("GET", self.base + "/api/v1/rules?workspace=local-lab", token=tok)
        self.assertEqual(code, 200)
        self.assertIn("ok", body)

    def test_cross_workspace_denied(self):
        tok = self._login()
        code, _ = _req("GET", self.base + "/api/v1/assets?workspace=other-ws", token=tok)
        self.assertEqual(code, 403)

    def test_unknown_v1_route_404(self):
        tok = self._login()
        code, _ = _req("GET", self.base + "/api/v1/nope", token=tok)
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
