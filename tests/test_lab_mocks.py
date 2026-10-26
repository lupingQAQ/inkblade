"""tests/test_lab_mocks.py — 实验室 mock 靶场两态断言（表驱动）。

每条路由在 vulnerable / fixed 两模式下断言状态码；
另含写盘边界（仅 Server.root）、IMDS 令牌/请求头流程与 Server 生命周期测试。
自测仅连接 127.0.0.1。
"""
import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.mock_targets import ADMIN_TOKEN, start_all


def request(method, url, body=None, headers=None):
    """发一次 HTTP 请求，返回 (status, payload)；payload 能解析 JSON 就解析。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return status, payload


# 表驱动用例：name/service/method/path/body/headers + 两模式期望状态码。
# /v1/models 同路径承载 vllm 对照面与 djev 中继面，用 X-Mock-Service 头消歧（缺省 djev）。
CASES = [
    {"name": "sglang 磁盘权重更新", "service": "sglang", "method": "POST", "path": "/update_weights_from_disk", "body": {}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "sglang 暂停推理", "service": "sglang", "method": "POST", "path": "/pause", "body": {}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "sglang 冻结权重", "service": "sglang", "method": "POST", "path": "/freeze", "body": {}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "sglang 恢复推理", "service": "sglang", "method": "POST", "path": "/resume", "body": {}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "slime 权重拉取", "service": "slime", "method": "POST", "path": "/pull_weights", "body": {"source_dir": "/models/poisoned", "local_checkpoint_dir": "/checkpoints/victim"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "areal 环境变量注入", "service": "areal", "method": "POST", "path": "/set_env", "body": {"key": "inkblade_probe", "value": "injected"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "areal 引擎创建", "service": "areal", "method": "POST", "path": "/create_engine", "body": {"module": "mock_module", "cls": "MockClass"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "areal 白名单方法调用", "service": "areal", "method": "POST", "path": "/call", "body": {"engine_id": "engine-probe", "method": "echo", "args": {"probe": "inkblade"}}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "ray 作业提交", "service": "ray", "method": "POST", "path": "/api/jobs/", "body": {"entrypoint": "python mock_entry.py"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "ray 作业列表", "service": "ray", "method": "GET", "path": "/api/jobs/", "body": None, "vulnerable_status": 200, "fixed_status": 200},
    {"name": "vllm 插件清单", "service": "vllm", "method": "GET", "path": "/plugins/list", "body": None, "headers": {"X-Mock-Service": "vllm"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "vllm 插件调用", "service": "vllm", "method": "POST", "path": "/plugins/invoke", "body": {"plugin": "jev", "args": {"query": "probe"}}, "headers": {"X-Mock-Service": "vllm"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "vllm 模型列表对照面", "service": "vllm", "method": "GET", "path": "/v1/models", "body": None, "headers": {"X-Mock-Service": "vllm"}, "vulnerable_status": 401, "fixed_status": 401},
    {"name": "djev 模型列表中继", "service": "djev", "method": "GET", "path": "/v1/models", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "djev 对话补全中继", "service": "djev", "method": "POST", "path": "/v1/chat/completions", "body": {"model": "mock-model", "messages": [{"role": "user", "content": "ping"}]}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "dify-agent 绑定创建", "service": "dify-agent", "method": "POST", "path": "/api/v1/bindings", "body": {"name": "inkblade-probe"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "dify-agent 沙箱作业", "service": "dify-agent", "method": "POST", "path": "/v1/jobs/run", "body": {"script": "echo inkblade-probe"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "open-webui 共享沙箱执行", "service": "open-webui", "method": "POST", "path": "/api/v1/utils/code/execute", "body": {"code": "print('inkblade-probe')"}, "vulnerable_status": 200, "fixed_status": 403},
    {"name": "aws 元数据令牌签发", "service": "imds-aws", "method": "PUT", "path": "/mock-imds/aws/latest/api/token", "body": None, "vulnerable_status": 200, "fixed_status": 200},
    {"name": "aws 角色凭据直取", "service": "imds-aws", "method": "GET", "path": "/mock-imds/aws/latest/meta-data/iam/security-credentials/role", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "azure 实例元数据", "service": "imds-azure", "method": "GET", "path": "/mock-imds/azure/metadata/instance?api-version=2021-02-01", "body": None, "vulnerable_status": 200, "fixed_status": 400},
    {"name": "aliyun RAM 角色凭据", "service": "imds-aliyun", "method": "GET", "path": "/mock-imds/aliyun/latest/meta-data/ram/security-credentials/", "body": None, "vulnerable_status": 200, "fixed_status": 404},
    {"name": "tencent CAM 角色凭据", "service": "imds-tencent", "method": "GET", "path": "/mock-imds/tencent/latest/meta-data/cam/security-credentials/", "body": None, "vulnerable_status": 200, "fixed_status": 404},
    {"name": "gcp 计算元数据无头拒绝", "service": "imds-gcp", "method": "GET", "path": "/mock-imds/gcp/computeMetadata/v1/instance/", "body": None, "vulnerable_status": 403, "fixed_status": 403},
    {"name": "路由清单端点", "service": "meta", "method": "GET", "path": "/__routes__", "body": None, "vulnerable_status": 200, "fixed_status": 200},
]


class TwoStatePerRouteTest(unittest.TestCase):
    """同一路由 vulnerable / fixed 两态状态码断言（表驱动全路由）。"""

    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def _assert_status(self, server, case, mode):
        status, payload = request(case["method"], server.url(case["path"]), case.get("body"), case.get("headers"))
        self.assertEqual(status, case[mode + "_status"], f"{case['name']} [{mode}] -> {payload}")

    def test_vulnerable_status_per_route(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                self._assert_status(self.vulnerable, case, "vulnerable")

    def test_fixed_status_per_route(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                self._assert_status(self.fixed, case, "fixed")


class RoutesManifestTest(unittest.TestCase):
    def test_manifest_covers_every_table_case(self):
        with start_all(mode="vulnerable") as server:
            status, payload = request("GET", server.url("/__routes__"))
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "vulnerable")
        entries = payload["routes"]
        self.assertEqual(len(entries), len(CASES))
        for case in CASES:
            base = case["path"].split("?", 1)[0].rstrip("/")
            matches = [
                e
                for e in entries
                if e["service"] == case["service"]
                and e["method"] == case["method"]
                and base.startswith(e["path"].replace("{role}", "").rstrip("/"))
            ]
            self.assertEqual(len(matches), 1, case["name"])
            entry = matches[0]
            self.assertEqual(entry["vulnerable"], case["vulnerable_status"], case["name"])
            self.assertEqual(entry["fixed"], case["fixed_status"], case["name"])


class SglangAdminKeyFlowTest(unittest.TestCase):
    def test_admin_key_unlocks_fixed_mode(self):
        with start_all(mode="fixed") as server:
            status, payload = request("POST", server.url("/pause"), {}, {"Authorization": f"Bearer {ADMIN_TOKEN}"})
            self.assertEqual(status, 200)
            self.assertTrue(payload["applied"])
            status, _ = request("POST", server.url("/pause"), {}, {"Authorization": "Bearer wrong-key"})
            self.assertEqual(status, 401)


class SlimeWeightPullMarkerTest(unittest.TestCase):
    def test_marker_written_under_injected_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="vulnerable", root=root) as server:
                status, payload = request("POST", server.url("/pull_weights"), {"source_dir": "/models/poisoned", "local_checkpoint_dir": "/checkpoints/victim"})
            self.assertEqual(status, 200)
            markers = list(root.glob("slime/**/*.marker"))
            self.assertEqual(len(markers), 1)
            marker = markers[0].resolve()
            self.assertTrue(marker.is_relative_to(root.resolve()))
            content = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(content["source_dir"], "/models/poisoned")
            self.assertEqual(content["local_checkpoint_dir"], "/checkpoints/victim")


class ArealEnvEngineCallTest(unittest.TestCase):
    def test_env_engine_and_whitelisted_echo(self):
        with start_all(mode="vulnerable") as server:
            status, _ = request("POST", server.url("/set_env"), {"key": "inkblade_probe", "value": "injected"})
            self.assertEqual(status, 200)
            status, created = request("POST", server.url("/create_engine"), {"module": "mock_module", "cls": "MockClass"})
            self.assertEqual(status, 200)
            engine_id = created["engine_id"]
            status, called = request("POST", server.url("/call"), {"engine_id": engine_id, "method": "echo", "args": {"probe": "inkblade"}})
            self.assertEqual(status, 200)
            self.assertEqual(called["result"], {"probe": "inkblade"})
            status, _ = request("POST", server.url("/call"), {"engine_id": engine_id, "method": "system", "args": {"cmd": "id"}})
            self.assertEqual(status, 400)


class RayJobMarkerAndListTest(unittest.TestCase):
    def test_submit_writes_marker_and_list_shows_job(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="vulnerable", root=root) as server:
                status, submitted = request("POST", server.url("/api/jobs/"), {"entrypoint": "python mock_entry.py"})
                self.assertEqual(status, 200)
                job_id = submitted["job_id"]
                markers = list(root.glob("ray/jobs/*.marker"))
                self.assertEqual(len(markers), 1)
                recorded = json.loads(markers[0].read_text(encoding="utf-8"))
                self.assertEqual(recorded["entrypoint"], "python mock_entry.py")
                status, listed = request("GET", server.url("/api/jobs/"))
                self.assertEqual(status, 200)
                self.assertIn(job_id, [job["job_id"] for job in listed["jobs"]])


class DifyAgentSandboxTest(unittest.TestCase):
    def test_binding_dir_marker_and_script_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="vulnerable", root=root) as server:
                status, _ = request("POST", server.url("/api/v1/bindings"), {"name": "inkblade-probe"})
                self.assertEqual(status, 200)
                marker = root / "dify-agent" / "bindings" / "inkblade-probe" / "BINDING.marker"
                self.assertTrue(marker.is_file())
                status, ran = request("POST", server.url("/v1/jobs/run"), {"script": "echo inkblade-probe"})
                self.assertEqual(status, 200)
                self.assertTrue(ran["simulated"])
                scripts = list(root.glob("dify-agent/shellctl/*.sh"))
                self.assertEqual(len(scripts), 1)
                self.assertIn("echo inkblade-probe", scripts[0].read_text(encoding="utf-8"))


class OpenWebuiSharedSandboxTest(unittest.TestCase):
    def test_code_written_and_mock_stdout(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="vulnerable", root=root) as server:
                status, payload = request("POST", server.url("/api/v1/utils/code/execute"), {"code": "print('inkblade-probe')"})
                self.assertEqual(status, 200)
                self.assertEqual(payload["stdout"], "B-was-here")
                cells = list(root.glob("open-webui/shared/*.py"))
                self.assertEqual(len(cells), 1)
                self.assertIn("inkblade-probe", cells[0].read_text(encoding="utf-8"))

    def test_fixed_mode_forbids_and_writes_nothing(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="fixed", root=root) as server:
                status, _ = request("POST", server.url("/api/v1/utils/code/execute"), {"code": "print('x')"})
                self.assertEqual(status, 403)
            self.assertFalse(list(root.glob("**/*")))


class AwsImdsTokenFlowTest(unittest.TestCase):
    def test_fixed_mode_requires_v2_token(self):
        with start_all(mode="fixed") as server:
            status, token = request("PUT", server.url("/mock-imds/aws/latest/api/token"))
            self.assertEqual(status, 200)
            self.assertTrue(str(token).startswith("mock-"))
            creds_path = "/mock-imds/aws/latest/meta-data/iam/security-credentials/role"
            status, _ = request("GET", server.url(creds_path))
            self.assertEqual(status, 401)
            status, creds = request("GET", server.url(creds_path), None, {"x-aws-ec2-metadata-token": str(token)})
            self.assertEqual(status, 200)
            self.assertTrue(str(creds["AccessKeyId"]).startswith("MOCK"))


class AzureImdsHeaderFlowTest(unittest.TestCase):
    def test_metadata_header_gate(self):
        with start_all(mode="fixed") as server:
            path = "/mock-imds/azure/metadata/instance?api-version=2021-02-01"
            status, _ = request("GET", server.url(path))
            self.assertEqual(status, 400)
            status, payload = request("GET", server.url(path), None, {"Metadata": "true"})
            self.assertEqual(status, 200)
            self.assertIn("access_token", payload["identity"])


class GcpImdsFlavorFlowTest(unittest.TestCase):
    def test_flavor_header_gate_both_modes(self):
        for mode in ("vulnerable", "fixed"):
            with self.subTest(mode=mode):
                with start_all(mode=mode) as server:
                    path = "/mock-imds/gcp/computeMetadata/v1/instance/"
                    status, _ = request("GET", server.url(path))
                    self.assertEqual(status, 403)
                    status, payload = request("GET", server.url(path), None, {"Metadata-Flavor": "Google"})
                    self.assertEqual(status, 200)
                    self.assertEqual(payload["service"], "imds-gcp")


class ServerLifecycleTest(unittest.TestCase):
    def test_auto_port_and_shutdown_releases(self):
        first = start_all(mode="vulnerable")
        second = start_all(mode="fixed")
        try:
            self.assertGreater(first.port, 0)
            self.assertNotEqual(first.port, second.port)
            status, _ = request("GET", second.url("/__routes__"))
            self.assertEqual(status, 200)
        finally:
            first.shutdown()
        with self.assertRaises(urllib.error.URLError):
            request("GET", first.url("/__routes__"))
        second.shutdown()

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            start_all(mode="bogus")


class DefaultRootTest(unittest.TestCase):
    def test_default_root_is_temp_and_cleaned_up(self):
        server = start_all()
        root = server.root
        try:
            self.assertTrue(root.is_dir())
            status, _ = request("POST", server.url("/api/v1/bindings"), {"name": "probe"})
            self.assertEqual(status, 200)
            self.assertTrue(list(root.glob("dify-agent/bindings/*")))
        finally:
            server.shutdown()
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
