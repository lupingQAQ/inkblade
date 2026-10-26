"""tests/test_longctx_sim.py — 长上下文/PD 分离推理仿真靶场两态断言（表驱动）。

覆盖：
- POST /v1/chat/completions：窗口内/超窗/1M 超窗/上下文上限绕过/max_tokens 超限/未知租户/缺租户头；
- GET /metrics：无鉴权开放 vs fixed 401（管理密钥 200）；
- POST/GET /kv/transfer：PD KV 通道未鉴权读写 vs fixed 401、跨租户带密钥 403；
- POST/GET /checkpoint/shards：分片未鉴权写入 vs fixed 401（管理密钥 200）、分片读回两态 200；
- GET /__routes__：清单自描述。

另含 prefix cache 跨租户复用（cached_tokens）、queue_depth/kv_cache_bytes 计数器增长、
KV 写入读回 sha256、checkpoint 分片落盘 sha256 的行为断言。
自测仅连接 127.0.0.1。
"""
import hashlib
import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.longctx_sim import (
    ADMIN_TOKEN,
    ROUTE_TABLE,
    checkpoint_shard_path,
    start_all,
)


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


def _get(payload, dotted):
    cur = payload
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _chat_body(**overrides):
    body = {
        "model": "longctx-mock",
        "messages": [{"role": "user", "content": "ping"}],
        "context_window": "128k",
        "prompt_tokens": 1024,
        "max_tokens": 32,
        "cache_salt": "salt-tenant-a",
    }
    body.update(overrides)
    return body


ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
TENANT_A = {"X-Tenant": "tenant-a"}
TENANT_B = {"X-Tenant": "tenant-b"}


# 表驱动两态用例：vulnerable_status / fixed_status + 可选期望字段（点号路径 + 比较）。
CASES = [
    {
        "name": "窗口内对话补全", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(), "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 200,
        "expect": [("usage.prefill_tokens", "==", 1024), ("context_window", "==", 131072)],
    },
    {
        "name": "128k 超窗请求", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(prompt_tokens=200000, cache_salt="salt-over-128k"), "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 400,
        "vulnerable_expect": [("usage.prefill_tokens", ">", 131072)],
    },
    {
        "name": "1M 超窗请求", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(context_window="1m", prompt_tokens=1200000, cache_salt="salt-over-1m"),
        "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 400,
        "vulnerable_expect": [("context_window", "==", 1048576), ("usage.prefill_tokens", ">", 1048576)],
    },
    {
        "name": "上下文上限绕过（声明 128k 实发 900k）", "method": "POST",
        "path": "/v1/chat/completions",
        "body": _chat_body(prompt_tokens=900000, cache_salt="salt-bypass"), "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 400,
        "vulnerable_expect": [("context_window", "==", 131072), ("usage.prefill_tokens", ">", 131072)],
    },
    {
        "name": "max_tokens 超限", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(max_tokens=1000000, cache_salt="salt-maxtok"), "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 400,
    },
    {
        "name": "未知租户", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(cache_salt="salt-unknown"), "headers": {"X-Tenant": "tenant-z"},
        "vulnerable_status": 200, "fixed_status": 401,
    },
    {
        "name": "缺少租户头", "method": "POST", "path": "/v1/chat/completions",
        "body": _chat_body(cache_salt="salt-no-tenant"), "headers": {},
        "vulnerable_status": 400, "fixed_status": 400,
    },
    {
        "name": "推理指标无鉴权", "method": "GET", "path": "/metrics",
        "body": None, "headers": {},
        "vulnerable_status": 200, "fixed_status": 401,
        "vulnerable_expect": [
            ("queue_depth", ">=", 0), ("kv_cache_usage", ">=", 0),
            ("prefill_pool.capacity", ">", 0), ("decode_pool.capacity", ">", 0),
            ("training.world_size", ">", 0),
        ],
    },
    {
        "name": "推理指标管理密钥", "method": "GET", "path": "/metrics",
        "body": None, "headers": ADMIN,
        "vulnerable_status": 200, "fixed_status": 200,
    },
    {
        "name": "PD KV 通道未鉴权读握手", "method": "POST", "path": "/kv/transfer",
        "body": {"op": "read", "block_id": "pd-handshake", "source_tenant": "tenant-a"},
        "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 401,
        "vulnerable_expect": [("op", "==", "read"), ("found", "==", False)],
    },
    {
        "name": "PD KV 通道未鉴权写", "method": "POST", "path": "/kv/transfer",
        "body": {"op": "write", "block_id": "kv-case", "value": "INKBLADE-BENIGN-KV",
                 "source_tenant": "tenant-a", "dest_tenant": "tenant-b", "layer": 3},
        "headers": TENANT_A,
        "vulnerable_status": 200, "fixed_status": 401,
        "vulnerable_expect": [("op", "==", "write"), ("block_id", "==", "kv-case")],
    },
    {
        "name": "PD KV 跨租户写（管理密钥）", "method": "POST", "path": "/kv/transfer",
        "body": {"op": "write", "block_id": "kv-cross", "value": "INKBLADE-BENIGN-CROSS",
                 "source_tenant": "tenant-a", "dest_tenant": "tenant-b"},
        "headers": {**ADMIN, **TENANT_A},
        "vulnerable_status": 200, "fixed_status": 403,
    },
    {
        "name": "checkpoint 分片读回（种子）", "method": "GET",
        "path": "/checkpoint/shards/shard-00000", "body": None, "headers": {},
        "vulnerable_status": 200, "fixed_status": 200,
    },
    {
        "name": "checkpoint 分片未鉴权写", "method": "POST", "path": "/checkpoint/shards",
        "body": {"shard_id": "shard-00001", "payload": "INKBLADE-BENIGN-SHARD\n"},
        "headers": {},
        "vulnerable_status": 200, "fixed_status": 401,
    },
    {
        "name": "checkpoint 分片管理密钥写", "method": "POST", "path": "/checkpoint/shards",
        "body": {"shard_id": "shard-00002", "payload": "INKBLADE-BENIGN-SHARD-ADMIN\n"},
        "headers": ADMIN,
        "vulnerable_status": 200, "fixed_status": 200,
    },
    {
        "name": "路由清单", "method": "GET", "path": "/__routes__", "body": None, "headers": {},
        "vulnerable_status": 200, "fixed_status": 200,
        "expect": [("route_count", ">=", 6)],
    },
]


def _assert_expect(testcase, payload, expectations, label):
    for dotted, op, expected in expectations or []:
        actual = _get(payload, dotted)
        if op == "==":
            testcase.assertEqual(actual, expected, f"{label}: {dotted}={actual!r}")
        elif op == ">":
            testcase.assertIsNotNone(actual, f"{label}: 缺字段 {dotted}")
            testcase.assertGreater(actual, expected, f"{label}: {dotted}={actual!r}")
        elif op == ">=":
            testcase.assertIsNotNone(actual, f"{label}: 缺字段 {dotted}")
            testcase.assertGreaterEqual(actual, expected, f"{label}: {dotted}={actual!r}")


class TwoStatePerRouteTest(unittest.TestCase):
    """同一用例 vulnerable / fixed 两态断言（表驱动全路由）。"""

    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def _assert_case(self, server, case, mode):
        status, payload = request(case["method"], server.url(case["path"]),
                                  case.get("body"), case.get("headers"))
        self.assertEqual(status, case[mode + "_status"], f"{case['name']} [{mode}] -> {payload}")
        _assert_expect(self, payload, case.get("expect"), case["name"])
        _assert_expect(self, payload, case.get(mode + "_expect"), case["name"])

    def test_vulnerable_status_per_case(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                self._assert_case(self.vulnerable, case, "vulnerable")

    def test_fixed_status_per_case(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                self._assert_case(self.fixed, case, "fixed")


class RoutesManifestTest(unittest.TestCase):
    def test_manifest_shape(self):
        with start_all(mode="vulnerable") as server:
            status, payload = request("GET", server.url("/__routes__"))
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "vulnerable")
        self.assertEqual(len(payload["routes"]), len(ROUTE_TABLE))
        services = {entry["service"] for entry in payload["routes"]}
        self.assertIn("longctx-infer", services)
        self.assertIn("meta", services)
        for entry in payload["routes"]:
            self.assertIsInstance(entry["vulnerable"], int)
            self.assertIsInstance(entry["fixed"], int)
            self.assertIn("path", entry)
            self.assertIn("method", entry)


class PrefixCacheIsolationTest(unittest.TestCase):
    """prefix cache：vulnerable 跨租户复用 cached_tokens>0；fixed 无 cache_salt 403 / 同租户带 salt 命中。"""

    def test_cross_tenant_reuse_vulnerable(self):
        with start_all(mode="vulnerable") as server:
            prefix = "INKBLADE-PREFIX-CROSS-TENANT-001"
            prime_status, prime = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_prefix=prefix, prefix_tokens=4096, prompt_tokens=4096,
                           cache_salt="salt-tenant-a"), TENANT_A)
            reuse_status, reuse = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_prefix=prefix, prefix_tokens=4096, prompt_tokens=4096,
                           cache_salt=None), TENANT_B)
        self.assertEqual(prime_status, 200)
        self.assertEqual(reuse_status, 200)
        self.assertEqual(prime["usage"]["cached_tokens"], 0)
        self.assertEqual(reuse["usage"]["cached_tokens"], 4096)
        self.assertGreater(reuse["usage"]["cached_tokens"], 0)

    def test_fixed_requires_cache_salt_and_isolates_tenants(self):
        with start_all(mode="fixed") as server:
            prefix = "INKBLADE-PREFIX-CROSS-TENANT-002"
            status, _ = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_prefix=prefix, prefix_tokens=4096, prompt_tokens=4096,
                           cache_salt="salt-tenant-a"), TENANT_A)
            self.assertEqual(status, 200)
            status, _ = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_prefix=prefix, prefix_tokens=4096, prompt_tokens=4096,
                           cache_salt=None), TENANT_B)
            self.assertEqual(status, 403)
            status, same = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_prefix=prefix, prefix_tokens=4096, prompt_tokens=4096,
                           cache_salt="salt-tenant-a"), TENANT_A)
            self.assertEqual(status, 200)
            self.assertEqual(same["usage"]["cached_tokens"], 4096)


class CounterEvidenceTest(unittest.TestCase):
    """计数器证据：超窗 → queue_depth 增长；1M 窗口小 prompt → kv_cache_bytes 放大。"""

    def test_queue_depth_growth_on_over_window(self):
        with start_all(mode="vulnerable") as server:
            _, before = request("GET", server.url("/metrics"))
            status, chat = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_tokens=200000, cache_salt="salt-queue"), TENANT_A)
            _, after = request("GET", server.url("/metrics"))
        self.assertEqual(status, 200)
        self.assertGreater(chat["usage"]["prefill_tokens"], chat["context_window"])
        self.assertEqual(after["queue_depth"], before["queue_depth"] + 1)
        self.assertGreater(after["prefill_pool"]["queued"], before["prefill_pool"]["queued"])

    def test_fixed_rejects_and_queue_stays_zero(self):
        with start_all(mode="fixed") as server:
            status, _ = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(prompt_tokens=200000, cache_salt="salt-queue"), TENANT_A)
            self.assertEqual(status, 400)
            _, metrics = request("GET", server.url("/metrics"), None, ADMIN)
        self.assertEqual(metrics["queue_depth"], 0)

    def test_memory_amplification_counter(self):
        with start_all(mode="vulnerable") as server:
            _, before = request("GET", server.url("/metrics"))
            status, chat = request(
                "POST", server.url("/v1/chat/completions"),
                _chat_body(context_window="1m", prompt_tokens=1024, max_tokens=64,
                           cache_salt="salt-amp"), TENANT_A)
            _, after = request("GET", server.url("/metrics"))
        self.assertEqual(status, 200)
        delta = after["kv_cache_bytes"] - before["kv_cache_bytes"]
        self.assertGreater(delta, 0)
        ratio = delta / (chat["usage"]["prompt_tokens"] * 2)
        self.assertGreater(ratio, 64, f"放大比异常: {ratio}")
        self.assertGreater(after["kv_cache_usage"], 0)


class KvChannelReadbackTest(unittest.TestCase):
    """KV 通道：vulnerable 写入后独立 GET 读回，value/sha256 一致。"""

    def test_write_then_readback(self):
        with start_all(mode="vulnerable") as server:
            value = "INKBLADE-BENIGN-KV-READBACK-001"
            status, written = request(
                "POST", server.url("/kv/transfer"),
                {"op": "write", "block_id": "kv-readback", "value": value,
                 "source_tenant": "tenant-a", "dest_tenant": "tenant-b"}, TENANT_A)
            read_status, readback = request("GET", server.url("/kv/transfer?block_id=kv-readback"))
        self.assertEqual(status, 200)
        self.assertEqual(written["sha256"], hashlib.sha256(value.encode()).hexdigest())
        self.assertEqual(read_status, 200)
        self.assertTrue(readback["found"])
        self.assertEqual(readback["value"], value)
        self.assertEqual(readback["sha256"], written["sha256"])

    def test_fixed_read_requires_admin(self):
        with start_all(mode="fixed") as server:
            status, _ = request("GET", server.url("/kv/transfer?block_id=kv-readback"))
            self.assertEqual(status, 401)
            status, payload = request("GET", server.url("/kv/transfer?block_id=kv-readback"), None, ADMIN)
            self.assertEqual(status, 200)
            self.assertFalse(payload["found"])


class CheckpointShardTest(unittest.TestCase):
    """checkpoint 分片：vulnerable 写盘 sha256 与响应一致，GET 读回内容一致。"""

    def test_write_and_readback_with_injected_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="vulnerable", root=root) as server:
                payload = "INKBLADE-BENIGN-SHARD-READBACK\nshard=00009\n"
                status, written = request(
                    "POST", server.url("/checkpoint/shards"),
                    {"shard_id": "shard-00009", "payload": payload})
                self.assertEqual(status, 200)
                path = checkpoint_shard_path(server.root, "shard-00009")
                self.assertTrue(path.is_file())
                self.assertTrue(path.resolve().is_relative_to(Path(tmp).resolve()))
                self.assertEqual(path.read_text(encoding="utf-8"), payload)
                self.assertEqual(written["sha256"], hashlib.sha256(payload.encode()).hexdigest())
                read_status, body = request("GET", server.url("/checkpoint/shards/shard-00009"))
                self.assertEqual(read_status, 200)
                self.assertEqual(body, payload)
                self.assertEqual(written["bytes"], len(payload.encode("utf-8")))

    def test_fixed_write_denied_and_file_absent(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="fixed", root=root) as server:
                status, _ = request(
                    "POST", server.url("/checkpoint/shards"),
                    {"shard_id": "shard-00010", "payload": "INKBLADE-BENIGN-SHARD-DENIED\n"})
                self.assertEqual(status, 401)
                self.assertFalse(checkpoint_shard_path(server.root, "shard-00010").exists())


class ServerLifecycleTest(unittest.TestCase):
    def test_auto_port_and_shutdown(self):
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


if __name__ == "__main__":
    unittest.main()
