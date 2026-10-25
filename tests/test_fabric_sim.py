"""tests/test_fabric_sim.py — 万卡 fabric 破坏面仿真两态表驱动测试（真实 HTTP）。

覆盖：
- 路由清单与 __routes__ 一致；
- vulnerable：SHARP 入组/篡改 reduce、IB Partition 改写、PFC 风暴、端口耗尽（诚实作业 503）、
  checkpoint I/O 无限速、apiserver/IMDS 无配额、上下文 OOM、gang 队列打满、Xid 复位、rail 错配；
- fixed：写面 401（管理密钥/作业令牌 200）、篡改/风暴/超限 400、限速/配额 429、超窗 400；
- 破坏效果全部以计数器/状态位度量（不真破坏）。
"""
import json
import unittest
import urllib.error
import urllib.request

from lab.fabric_dos_sim import ADMIN_TOKEN, JOB_TOKEN, ROUTE_TABLE, start_all

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
JOB_HEADERS = {"X-Job-Token": JOB_TOKEN}


def call(server, method, path, body=None, headers=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(server.url(path), data=data, method=method,
                                 headers=dict(headers or {}))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError:
        payload = raw.decode("utf-8", "replace")
    return status, payload


class VulnerableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_routes_manifest(self):
        status, payload = call(self.server, "GET", "/__routes__")
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "vulnerable")
        self.assertEqual(len(payload["routes"]), len(ROUTE_TABLE))

    def test_sharp_join_and_tamper_silent(self):
        status, payload = call(self.server, "POST", "/sharp/sessions",
                               {"op": "join", "rank": "trident-ext"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["joined"])
        self.assertIn("trident-ext", payload["members"])
        contribs = [1, 2, 3, 4, 5, 6, 7, 8]
        _, base = call(self.server, "POST", "/sharp/reduce", {"contributions": contribs})
        self.assertEqual(base["result"], 36.0)
        self.assertFalse(base["tampered"])
        _, tampered = call(self.server, "POST", "/sharp/reduce",
                           {"contributions": contribs, "tamper_factor": 3.0})
        self.assertEqual(tampered["result"], 108.0)
        self.assertTrue(tampered["tampered"])
        self.assertTrue(tampered["silent"])

    def test_ib_partition_membership_rewrite(self):
        status, payload = call(self.server, "POST", "/ib/sm/partition",
                               {"pkey": "0x8001", "add_members": ["guid-trident"]})
        self.assertEqual(status, 200)
        self.assertIn("guid-trident", payload["members"])
        _, listing = call(self.server, "GET", "/ib/sm/partition")
        self.assertIn("guid-trident", listing["partitions"]["0x8001"]["members"])

    def test_pfc_storm_counter(self):
        _, before = call(self.server, "GET", "/roce/pfc")
        for _ in range(3):
            status, payload = call(self.server, "POST", "/roce/pfc",
                                   {"mode": "storm", "interfaces": ["all"]})
            self.assertEqual(status, 200)
        _, after = call(self.server, "GET", "/roce/pfc")
        self.assertGreaterEqual(
            after["pfc_pause_frames"] - before["pfc_pause_frames"], 50000)
        self.assertTrue(after["pfc"]["storm"])

    def test_bootstrap_exhaustion_blocks_honest_job(self):
        exhausted = None
        for _ in range(30):
            status, payload = call(self.server, "POST", "/nccl/bootstrap",
                                   {"job": "trident-exhaust", "ranks": 2})
            if status != 200:
                exhausted = (status, payload)
                break
        self.assertIsNotNone(exhausted)
        self.assertEqual(exhausted[0], 503)
        status, victim = call(self.server, "POST", "/nccl/bootstrap",
                              {"job": "honest-victim", "ranks": 1, "honest": True})
        self.assertEqual(status, 503)
        self.assertEqual(victim["error"], "bootstrap_ports_exhausted")
        self.assertTrue(victim["honest"])

    def test_checkpoint_io_unlimited(self):
        for _ in range(5):
            status, payload = call(self.server, "POST", "/checkpoint/io",
                                   {"bytes_mb": 4096, "burst": 4})
            self.assertEqual(status, 200)
            self.assertFalse(payload["rate_limited"])
        self.assertGreaterEqual(payload["io_bytes_mb"], 40960)

    def test_api_and_imds_flood_no_quota(self):
        status, payload = call(self.server, "POST", "/apiserver/request", {"count": 250})
        self.assertEqual(status, 200)
        self.assertFalse(payload["quota_enforced"])
        status, imds = call(self.server, "POST", "/imds/request", {"count": 250})
        self.assertEqual(status, 200)

    def test_context_oom_silent(self):
        status, payload = call(self.server, "POST", "/train/context",
                               {"context_tokens": 4000000, "declared_context_tokens": 8192})
        self.assertEqual(status, 200)
        self.assertTrue(payload["accepted"])
        self.assertTrue(payload["oom"])
        self.assertGreater(payload["kv_bytes"], payload["capacity_bytes"])
        self.assertTrue(payload["silent"])

    def test_gang_queue_clog(self):
        last = None
        for i in range(5):
            status, last = call(self.server, "POST", "/sched/gang",
                                {"job_id": f"ph-{i}", "gang_size": 8,
                                 "placeholders": 8, "hold": True})
            self.assertEqual(status, 200)
        self.assertGreater(last["pending_gpus"], last["capacity"])
        self.assertTrue(last["clogged"])

    def test_xid_triggers_driver_reset(self):
        status, payload = call(self.server, "POST", "/gpu/health",
                               {"gpu": "gpu-0", "xid_code": 79})
        self.assertEqual(status, 200)
        self.assertTrue(payload["reset_triggered"])
        self.assertFalse(payload["healthy"])
        _, health = call(self.server, "GET", "/gpu/health")
        self.assertGreaterEqual(health["driver_resets"], 1)

    def test_rail_mismatch_and_step_penalty(self):
        _, before = call(self.server, "POST", "/train/step", {"steps": 1})
        status, payload = call(self.server, "POST", "/nccl/rail",
                               {"rank": "rank-7", "force_rail": "rail-0"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["mismatch"])
        self.assertGreaterEqual(payload["cross_rail_flows"], 1)
        _, after = call(self.server, "POST", "/train/step", {"steps": 1})
        self.assertGreater(after["step_ms"], before["step_ms"])

    def test_metrics_open(self):
        status, payload = call(self.server, "GET", "/metrics")
        self.assertEqual(status, 200)
        for section in ("sharp", "ib", "roce", "nccl", "checkpoint_io", "api",
                        "memory", "gang", "gpu", "training"):
            self.assertIn(section, payload)

    def test_gradient_byzantine_silent_divergence(self):
        _, baseline = call(self.server, "GET", "/train/loss")
        loss_before = baseline["loss_history"][-1]
        status, payload = call(self.server, "POST", "/train/gradient",
                               {"mode": "byzantine", "scale": 3.0})
        self.assertEqual(status, 200)
        self.assertTrue(payload["silent"])
        self.assertGreater(payload["loss_after"], loss_before)


class FixedHardeningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_write_planes_401_without_credentials(self):
        cases = [
            ("POST", "/sharp/sessions", {"op": "join", "rank": "x"}),
            ("POST", "/sharp/reduce", {"contributions": [1, 2]}),
            ("POST", "/ib/sm/partition", {"add_members": ["g"]}),
            ("POST", "/roce/pfc", {"mode": "storm"}),
            ("POST", "/nccl/rank", {"rank": "rank-7", "straggler_ms": 5000}),
            ("POST", "/nccl/rail", {"rank": "rank-7", "force_rail": "rail-0"}),
            ("POST", "/train/gradient", {"scale": 3.0}),
            ("POST", "/gpu/health", {"xid_code": 79}),
            ("GET", "/metrics", None),
            ("GET", "/ib/sm/partition", None),
            ("GET", "/roce/pfc", None),
            ("GET", "/nccl/rail", None),
        ]
        for method, path, body in cases:
            with self.subTest(route=f"{method} {path}"):
                status, _ = call(self.server, method, path, body)
                self.assertEqual(status, 401)

    def test_job_token_allows_join_but_ports_capped(self):
        status, payload = call(self.server, "POST", "/sharp/sessions",
                               {"op": "join", "rank": "legit"}, JOB_HEADERS)
        self.assertEqual(status, 200)
        status, payload = call(self.server, "POST", "/nccl/bootstrap",
                               {"job": "legit-job", "ranks": 8}, JOB_HEADERS)
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"], "per_job_port_cap")

    def test_admin_tamper_rejected(self):
        status, payload = call(self.server, "POST", "/sharp/reduce",
                               {"contributions": [1, 2], "tamper_factor": 3.0},
                               ADMIN_HEADERS)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "peer_contribution_rejected")
        status, payload = call(self.server, "POST", "/sharp/reduce",
                               {"contributions": [1, 2]}, ADMIN_HEADERS)
        self.assertEqual(status, 200)

    def test_pfc_storm_profile_rejected(self):
        status, payload = call(self.server, "POST", "/roce/pfc", {"mode": "storm"},
                               ADMIN_HEADERS)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "storm_profile_rejected")

    def test_straggler_injection_rejected(self):
        status, payload = call(self.server, "POST", "/nccl/rank",
                               {"rank": "rank-7", "straggler_ms": 5000}, ADMIN_HEADERS)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "straggler_rejected")

    def test_context_limit_enforced(self):
        status, payload = call(self.server, "POST", "/train/context",
                               {"context_tokens": 4000000})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "context_limit_enforced")

    def test_io_rate_limit_and_quota(self):
        status, payload = call(self.server, "POST", "/checkpoint/io",
                               {"bytes_mb": 4096, "burst": 4}, JOB_HEADERS)
        self.assertIn(status, (401, 429))
        status, payload = call(self.server, "POST", "/apiserver/request", {"count": 250})
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"], "request_quota")
        status, payload = call(self.server, "POST", "/imds/request", {"count": 250})
        self.assertEqual(status, 429)

    def test_gang_requires_token_and_quota(self):
        status, _ = call(self.server, "POST", "/sched/gang",
                         {"gang_size": 8, "placeholders": 8})
        self.assertEqual(status, 401)
        last = None
        for i in range(6):
            status, last = call(self.server, "POST", "/sched/gang",
                                {"job_id": f"legit-{i}", "gang_size": 8}, JOB_HEADERS)
            if status == 429:
                break
        self.assertEqual(status, 429)
        self.assertEqual(last["error"], "gang_quota")

    def test_open_measurement_endpoints(self):
        status, _ = call(self.server, "POST", "/train/step", {"steps": 1})
        self.assertEqual(status, 200)
        status, _ = call(self.server, "GET", "/train/loss")
        self.assertEqual(status, 200)
        status, _ = call(self.server, "GET", "/gpu/health")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
