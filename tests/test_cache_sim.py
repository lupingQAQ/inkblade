"""tests/test_cache_sim.py — 多租户缓存安全仿真靶场两态契约（前缀/近似/远程池/路由指标）。

覆盖：
- 路由清单契约（/__routes__ 与 ROUTE_TABLE 一致，缓存面全部路由在册）；
- 前缀缓存：vulnerable 全局键跨租户命中（cached_tokens>0、TTFT 命中档）；
  fixed 键含 tenant|salt（跨租户无 salt 403、同租户同 salt 命中、同租户换 salt 不命中）；
- 时序口径：成员/对照 TTFT 两档严格分离（vulnerable），fixed 两类皆未命中（无差分）；
- 近似缓存：相似度阈值边界（≥ 阈值误命中他租户条目、< 阈值 miss、fixed 仅本租户）；
  阈值可配（start_all(approx_threshold=…)）；
- 远程 KV 池：vulnerable 无命名空间校验（他租户块可读、pinned 可设且逐出压力下存续）；
  fixed 越权 403、pinned 降级 lru、逐出后 404；
- LRU 逐出与残留：逐出计数增长；vulnerable 残留层跨租户可读（tenant-b + benign marker）；
  fixed zeroize 404；
- 路由指标：vulnerable 按租户暴露（tenant-b 命中率/前缀样本）；fixed 仅本租户视图；
- 种子齐备：成员前缀 30 条、残留靶、KV 池受害/对照块、近似缓存受害/对照条目。
"""
import json
import unittest
import urllib.error
import urllib.parse
import urllib.request

from lab.cache_sim import (
    APPROX_SIMILARITY_THRESHOLD,
    CONTROL_APPROX_TEXT,
    CONTROL_POOL_BLOCK_ID,
    MEMBER_SEED_COUNT,
    ROUTE_TABLE,
    VICTIM_APPROX_RESPONSE,
    VICTIM_APPROX_TEXT,
    VICTIM_POOL_BLOCK_ID,
    VICTIM_RESIDUE_PREFIX,
    member_prefixes,
    start_all,
)


def http(url, method="GET", body=None, headers=None, timeout=10):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        payload = raw.decode("utf-8", "replace")
    return status, payload


class _Base(unittest.TestCase):
    mode = "vulnerable"

    @classmethod
    def setUpClass(cls):
        cls.server = start_all(mode=cls.mode)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def chat(self, prefix, tenant, salt=None, mode_body=None, prefix_tokens=2048):
        body = {"prompt_prefix": prefix, "prefix_tokens": prefix_tokens,
                "max_tokens": 1}
        if salt is not None:
            body["cache_salt"] = salt
        if mode_body:
            body.update(mode_body)
        return http(self.server.url("/v1/chat/completions"), "POST", body,
                    {"X-Tenant": tenant})


class RoutesManifestTest(_Base):
    def test_manifest_matches_route_table(self):
        status, payload = http(self.server.url("/__routes__"))
        self.assertEqual(status, 200)
        paths = {(r["method"], r["path"]) for r in payload["routes"]}
        for entry in ROUTE_TABLE:
            self.assertIn((entry["method"], entry["path"]), paths)
        for path in ("/v1/chat/completions", "/config", "/router/metrics",
                     "/approx/lookup", "/approx/store", "/kvpool/blocks",
                     "/kvpool/blocks/{block}", "/cache/residue"):
            self.assertTrue(any(r["path"] == path for r in payload["routes"]), path)

    def test_seeds_present(self):
        status, payload = http(self.server.url("/__routes__"))
        self.assertTrue(payload["seeds"]["victim_pool_block"])
        _, metrics = http(self.server.url("/router/metrics"))
        tenant_b = metrics["per_tenant"]["tenant-b"]
        self.assertGreaterEqual(tenant_b["distinct_prefixes"], MEMBER_SEED_COUNT)


class VulnerablePrefixCacheTest(_Base):
    mode = "vulnerable"

    def test_cross_tenant_hit_without_salt(self):
        prefix = "probe-prefix-alpha shared corpus section one"
        s1, _ = self.chat(prefix, "tenant-a", salt="salt-a")
        self.assertEqual(s1, 200)
        s2, second = self.chat(prefix, "tenant-b")
        self.assertEqual(s2, 200)
        self.assertGreater(second["usage"]["cached_tokens"], 0)
        self.assertTrue(second["cache"]["hit"])
        self.assertFalse(second["cache"]["salt_present"])

    def test_ttft_two_regimes_and_deterministic_jitter(self):
        member = member_prefixes()[0]
        _, miss = self.chat("control-miss-deterministic unique corpus", "tenant-a")
        self.assertGreaterEqual(miss["ttft_ms"], 185)
        _, hit = self.chat(member, "tenant-a")
        self.assertLess(hit["ttft_ms"], 40)
        # 抖动确定性：同 digest+请求序号不同轮结果稳定（重复请求仍命中档）
        _, again = self.chat(member, "tenant-a")
        self.assertLess(again["ttft_ms"], 40)


class FixedPrefixCacheTest(_Base):
    mode = "fixed"

    def test_cross_tenant_probe_is_plain_miss_no_oracle(self):
        prefix = "probe-prefix-fixed shared corpus section two"
        _, first = self.chat(prefix, "tenant-b")  # 受害租户无 salt 预热（常见姿态）
        self.assertFalse(first["cache"]["hit"])
        status, second = self.chat(prefix, "tenant-a")  # 攻击者同前缀无 salt 探测
        self.assertEqual(status, 200)
        self.assertFalse(second["cache"]["hit"])
        self.assertEqual(second["usage"]["cached_tokens"], 0,
                         "fixed 模式跨租户探测不得命中（也不得以 403 泄露存在性）")

    def test_same_tenant_same_salt_hits_and_different_salt_misses(self):
        prefix = "probe-prefix-fixed same tenant semantics"
        _, first = self.chat(prefix, "tenant-a", salt="s1")
        self.assertFalse(first["cache"]["hit"])
        _, second = self.chat(prefix, "tenant-a", salt="s1")
        self.assertTrue(second["cache"]["hit"])
        self.assertGreater(second["usage"]["cached_tokens"], 0)
        _, third = self.chat(prefix, "tenant-a", salt="s2")
        self.assertFalse(third["cache"]["hit"])

    def test_unknown_tenant_rejected(self):
        status, payload = self.chat("any prefix", "tenant-evil")
        self.assertEqual(status, 401)


class ApproxCacheTest(_Base):
    mode = "vulnerable"

    def test_false_hit_cross_tenant_above_threshold(self):
        probe = VICTIM_APPROX_TEXT.replace("42.7M", "42.8M")  # 单词替换 sim≈0.88 ≥ 0.85
        status, payload = http(self.server.url("/approx/lookup"), "POST",
                               {"text": probe}, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["hit"], payload)
        self.assertGreaterEqual(payload["best_similarity"], payload["threshold"])
        self.assertEqual(payload["matched"]["tenant"], "tenant-b")
        self.assertIn("INKBLADE-BENIGN-APPROX-VICTIM", payload["matched"]["response"])

    def test_below_threshold_misses(self):
        probe = "completely unrelated topic about kubernetes network policy tuning"
        status, payload = http(self.server.url("/approx/lookup"), "POST",
                               {"text": probe}, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertFalse(payload["hit"])
        self.assertIsNone(payload["matched"])

    def test_exact_control_entry_hits_own_tenant(self):
        status, payload = http(self.server.url("/approx/lookup"), "POST",
                               {"text": CONTROL_APPROX_TEXT}, {"X-Tenant": "tenant-a"})
        self.assertTrue(payload["hit"])
        self.assertEqual(payload["matched"]["tenant"], "tenant-a")

    def test_threshold_configurable(self):
        with start_all(mode="vulnerable", approx_threshold=0.99) as server:
            probe = VICTIM_APPROX_TEXT.replace("42.7M", "42.8M")
            _, payload = http(server.url("/approx/lookup"), "POST",
                              {"text": probe}, {"X-Tenant": "tenant-a"})
            self.assertEqual(payload["threshold"], 0.99)
            self.assertFalse(payload["hit"])  # 0.89 < 0.99 → 收紧后不再误命中
            _, config = http(server.url("/config"))
            self.assertEqual(config["approx_cache"]["similarity_threshold"], 0.99)


class FixedApproxCacheTest(_Base):
    mode = "fixed"

    def test_victim_entry_not_searched_for_other_tenant(self):
        status, payload = http(self.server.url("/approx/lookup"), "POST",
                               {"text": VICTIM_APPROX_TEXT}, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertFalse(payload["hit"])
        self.assertIsNone(payload["matched"])
        self.assertEqual(payload["scope"], "tenant")

    def test_own_tenant_entry_still_hits(self):
        status, payload = http(self.server.url("/approx/lookup"), "POST",
                               {"text": CONTROL_APPROX_TEXT}, {"X-Tenant": "tenant-a"})
        self.assertTrue(payload["hit"])
        self.assertEqual(payload["matched"]["tenant"], "tenant-a")


class KvPoolTest(_Base):
    mode = "vulnerable"

    def test_cross_tenant_block_read(self):
        status, payload = http(
            self.server.url(f"/kvpool/blocks/{VICTIM_POOL_BLOCK_ID}"),
            headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["found"])
        self.assertEqual(payload["tenant"], "tenant-b")
        self.assertIn("INKBLADE-BENIGN-POOL-VICTIM", str(payload["value"]))

    def test_own_control_block_readable(self):
        status, payload = http(
            self.server.url(f"/kvpool/blocks/{CONTROL_POOL_BLOCK_ID}"),
            headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["found"])

    def test_pinned_block_survives_eviction_pressure(self):
        status, written = http(self.server.url("/kvpool/blocks"), "POST", {
            "block_id": "poison-pinned-test", "namespace": "global",
            "value": "INKBLADE-BENIGN-POISON pinned persistence probe",
            "eviction_policy": "pinned",
        }, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(written["pinned"])
        for i in range(160):
            self.chat(f"pressure-prefix-{i:04d} unique flood corpus", "tenant-a")
        _, metrics = http(self.server.url("/router/metrics"))
        self.assertGreaterEqual(metrics["pool"]["evictions_total"], 1)
        status, payload = http(self.server.url("/kvpool/blocks/poison-pinned-test"),
                               headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["found"])
        self.assertTrue(payload["pinned"])


class FixedKvPoolTest(_Base):
    mode = "fixed"

    def test_cross_tenant_read_denied(self):
        status, payload = http(
            self.server.url(f"/kvpool/blocks/{VICTIM_POOL_BLOCK_ID}"),
            headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "kv_pool_namespace_isolation")

    def test_admin_can_read_and_pin(self):
        status, payload = http(
            self.server.url(f"/kvpool/blocks/{VICTIM_POOL_BLOCK_ID}"),
            headers={"Authorization": "Bearer cache-admin-key"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["found"])

    def test_pinning_denied_for_tenant_and_block_evicted(self):
        status, written = http(self.server.url("/kvpool/blocks"), "POST", {
            "block_id": "poison-fixed-test", "namespace": "tenant-a",
            "value": "INKBLADE-BENIGN-POISON fixed probe",
            "eviction_policy": "pinned",
        }, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertFalse(written["pinned"])
        self.assertTrue(written.get("pinning_denied"))
        for i in range(160):
            self.chat(f"pressure-fixed-{i:04d} unique flood corpus", "tenant-a")
        status, _ = http(self.server.url("/kvpool/blocks/poison-fixed-test"),
                         headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 404)

    def test_cross_tenant_namespace_write_denied(self):
        status, payload = http(self.server.url("/kvpool/blocks"), "POST", {
            "block_id": "poison-cross-ns", "namespace": "tenant-b",
            "value": "INKBLADE-BENIGN-POISON cross namespace probe",
        }, {"X-Tenant": "tenant-a"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "cross_tenant_kv_write_denied")


class EvictionResidueTest(_Base):
    mode = "vulnerable"

    def test_evicted_victim_prefix_residue_readable_cross_tenant(self):
        _, before = http(self.server.url("/router/metrics"))
        for i in range(160):
            self.chat(f"residue-flood-{i:04d} unique flood corpus", "tenant-a")
        _, after = http(self.server.url("/router/metrics"))
        self.assertGreaterEqual(after["pool"]["evictions_total"],
                                before["pool"]["evictions_total"] + 1)
        status, payload = http(
            self.server.url("/cache/residue?prefix=" + urllib.parse.quote(VICTIM_RESIDUE_PREFIX)),
            headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["found"])
        self.assertEqual(payload["tenant"], "tenant-b")
        self.assertIn("INKBLADE-BENIGN-RESIDUE-VICTIM", payload["prefix_preview"])


class FixedEvictionResidueTest(_Base):
    mode = "fixed"

    def test_residue_zeroized(self):
        for i in range(160):
            self.chat(f"residue-fixed-{i:04d} unique flood corpus", "tenant-a")
        status, payload = http(
            self.server.url("/cache/residue?prefix=" + urllib.parse.quote(VICTIM_RESIDUE_PREFIX)),
            headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 404)
        self.assertFalse(payload["found"])


class RouterMetricsTest(_Base):
    mode = "vulnerable"

    def test_per_tenant_metrics_exposed_without_auth(self):
        status, payload = http(self.server.url("/router/metrics"),
                               headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertIn("tenant-b", payload["per_tenant"])
        tenant_b = payload["per_tenant"]["tenant-b"]
        self.assertGreaterEqual(tenant_b["distinct_prefixes"], MEMBER_SEED_COUNT)
        self.assertIn("prefix_hit_rate", tenant_b)
        self.assertTrue(tenant_b["top_prefix_samples"])

    def test_config_shows_weak_policy(self):
        status, payload = http(self.server.url("/config"))
        self.assertEqual(status, 200)
        self.assertFalse(payload["cache_salt_policy"]["enabled"])
        self.assertEqual(payload["cache_salt_policy"]["key_scope"], "global")
        self.assertEqual(payload["approx_cache"]["scope"], "global")
        self.assertEqual(payload["kv_pool"]["residue_policy"], "retain")
        self.assertEqual(payload["approx_cache"]["similarity_threshold"],
                         APPROX_SIMILARITY_THRESHOLD)


class FixedRouterMetricsTest(_Base):
    mode = "fixed"

    def test_no_identity_unauthorized(self):
        status, _ = http(self.server.url("/router/metrics"))
        self.assertEqual(status, 401)

    def test_tenant_scope_hides_other_tenants(self):
        status, payload = http(self.server.url("/router/metrics"),
                               headers={"X-Tenant": "tenant-a"})
        self.assertEqual(status, 200)
        self.assertNotIn("tenant-b", payload["per_tenant"])
        self.assertEqual(payload["aggregated"]["scope"], "own-tenant")

    def test_admin_sees_global_scope(self):
        status, payload = http(self.server.url("/router/metrics"),
                               headers={"Authorization": "Bearer cache-admin-key"})
        self.assertEqual(status, 200)
        self.assertIn("tenant-b", payload["per_tenant"])
        self.assertEqual(payload["aggregated"]["scope"], "global")

    def test_config_requires_admin(self):
        status, _ = http(self.server.url("/config"))
        self.assertEqual(status, 401)
        status, payload = http(self.server.url("/config"),
                               headers={"Authorization": "Bearer cache-admin-key"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["cache_salt_policy"]["per_tenant_salt"])
        self.assertEqual(payload["kv_pool"]["residue_policy"], "zeroize")
        self.assertEqual(payload["kv_pool"]["namespace_isolation"], True)


class TimingSidechannelSimTest(_Base):
    mode = "vulnerable"

    def test_member_vs_control_ttft_separation(self):
        members = member_prefixes(MEMBER_SEED_COUNT)
        controls = [f"control-corpus-{i:02d} unrelated analytics topic" for i in range(30)]
        member_ttft = [self.chat(p, "tenant-a")[1]["ttft_ms"] for p in members]
        control_ttft = [self.chat(p, "tenant-a")[1]["ttft_ms"] for p in controls]
        self.assertTrue(all(t < 60 for t in member_ttft), member_ttft)
        self.assertTrue(all(t >= 185 for t in control_ttft), control_ttft)
        mean_delta = sum(control_ttft) / len(control_ttft) - sum(member_ttft) / len(member_ttft)
        self.assertGreater(mean_delta, 100)


class FixedTimingSimTest(_Base):
    mode = "fixed"

    def test_no_separation_when_tenant_scoped(self):
        members = member_prefixes(MEMBER_SEED_COUNT)
        controls = [f"control-fixed-{i:02d} unrelated analytics topic" for i in range(30)]
        member_ttft = [self.chat(p, "tenant-a")[1]["ttft_ms"] for p in members]
        control_ttft = [self.chat(p, "tenant-a")[1]["ttft_ms"] for p in controls]
        mean_delta = abs(sum(control_ttft) / len(control_ttft)
                         - sum(member_ttft) / len(member_ttft))
        self.assertLess(mean_delta, 30, "fixed 模式两类皆未命中，不应有时序差分")


if __name__ == "__main__":
    unittest.main()
