# -*- coding: utf-8 -*-
"""arch-intel 覆盖矩阵门槛校验测试（设计基线第 12 节权威门槛）。

先于 trident/arch-intel/check.py 编写（TDD）：fixture dict 注入，
不依赖真实语料文件即可校验门槛函数语义。
"""

import importlib.util
import json
import unittest
from pathlib import Path

ARCH_INTEL = Path(__file__).resolve().parent.parent / "trident" / "arch-intel"

# arch-intel 目录名含连字符（设计基线第 14 节目录结构），按路径加载模块
_spec = importlib.util.spec_from_file_location(
    "trident_arch_intel_check", ARCH_INTEL / "check.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CLOUD_PROVIDERS = _mod.CLOUD_PROVIDERS
NETWORK_TOPICS = _mod.NETWORK_TOPICS
REQUIRED = _mod.REQUIRED
verify = _mod.verify


def make_source(sid, category, org="org", topics=(), status="verified", cloud=None):
    s = {
        "id": sid,
        "file": f"trident/arch-intel/corpus/{sid}.md",
        "category": category,
        "organization": org,
        "system": sid,
        "urls": ["https://example.invalid/" + sid],
        "verification": {"date": "2026-10-25", "status": status, "method": "websearch"},
        "topics": list(topics),
    }
    if cloud:
        s["cloud"] = cloud
    return s


def make_matrix(self_built=8, cloud_counts=None, hybrid=3, network=8,
                network_topics=None, extra=None):
    """构造任意规模的最小矩阵 fixture。"""
    cloud_counts = cloud_counts or {p: 2 for p in CLOUD_PROVIDERS}
    sources = []
    for i in range(self_built):
        sources.append(make_source(f"self{i}", "self-built-networking", org=f"o{i}"))
    for prov, n in cloud_counts.items():
        for i in range(n):
            sources.append(
                make_source(f"{prov}{i}", "cloud-provider", org=prov, cloud=prov)
            )
    for i in range(hybrid):
        sources.append(make_source(f"hyb{i}", "hybrid-interconnect", org=f"h{i}"))
    network_topics = (
        network_topics if network_topics is not None else list(NETWORK_TOPICS)
    )
    per_topic = {t: 0 for t in network_topics}
    built = []
    for i in range(network):
        topic = network_topics[i % len(network_topics)]
        per_topic[topic] += 1
        built.append(topic)
    # 补齐：确保每个必需 topic 至少 1 源
    for topic, n in per_topic.items():
        while n < 1:
            built.append(topic)
            n += 1
    for t in built:
        sources.append(
            make_source(f"net{len(sources)}", "network-specialized", org="net-org",
                        topics=[t])
        )
    if extra:
        sources.extend(extra)
    return {"schema": "test-fixture", "sources": sources}


class TestThresholdsFixture(unittest.TestCase):
    """门槛函数语义：fixture 注入，覆盖达标/不达标边界。"""

    def test_minimum_matrix_all_ok(self):
        r = verify(make_matrix())
        self.assertTrue(r["ok"])
        self.assertTrue(r["self-built-networking"]["ok"])
        self.assertTrue(r["hybrid-interconnect"]["ok"])
        self.assertTrue(r["network-specialized"]["ok"])
        for prov in CLOUD_PROVIDERS:
            self.assertTrue(r["cloud-providers"][prov]["ok"], prov)

    def test_selfbuilt_below_threshold(self):
        r = verify(make_matrix(self_built=7))
        self.assertFalse(r["self-built-networking"]["ok"])
        self.assertEqual(r["self-built-networking"]["count"], 7)
        self.assertEqual(r["self-built-networking"]["required"], 8)
        self.assertFalse(r["ok"])

    def test_selfbuilt_exactly_at_threshold(self):
        r = verify(make_matrix(self_built=8))
        self.assertTrue(r["self-built-networking"]["ok"])

    def test_cloud_provider_below_two(self):
        counts = {p: 2 for p in CLOUD_PROVIDERS}
        counts["azure"] = 1
        r = verify(make_matrix(cloud_counts=counts))
        self.assertFalse(r["cloud-providers"]["azure"]["ok"])
        self.assertFalse(r["cloud-providers"]["ok"])
        self.assertFalse(r["ok"])

    def test_all_cloud_providers_required(self):
        counts = {p: 2 for p in CLOUD_PROVIDERS}
        del counts["huawei"]
        r = verify(make_matrix(cloud_counts=counts))
        self.assertFalse(r["cloud-providers"]["huawei"]["ok"])
        self.assertFalse(r["ok"])

    def test_hybrid_below_threshold(self):
        r = verify(make_matrix(hybrid=2))
        self.assertFalse(r["hybrid-interconnect"]["ok"])
        self.assertFalse(r["ok"])

    def test_network_count_below_threshold(self):
        # 7 个专源、每个各占一个 topic：不补齐、不越限 → 仅数量不达标
        topics = list(NETWORK_TOPICS)[:7]
        r = verify(make_matrix(network=7, network_topics=topics))
        self.assertFalse(r["network-specialized"]["ok"])
        self.assertEqual(r["network-specialized"]["count"], 7)
        self.assertEqual(
            r["network-specialized"]["required"], REQUIRED["network-specialized"]
        )

    def test_network_missing_topic_fails(self):
        topics = [t for t in NETWORK_TOPICS if t != "dra-compute-domain-imex"]
        r = verify(make_matrix(network=8, network_topics=topics))
        self.assertFalse(r["network-specialized"]["ok"])
        self.assertFalse(
            r["network-specialized"]["topics"]["dra-compute-domain-imex"]["ok"]
        )

    def test_unverified_sources_not_counted(self):
        stale = make_source("stale", "self-built-networking",
                            status="unverified-stale-link")
        r = verify(make_matrix(self_built=7, extra=[stale]))
        self.assertEqual(r["self-built-networking"]["count"], 7)
        self.assertFalse(r["self-built-networking"]["ok"])

    def test_empty_matrix_all_fail(self):
        r = verify({"schema": "x", "sources": []})
        self.assertFalse(r["ok"])
        self.assertFalse(r["self-built-networking"]["ok"])
        self.assertFalse(r["hybrid-interconnect"]["ok"])
        self.assertFalse(r["network-specialized"]["ok"])
        self.assertFalse(r["cloud-providers"]["ok"])


class TestRealMatrix(unittest.TestCase):
    """真实语料矩阵：达标且与 corpus 文件一一对应。"""

    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(
            (ARCH_INTEL / "coverage-matrix.json").read_text(encoding="utf-8")
        )
        cls.result = verify(cls.matrix)

    def test_all_categories_pass(self):
        self.assertTrue(self.result["ok"], f"门槛未达标：{self.result}")

    def test_every_source_has_corpus_file(self):
        for s in self.matrix["sources"]:
            p = Path(__file__).resolve().parent.parent / s["file"]
            self.assertTrue(p.exists(), f"corpus 文件缺失：{s['file']}")
            self.assertEqual(p.read_text(encoding="utf-8")[:2], "# ",
                             f"corpus 首行应为标题：{p.name}")

    def test_every_corpus_file_listed(self):
        corpus_dir = ARCH_INTEL / "corpus"
        listed = {s["id"] for s in self.matrix["sources"]}
        for f in corpus_dir.glob("*.md"):
            self.assertIn(f.stem, listed, f"corpus 文件未入矩阵：{f.name}")


if __name__ == "__main__":
    unittest.main()
