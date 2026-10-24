# -*- coding: utf-8 -*-
"""arch-intel 覆盖矩阵门槛校验（设计基线第 12.2 节最低门槛，权威）。

四类门槛：
- self-built-networking（自建与超大规模训练组网）≥ 8 源
- cloud-providers（六云商）AWS / Azure / 阿里 / 腾讯 / GCP / 华为 各 ≥ 2 源
- hybrid-interconnect（混合互联与边界）≥ 3 源
- network-specialized（网络架构专源）≥ 8 源，且必需 topic 全覆盖
  （CNI、Multus/SR-IOV、Network Operator、DRA/ComputeDomain/IMEX、
  Gateway API Inference Extension、llm-d/NIXL、NCCL、IB/RoCE、存储协议）

只有核验状态为 verified 的源才计入门槛（stale/failed 显式记录缺口）。
verify(matrix: dict) -> dict：返回各类达标布尔 + 计数明细；顶层 ok = 全部达标。

用法：python trident/arch-intel/check.py [coverage-matrix.json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# 设计基线 12.2：最低门槛（权威，勿随意调整）
REQUIRED = {
    "self-built-networking": 8,
    "cloud-providers-per-provider": 2,
    "hybrid-interconnect": 3,
    "network-specialized": 8,
}

# 六云商（渗透检测的直接靶面）
CLOUD_PROVIDERS = ("aws", "azure", "aliyun", "tencent", "gcp", "huawei")

# 网络专源必需 topic（机器键，映射 设计基线 12.1「网络架构专源」清单）
NETWORK_TOPICS = (
    "cni",
    "multus-sriov",
    "network-operator",
    "dra-compute-domain-imex",
    "gateway-api-inference-extension",
    "llm-d-nixl",
    "nccl",
    "ib-roce",
    "storage-protocol",
)

VERIFIED = "verified"


def _is_verified(source: dict) -> bool:
    return source.get("verification", {}).get("status") == VERIFIED


def _category_result(count: int, required: int) -> dict:
    return {"count": count, "required": required, "ok": count >= required}


def verify(matrix: dict) -> dict:
    """校验覆盖矩阵：各类达标布尔 + 计数明细。"""
    sources = matrix.get("sources", [])
    verified = [s for s in sources if _is_verified(s)]
    by_cat: dict[str, list[dict]] = {}
    for s in verified:
        by_cat.setdefault(s.get("category", ""), []).append(s)

    self_built = _category_result(
        len(by_cat.get("self-built-networking", [])),
        REQUIRED["self-built-networking"],
    )

    clouds = {}
    for prov in CLOUD_PROVIDERS:
        n = sum(1 for s in by_cat.get("cloud-provider", []) if s.get("cloud") == prov)
        clouds[prov] = _category_result(
            n, REQUIRED["cloud-providers-per-provider"]
        )
    clouds_ok = all(c["ok"] for c in clouds.values())

    hybrid = _category_result(
        len(by_cat.get("hybrid-interconnect", [])),
        REQUIRED["hybrid-interconnect"],
    )

    net_sources = by_cat.get("network-specialized", [])
    topics = {}
    for topic in NETWORK_TOPICS:
        n = sum(1 for s in net_sources if topic in s.get("topics", []))
        topics[topic] = _category_result(n, 1)
    network = _category_result(
        len(net_sources), REQUIRED["network-specialized"]
    )
    network["topics"] = topics
    network["ok"] = network["ok"] and all(t["ok"] for t in topics.values())

    result = {
        "schema": "arch-intel-coverage-verification",
        "total_sources": len(sources),
        "verified_sources": len(verified),
        "self-built-networking": self_built,
        "cloud-providers": {**clouds, "ok": clouds_ok},
        "hybrid-interconnect": hybrid,
        "network-specialized": network,
    }
    result["ok"] = all(
        (
            self_built["ok"],
            clouds_ok,
            hybrid["ok"],
            network["ok"],
        )
    )
    return result


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "coverage-matrix.json"
    matrix = json.loads(path.read_text(encoding="utf-8"))
    report = verify(matrix)
    report.pop("ok")
    # 顶层摘要：一行一类
    lines = []
    lines.append(
        "self-built-networking: {count}/{required} ok={ok}".format(
            **report["self-built-networking"]
        )
    )
    for prov in CLOUD_PROVIDERS:
        r = report["cloud-providers"][prov]
        lines.append(f"cloud-providers.{prov}: {r['count']}/{r['required']} ok={r['ok']}")
    lines.append(
        "hybrid-interconnect: {count}/{required} ok={ok}".format(
            **report["hybrid-interconnect"]
        )
    )
    net = report["network-specialized"]
    lines.append(f"network-specialized: {net['count']}/{net['required']} ok={net['ok']}")
    for topic in NETWORK_TOPICS:
        r = net["topics"][topic]
        lines.append(f"  topic {topic}: {r['count']}/{r['required']} ok={r['ok']}")
    lines.append(
        f"verified {report['verified_sources']}/{report['total_sources']} sources"
    )
    print("\n".join(lines), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
