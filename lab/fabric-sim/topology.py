# -*- coding: utf-8 -*-
"""Rail-optimized 多平面 fat-tree 逻辑拓扑（模拟，不是真实交换机配置）。

为控制 10,000 节点的对象数量，逻辑上保留每 host × rail 的 NIC、leaf/spine 路径，
但不物化全部 host-to-host 链路；链路在流路径上按需生成。
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Topology:
    nodes: int
    rails: int
    planes: int
    leaves: int
    spines: int
    hosts_per_leaf: int
    link_gbps: float = 400.0
    core_gbps: float = 800.0
    latency_us: float = 1.0

    @classmethod
    def build(cls, nodes: int, *, rails: int = 8, planes: int = 2,
              leaves: int | None = None, spines: int = 32,
              link_gbps: float = 400.0) -> "Topology":
        if nodes < 64:
            raise ValueError("节点数至少 64（模拟器面向 1024–10000）")
        if rails < 1 or planes < 1:
            raise ValueError("rails/planes 必须 >= 1")
        if leaves is None:
            leaves = 64 if nodes <= 1024 else min(80, max(16, math.ceil(nodes / 128)))
        hosts_per_leaf = math.ceil(nodes / leaves)
        return cls(nodes=nodes, rails=rails, planes=planes, leaves=leaves,
                   spines=spines, hosts_per_leaf=hosts_per_leaf,
                   link_gbps=link_gbps, core_gbps=link_gbps * 2)

    def host_leaf(self, host: int, rail: int) -> int:
        """host 在 rail 上的 leaf id（逻辑聚合，跨 rail 落在不同平面）。"""
        group = (host // self.hosts_per_leaf) % max(1, self.leaves // self.planes)
        return (group * self.planes + (rail % self.planes)) % self.leaves

    def leaf_plane(self, leaf: int) -> int:
        return leaf % self.planes

    def rail_of_host(self, host: int, rail: int) -> str:
        return f"host-{host}:rail-{rail}"

    def path(self, src: int, dst: int, src_rail: int, dst_rail: int,
             *, failed: set[str] | None = None, spine_hint: int = 0) -> list[dict]:
        """返回 [(link_id, gbps, latency_us, kind)]；跨平面经 core。"""
        failed = failed or set()
        src_leaf = self.host_leaf(src, src_rail)
        dst_leaf = self.host_leaf(dst, dst_rail)
        src_plane = self.leaf_plane(src_leaf)
        dst_plane = self.leaf_plane(dst_leaf)
        links: list[dict] = [{
            "id": f"host:{src}:{src_rail}", "gbps": self.link_gbps,
            "latency_us": self.latency_us, "kind": "host"}]
        # 选一条未故障的 leaf→spine 链路（ECMP 风格轮转）
        spine = None
        for attempt in range(self.spines):
            candidate = (spine_hint + attempt) % self.spines
            lid = f"leaf:{src_leaf}:spine:{candidate}"
            if lid not in failed:
                spine = candidate
                break
        if spine is None:
            raise RuntimeError("无可用 spine（全故障）")
        links.append({"id": f"leaf:{src_leaf}:spine:{spine}", "gbps": self.link_gbps,
                      "latency_us": self.latency_us, "kind": "leaf-spine"})
        if src_plane != dst_plane:
            links.append({"id": f"core:plane-{src_plane}:plane-{dst_plane}:spine:{spine}",
                          "gbps": self.core_gbps, "latency_us": self.latency_us * 2,
                          "kind": "interplane"})
        links.append({"id": f"spine:{spine}:leaf:{dst_leaf}", "gbps": self.link_gbps,
                      "latency_us": self.latency_us, "kind": "spine-leaf"})
        links.append({"id": f"host:{dst}:{dst_rail}", "gbps": self.link_gbps,
                      "latency_us": self.latency_us, "kind": "host"})
        return links

    def to_dict(self) -> dict:
        return {"nodes": self.nodes, "rails": self.rails, "planes": self.planes,
                "leaves": self.leaves, "spines": self.spines,
                "hosts_per_leaf": self.hosts_per_leaf,
                "link_gbps": self.link_gbps, "core_gbps": self.core_gbps,
                "logical_links": "on-demand per flow (not materialized)"}

    def nodes_snapshot(self, *, omit_hca_every: int = 17) -> list[dict]:
        """生成 fabric-topology-isolation 可消费的节点快照（HCA 缺失触发 rail 错配）。"""
        out = []
        for host in range(self.nodes):
            rail = host % self.rails
            plane = self.host_leaf(host, rail) % self.planes
            labels = {"topology.rail": f"rail-{rail}",
                      "topology.plane": f"plane-{plane}"}
            annotations = {} if omit_hca_every and host % omit_hca_every == 0 else {
                "fabric.hca.inventory": ":ib"}
            out.append({"kind": "Node", "name": f"gpu-{host:05d}",
                        "labels": labels, "annotations": annotations})
        return out
