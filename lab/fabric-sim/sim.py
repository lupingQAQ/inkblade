# -*- coding: utf-8 -*-
"""纯 Python 离散事件/流水线 fabric 仿真（模拟，非真实硬件）。

模型：每个 flow 按 chunk 串行推进，路径上每条 link 是 FIFO 服务队列；队列积压触发
PFC 暂停帧与 ECN 标记；跨 rail 走 inter-plane core；straggler 降低单 host link 容量；
link failure 触发 spine 重选。所有指标来自仿真事件计数，不读外部答案。
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field

try:
    from .topology import Topology
except ImportError:  # 直接以脚本/顶层模块加载时
    from topology import Topology

SCENARIOS = ("baseline", "pfc-storm", "ecn", "rail-mismatch", "straggler",
             "link-failure", "mixed")
MB = 1024 * 1024
GBPS = 1_000_000_000


@dataclass
class LinkState:
    link_id: str
    gbps: float
    free_time_s: float = 0.0
    bytes: int = 0
    peak_queue_bytes: float = 0.0
    pfc_pause_frames: int = 0
    ecn_marks: int = 0
    drops: int = 0

    @property
    def capacity_bytes_s(self) -> float:
        return self.gbps * GBPS / 8


@dataclass
class Flow:
    flow_id: int
    src: int
    dst: int
    src_rail: int
    dst_rail: int
    size_bytes: int
    chunks: int
    start_s: float = 0.0
    completion_s: float = 0.0
    bytes_done: int = 0
    rerouted: bool = False


@dataclass
class Telemetry:
    scenario: str
    seed: int
    topology: dict
    flows: list[dict]
    ranks: dict
    links: list[dict]
    pfc_pause_frames: int
    ecn_marks: int
    drops: int
    cross_rail_flows: int
    rail_mismatch_flows: int
    failed_links: int
    rerouted_flows: int
    total_bytes: int
    chunks: int
    max_completion_ms: float
    median_completion_ms: float
    worst_rank: str
    worst_rank_ms: float
    goodput_gbps: float
    rail_matrix: dict
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema": "trident-fabric-sim/2026-10",
            "source": "discrete-event simulation",
            "hardware": False,
            "disclaimer": "模拟，非真实硬件；不能替代 10K GPU 实测",
            "scenario": self.scenario, "seed": self.seed,
            "topology": self.topology, "ranks": self.ranks,
            "flows": self.flows, "links": self.links,
            "pfc_pause_frames": self.pfc_pause_frames,
            "ecn_marks": self.ecn_marks, "drops": self.drops,
            "cross_rail_flows": self.cross_rail_flows,
            "rail_mismatch_flows": self.rail_mismatch_flows,
            "failed_links": self.failed_links,
            "rerouted_flows": self.rerouted_flows,
            "total_bytes": self.total_bytes, "chunks": self.chunks,
            "max_completion_ms": round(self.max_completion_ms, 4),
            "median_completion_ms": round(self.median_completion_ms, 4),
            "worst_rank": self.worst_rank,
            "worst_rank_ms": round(self.worst_rank_ms, 4),
            "goodput_gbps": round(self.goodput_gbps, 3),
            "rail_matrix": self.rail_matrix,
            "notes": self.notes,
        }


def _scenario_config(scenario: str, nodes: int) -> dict:
    cfg = {
        "ranks": min(nodes, 64), "bytes_per_flow": 16 * MB, "chunks": 16,
        "mismatch_fraction": 0.0, "storm_links": 0, "pfc_per_chunk": 25000,
        "straggler_rank": None, "straggler_factor": 1.0,
        "failures": 0, "kmin": 256 * 1024, "kmax": 1024 * 1024,
        "xoff": 16 * 1024 * 1024,
    }
    if scenario == "pfc-storm":
        cfg.update(storm_links=2, ranks=64, chunks=16)
    elif scenario == "ecn":
        cfg.update(ranks=min(nodes, 256), bytes_per_flow=8 * MB, chunks=8,
                   kmin=64 * 1024, kmax=256 * 1024, xoff=4 * 1024 * 1024)
    elif scenario == "rail-mismatch":
        cfg.update(mismatch_fraction=0.5)
    elif scenario == "straggler":
        cfg.update(straggler_rank=min(7, min(nodes, 64) - 1), straggler_factor=0.05)
    elif scenario == "link-failure":
        cfg.update(failures=2)
    elif scenario == "mixed":
        cfg.update(ranks=min(nodes, 128), bytes_per_flow=12 * MB, chunks=12,
                   mismatch_fraction=0.25, storm_links=2,
                   straggler_rank=min(7, min(nodes, 128) - 1), straggler_factor=0.08,
                   failures=2, kmin=96 * 1024, kmax=384 * 1024, xoff=4 * 1024 * 1024)
    return cfg


def simulate(topology: Topology, scenario: str = "baseline", *, seed: int = 7,
             ranks: int | None = None, bytes_per_flow: int | None = None,
             chunks: int | None = None) -> Telemetry:
    if scenario not in SCENARIOS:
        raise ValueError(f"未知 scenario {scenario}")
    cfg = _scenario_config(scenario, topology.nodes)
    if ranks:
        cfg["ranks"] = max(2, min(topology.nodes, ranks))
    if bytes_per_flow:
        cfg["bytes_per_flow"] = int(bytes_per_flow)
    if chunks:
        cfg["chunks"] = max(1, int(chunks))
    rng = random.Random(seed)
    rank_hosts = [i * topology.nodes // cfg["ranks"] for i in range(cfg["ranks"])]
    straggler_host = (rank_hosts[cfg["straggler_rank"]]
                      if cfg["straggler_rank"] is not None else None)
    # 故障链路：选 rank 0/1 的源 leaf，确保默认 ECMP 路径确实受影响
    failed: set[str] = set()
    for i in range(cfg["failures"]):
        leaf = topology.host_leaf(rank_hosts[i % len(rank_hosts)], i % topology.rails)
        failed.add(f"leaf:{leaf}:spine:{i % topology.spines}")
    storm_links = {f"rain-{i}" for i in range(cfg["storm_links"])}
    states: dict[str, LinkState] = {}
    flows: list[Flow] = []
    pfc_total = ecn_total = drops = 0
    cross_rail = mismatch = rerouted = 0
    rail_matrix: dict[str, dict[str, int]] = {}

    def state(link: dict) -> LinkState:
        lid = link["id"]
        if lid not in states:
            states[lid] = LinkState(lid, link["gbps"])
        return states[lid]

    def send(flow: Flow, chunk_bytes: int, now: float) -> float:
        nonlocal pfc_total, ecn_total, drops, rerouted
        src_rail = flow.src_rail
        dst_rail = flow.dst_rail
        path = None
        hint = flow.flow_id % topology.spines
        for attempt in range(topology.spines):
            try:
                candidate = topology.path(flow.src, flow.dst, src_rail, dst_rail,
                                          failed=failed, spine_hint=hint + attempt)
                path = candidate
                break
            except RuntimeError:
                continue
        if path is None:
            raise RuntimeError("fabric 无可用路径（spine 全故障）")
        default_link = f"leaf:{topology.host_leaf(flow.src, src_rail)}:spine:{hint}"
        if default_link in failed and not flow.rerouted:
            flow.rerouted = True
            rerouted += 1
        for link in path:
            st = state(link)
            capacity = st.capacity_bytes_s
            if straggler_host is not None and link["id"].startswith(f"host:{straggler_host}:"):
                capacity *= cfg["straggler_factor"]
            start = max(now, st.free_time_s)
            backlog = max(0.0, (st.free_time_s - now) * capacity)
            st.peak_queue_bytes = max(st.peak_queue_bytes, backlog)
            if backlog > cfg["xoff"]:
                delta = max(1, int(backlog / cfg["xoff"]))
                st.pfc_pause_frames += delta
                pfc_total += delta
            if storm_links and link["kind"] == "host":
                # 每个 flow 的源 host link 注入风暴档；等价于 PFC 配置面被写成 storm
                st.pfc_pause_frames += cfg["pfc_per_chunk"]
                pfc_total += cfg["pfc_per_chunk"]
            if backlog > cfg["kmin"]:
                st.ecn_marks += 1
                ecn_total += 1
            if backlog > cfg["kmax"]:
                st.drops += 1
                drops += 1
            service = chunk_bytes / capacity
            st.free_time_s = start + service
            st.bytes += chunk_bytes
            now = st.free_time_s + link["latency_us"] / 1_000_000
        return now

    for i in range(cfg["ranks"]):
        src = rank_hosts[i]
        dst = rank_hosts[(i + 1) % cfg["ranks"]]
        src_rail = i % topology.rails
        dst_rail = src_rail
        if cfg["mismatch_fraction"] and rng.random() < cfg["mismatch_fraction"]:
            dst_rail = (src_rail + 1 + rng.randrange(max(1, topology.rails - 1))) % topology.rails
        if src_rail != dst_rail:
            mismatch += 1
        flow = Flow(i, src, dst, src_rail, dst_rail, cfg["bytes_per_flow"],
                    cfg["chunks"], start_s=i * 0.000001)
        chunk = max(1, cfg["bytes_per_flow"] // cfg["chunks"])
        now = flow.start_s
        for _ in range(cfg["chunks"]):
            now = send(flow, chunk, now)
            flow.bytes_done += chunk
        flow.completion_s = now
        flows.append(flow)
        if src_rail != dst_rail:
            cross_rail += 1
        key = f"leaf{topology.host_leaf(src, src_rail)}"
        bucket = rail_matrix.setdefault(key, {})
        bucket[f"rail-{src_rail}"] = bucket.get(f"rail-{src_rail}", 0) + chunk * cfg["chunks"]

    completions = sorted(f.completion_s * 1000 for f in flows)
    median = completions[len(completions) // 2] if completions else 0.0
    rank_completion: dict[str, float] = {}
    for flow in flows:
        rank_completion[f"rank-{flow.flow_id}"] = round(flow.completion_s * 1000, 4)
    worst_rank = max(rank_completion, key=rank_completion.get)
    worst_ms = rank_completion[worst_rank]
    total_bytes = sum(f.bytes_done for f in flows)
    makespan = max(f.completion_s for f in flows) if flows else 1.0
    telemetry = Telemetry(
        scenario=scenario, seed=seed, topology=topology.to_dict(),
        flows=[{"id": f.flow_id, "src": f.src, "dst": f.dst,
                "src_rail": f.src_rail, "dst_rail": f.dst_rail,
                "completion_ms": round(f.completion_s * 1000, 4),
                "rerouted": f.rerouted} for f in flows],
        ranks=rank_completion, links=[{
            "id": s.link_id, "gbps": s.gbps, "bytes": s.bytes,
            "peak_queue_bytes": round(s.peak_queue_bytes, 2),
            "pfc_pause_frames": s.pfc_pause_frames, "ecn_marks": s.ecn_marks,
            "drops": s.drops} for s in sorted(states.values(), key=lambda x: x.link_id)],
        pfc_pause_frames=pfc_total, ecn_marks=ecn_total, drops=drops,
        cross_rail_flows=cross_rail, rail_mismatch_flows=mismatch,
        failed_links=len(failed), rerouted_flows=rerouted,
        total_bytes=total_bytes, chunks=sum(cfg["chunks"] for _ in flows),
        max_completion_ms=max(completions) if completions else 0.0,
        median_completion_ms=median, worst_rank=worst_rank, worst_rank_ms=worst_ms,
        goodput_gbps=(total_bytes * 8 / makespan / GBPS) if makespan else 0.0,
        rail_matrix=rail_matrix,
        notes=[f"ranks={cfg['ranks']}", f"chunks/flow={cfg['chunks']}",
               f"storm_links={len(storm_links)}", f"failed_links={len(failed)}",
               "logical topology aggregated; not real switch config"])
    return telemetry
