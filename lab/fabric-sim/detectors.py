# -*- coding: utf-8 -*-
"""与 trident fabric 模块同阈值的判定器（PFC/ECN/rail/straggler/链路故障）。"""
from __future__ import annotations

try:
    from .sim import Telemetry
except ImportError:
    from sim import Telemetry

PFC_STORM_THRESHOLD = 50000       # trident/modules/roce-pfc-storm/run.py
PFC_PAUSE_WARN = 1000
ECN_RATIO_WARN = 0.05
STRAGGLER_RATIO = 2.0             # trident/modules/nccl-straggler-injection/run.py
STRAGGLER_ABS_MS = 5000
RAIL_MISMATCH_WARN = 0


def detect(t: Telemetry) -> list[dict]:
    findings: list[dict] = []
    if t.pfc_pause_frames >= PFC_STORM_THRESHOLD:
        findings.append({
            "rule": "fabric.pfc-pause-storm", "sev": "high",
            "title": f"PFC 暂停风暴：{t.pfc_pause_frames} 帧（阈值 {PFC_STORM_THRESHOLD}）",
            "detail": {"pfc_pause_frames": t.pfc_pause_frames,
                       "storm_links": [l["id"] for l in t.links if l["pfc_pause_frames"] > 0][:8]},
        })
    elif t.pfc_pause_frames >= PFC_PAUSE_WARN:
        findings.append({
            "rule": "fabric.pfc-pause-warn", "sev": "medium",
            "title": f"PFC 暂停帧偏高：{t.pfc_pause_frames}",
            "detail": {"pfc_pause_frames": t.pfc_pause_frames},
        })
    ecn_ratio = t.ecn_marks / max(1, t.chunks)
    if t.ecn_marks and (ecn_ratio >= ECN_RATIO_WARN or t.ecn_marks >= 1000):
        findings.append({
            "rule": "fabric.ecn-congestion", "sev": "medium",
            "title": f"ECN 标记拥塞：{t.ecn_marks}（{ecn_ratio:.1%} chunks）",
            "detail": {"ecn_marks": t.ecn_marks, "ratio": round(ecn_ratio, 4),
                       "drops": t.drops},
        })
    if t.cross_rail_flows > RAIL_MISMATCH_WARN:
        findings.append({
            "rule": "fabric.rail-mismatch", "sev": "medium",
            "title": f"rail 错配：{t.cross_rail_flows} 条流跨 rail（本应 rail-local）",
            "detail": {"cross_rail_flows": t.cross_rail_flows,
                       "rail_mismatch_flows": t.rail_mismatch_flows,
                       "flow_ids": [f["id"] for f in t.flows if f["src_rail"] != f["dst_rail"]][:16]},
        })
    ratio = (t.worst_rank_ms / t.median_completion_ms) if t.median_completion_ms else 0.0
    if t.worst_rank_ms >= STRAGGLER_ABS_MS or ratio >= STRAGGLER_RATIO:
        findings.append({
            "rule": "fabric.nccl-straggler", "sev": "high" if ratio >= 5 else "medium",
            "title": f"NCCL straggler：{t.worst_rank} {t.worst_rank_ms:.2f}ms"
                     f"（中位 {t.median_completion_ms:.2f}ms，{ratio:.1f}×）",
            "detail": {"worst_rank": t.worst_rank, "worst_ms": round(t.worst_rank_ms, 4),
                       "median_ms": round(t.median_completion_ms, 4),
                       "ratio": round(ratio, 3)},
        })
    if t.failed_links:
        findings.append({
            "rule": "fabric.link-failure", "sev": "info",
            "title": f"链路故障 {t.failed_links} 条，已重路由 {t.rerouted_flows} 条流",
            "detail": {"failed_links": t.failed_links, "rerouted_flows": t.rerouted_flows},
        })
    if not findings:
        findings.append({
            "rule": "fabric.baseline-clean", "sev": "info",
            "title": "fabric 基线未见 PFC/ECN/rail/straggler 异常",
            "detail": {"pfc_pause_frames": t.pfc_pause_frames, "ecn_marks": t.ecn_marks,
                       "cross_rail_flows": t.cross_rail_flows, "ranks": len(t.ranks)},
        })
    return findings


def verdict(t: Telemetry, findings: list[dict] | None = None) -> dict:
    findings = findings if findings is not None else detect(t)
    sev = [f["sev"] for f in findings]
    return {
        "schema": "trident-fabric-verdict/2026-10",
        "scenario": t.scenario,
        "ok": "high" not in sev,
        "high": sev.count("high"), "medium": sev.count("medium"),
        "info": sev.count("info"), "findings": findings,
        "simulated": True,
    }
