# -*- coding: utf-8 -*-
"""CNI 语义可达性图（spec 5.2 网络架构模块 / 5.6 设计约束）。

聚合网络架构模块族其余九个模块的指纹 findings → core.reachability.infer
推演可达性图 → 落 run（graph_nodes/graph_edges，经 upsert_node/add_edge）→
输出五维可达矩阵 finding 与 artifact。
任何「网络可达」结论注明层级与判定方式；本模块不发起任何网络请求
（主动实测仅在主动探测/利用验证级别且授权下另行执行）。
"""

from __future__ import annotations

import json
from pathlib import Path

try:  # 常规：包在 sys.path 上
    from inkblade.core.reachability import MATRIX_DIMENSIONS, infer
except ImportError:  # 兜底：按本文件位置定位仓库根
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from inkblade.core.reachability import MATRIX_DIMENSIONS, infer

SOURCE_MODULES = (
    "fabric-topology-isolation",
    "cni-stack-capability",
    "multus-sriov-rdma-bypass",
    "collective-communication-surface",
    "gpu-network-operator-posture",
    "inference-gateway-pd",
    "storage-protocol-csi",
    "dns-service-discovery",
    "scheduler-network-semantics",
)


def _parse_marker(detail: str) -> dict:
    if " ||fingerprints=" not in detail:
        return {}
    tail = detail.rsplit(" ||fingerprints=", 1)[1].split(" ||combo=", 1)[0]
    try:
        parsed = json.loads(tail)
        return {k: v for k, v in parsed.items() if isinstance(v, bool)} if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _merge_file(merged: dict, stem: str, data) -> None:
    if isinstance(data, dict):
        kind = str(data.get("kind", ""))
        if kind.endswith("List"):  # PodList/NetworkPolicyList/... 项缺 kind → 补单数 kind
            for it in data.get("items", []) or []:
                if isinstance(it, dict) and not it.get("kind"):
                    it["kind"] = kind[:-4]
        merged.setdefault("_sources", {})[stem] = data
        for k, v in data.items():
            if k in merged and isinstance(merged[k], list) and isinstance(v, list):
                merged[k] = merged[k] + v
            elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k].update(v)
            else:
                merged[k] = v
    elif isinstance(data, list):
        merged["items"] = merged.get("items", []) + data


def _load_snapshot(params: dict) -> dict:
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 lab/fixtures/network/ 路径）")
    if isinstance(snap, dict):
        return snap
    paths = snap if isinstance(snap, (list, tuple)) else [snap]
    merged: dict = {}
    for raw in paths:
        p = Path(str(raw))
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            _merge_file(merged, f.stem, json.loads(f.read_text(encoding="utf-8")))
    return merged


def _artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run")
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def _finding(sev: str, title: str, detail: str, fps: dict, combo=()) -> dict:
    f = {"sev": sev, "title": title, "detail": detail,
         "fingerprints": {k: bool(v) for k, v in fps.items()},
         "combo": list(combo)}
    tail = " ||fingerprints=" + json.dumps(f["fingerprints"], sort_keys=True, ensure_ascii=False)
    if combo:
        tail += " ||combo=" + ",".join(combo)
    f["detail"] += tail
    return f


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    run = ctx.get("run")

    # --- 聚合指纹：run 内前序模块 findings 标记 + 直接参数 + 快照自带 ---
    fps: dict = {}
    if run is not None:
        for step_key, detail in run.query("SELECT step_key, detail FROM findings WHERE run=?", (run.name,)):
            if step_key in SOURCE_MODULES:
                fps.update(_parse_marker(str(detail)))
    direct = params.get("fingerprints")
    if isinstance(direct, dict):
        fps.update({k: v for k, v in direct.items() if isinstance(v, bool)})
    snap_fps = snap.get("fingerprints")
    if isinstance(snap_fps, dict):
        fps.update({k: v for k, v in snap_fps.items() if isinstance(v, bool)})

    # --- 推演 + 落库（infer 内部经 run.upsert_node / run.add_edge 持久化） ---
    g = infer(fps, run=run)
    matrix = g.render_matrix()
    counts = {dim: len(edges) for dim, edges in matrix.items()}
    reached = sum(counts.values())

    lines = [
        f"{dim}: {counts[dim]} 条边" + (
            "（" + "；".join(f"{e['src']}→{e['dst']} {e['verdict']}/{e['method']}" for e in edges[:3]) + "）"
            if edges else "")
        for dim, edges in matrix.items()
    ]
    sev = "high" if reached else "info"
    detail = (
        "五维可达矩阵（CNI 语义感知，默认静态推演/配置证据；主动实测仅授权级别另行执行）：\n"
        + "\n".join(lines)
        + f"\n聚合指纹 {len(fps)} 项；图节点 {len(g.nodes)}、边 {len(g.edges)} 已落 graph_nodes/graph_edges。"
        "注意：「有 NetworkPolicy」≠「隔离有效」——SR-IOV/IB/hostNetwork 旁路边见矩阵中「旁路」判定。"
    )

    finding = _finding(
        sev, "五维可达矩阵（CNI 语义感知）", detail,
        {k: v for k, v in fps.items() if k in (
            "hostnetwork-pod", "sriov-attachment", "ib-attachment", "network-policy-coverage",
            "vpc-native-cni", "security-group-gap", "ib-fabric", "ib-partition")},
        combo=tuple(sig for sig, need in (
            ("multus-sriov-rdma-bypass", ("sriov-attachment",)),
            ("ib-flatnet-no-partition", ("ib-fabric",)),
            ("vpc-cni-dual-controlplane-mismatch", ("vpc-native-cni",)),
        ) if all(fps.get(k) for k in need)))

    artifacts = _artifact(ctx, "reachability-matrix.json", {
        "matrix": matrix, "counts": counts,
        "nodes": [n.to_dict() for n in g.nodes],
        "edges": [e.to_dict() for e in g.edges],
        "fingerprints": fps, "dimensions": list(MATRIX_DIMENSIONS),
    })
    return {
        "summary": f"可达性图：指纹 {len(fps)}，节点 {len(g.nodes)}，边 {len(g.edges)}，"
                   f"命中维度 {sum(1 for c in counts.values() if c)}/5",
        "artifacts": artifacts,
        "findings": [finding],
    }
