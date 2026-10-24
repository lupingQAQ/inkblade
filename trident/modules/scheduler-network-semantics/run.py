# -*- coding: utf-8 -*-
"""调度网络语义（spec 5.2 网络架构模块 / 5.6 主机网络层）。

Volcano/Kueue/拓扑感知调度、跨 namespace 提交面、gang 调度拒绝服务面、
资源声明与拓扑错配：调度器的网络/拓扑假设决定集合通信可达对与资源囤积面。
"""

from __future__ import annotations

import json
from pathlib import Path


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


def _quantity_num(q) -> float:
    s = str(q)
    mult = 1.0
    for suf, m in (("Ki", 1024), ("Mi", 1024 ** 2), ("Gi", 1024 ** 3), ("Ti", 1024 ** 4), ("k", 1e3), ("M", 1e6)):
        if s.endswith(suf):
            mult, s = m, s[: -len(suf)]
            break
    try:
        return float(s) * mult
    except ValueError:
        return 0.0


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    items = snap.get("items", [])
    findings: list[dict] = []
    fps: dict = {}

    queues = {i.get("metadata", {}).get("name", "?"): i for i in items if i.get("kind") == "Queue"}
    podgroups = [i for i in items if i.get("kind") == "PodGroup"]
    clusterqueues = [i for i in items if i.get("kind") == "ClusterQueue"]
    flavors = [i for i in items if i.get("kind") == "ResourceFlavor"]
    localqueues = [i for i in items if i.get("kind") == "LocalQueue"]
    roles = [i for i in items if i.get("kind") == "ClusterRole"]
    bindings = [i for i in items if i.get("kind") == "ClusterRoleBinding"]

    # --- gang 调度拒绝服务面 ---
    for pg in podgroups:
        spec = pg.get("spec", {}) or {}
        queue = queues.get(str(spec.get("queue", "")), {})
        qspec = queue.get("spec", {}) or {}
        capacity = _quantity_num(qspec.get("capacity", 0))
        need_cpu = _quantity_num((spec.get("minResources", {}) or {}).get("cpu", 0))
        gang_pending = need_cpu > capacity > 0
        if podgroups or gang_pending:
            fps["volcano"] = True
            fps["gang-scheduling"] = True
        if gang_pending:
            fps["gang-dos-surface"] = True
            findings.append(_finding(
                "medium", "gang 调度资源囤积拒绝服务面",
                f"PodGroup {pg.get('metadata', {}).get('name', '?')}（minMember={spec.get('minMember')}，"
                f"minResources={spec.get('minResources')}）需求超过队列 {spec.get('queue')} 容量 "
                f"（capacity={qspec.get('capacity')}，reclaimable={qspec.get('reclaimable')}）："
                "gang 永久 Pending 占位 + 不可回收 → 其他租户训练被饿死（拒绝服务面，无需特权）。",
                {"gang-dos-surface": True, "gang-scheduling": True, "volcano": True},
                combo=("nccl-collective-join",)))
        break

    # --- 跨 namespace 提交面 ---
    open_cqs = [cq for cq in clusterqueues
                if not ((cq.get("spec", {}) or {}).get("namespaceSelector") or {}).get("matchLabels")]
    wide_roles = []
    for b in bindings:
        ref = (b.get("roleRef", {}) or {}).get("name", "")
        for r in roles:
            if r.get("metadata", {}).get("name", "") != ref:
                continue
            for rule in r.get("rules", []) or []:
                if "create" in rule.get("verbs", []) and any(
                    res in rule.get("resources", []) for res in ("jobs", "podgroups", "rayjobs", "workloads")
                ):
                    for subj in b.get("subjects", []) or []:
                        if subj.get("name") in ("system:authenticated", "system:anonymous", "*"):
                            wide_roles.append({"binding": b.get("metadata", {}).get("name", "?"),
                                               "role": ref, "subject": subj.get("name")})
    if open_cqs and (localqueues or wide_roles):
        fps["kueue"] = True
        fps["cross-namespace-submit"] = True
        findings.append(_finding(
            "medium", "跨 namespace 训练作业提交面",
            f"ClusterQueue namespaceSelector 为空（全命名空间）={[c.get('metadata', {}).get('name') for c in open_cqs]}；"
            f"LocalQueue={len(localqueues)}（如 {[l.get('metadata', {}).get('namespace') for l in localqueues]}）；"
            f"宽授权绑定={json.dumps(wide_roles, ensure_ascii=False)}。任意命名空间（含低信任沙箱）"
            "可把作业注入共享训练队列：经 RDMA/IB 拓扑与集合通信组直接接触高价值训练面。",
            {"cross-namespace-submit": True, "kueue": True,
             "wide-submit-binding": bool(wide_roles)},
            combo=("ray-dashboard-job", "nccl-collective-join")))

    # --- 拓扑感知与网络资源错配 ---
    if flavors:
        fps["topology-aware-scheduling"] = True
        covered: set[str] = set()
        for cq in clusterqueues:
            for rg in (cq.get("spec", {}) or {}).get("resourceGroups", []) or []:
                covered |= set(rg.get("coveredResources", []) or [])
        wanted: set[str] = set()
        for pg in podgroups:
            wanted |= set((pg.get("spec", {}) or {}).get("minResources", {}) or {})
        for item in snap.get("items", []):
            if item.get("kind") == "Pod":
                for c in (item.get("spec", {}) or {}).get("containers", []) or []:
                    wanted |= set(((c.get("resources", {}) or {}).get("requests", {}) or {}))
        network_resources = {r for r in wanted - covered
                             if r.startswith("rdma/") or "hca" in r or r.startswith("nvidia.com/")}
        if network_resources:
            fps["topology-mismatch"] = True
            findings.append(_finding(
                "medium", "拓扑感知调度与网络资源声明错配",
                f"ResourceFlavor={[f.get('metadata', {}).get('name') for f in flavors]}"
                f"（topology 注解={[f.get('metadata', {}).get('annotations', {}) for f in flavors]}）；"
                f"队列 covered={sorted(covered)}；工作负载声明 {sorted(wanted)}。"
                f"未覆盖的网络/GPU 资源 {sorted(network_resources)} 会在拓扑约束外落位："
                "集合通信跨 rail/plane 直连（可达对设计被破坏）或拓扑约束失效回退。",
                {"topology-mismatch": True, "topology-aware-scheduling": True},
                combo=("nccl-collective-join",)))
        else:
            findings.append(_finding(
                "info", "拓扑感知调度在位",
                f"ResourceFlavor 清单：{[f.get('metadata', {}).get('name') for f in flavors]}；"
                f"covered={sorted(covered)}。未见网络资源错配。",
                {"topology-aware-scheduling": True}))

    if not findings:
        findings.append(_finding(
            "info", "未发现 Volcano/Kueue 调度对象", "快照内无 Queue/PodGroup/ClusterQueue/ResourceFlavor。",
            {"scheduler-mapped": False}))

    artifacts = _artifact(ctx, "scheduler-network.json", {
        "queues": list(queues.values()), "podgroups": podgroups,
        "clusterqueues": clusterqueues, "flavors": flavors,
        "wide_bindings": wide_roles, "fingerprints": fps,
    })
    return {
        "summary": f"调度语义：Volcano PG {len(podgroups)}，Kueue CQ {len(clusterqueues)}，"
                   f"宽提交绑定 {len(wide_roles)}，flavor {len(flavors)}",
        "artifacts": artifacts,
        "findings": findings,
    }
