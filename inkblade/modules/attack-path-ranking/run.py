"""attack-path-ranking — 最短攻击路径 + 割点/瓶颈排序（KubeHound CM-23）。

构图：subject → pod/secret → node/cloud；BFS 求最短路径；统计经过节点频次作为瓶颈。
只读：图全部来自快照，不探测、不执行。
"""
from __future__ import annotations

import importlib.util
from collections import Counter, deque
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
pods, pod_id, is_privileged, host_paths = _C.pods, _C.pod_id, _C.is_privileged, _C.host_paths
wildcard_subjects, subjects_with, section = _C.wildcard_subjects, _C.subjects_with, _C.section

RANK = {"critical": 0, "high": 1, "medium": 2}
WEIGHT = {"critical": 10, "high": 5, "medium": 2}


def build_graph(snapshot: dict) -> tuple[dict[str, str], list[tuple[str, str, str, str]]]:
    """返回 (nodes{id: kind}, edges[(src,dst,label,sev)])。"""
    nodes: dict[str, str] = {}
    edges: list[tuple[str, str, str, str]] = []

    def node(nid: str, kind: str) -> str:
        nodes.setdefault(nid, kind)
        return nid

    node("node:any", "node")
    node("cloud:any", "cloud")

    for pod in pods(snapshot):
        pid = node(f"pod:{pod_id(pod)}", "pod")
        privileged = is_privileged(pod) or any(h["path"] == "/" for h in host_paths(pod))
        sock = any("docker.sock" in h["path"] for h in host_paths(pod))
        if privileged or sock:
            edges.append((pid, "node:any", "CE_PRIV_MOUNT" if privileged else "CONTAINER_ATTACH",
                          "critical"))
        elif pod.get("hostPID"):
            edges.append((pid, "node:any", "SHARE_PS", "high"))
    metadata = (snapshot.get("inpod") or {}).get("cloud_metadata") or {}
    if any(isinstance(v, dict) and v.get("reachable") for v in metadata.values()):
        edges.append(("node:any", "cloud:any", "CLOUD_METADATA", "critical"))

    for subject in wildcard_subjects(snapshot):
        sid = node(f"subject:{subject}", "subject")
        edges.append((sid, "node:any", "SA_ESCALATE", "critical"))
        edges.append((sid, "cloud:any", "SA_ESCALATE", "critical"))
    for subject in subjects_with(snapshot, "create", "pods"):
        sid = node(f"subject:{subject}", "subject")
        for pod in pods(snapshot):
            if is_privileged(pod) or host_paths(pod):
                edges.append((sid, f"pod:{pod_id(pod)}", "POD_CREATE", "high"))
        edges.append((sid, "node:any", "POD_CREATE", "high"))
    for subject in subjects_with(snapshot, "create", "pods/exec"):
        sid = node(f"subject:{subject}", "subject")
        for pod in pods(snapshot):
            if is_privileged(pod) or host_paths(pod):
                edges.append((sid, f"pod:{pod_id(pod)}", "POD_EXEC", "critical"))
    for subject in subjects_with(snapshot, "get", "secrets"):
        sid = node(f"subject:{subject}", "subject")
        for secret in section(snapshot, "secrets"):
            if "token" in str(secret.get("type", "")) or "-token-" in str(secret.get("name", "")):
                edges.append((sid, f"secret:{secret.get('namespace', 'default')}/{secret.get('name')}",
                              "TOKEN_STEAL", "critical"))
    for subject in subjects_with(snapshot, "create", "rolebindings") + \
            subjects_with(snapshot, "create", "clusterrolebindings"):
        sid = node(f"subject:{subject}", "subject")
        edges.append((sid, "node:any", "ROLE_BIND", "critical"))
    return nodes, edges


def rank_paths(snapshot: dict, *, limit: int = 5) -> list[dict]:
    nodes, edges = build_graph(snapshot)
    adj: dict[str, list[tuple[str, str, str]]] = {}
    for src, dst, label, sev in edges:
        adj.setdefault(src, []).append((dst, label, sev))
    goals = {"node:any", "cloud:any"}
    paths: list[dict] = []
    for start in sorted(n for n, kind in nodes.items() if kind == "subject"):
        prev: dict[str, tuple[str, str, str]] = {}
        seen = {start}
        dq = deque([start])
        found = None
        while dq:
            cur = dq.popleft()
            if cur in goals:
                found = cur
                break
            for dst, label, sev in adj.get(cur, []):
                if dst in seen:
                    continue
                seen.add(dst)
                prev[dst] = (cur, label, sev)
                dq.append(dst)
        if found is None:
            continue
        chain = [found]
        labels = []
        sevs = []
        while chain[-1] != start:
            parent, label, sev = prev[chain[-1]]
            labels.append(label)
            sevs.append(sev)
            chain.append(parent)
        chain.reverse()
        labels.reverse()
        sevs.reverse()
        score = sum(WEIGHT.get(s, 1) for s in sevs)
        paths.append({"start": start, "goal": found, "nodes": chain,
                      "edges": labels, "score": score, "severity": sevs[0] if sevs else "medium"})
    paths.sort(key=lambda p: (-p["score"], len(p["nodes"]), p["start"]))
    return paths[: max(1, limit)]


def analyze(snapshot: dict, params: dict) -> list[dict]:
    limit = int(params.get("limit") or 5)
    paths = rank_paths(snapshot, limit=limit)
    out: list[dict] = []
    for i, path in enumerate(paths, 1):
        out.append(finding(
            path["severity"],
            f"最短攻击路径 #{i}（score={path['score']}）：{path['start']} → {path['goal']}",
            "链：" + " → ".join(path["nodes"]) + f"；边：{', '.join(path['edges'])}",
            evidence=f"path={path['nodes']} edges={path['edges']} score={path['score']}",
            mapping_text="KubeHound 最短攻击路径/关键节点（CM-23）",
            fix="按路径首跳收敛（RBAC 最小化 / 特权工作负载准入）",
            path=path["nodes"], score=path["score"],
        ))
    # 瓶颈节点：出现在最多路径上的中间/汇聚节点（割点近似）
    counter = Counter()
    for path in rank_paths(snapshot, limit=100):
        for nid in path["nodes"]:
            if not nid.startswith("subject:"):
                counter[nid] += 1
    for nid, hits in counter.most_common(3):
        if hits >= 2:
            out.append(finding(
                "high", f"瓶颈节点：{nid} 被 {hits} 条攻击路径复用",
                "单点修复收益最大（割点近似）：优先收敛该节点的权限/特权。",
                evidence=f"node={nid} paths={hits}",
                mapping_text="KubeHound 关键节点排序", fix="优先修复割点（RBAC/准入/隔离）",
                bottleneck=nid,
            ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    paths = rank_paths(snapshot, limit=100)
    return {"paths": len(paths), "top_score": paths[0]["score"] if paths else 0,
            "subjects": len({p["start"] for p in paths})}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="攻击路径排序", extra=extra)
