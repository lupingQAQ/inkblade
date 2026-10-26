"""kubehound-edges — KubeHound 26 类攻击边逐边判定（CE/EXPLOIT/IDENTITY/POD/TOKEN/VOLUME/…）。

只读：从集群快照的 Pod/RBAC/节点/云元数据面推导「主体 → 资源 → 逃逸」边，
每条边给证据样本与最小修复；不创建/不执行任何对象。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
pods, pod_id, is_privileged, host_paths, pod_caps = _C.pods, _C.pod_id, _C.is_privileged, _C.host_paths, _C.pod_caps
subjects_with, wildcard_subjects, section = _C.subjects_with, _C.wildcard_subjects, _C.section

EDGE_TOTAL = 26
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAPPING = "KubeHound 攻击边（docs/reference/attacks/index.md，26 类）"


class _Collector:
    def __init__(self):
        self.edges: dict[str, dict] = {}

    def add(self, edge: str, sev: str, title: str, evidence: str) -> None:
        item = self.edges.setdefault(edge, {"sev": sev, "titles": [], "evidence": []})
        if RANK[sev] < RANK[item["sev"]]:
            item["sev"] = sev
        if title not in item["titles"]:
            item["titles"].append(title)
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)

    def findings(self) -> list[dict]:
        out = []
        for edge in sorted(self.edges):
            item = self.edges[edge]
            out.append(finding(
                item["sev"],
                f"[{edge}] " + "；".join(item["titles"][:2]) + (
                    f"（+{len(item['titles']) - 2}）" if len(item["titles"]) > 2 else ""),
                f"KubeHound 边 {edge} 在目标集群可观测：{len(item['evidence'])} 条证据。",
                evidence="; ".join(item["evidence"][:3]),
                mapping_text=MAPPING,
                fix=_FIXES.get(edge, "收敛 RBAC/工作负载特权面；准入与审计双控"),
                edge=edge,
            ))
        return out


_FIXES = {
    "CE_PRIV_MOUNT": "禁止宿主根/敏感目录挂载；PSS restricted",
    "CE_MODULE_LOAD": "禁 SYS_MODULE 与 /lib/modules 挂载",
    "CE_NSENTER": "禁 hostPID + 去特权",
    "CE_VAR_LOG_SYMLINK": "/var/log 不落宿主；符号链接防护",
    "EXPLOIT_HOST_WRITE": "宿主挂载只读且最小路径",
    "TOKEN_STEAL": "bound token + 最小 RBAC",
    "TOKEN_LIST": "secret list 收敛到平台组件",
    "TOKEN_BRUTEFORCE": "token 名称不可枚举（随机化）+ 短有效期",
    "ROLE_BIND": "rolebinding 创建收敛到 break-glass",
    "POD_CREATE": "create pods 收敛到控制器 SA + 准入限制特权",
    "PERMISSION_DISCOVER": "限制 SSRR/SSAR 到审计组件",
    "IDENTITY_IMPERSONATE": "impersonate 仅 break-glass 且全程审计",
    "NODE_PROXY": "nodes/proxy 禁用（KAS 1.30+ 默认）",
}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    col = _Collector()
    all_pods = pods(snapshot)
    automount = [pod_id(p) for p in all_pods if _C.automount_token(p)]

    for pod in all_pods:
        pid = pod_id(pod)
        paths = [hp["path"] for hp in host_paths(pod)]
        caps = pod_caps(pod)
        sock = any("docker.sock" in p or "containerd.sock" in p or "crio.sock" in p for p in paths)
        if is_privileged(pod) or "/" in paths:
            col.add("CE_PRIV_MOUNT", "critical", f"{pid} 特权/根挂载", f"pod={pid} paths={paths}")
        if "SYS_MODULE" in caps or any(p == "/lib/modules" for p in paths):
            col.add("CE_MODULE_LOAD", "critical", f"{pid} 内核模块加载面", f"pod={pid} caps={sorted(caps)}")
        if pod.get("hostPID") and is_privileged(pod):
            col.add("CE_NSENTER", "critical", f"{pid} hostPID×特权", f"pod={pid}")
        if any(p == "/var/log" or p.startswith("/var/log/") for p in paths):
            col.add("CE_VAR_LOG_SYMLINK", "high", f"{pid} /var/log 挂载", f"pod={pid} paths={paths}")
        if paths:
            col.add("EXPLOIT_HOST_TRAVERSE", "high", f"{pid} 宿主路径遍历面", f"pod={pid} paths={paths}")
            col.add("EXPLOIT_HOST_WRITE", "high", f"{pid} 宿主路径可写假设", f"pod={pid} paths={paths}")
            col.add("VOLUME_ACCESS", "medium", f"{pid} 宿主卷访问", f"pod={pid} paths={paths}")
        if any(p.startswith(("/etc", "/proc", "/sys")) for p in paths):
            col.add("EXPLOIT_HOST_READ", "medium", f"{pid} 宿主配置读取面", f"pod={pid} paths={paths}")
        if sock:
            col.add("CONTAINER_ATTACH", "critical", f"{pid} 运行时 socket 挂载", f"pod={pid} paths={paths}")
        if pod.get("hostPID"):
            col.add("SHARE_PS", "high", f"{pid} 共享进程命名空间", f"pod={pid}")
        if pod.get("hostNetwork"):
            col.add("HOST_NETWORK", "medium", f"{pid} 共享宿主网络", f"pod={pid}")

    for subject in wildcard_subjects(snapshot):
        col.add("SA_ESCALATE", "critical", f"{subject} 通配符权限", f"subject={subject}")
    for subject in subjects_with(snapshot, "create", "pods"):
        col.add("POD_CREATE", "high", f"{subject} 可创建 Pod", f"subject={subject}")
    for subject in subjects_with(snapshot, "create", "pods/exec"):
        col.add("POD_EXEC", "high", f"{subject} 可 exec Pod", f"subject={subject}")
    for subject in subjects_with(snapshot, "create", "pods/attach"):
        col.add("POD_ATTACH", "medium", f"{subject} 可 attach Pod", f"subject={subject}")
    for subject in subjects_with(snapshot, "create", "pods/ephemeralcontainers"):
        col.add("POD_EPHEMERAL", "high", f"{subject} 可注入临时容器", f"subject={subject}")
    for resource in ("rolebindings", "clusterrolebindings"):
        for subject in subjects_with(snapshot, "create", resource):
            col.add("ROLE_BIND", "critical", f"{subject} 可创建 {resource}", f"subject={subject}")
    for subject in subjects_with(snapshot, "get", "secrets"):
        if automount:
            col.add("TOKEN_STEAL", "critical", f"{subject} 读 Secret × {len(automount)} 个 automount Pod",
                    f"subject={subject} automount={automount[:3]}")
        else:
            col.add("TOKEN_STEAL", "medium", f"{subject} 可读 Secret（无 automount Pod）", f"subject={subject}")
    for subject in subjects_with(snapshot, "list", "secrets"):
        col.add("TOKEN_LIST", "high", f"{subject} 可枚举 Secret", f"subject={subject}")
    for subject in subjects_with(snapshot, "impersonate", "users") + subjects_with(snapshot, "impersonate", "*"):
        col.add("IDENTITY_IMPERSONATE", "critical", f"{subject} 可 impersonate", f"subject={subject}")
    for subject in subjects_with(snapshot, "get", "nodes/proxy"):
        col.add("NODE_PROXY", "critical", f"{subject} 可走 nodes/proxy", f"subject={subject}")

    metadata = (snapshot.get("inpod") or {}).get("cloud_metadata") or {}
    for provider, info in metadata.items():
        if isinstance(info, dict) and info.get("reachable"):
            col.add("CLOUD_METADATA", "critical", f"{provider} 元数据可达", f"provider={provider}")
    for node in section(snapshot, "nodes"):
        runc = str(node.get("runc", ""))
        try:
            from trident.kubetrail.lpe import version_lt
        except Exception:  # 独立加载（无包上下文）时跳过精确版本判定
            version_lt = None
        if runc and version_lt is not None and version_lt(runc, "1.1.12"):
            col.add("CVE_EXPLOIT", "critical",
                    f"{node.get('name', '?')} runc {runc} 落在 CVE-2024-21626 面",
                    f"node={node.get('name')} runc={runc}")

    return col.findings()


def extra(snapshot: dict, findings: list[dict]) -> dict:
    edges = {f.get("edge") for f in findings}
    return {"edges_covered": len(edges), "edges_total": EDGE_TOTAL,
            "edges": sorted(e for e in edges if e),
            "unobservable": sorted(set(_ALL_EDGES) - edges)}


_ALL_EDGES = {
    "CE_MODULE_LOAD", "CE_NSENTER", "CE_PRIV_MOUNT", "CE_VAR_LOG_SYMLINK",
    "EXPLOIT_HOST_READ", "EXPLOIT_HOST_WRITE", "EXPLOIT_HOST_TRAVERSE",
    "POD_CREATE", "POD_EXEC", "POD_ATTACH", "POD_EPHEMERAL", "ROLE_BIND",
    "TOKEN_STEAL", "TOKEN_LIST", "TOKEN_BRUTEFORCE", "IDENTITY_ASSUME",
    "IDENTITY_IMPERSONATE", "VOLUME_ACCESS", "SHARE_PS", "CONTAINER_ATTACH",
    "PERMISSION_DISCOVER", "NODE_PROXY", "CLOUD_METADATA", "CVE_EXPLOIT",
    "HOST_NETWORK", "SA_ESCALATE",
}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeHound 攻击边", extra=extra)
