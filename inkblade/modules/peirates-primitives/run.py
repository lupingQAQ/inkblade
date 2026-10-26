"""peirates-primitives — Peirates 37 条命令原语可用性映射（含 scan-configmaps 凭据扫描）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, pods, pod_id, host_paths, is_privileged = _C.section, _C.pods, _C.pod_id, _C.host_paths, _C.is_privileged
subjects_with, automount_token = _C.subjects_with, _C.automount_token

PRIMITIVES = (
    "sa-menu", "ns-menu", "get-pods", "dump-pod-info", "find-volume-mounts",
    "list-secrets", "get-secrets", "scan-configmaps", "secret-to-sa", "sa-to-secret",
    "dump-token", "get-token", "can-i", "whoami", "get-namespaces", "get-nodes",
    "node-proxy", "get-services", "get-endpoints", "exec-via-kubelet", "kubelet-logs",
    "kubelet-run", "cloud-metadata", "aws-token", "gcp-token", "azure-token",
    "kops-state", "s3-ls", "get-configmaps", "get-roles", "get-rolebindings",
    "get-clusterroles", "get-clusterrolebindings", "escape-hostpath", "escape-socket",
    "escape-privileged", "escape-hostpid",
)


def _available(snapshot: dict) -> dict[str, str]:
    view = snapshot.get("inpod") or {}
    avail: dict[str, str] = {}
    paths = [h["path"] for p in pods(snapshot) for h in host_paths(p)]
    for path in (view.get("filesystem") or {}).get("mounts") or []:
        paths.append(str(path.get("path", "")))

    def add(name: str, evidence: str) -> None:
        avail.setdefault(name, evidence)

    if subjects_with(snapshot, "get", "pods") or pods(snapshot):
        add("get-pods", "pods/cani")
        add("dump-pod-info", f"{len(pods(snapshot))} pods")
    if paths:
        add("find-volume-mounts", f"paths={paths[:3]}")
    if subjects_with(snapshot, "list", "secrets"):
        add("list-secrets", f"subjects={subjects_with(snapshot, 'list', 'secrets')}")
    if subjects_with(snapshot, "get", "secrets"):
        add("get-secrets", f"subjects={subjects_with(snapshot, 'get', 'secrets')}")
    if subjects_with(snapshot, "list", "configmaps") or section(snapshot, "configmaps"):
        add("scan-configmaps", "configmaps 可见")
    if any("token" in str(s.get("type", "")) for s in section(snapshot, "secrets")):
        add("secret-to-sa", "token secret")
        add("sa-to-secret", "token secret")
    automount = [pod_id(p) for p in pods(snapshot) if automount_token(p)]
    if automount:
        add("dump-token", f"automount={automount[:3]}")
        add("get-token", f"automount={automount[:3]}")
    if subjects_with(snapshot, "create", "selfsubjectaccessreviews"):
        add("can-i", "SSAR allowed")
    if section(snapshot, "nodes"):
        add("get-nodes", "nodes 可见")
    if subjects_with(snapshot, "get", "nodes/proxy"):
        add("node-proxy", "nodes/proxy allowed")
    if any("exec" in (n.get("endpoints") or []) for n in section(snapshot, "kubelet")):
        add("exec-via-kubelet", "kubelet exec endpoint")
    if any("logs" in (n.get("endpoints") or []) for n in section(snapshot, "kubelet")):
        add("kubelet-logs", "kubelet logs endpoint")
    if any("run" in (n.get("endpoints") or []) for n in section(snapshot, "kubelet")):
        add("kubelet-run", "kubelet run endpoint")
    meta = view.get("cloud_metadata") or {}
    for provider, info in meta.items():
        if isinstance(info, dict) and info.get("reachable"):
            add("cloud-metadata", f"provider={provider}")
            add(f"{provider}-token", f"provider={provider}")
    if (snapshot.get("cloud") or {}).get("kops_state"):
        add("kops-state", "kops state store")
    if any(p == "/" for p in paths) or any(is_privileged(p) for p in pods(snapshot)):
        add("escape-privileged", "privileged/root hostPath")
    if any("docker.sock" in p or "containerd.sock" in p for p in paths):
        add("escape-socket", "runtime socket")
        add("escape-hostpath", "hostPath")
    if any(p.get("hostPID") for p in pods(snapshot)):
        add("escape-hostpid", "hostPID")
    if any(s.get("type") in ("LoadBalancer", "NodePort") for s in section(snapshot, "services")):
        add("get-services", "对外 Service")
    return avail


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from inkblade.kubetrail.manifestscan import scan_configmaps

    available = _available(snapshot)
    out: list[dict] = []
    dangerous = {
        "list-secrets": ("critical", "枚举全部 Secret"),
        "get-secrets": ("critical", "读取 Secret 内容"),
        "scan-configmaps": ("high", "扫描 ConfigMap 配置凭据"),
        "secret-to-sa": ("high", "Secret → ServiceAccount 映射"),
        "sa-to-secret": ("high", "ServiceAccount → Secret 映射"),
        "dump-token": ("critical", "导出 SA token"),
        "get-token": ("high", "读取 SA token"),
        "exec-via-kubelet": ("critical", "kubelet exec 通道"),
        "kubelet-run": ("critical", "kubelet run 通道"),
        "node-proxy": ("critical", "nodes/proxy 代理"),
        "cloud-metadata": ("critical", "云元数据凭据收割"),
        "aws-token": ("critical", "AWS 角色凭据"),
        "gcp-token": ("critical", "GCP token"),
        "azure-token": ("critical", "Azure MSI token"),
        "kops-state": ("high", "kops state 凭据"),
        "escape-socket": ("critical", "运行时 socket 逃逸"),
        "escape-privileged": ("critical", "特权容器逃逸"),
        "escape-hostpath": ("critical", "hostPath 逃逸"),
        "escape-hostpid": ("high", "hostPID 逃逸"),
    }
    for name, evidence in sorted(available.items()):
        if name not in dangerous:
            continue
        sev, desc = dangerous[name]
        out.append(finding(
            sev, f"Peirates 原语可用：{name}（{desc}）",
            f"命令原语 {name} 在当前快照可执行（只判定可用性，不执行）。",
            evidence=evidence,
            mapping_text="Peirates docs/commands/README.md（37 条）",
            fix="收敛相应 RBAC/准入/网络面；原语执行需逐动作审批",
            primitive=name,
        ))
    # scan-configmaps：真实扫描 ConfigMap 明文凭据（三态脱敏）
    scan = scan_configmaps(section(snapshot, "configmaps"))
    for hit in scan["findings"]:
        out.append({
            **hit,
            "title": "scan-configmaps：" + hit["title"],
            "primitive": "scan-configmaps",
            "evidence": hit.get("evidence", "") + " primitive=scan-configmaps",
        })
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    available = _available(snapshot)
    return {"primitives_total": len(PRIMITIVES), "available": len(available),
            "available_names": sorted(available),
            "groups": {"rbac": sum(1 for p in available if p.startswith(("get-", "list-", "sa-", "secret-"))),
                       "escape": sum(1 for p in available if p.startswith("escape-")),
                       "cloud": sum(1 for p in available if "token" in p or p in ("cloud-metadata", "kops-state"))}}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="Peirates 命令原语", extra=extra)
