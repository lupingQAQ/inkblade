"""cdk-techniques — CDK 30 EXP / 13 evaluate 技术分类映射（登记不执行）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, pods, pod_caps, host_paths, is_privileged = _C.section, _C.pods, _C.pod_caps, _C.host_paths, _C.is_privileged
subjects_with = _C.subjects_with

EXPLOITS = (
    ("runc-pwn", "runc < 1.0（CVE-2019-5736 面）", "critical"),
    ("shim-pwn", "containerd-shim 旧版本", "high"),
    ("docker-sock-pwn", "docker.sock 可达", "critical"),
    ("mount-disk", "块设备挂载", "high"),
    ("lxcfs-rw", "LXCFS 可写挂载", "medium"),
    ("mount-cgroup", "cgroup 可写", "critical"),
    ("abuse-unpriv-userns", "user namespace 可写/共享", "high"),
    ("mount-procfs", "/proc 挂载", "high"),
    ("check-ptrace", "SYS_PTRACE 能力", "high"),
    ("rewrite-cgroup-devices", "cgroup devices 可写", "high"),
    ("cap-dac-read-search", "DAC_READ_SEARCH 能力", "high"),
    ("cap-sys-admin", "SYS_ADMIN 能力", "critical"),
    ("core-pattern", "core_pattern 可写", "critical"),
    ("modprobe", "modprobe 可写", "critical"),
    ("kernel-keyring", "内核 keyring 可读", "high"),
    ("cronjob-persistence", "CronJob 持久化工作负载", "high"),
    ("shadow-apiserver", "static pod/影子 apiserver", "high"),
    ("webshell", "ConfigMap/工作负载内 webshell 线索", "medium"),
    ("etcd-token", "etcd 无认证", "high"),
    ("secret-dump", "Secret 可读", "high"),
    ("configmap-dump", "ConfigMap 可读", "medium"),
    ("registry-brute", "镜像仓库凭据可读", "medium"),
    ("ak-scan", "云 AK 扫描命中", "high"),
    ("cloud-metadata", "云元数据可达", "critical"),
    ("sa-token", "SA token 可读", "high"),
    ("node-proxy", "nodes/proxy 可达", "high"),
    ("kubelet-exec", "kubelet exec 通道", "critical"),
    ("dind", "Docker-in-Docker", "high"),
    ("device-mount", "设备直通", "medium"),
    ("escape-hostpid", "hostPID × 特权", "critical"),
)

EVALUATE = (
    "privileged", "capabilities", "hostpath", "socket", "cgroups", "userns", "seccomp",
    "docker", "kernel", "lxcfs", "devices", "token", "environment",
)


def _view(snapshot: dict) -> dict:
    return snapshot.get("inpod") or snapshot


def _hits(snapshot: dict) -> dict[str, str]:
    view = _view(snapshot)
    paths = [m.get("path", "") for m in (view.get("filesystem") or {}).get("mounts") or []]
    for pod in pods(snapshot):
        paths += [h["path"] for h in host_paths(pod)]
    caps = {str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
    for pod in pods(snapshot):
        caps |= pod_caps(pod)
    sys_keys = [k for k, v in (view.get("sys") or {}).items() if v]
    nodes = section(snapshot, "nodes")
    runcs = [str(n.get("runc", "")) for n in nodes if n.get("runc")]
    containerd = [str(n.get("containerRuntime", "")) for n in nodes]
    persistence = snapshot.get("persistence") or {}
    configmap_text = str(snapshot.get("configmaps") or "")
    hits: dict[str, str] = {}

    def hit(name: str, evidence: str) -> None:
        hits.setdefault(name, evidence)

    if any(r.startswith("0.") for r in runcs):
        hit("runc-pwn", f"runc={runcs}")
    if any("docker://" in c and "24" not in c for c in containerd):
        hit("shim-pwn", f"runtime={containerd}")
    if any("docker.sock" in p for p in paths):
        hit("docker-sock-pwn", f"paths={paths[:3]}")
    if any("/dev/sd" in p or "/dev/nvme" in p for p in paths):
        hit("mount-disk", f"paths={paths[:3]}")
    if (view.get("lxcfs") or {}).get("mounted"):
        hit("lxcfs-rw", "lxcfs=mounted")
    if str((view.get("cgroups") or {}).get("version")) == "v1" and (view.get("cgroups") or {}).get("writable"):
        hit("mount-cgroup", "cgroups=v1 writable")
        hit("rewrite-cgroup-devices", "cgroups=v1 writable")
    if (view.get("userns") or {}).get("mode") == "host":
        hit("abuse-unpriv-userns", "userns=host")
    if any(p.startswith("/proc") for p in paths):
        hit("mount-procfs", f"paths={paths[:3]}")
    if "SYS_PTRACE" in caps:
        hit("check-ptrace", "cap=SYS_PTRACE")
    if "DAC_READ_SEARCH" in caps:
        hit("cap-dac-read-search", "cap=DAC_READ_SEARCH")
    if "SYS_ADMIN" in caps:
        hit("cap-sys-admin", "cap=SYS_ADMIN")
    if any("core_pattern" in k for k in sys_keys):
        hit("core-pattern", f"sys={sys_keys}")
    if any("modprobe" in k for k in sys_keys):
        hit("modprobe", f"sys={sys_keys}")
    if any(w.get("kind") == "CronJob" for w in persistence.get("workloads") or []):
        hit("cronjob-persistence", "CronJob in persistence.workloads")
    if persistence.get("static_pods"):
        hit("shadow-apiserver", f"static_pods={persistence.get('static_pods')}")
    if "webshell" in configmap_text.lower() or "shell.php" in configmap_text.lower():
        hit("webshell", "configmap 含 webshell 线索")
    if any(not e.get("client_cert_auth") for e in section(snapshot, "etcd")):
        hit("etcd-token", "etcd client_cert_auth=false")
    if subjects_with(snapshot, "get", "secrets"):
        hit("secret-dump", f"subjects={subjects_with(snapshot, 'get', 'secrets')}")
    if subjects_with(snapshot, "list", "configmaps"):
        hit("configmap-dump", f"subjects={subjects_with(snapshot, 'list', 'configmaps')}")
    if any(s.get("type") == "kubernetes.io/dockerconfigjson" for s in section(snapshot, "secrets")):
        hit("registry-brute", "dockerconfigjson secret")
    if "AKIA" in configmap_text:
        hit("ak-scan", "configmap 含 AWS AK 前缀")
    meta = view.get("cloud_metadata") or {}
    if any(isinstance(v, dict) and v.get("reachable") for v in meta.values()):
        hit("cloud-metadata", f"reachable={[k for k, v in meta.items() if isinstance(v, dict) and v.get('reachable')]}")
    if view.get("token") or (view.get("service_account") or {}).get("automount"):
        hit("sa-token", "SA token mounted")
    if subjects_with(snapshot, "get", "nodes/proxy"):
        hit("node-proxy", "nodes/proxy subjects")
    if any("exec" in (k.get("endpoints") or []) for k in section(snapshot, "kubelet")):
        hit("kubelet-exec", "kubelet exec endpoint")
    if (view.get("runtime") or {}).get("dind"):
        hit("dind", "dind=true")
    if (view.get("devices") or []):
        hit("device-mount", f"devices={view.get('devices')}")
    if any(p.get("hostPID") and is_privileged(p) for p in pods(snapshot)):
        hit("escape-hostpid", "hostPID×privileged")
    return hits


def analyze(snapshot: dict, params: dict) -> list[dict]:
    hits = _hits(snapshot)
    out = []
    for name, desc, sev in EXPLOITS:
        if name not in hits:
            continue
        out.append(finding(
            sev, f"CDK {name} 面可观测：{desc}",
            f"CDK exploit 技术分类 {name}（登记，不执行）；证据 {hits[name]}。",
            evidence=hits[name],
            mapping_text="CDK README Exploit 表（30）/ Evaluate（13）",
            fix="按技术面对应项收敛（能力/挂载/RBAC/准入）",
            technique=f"cdk:{name}", category="exploit",
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    view = _view(snapshot)
    caps = {str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
    evaluate_results = {
        "privileged": any(is_privileged(p) for p in pods(snapshot)),
        "capabilities": bool(caps),
        "hostpath": bool(host_paths({} if not pods(snapshot) else pods(snapshot)[0])) or bool(
            (view.get("filesystem") or {}).get("mounts")),
        "socket": bool((view.get("runtime") or {}).get("socket")),
        "cgroups": bool(view.get("cgroups")),
        "userns": bool((view.get("userns") or {}).get("mode")),
        "seccomp": bool((view.get("seccomp") or {}).get("mode")),
        "docker": "docker" in str((view.get("runtime") or {}).get("engine", "")),
        "kernel": bool((view.get("node") or {}).get("kernel")
                       or (snapshot.get("cluster") or {}).get("version")),
        "lxcfs": bool((view.get("lxcfs") or {}).get("mounted")),
        "devices": bool(view.get("devices")),
        "token": bool(view.get("token")),
        "environment": bool(view.get("environment")),
    }
    return {"exp_total": len(EXPLOITS), "exp_available": len({f.get("technique") for f in findings}),
            "evaluate_total": len(EVALUATE),
            "evaluate_checked": sum(1 for v in evaluate_results.values() if v),
            "evaluate_results": evaluate_results}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="CDK 技术分类", extra=extra)
