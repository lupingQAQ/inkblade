# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""in-pod 原生采集器（KubeTrail collectors 语义移植，只读 / 副作用显式标注）。

13 个采集 bucket（safe 只读；full 为主动探测/系统调用面，本移植只做 **只读 view 解析**）：
identity / environment / serviceaccount / proc / proc_sys_escape / filesystem / node_local /
runtime_local / k8s_context / k8s_permissions / credential_sweep / cloud_metadata / syscalls。

两种输入：
- ``view``：已采集的快照 dict（``inpod`` 节，测试/控制台侧）；
- ``root``：容器根目录（``/`` 的只读副本或 fixture 树），安全读取
  ``proc/self/status``、``proc/self/mountinfo``、``etc/shadow``、SA token 等，
  路径解析后必须仍在 root 下（禁 ``..`` 越界），单文件 ≤64KiB。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

COLLECTORS = {
    "identity": {"mode": "safe", "description": "uid/gid/hostname/capabilities 身份视角"},
    "environment": {"mode": "safe", "description": "环境变量中的云/框架凭据线索"},
    "serviceaccount": {"mode": "safe", "description": "挂载 SA、audience、automount"},
    "proc": {"mode": "safe", "description": "PID 命名空间与宿主进程可见性"},
    "proc_sys_escape": {"mode": "safe", "description": "/proc/sys 可写内核参数（core_pattern/modprobe）"},
    "filesystem": {"mode": "safe", "description": "挂载面（hostPath/敏感目录/设备）"},
    "node_local": {"mode": "safe", "description": "节点信息（kernel/os/runtime）"},
    "runtime_local": {"mode": "safe", "description": "容器运行时 socket/DIND/containerd"},
    "k8s_context": {"mode": "safe", "description": "命名空间/服务账号/集群 API 视角"},
    "k8s_permissions": {"mode": "safe", "description": "token 权限（由 can-i 快照提供）"},
    "credential_sweep": {"mode": "safe", "description": "凭据文件可读性（aws/docker/shadow）"},
    "cloud_metadata": {"mode": "safe", "description": "云元数据可达性（AWS/Azure/GCP）"},
    "syscalls": {"mode": "full", "description": "seccomp/apparmor/userns 限制面（只读推断）"},
}

DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN",
                  "DAC_READ_SEARCH", "BPF", "PERFMON"}
MAX_FILE_BYTES = 64 * 1024


def _read_under(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return ""
    if not path.is_file():
        return ""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_from_root(root: Path | str) -> dict:
    """从容器根目录只读采集（fixture 树/离线副本），返回 view dict 片段。"""
    base = Path(root)
    view: dict = {}
    status = _read_under(base, "proc/self/status")
    if status:
        uid = re.search(r"^Uid:\s+(\d+)", status, re.M)
        nspid = re.search(r"^NSpid:\s+(.+)$", status, re.M)
        caps = re.search(r"^CapEff:\s+([0-9a-fA-F]+)", status, re.M)
        view["identity"] = {
            "uid": int(uid.group(1)) if uid else None,
            "pid_namespace": "host" if nspid and len(nspid.group(1).split()) == 1 else "container",
            "cap_hex": caps.group(1) if caps else "",
        }
    mounts = _read_under(base, "proc/self/mountinfo")
    if mounts:
        parsed = []
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                parsed.append({"path": parts[4], "options": parts[5] if len(parts) > 5 else "",
                               "type": parts[-3] if len(parts) >= 3 else ""})
        view["filesystem"] = {"mounts": parsed}
    core = _read_under(base, "proc/sys/kernel/core_pattern")
    modprobe = _read_under(base, "proc/sys/kernel/modprobe")
    if core or modprobe:
        view["sys"] = {}
        if core:
            view["sys"]["/proc/sys/kernel/core_pattern"] = core.strip()
        if modprobe:
            view["sys"]["/proc/sys/kernel/modprobe"] = modprobe.strip()
    token = _read_under(base, "var/run/secrets/kubernetes.io/serviceaccount/token")
    if token:
        view["token"] = {"path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                         "jwt": token.strip(), "legacy": False}
    shadow = _read_under(base, "etc/shadow")
    credentials = []
    if shadow:
        credentials.append({"path": "/etc/shadow", "readable": True, "kind": "shadow"})
    kubeconfig = _read_under(base, "root/.kube/config")
    if kubeconfig:
        view["kubeconfig"] = {"path": "/root/.kube/config", "readable": True, "clusters": 1}
    if credentials:
        view["credentials"] = {"files": credentials}
    view["_collected_from_root"] = str(base)
    return view


def merge_views(*views: dict) -> dict:
    merged: dict = {}
    for view in views:
        for key, value in (view or {}).items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
    return merged


def collect(view: dict, *, root: Path | str | None = None) -> dict:
    from_root = collect_from_root(root) if root else {}
    merged = merge_views(from_root, view or {})
    findings = assess(merged)
    return {
        "collectors": list(COLLECTORS),
        "collector_count": len(COLLECTORS),
        "view": merged,
        "findings": findings,
        "summary": {
            "collectors": len(COLLECTORS),
            "inputs": (["root"] if root else []) + (["view"] if view else []),
            "exposures": len(findings),
            "critical": sum(1 for f in findings if f["sev"] == "critical"),
        },
    }


def _finding(sev, title, detail, evidence, fix):
    return {"sev": sev, "title": title, "detail": detail, "evidence": evidence,
            "mapping": "KubeTrail in-pod 采集器（CM-22）", "fix": fix}


def assess(view: dict) -> list[dict]:
    if not view:
        return []
    out: list[dict] = []
    identity = view.get("identity") or {}
    if identity.get("uid") == 0:
        out.append(_finding("high", "容器以 root（uid=0）运行",
                            "root 身份放大逃逸与凭据读取面（in-pod 本地视角）。",
                            "uid=0", "runAsNonRoot + 只读根文件系统"))
    if (identity.get("pid_namespace") == "host") or (view.get("proc") or {}).get("host_pid_visible"):
        out.append(_finding("critical", "PID 命名空间与宿主共享（hostPID）",
                            "可见宿主进程（命令行凭据/同宿进程内存路径），nsenter 逃逸前置成立。",
                            "pid_namespace=host", "禁用 hostPID；必要调试走受审计通道"))

    token = view.get("token") or {}
    sa = view.get("service_account") or {}
    if token or sa.get("automount"):
        legacy = bool(token.get("legacy"))
        out.append(_finding("high" if legacy else "medium",
                            f"SA token 挂载（{'legacy 长期' if legacy else 'bound'}）",
                            "token 可用于 API 横向；legacy token 无受众/绑定约束。",
                            f"path={token.get('path', sa.get('name', ''))}", "改用 bound token + 最小 RBAC"))

    for key, value in (view.get("environment") or {}).items():
        if any(s in key.upper() for s in ("AWS_", "AZURE_", "GOOGLE_", "TOKEN", "SECRET", "KEY")):
            out.append(_finding("high", f"环境变量暴露凭据线索：{key}",
                                "云/框架凭据环境变量可被同容器进程与崩溃转储读取。",
                                f"env={key}", "改用工作负载身份/外部密钥管理"))

    sys_writes = {k: v for k, v in (view.get("sys") or {}).items() if v}
    for key, value in sys_writes.items():
        if value and value not in ("0", "disabled"):
            out.append(_finding("critical", f"/proc/sys 可写内核参数：{key}",
                                "core_pattern/modprobe 可写 = 内核级命令执行（逃逸原语）。",
                                f"{key}={str(value)[:40]}", "只读挂载 /proc/sys；最小化 SYS_ADMIN"))

    sockets = []
    runtime = view.get("runtime") or {}
    for mount in (view.get("filesystem") or {}).get("mounts") or []:
        path = str(mount.get("path", ""))
        if "docker.sock" in path or "containerd.sock" in path or "crio.sock" in path:
            sockets.append(path)
        elif path in ("/", "/etc/kubernetes") or path.startswith("/proc/sys"):
            sev = "critical" if path == "/" else "high"
            out.append(_finding(sev, f"敏感宿主挂载：{path}",
                                "宿主根/控制面目录挂载可读写 = 逃逸与横向双支点。",
                                f"mount={path}", "禁止宿主挂载；按需只读子路径"))
        elif path.startswith("/dev/") and ("nvidia" in path or "kfd" in path):
            out.append(_finding("medium", f"GPU 设备直通：{path}",
                                "设备节点直通放大驱动面（ioctl/固件）风险。",
                                f"device={path}", "使用 device plugin/DRA，禁裸设备挂载"))
    if sockets or runtime.get("socket"):
        sock = runtime.get("socket") or sockets[0]
        out.append(_finding("critical", f"容器运行时 socket 可达：{sock}",
                            "持有 runtime socket 可在宿主拉起特权容器（root 级逃逸闭环）。",
                            f"socket={sock}", "禁止 socket 挂载；调试走受审计运维通道"))
    if runtime.get("dind"):
        out.append(_finding("high", "Docker-in-Docker（特权构建面）",
                            "DIND 需要特权与内核能力，逃逸面显著扩大。",
                            "dind=true", "改用 rootless buildkit/受控 CI runner"))

    caps = {str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
    dangerous = sorted(caps & DANGEROUS_CAPS)
    if dangerous:
        out.append(_finding("high", f"危险 capabilities：{dangerous}",
                            "SYS_ADMIN/SYS_MODULE/SYS_PTRACE 等直接提供逃逸或内核模块原语。",
                            f"caps={dangerous}", "drop ALL + 最小 add；准入限制"))

    cgroups = view.get("cgroups") or {}
    if str(cgroups.get("version")) == "v1" and cgroups.get("writable") and cgroups.get("release_agent"):
        out.append(_finding("critical", "cgroups v1 可写 + release_agent（CVE-2022-0492 面）",
                            "可写 release_agent 可在宿主执行命令（容器逃逸原语）。",
                            "cgroups=v1 writable=true release_agent=set", "升级 cgroups v2；禁 SYS_ADMIN"))

    seccomp = (view.get("seccomp") or {}).get("mode", "")
    if str(seccomp).lower() in ("unconfined", "unset", ""):
        out.append(_finding("high", f"seccomp 未启用（{seccomp or 'unset'}）",
                            "无系统调用过滤，内核攻击面全开。", f"seccomp={seccomp}",
                            "RuntimeDefault/Localhost profile"))
    apparmor = (view.get("apparmor") or {}).get("mode", "")
    if str(apparmor).lower() in ("unconfined", "unset", ""):
        out.append(_finding("medium", f"AppArmor 未启用（{apparmor or 'unset'}）",
                            "缺少 MAC 约束层。", f"apparmor={apparmor}", "启用 AppArmor/SELinux"))
    if (view.get("userns") or {}).get("mode") == "host":
        out.append(_finding("high", "user namespace 与宿主共享（host userns）",
                            "无 userns 隔离，容器内 root 即宿主 uid 映射 root。",
                            "userns=host", "启用 usernsRemap/rootless"))
    if (view.get("lxcfs") or {}).get("mounted"):
        out.append(_finding("medium", "LXCFS 挂载（资源视图伪造面）",
                            "LXCFS 可写/可挂载时影响资源视图与逃逸面。",
                            "lxcfs=mounted", "只读挂载最小路径"))

    metadata = view.get("cloud_metadata") or {}
    for provider in ("aws", "azure", "gcp"):
        info = metadata.get(provider) or {}
        if info.get("reachable"):
            out.append(_finding("critical", f"云元数据可达（{provider}）",
                                "可读取实例角色/MSI 凭据 → 云侧横向与权重桶访问。",
                                f"provider={provider} role={info.get('role', info.get('msi', ''))}",
                                "IMDSv2 + hop limit 1；网络策略禁 169.254.169.254"))

    kubeconfig = view.get("kubeconfig") or {}
    if kubeconfig.get("readable"):
        out.append(_finding("high", f"kubeconfig 可读：{kubeconfig.get('path', '')}",
                            "集群凭据可读 → 控制面横向（{n} 个集群）。".format(n=kubeconfig.get("clusters", "?")),
                            f"path={kubeconfig.get('path', '')}", "移除凭据文件；使用 bound SA"))

    for cred in (view.get("credentials") or {}).get("files") or []:
        if not cred.get("readable"):
            continue
        sev = "critical" if cred.get("kind") == "shadow" else "high"
        out.append(_finding(sev, f"凭据文件可读：{cred.get('path', '')}（{cred.get('kind', '')}）",
                            "本地凭据可读 → 密码哈希/云密钥/镜像仓库凭据外带。",
                            f"file={cred.get('path')} kind={cred.get('kind')}",
                            "只读根文件系统 + 最小镜像 + 密钥外置"))
    return out
