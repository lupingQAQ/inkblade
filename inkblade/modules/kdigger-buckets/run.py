"""kdigger-buckets — kdigger 20 个 in-pod 采集 bucket 的只读判定。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, mapping = _C.section, _C.mapping

BUCKETS = (
    "admission", "apiresources", "authorization", "capabilities", "cgroups", "cloudmetadata",
    "containerdetect", "devices", "environment", "mount", "node", "pidnamespace", "processes",
    "runtime", "services", "syscalls", "token", "userid", "usernamespace", "version",
)
DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN",
                  "DAC_READ_SEARCH", "BPF", "PERFMON"}


def _view(snapshot: dict) -> dict:
    return snapshot.get("inpod") or snapshot


def analyze(snapshot: dict, params: dict) -> list[dict]:
    view = _view(snapshot)
    if not view and not snapshot.get("admission"):
        return []
    out: list[dict] = []

    def add(bucket: str, sev: str, title: str, detail: str, evidence: str, fix: str) -> None:
        out.append(finding(sev, f"bucket {bucket}：{title}", detail, evidence=evidence,
                           mapping_text="kdigger 20 bucket（in-pod 视角）",
                           fix=fix, bucket=bucket))

    meta = view.get("cloud_metadata") or {}
    for provider, info in meta.items():
        if isinstance(info, dict) and info.get("reachable"):
            add("cloudmetadata", "critical", f"{provider} 元数据可达",
                "实例角色/MSI 凭据可读 → 云侧横向。", f"provider={provider}",
                "IMDSv2 + hop limit 1 + 网络策略")
    if (snapshot.get("admission") or {}).get("pod_security_enforced") is False:
        add("admission", "high", "PSA/准入未强制",
            "特权/hostPath 模板可落地（与 kdigger dry-run 面一致）。", "pod_security_enforced=false",
            "启用 PSA restricted + 拒绝特权")

    runtime = view.get("runtime") or {}
    if runtime.get("socket"):
        add("runtime", "critical", f"运行时 socket 可达：{runtime.get('socket')}",
            "socket = 宿主拉起特权容器（root 级）。", f"socket={runtime.get('socket')}",
            "禁 socket 挂载")
        add("containerdetect", "high", f"检测到 {runtime.get('engine', '?')} 运行时",
            "运行时类型/版本决定逃逸原语（runc/shim）。",
            f"engine={runtime.get('engine')} version={runtime.get('version')}",
            "运行时版本固定 + 补丁基线")
    for mount in (view.get("filesystem") or {}).get("mounts") or []:
        path = str(mount.get("path", ""))
        if path == "/" or path.startswith("/etc/kubernetes"):
            add("mount", "critical", f"宿主敏感挂载：{path}",
                "宿主根/控制面目录读写 = 逃逸。", f"mount={path}", "禁宿主挂载")
        elif path.startswith("/proc") and mount.get("rw"):
            add("mount", "high", f"/proc 可写挂载：{path}",
                "/proc/sys 可写提供内核参数操控面。", f"mount={path}", "只读 /proc")
        elif path.startswith("/dev/") and any(d in path for d in ("nvidia", "kfd")):
            add("devices", "medium", f"设备直通：{path}",
                "GPU 设备 ioctl 面。", f"device={path}", "device plugin/DRA")
    for key, value in (view.get("sys") or {}).items():
        if value:
            add("mount", "critical", f"可写内核参数：{key}",
                "core_pattern/modprobe 可写 = 内核命令执行。", f"{key}={str(value)[:40]}",
                "只读 /proc/sys + drop SYS_ADMIN")

    caps = {str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
    if caps & DANGEROUS_CAPS:
        add("capabilities", "high", f"危险能力 {sorted(caps & DANGEROUS_CAPS)}",
            "能力集直接提供逃逸/内核面。", f"caps={sorted(caps)}", "drop ALL + 最小 add")
    cgroups = view.get("cgroups") or {}
    if str(cgroups.get("version")) == "v1" and cgroups.get("writable"):
        add("cgroups", "critical", "cgroups v1 可写",
            "release_agent 检测面（CVE-2022-0492 前置）。", "cgroups=v1 writable=true",
            "升级 cgroups v2")
    if (view.get("pidnamespace") or {}).get("mode") == "host" or \
            (view.get("proc") or {}).get("pid_namespace") == "host":
        add("pidnamespace", "critical", "PID 命名空间与宿主共享",
            "nsenter/进程凭据读取面成立。", "pidnamespace=host", "禁 hostPID")
    if (view.get("processes") or {}).get("host_pid_visible") or \
            (view.get("proc") or {}).get("host_pid_visible"):
        add("processes", "high", "宿主进程可见",
            "可见宿主进程命令行与内存路径。", "host_pid_visible=true", "禁 hostPID")
    mode = str((view.get("seccomp") or {}).get("mode", "")).lower()
    if mode in ("unconfined", "unset", ""):
        add("syscalls", "high", f"seccomp 未启用（{mode or 'unset'}）",
            "系统调用面全开。", f"seccomp={mode}", "RuntimeDefault")
    sa = view.get("service_account") or {}
    if sa.get("automount") or view.get("token"):
        add("token", "high" if (view.get("token") or {}).get("legacy") else "medium",
            "SA token 挂载", "API 凭据面。", f"sa={sa.get('name')} automount={sa.get('automount')}",
            "bound token + 最小 RBAC")
    if (view.get("identity") or {}).get("uid") == 0:
        add("userid", "high", "uid=0", "root 身份放大逃逸面。", "uid=0", "runAsNonRoot")
    if (view.get("userns") or {}).get("mode") == "host":
        add("usernamespace", "high", "host user namespace",
            "容器 root 即宿主映射 root。", "userns=host", "usernsRemap/rootless")
    if view.get("kubeconfig", {}).get("readable"):
        add("apiresources", "high", f"kubeconfig 可读：{view['kubeconfig'].get('path')}",
            "集群控制面入口。", f"path={view['kubeconfig'].get('path')}", "移除凭据文件")
    env = view.get("environment") or {}
    sensitive = [k for k in env if any(s in k.upper() for s in ("AWS_", "AZURE_", "GOOGLE_", "TOKEN", "SECRET", "KEY"))]
    if sensitive:
        add("environment", "high", f"敏感环境变量 {sensitive[:4]}",
            "凭据环境变量可读。", f"env={sensitive[:4]}", "工作负载身份/外部密钥管理")
    for cred in (view.get("credentials") or {}).get("files") or []:
        if cred.get("readable"):
            add("authorization", "critical" if cred.get("kind") == "shadow" else "high",
                f"凭据文件可读：{cred.get('path')}", "本地凭据外带。",
                f"file={cred.get('path')}", "只读根文件系统")
    for service in section(snapshot, "services"):
        if service.get("type") in ("LoadBalancer", "NodePort"):
            add("services", "medium",
                f"服务对外暴露：{service.get('namespace')}/{service.get('name')}",
                f"类型 {service.get('type')} 可被集群外访问。",
                f"service={service.get('name')}", "收敛 LoadBalancer/NodePort")
    cluster = snapshot.get("cluster") or {}
    node = view.get("node") or {}
    if cluster.get("version") or node.get("kernel"):
        add("version", "info", "版本可指纹化",
            "K8s/内核版本暴露便于 CVE 匹配。",
            f"k8s={cluster.get('version')} kernel={node.get('kernel')}", "版本信息最小暴露")
    return out


def _observed(snapshot: dict) -> list[str]:
    view = _view(snapshot)
    present = set()
    if view.get("identity"):
        present.update({"identity", "userid"})
    if view.get("environment"):
        present.add("environment")
    if view.get("service_account") or view.get("token"):
        present.add("token")
    if view.get("proc"):
        present.add("pidnamespace")
        if view["proc"].get("host_pid_visible"):
            present.add("processes")
    if view.get("sys"):
        present.add("mount")
    if view.get("filesystem") or view.get("devices"):
        present.update({"mount", "devices"})
    if view.get("runtime"):
        present.update({"runtime", "containerdetect"})
    if view.get("capabilities"):
        present.add("capabilities")
    if view.get("cgroups"):
        present.add("cgroups")
    if view.get("seccomp") or view.get("apparmor") or view.get("userns"):
        present.add("syscalls")
    if view.get("userns"):
        present.add("usernamespace")
    if view.get("cloud_metadata"):
        present.add("cloudmetadata")
    if view.get("kubeconfig"):
        present.add("apiresources")
    if view.get("credentials"):
        present.add("authorization")
    if view.get("node") or (snapshot.get("cluster") or {}).get("version"):
        present.add("version")
    if snapshot.get("admission"):
        present.add("admission")
    if view.get("cani") or snapshot.get("cani"):
        present.add("authorization")
    if section(snapshot, "services"):
        present.add("services")
    return sorted(present)


def extra(snapshot: dict, findings: list[dict]) -> dict:
    observed = _observed(snapshot)
    return {"buckets_total": len(BUCKETS), "buckets_observed": len(observed),
            "buckets": observed, "risky": len({f.get("bucket") for f in findings})}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="kdigger buckets", extra=extra)
