"""privileged-workloads — 特权工作负载盘点：privileged/host* 标志/seccomp 豁免/敏感 hostPath/危险 capabilities。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON"}
SENSITIVE_HOSTPATHS = (
    "/var/run/docker.sock", "/var/run/containerd.sock", "/run/containerd", "/var/run/crio",
    "/proc", "/sys", "/dev",
)


def _hostpath_hit(path: str):
    for sens in SENSITIVE_HOSTPATHS:
        if path == sens or path.startswith(sens + "/"):
            return sens
    return None


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    for pod in snapshot.get("pods", []):
        pid = f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"
        for container in pod.get("containers", []):
            sc = container.get("securityContext") or {}
            if sc.get("privileged"):
                findings.append(finding(
                    "high", f"{pid}：容器 {container.get('name', '?')} privileged=true",
                    detail="特权容器直接持有宿主全部能力（cap_eff 全 1），是宿主逃逸与横向的首要原语。",
                    evidence=f"container={container.get('name')} image={container.get('image')} privileged=true",
                    mapping="权限链「特权 GPU Pod 宿主逃逸」前置；准入基线（PSS restricted）",
                    fix="去除 privileged；GPU 需求走设备插件/DRAD；准入强制 restricted/baseline 例外审批",
                ))
            caps = sorted(set((sc.get("capabilities") or {}).get("add") or []) & DANGEROUS_CAPS)
            if caps:
                findings.append(finding(
                    "high", f"{pid}：危险 capabilities {caps}",
                    detail="SYS_ADMIN/SYS_PTRACE 等能力可直接用于宿主文件系统与进程操作（逃逸原语）。",
                    evidence=f"container={container.get('name')} capabilities.add={caps}",
                    mapping="逃逸原语检查（escape-primitives）交叉",
                    fix="按最小能力裁剪；必须项走豁免清单与审批",
                ))
            if sc.get("seccompProfile") == "Unconfined":
                findings.append(finding(
                    "medium", f"{pid}：seccomp 豁免（Unconfined）",
                    detail="seccomp Unconfined 放开系统调用面，扩大内核漏洞利用窗口。",
                    evidence=f"container={container.get('name')} seccompProfile=Unconfined",
                    mapping="准入基线（PodSecurity）",
                    fix="改 RuntimeDefault 并验证训练负载兼容性",
                ))
        for volume in pod.get("volumes", []):
            hp = (volume.get("hostPath") or {}).get("path", "")
            hit = _hostpath_hit(hp) if hp else None
            if hit:
                findings.append(finding(
                    "high", f"{pid}：敏感 hostPath {hp}",
                    detail=f"挂载宿主敏感路径（命中 {hit}）：可读写宿主配置/运行时入口/内核接口。",
                    evidence=f"volume={volume.get('name')} hostPath={hp}",
                    mapping="逃逸原语检查（escape-primitives）/ 容器运行时 Socket 逃逸",
                    fix="hostPath 白名单化（仅显式批准的只读挂载）；改用 CSI/Projected 卷",
                ))
        for flag, label in (("hostNetwork", "hostNetwork"), ("hostIPC", "hostIPC"), ("hostPID", "hostPID")):
            if pod.get(flag):
                findings.append(finding(
                    "medium", f"{pid}：{label}=true",
                    detail=f"{label} 共享宿主对应命名空间：绕过 CNI/NetworkPolicy（hostNetwork）或直取宿主 IPC/进程信息。",
                    evidence=f"{label}=true",
                    mapping="网络分层「主机网络层」旁路；逃逸原语检查",
                    fix="收敛 host* 标志；必须使用时登记例外并配准入拦截",
                ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="特权工作负载盘点")
