"""escape-primitives — 逃逸原语检查：宿主 socket/根与敏感目录挂载/危险 capabilities/特权×GPU 组合/SA 逃逸矩阵。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "/run/crio")
DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON"}
HOST_SENSITIVE_DIRS = ("/proc", "/sys", "/dev")
GPU_IMAGE_HINTS = ("sglang", "vllm", "ray", "cuda", "torch", "train", "verl", "areal", "triton", "deepspeed", "megatron")


def analyze(snapshot: dict, params: dict) -> list[dict]:
    pods = snapshot.get("pods", [])
    findings: list[dict] = []
    privileged_precedent = False

    for pod in pods:
        ns = pod.get("namespace", "default")
        pid = f"{ns}/{pod.get('name', '?')}"
        images = [str(c.get("image", "")).lower() for c in pod.get("containers", [])]
        for volume in pod.get("volumes", []):
            hp = (volume.get("hostPath") or {}).get("path", "")
            if not hp:
                continue
            if any(s in hp for s in RUNTIME_SOCKETS):
                privileged_precedent = True
                findings.append(finding(
                    "critical", f"{pid}：宿主容器运行时 socket 挂载（{hp}）",
                    detail="持有 docker.sock/containerd.sock 即可在宿主拉起特权容器（root 级逃逸闭环）。",
                    evidence=f"pod={pid} hostPath={hp}",
                    mapping="权限链「容器运行时 Socket 逃逸」",
                    fix="禁止运行时 socket 挂载（准入阻断）；必须调试时走受审计的运维通道",
                ))
            elif hp == "/":
                privileged_precedent = True
                findings.append(finding(
                    "critical", f"{pid}：宿主根文件系统挂载（/）",
                    detail="根挂载 = 宿主全部文件可读写（含 /etc、运行时与密钥）。",
                    evidence=f"pod={pid} hostPath=/",
                    mapping="权限链「特权 GPU Pod 宿主逃逸」",
                    fix="准入阻断根挂载；按需只读挂载具体子路径",
                ))
            elif any(hp == d or hp.startswith(d + "/") for d in HOST_SENSITIVE_DIRS):
                findings.append(finding(
                    "high", f"{pid}：宿主敏感目录挂载（{hp}）",
                    detail="/proc、/sys、/dev 挂载提供内核接口与设备面（含 /proc/sys 可写即内核参数操控）。",
                    evidence=f"pod={pid} hostPath={hp}",
                    mapping="逃逸原语；主机网络层",
                    fix="仅只读挂载必要路径；设备需求走 device plugin/DRA",
                ))
        for container in pod.get("containers", []):
            sc = container.get("securityContext") or {}
            if sc.get("privileged"):
                privileged_precedent = True
                if any(h in img for img in images for h in GPU_IMAGE_HINTS):
                    findings.append(finding(
                        "high", f"{pid}：特权 × GPU 框架镜像（{container.get('image', '?')}）→ 宿主逃逸原语组合",
                        detail="特权 + GPU/训练镜像组合（GPU 设备与 NVML/驱动面可达）：既定逃逸矩阵条件成立。",
                        evidence=f"pod={pid} privileged=true image={container.get('image')}",
                        mapping="权限链「特权 GPU Pod 宿主逃逸」；组合签名「硬件路线 → 权限姿态」",
                        fix="去特权 + 设备插件化；准入强制 PSS restricted（GPU 例外走审批通道）",
                    ))
            caps = sorted(set((sc.get("capabilities") or {}).get("add") or []) & DANGEROUS_CAPS)
            if caps:
                findings.append(finding(
                    "high", f"{pid}：危险 capabilities {caps}",
                    detail="SYS_ADMIN/SYS_PTRACE/NET_ADMIN 等可直接操控宿主文件系统、进程与网络（逃逸原语）。",
                    evidence=f"pod={pid} capabilities.add={caps}",
                    mapping="逃逸原语检查；Falco/Sigma 检测映射",
                    fix="最小能力集；必须项入豁免清单并审计",
                ))
        for flag, label, detail in (
            ("hostPID", "宿主进程可见", "hostPID 可见宿主全部进程（含凭据参数/同行进程内存路径）"),
            ("hostIPC", "宿主 IPC 命名空间共享", "hostIPC 可达共享内存段（密钥/梯度缓冲旁路）"),
            ("hostNetwork", "宿主网络命名空间共享", "hostNetwork 绕过 CNI/NetworkPolicy 并直连宿主服务"),
        ):
            if pod.get(flag):
                findings.append(finding(
                    "medium", f"{pid}：{label}（{flag}=true）",
                    detail=detail + "。",
                    evidence=f"pod={pid} {flag}=true",
                    mapping="逃逸原语（内核/宿主线索）；主机网络层",
                    fix="收敛 host* 标志；例外登记并准入管控",
                ))

    # SA 逃逸矩阵：can-i 权限 × 集群特权先例
    for entry in snapshot.get("cani", []):
        subject = entry.get("subject", "?")
        allowed = entry.get("allowed", [])
        can_create_pods = "*" in allowed or any(
            a.split(" ", 1)[0] == "create" and a.endswith(" pods") for a in allowed
        )
        can_exec = "*" in allowed or any("pods/exec" in a for a in allowed)
        if can_create_pods:
            if privileged_precedent:
                findings.append(finding(
                    "critical", f"SA 逃逸矩阵：{subject} 可创建 Pod × 集群存在特权/socket 先例 → 节点逃逸路径成立",
                    detail="可建 Pod 的主体能复刻集群既有特权模板（Privileged/hostPath socket），一步到节点 root。",
                    evidence=f"subject={subject} create_pods=true privileged_precedent=true",
                    mapping="权限链「宽 ServiceAccount 提权」→「特权 GPU Pod 宿主逃逸」",
                    fix="create pods 收敛到控制器 SA；准入限制特权字段；节点池最小化",
                ))
            else:
                findings.append(finding(
                    "high", f"SA 逃逸矩阵：{subject} 可创建 Pod（暂无特权先例，仍为提权支点）",
                    detail="可建 Pod 即可控镜像与命令（供应链注入面）；若准入不拦特权则随时升级为逃逸。",
                    evidence=f"subject={subject} create_pods=true privileged_precedent=false",
                    mapping="权限链「宽 ServiceAccount 提权」",
                    fix="收敛 create pods；镜像白名单 + 准入特权拦截",
                ))
        if can_exec:
            findings.append(finding(
                "high", f"SA 逃逸矩阵：{subject} 可 exec 任意 Pod",
                detail="exec 可进入任意（含特权）容器，借用其能力与挂载凭据（提权/横向双支点）。",
                evidence=f"subject={subject} pods_exec=true",
                mapping="权限链「宽 ServiceAccount 提权」；链「Ray Dashboard → 集群控制」末段",
                fix="exec 收敛到 break-glass 角色并全程审计",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="逃逸原语检查")
