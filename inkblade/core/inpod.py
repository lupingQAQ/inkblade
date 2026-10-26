# -*- coding: utf-8 -*-
"""in-pod 只读采集器（CM-22，safe 模式等价物）：/proc /sys /cgroup /socket 本地扫。

- 输入是一个**根文件系统快照**路径（真实 in-pod 场景由 sidecar 以只读方式复制/挂载，
  本模块绝不写目标根）；
- 解析：``/proc/net/tcp`` 监听/连接、``/proc/self/status`` CapEff、``/proc/self/cgroup``、
  ``/proc/mounts``、``/sys/class/net/*/address``、常见运行时 socket 文件是否存在；
- 产出：容器逃逸面 findings（docker/containerd socket、host cgroup、CAP_SYS_ADMIN、
  敏感 hostPath、0.0.0.0 监听）；
- 所有文件读取都是 ``errors=ignore``，缺失文件跳过；不执行命令、不建立连接。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SOCKET_PATHS = (
    "/var/run/docker.sock", "/run/docker.sock",
    "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
    "/var/run/kubelet.sock", "/run/k3s/containerd/containerd.sock",
)
SENSITIVE_MOUNT_PREFIXES = ("/var/run/docker.sock", "/run/containerd", "/proc", "/sys",
                            "/dev", "/etc/kubernetes")
CAP_NAMES = {
    0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER", 4: "FSETID",
    5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP", 9: "LINUX_IMMUTABLE",
    10: "NET_BIND_SERVICE", 11: "NET_BROADCAST", 12: "NET_ADMIN", 13: "NET_RAW",
    14: "IPC_LOCK", 15: "IPC_OWNER", 16: "SYS_MODULE", 17: "SYS_RAWIO",
    18: "SYS_CHROOT", 19: "SYS_PTRACE", 20: "SYS_PACCT", 21: "SYS_ADMIN",
    22: "SYS_BOOT", 23: "SYS_NICE", 24: "SYS_RESOURCE", 25: "SYS_TIME",
    26: "SYS_TTY_CONFIG", 27: "MKNOD", 28: "LEASE", 29: "AUDIT_WRITE",
    30: "AUDIT_CONTROL", 31: "SETFCAP",
}
STATE = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
         "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
         "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def _read(root: Path, rel: str) -> str:
    p = root / rel.lstrip("/")
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _proc_addr(text: str) -> dict:
    ip_hex, _, port_hex = text.partition(":")
    try:
        ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
        port = int(port_hex, 16)
    except (ValueError, IndexError):
        return {"ip": "", "port": 0}
    return {"ip": ip, "port": port}


def _parse_tcp(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = _proc_addr(parts[1])
        remote = _proc_addr(parts[2])
        rows.append({"local": local, "remote": remote,
                     "state": STATE.get(parts[3].upper(), parts[3]),
                     "uid": parts[7] if len(parts) > 7 else ""})
    return rows


def _caps(text: str) -> list[str]:
    for line in text.splitlines():
        if line.startswith("CapEff:"):
            try:
                value = int(line.split()[1], 16)
            except (ValueError, IndexError):
                return []
            return [CAP_NAMES.get(i, f"CAP_{i}") for i in range(64)
                    if value & (1 << i) and i in CAP_NAMES]
    return []


def _mounts(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            out.append({"device": parts[0], "mount": parts[1], "fstype": parts[2],
                        "options": parts[3]})
    return out


def collect(root: Path | str) -> dict:
    r = Path(root)
    if not r.is_dir():
        raise ValueError(f"快照根不存在：{r}")
    cgroup = _read(r, "/proc/self/cgroup")
    snapshot = {
        "root": str(r), "read_only": True,
        "tcp": _parse_tcp(_read(r, "/proc/net/tcp")),
        "cgroup": cgroup.strip().splitlines(),
        "caps": _caps(_read(r, "/proc/self/status")),
        "mounts": _mounts(_read(r, "/proc/mounts")),
        "sockets": [p for p in SOCKET_PATHS if (r / p.lstrip("/")).exists()],
        "interfaces": [],
        "files_read": [p for p in ("/proc/net/tcp", "/proc/self/cgroup",
                                   "/proc/self/status", "/proc/mounts")
                       if (r / p.lstrip("/")).is_file()],
    }
    net = r / "sys" / "class" / "net"
    if net.is_dir():
        for iface in sorted(net.iterdir()):
            addr = iface / "address"
            if addr.is_file():
                try:
                    snapshot["interfaces"].append({"name": iface.name,
                                                   "mac": addr.read_text().strip()})
                except OSError:
                    pass
    return snapshot


def analyze(snapshot: dict) -> list[dict]:
    findings = []
    sockets = snapshot.get("sockets") or []
    if any("docker" in s for s in sockets):
        findings.append({"sev": "critical", "title": "容器运行时 docker socket 暴露",
                         "detail": "挂载/存在 docker.sock：可直接创建特权容器逃逸到宿主",
                         "evidence": ",".join(s for s in sockets if "docker" in s)})
    if any("containerd" in s or "crio" in s or "kubelet" in s for s in sockets):
        findings.append({"sev": "high", "title": "容器运行时/ kubelet socket 暴露",
                         "detail": "运行时 socket 可被用于执行容器/读取镜像凭据",
                         "evidence": ",".join(sockets)})
    cgroup_text = "\n".join(snapshot.get("cgroup") or [])
    if not cgroup_text or "/" == cgroup_text.strip().split("\n")[-1].split(":", 2)[-1].strip():
        findings.append({"sev": "high", "title": "宿主 cgroup 命名空间（未隔离）",
                         "detail": "cgroup 路径为 /，提示容器未使用独立 cgroup namespace"})
    caps = set(snapshot.get("caps") or [])
    for cap, sev, why in (("SYS_ADMIN", "high", "可 mount/namespace 逃逸"),
                          ("SYS_PTRACE", "medium", "可注入同宿主进程"),
                          ("NET_ADMIN", "medium", "可改网络策略/抓包"),
                          ("SYS_MODULE", "high", "可加载内核模块")):
        if cap in caps:
            findings.append({"sev": sev, "title": f"危险 capability：CAP_{cap}",
                             "detail": why, "evidence": ",".join(sorted(caps))})
    mounts = snapshot.get("mounts") or []
    for m in mounts:
        mount = str(m.get("mount", ""))
        if any(mount == p or mount.startswith(p + "/") for p in SENSITIVE_MOUNT_PREFIXES):
            findings.append({"sev": "high", "title": f"敏感 hostPath 挂载：{mount}",
                             "detail": f"{m.get('device')} → {mount} ({m.get('fstype')})",
                             "evidence": mount})
    exposed = [t for t in snapshot.get("tcp") or []
               if t.get("state") == "LISTEN" and t.get("local", {}).get("ip") == "0.0.0.0"]
    if exposed:
        findings.append({"sev": "medium", "title": "监听 0.0.0.0 的 TCP 端口",
                         "detail": "容器内服务对 Pod 网络/宿主端口暴露："
                                   + ", ".join(str(t["local"]["port"]) for t in exposed),
                         "evidence": ",".join(str(t["local"]["port"]) for t in exposed)})
    return findings


def scan(root: Path | str) -> dict:
    snapshot = collect(root)
    findings = analyze(snapshot)
    return {"snapshot": snapshot, "findings": findings, "count": len(findings),
            "read_only": True, "writes": 0}
