# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""Linux 内核 LPE 启发式（KubeTrail 16 条 LPE CVE 检测语义移植，**只判定不利用**）。

输入：in-pod/节点 view（kernel / os / runtime / capabilities / seccomp / userns /
cgroups / 挂载 / 可写 /proc/sys / 凭据）。
输出：命中规则 → findings（含 cve / confidence=heuristic / 依据），未命中不输出。

边界：版本区间判定基于公开 advisory 的受影响范围，未执行任何利用；内核回移补丁
（distro backport）可能使判定偏保守，报告中必须保留 ``confidence`` 与 ``evidence``。
"""

from __future__ import annotations

import re

# 16 条 LPE CVE（与 KubeTrail README.en.md LPE 表对齐；只判定受影响面）
RULES = (
    {"cve": "CVE-2022-0847", "name": "Dirty Pipe", "sev": "critical",
     "min": "5.8", "below": ("5.16.11", "5.15.25", "5.10.102"),
     "requires": [], "note": "管道页缓存覆写 → 任意文件写（容器内 root 逃逸到宿主文件）"},
    {"cve": "CVE-2021-4034", "name": "PwnKit (pkexec)", "sev": "critical",
     "min": None, "below": None, "requires": ["pkexec"],
     "note": "polkit pkexec 环境变量注入 → 本地 root"},
    {"cve": "CVE-2024-1086", "name": "nf_tables use-after-free", "sev": "critical",
     "min": "5.14", "below": ("5.15.149", "6.1.76", "6.6.15", "6.7.3"),
     "requires": ["userns_or_net_admin"], "note": "netfilter nf_tables UAF → 本地提权"},
    {"cve": "CVE-2016-5195", "name": "Dirty COW", "sev": "high",
     "min": "2.6", "below": ("4.8.3",), "requires": [],
     "note": "COW 竞争条件 → 只读映射写"},
    {"cve": "CVE-2022-0492", "name": "cgroups v1 release_agent", "sev": "critical",
     "min": "2.6", "below": None, "requires": ["cgroups_v1_writable", "sys_admin"],
     "note": "release_agent 写入 → 宿主命令执行"},
    {"cve": "CVE-2024-21626", "name": "Leaky Vessels (runc)", "sev": "critical",
     "min": None, "below": None, "requires": ["runc_old", "proc_fd_visible"],
     "note": "runc 工作目录 fd 泄露 → 宿主文件系统访问"},
    {"cve": "CVE-2019-5736", "name": "runc overwrite", "sev": "critical",
     "min": None, "below": None, "requires": ["runc_ancient"],
     "note": "runc 二进制覆写 → 宿主 root"},
    {"cve": "CVE-2020-15257", "name": "containerd-shim abstract socket", "sev": "high",
     "min": None, "below": None, "requires": ["containerd_old"],
     "note": "shim abstract socket 未授权访问 → 容器逃逸"},
    {"cve": "CVE-2021-22555", "name": "netfilter heap OOB", "sev": "high",
     "min": "2.6", "below": ("5.12.4",), "requires": ["net_admin"],
     "note": "iptables 堆越界写 → 本地提权"},
    {"cve": "CVE-2023-0386", "name": "overlayfs copy-up", "sev": "high",
     "min": "5.11", "below": ("6.2",), "requires": ["userns"],
     "note": "overlayfs 权限提升 → 本地 root"},
    {"cve": "CVE-2021-3493", "name": "Ubuntu overlayfs", "sev": "high",
     "min": "4.4", "below": ("5.11",), "requires": ["ubuntu"],
     "note": "Ubuntu overlayfs 未授权写 → 本地 root"},
    {"cve": "CVE-2019-13272", "name": "ptrace PTRACE_TRACEME", "sev": "high",
     "min": "3.0", "below": ("5.1.17",), "requires": ["sys_ptrace"],
     "note": "ptrace 关系混淆 → 本地 root"},
    {"cve": "CVE-2022-2588", "name": "cls_route UAF", "sev": "high",
     "min": "2.6", "below": ("5.19.4",), "requires": ["net_admin"],
     "note": "netfilter cls_route UAF → 本地提权"},
    {"cve": "CVE-2023-32233", "name": "nf_tables batch UAF", "sev": "critical",
     "min": "6.0", "below": ("6.3.2",), "requires": ["userns"],
     "note": "nf_tables 批处理 UAF → 本地 root"},
    {"cve": "CVE-2023-2640", "name": "Ubuntu overlayfs (gameover)", "sev": "high",
     "min": "5.15", "below": ("6.2",), "requires": ["ubuntu"],
     "note": "Ubuntu 内核 overlayfs 权限提升"},
    {"cve": "CVE-2023-32629", "name": "Ubuntu overlayfs (gameover)", "sev": "high",
     "min": "5.15", "below": ("6.2",), "requires": ["ubuntu"],
     "note": "Ubuntu 内核 overlayfs 权限提升"},
)

DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_CHROOT", "NET_ADMIN",
                  "DAC_READ_SEARCH", "BPF", "PERFMON"}


class LpeError(ValueError):
    """版本/输入非法。"""


def parse_version(value: str) -> tuple[int, ...]:
    text = str(value or "").strip()
    match = re.match(r"^(\d+(?:\.\d+){0,3})", text)
    if not match:
        raise LpeError(f"无法解析版本 {value!r}")
    return tuple(int(x) for x in match.group(1).split("."))


def version_lt(observed: str, limit: str) -> bool:
    a = list(parse_version(observed))
    b = list(parse_version(limit))
    width = max(len(a), len(b))
    a += [0] * (width - len(a))
    b += [0] * (width - len(b))
    return tuple(a) < tuple(b)


def _kernel_affected(kernel: str, rule: dict) -> bool:
    if not rule.get("below"):
        return True
    if rule.get("min") and version_lt(kernel, rule["min"]):
        return False
    return any(version_lt(kernel, limit) for limit in rule["below"])


def _flags(view: dict) -> dict:
    runtime = view.get("runtime") or {}
    caps = {str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
    userns = (view.get("userns") or {}).get("mode")
    cgroups = view.get("cgroups") or {}
    kernel = str((view.get("node") or {}).get("kernel") or view.get("kernel") or "")
    os_text = str((view.get("node") or {}).get("os") or view.get("os") or "").lower()
    mounts = (view.get("filesystem") or {}).get("mounts") or []
    paths = {str(m.get("path", "")) for m in mounts}
    runc = str(runtime.get("runc") or view.get("runc") or "")
    containerd = str(runtime.get("containerd_version") or view.get("containerd") or "")
    return {
        "kernel": kernel,
        "ubuntu": "ubuntu" in os_text,
        "sys_admin": "SYS_ADMIN" in caps,
        "net_admin": "NET_ADMIN" in caps,
        "sys_ptrace": "SYS_PTRACE" in caps,
        "userns": bool(userns and userns != "host"),
        "userns_host": userns == "host",
        "userns_or_net_admin": bool(userns and userns != "host") or "NET_ADMIN" in caps,
        "cgroups_v1_writable": str(cgroups.get("version")) == "v1" and bool(cgroups.get("writable")),
        "proc_fd_visible": bool(runtime.get("socket")) or "/proc" in paths,
        "runc_old": bool(runc) and version_lt(runc, "1.1.12"),
        "runc_ancient": bool(runc) and version_lt(runc, "1.0.0"),
        "containerd_old": bool(containerd) and version_lt(containerd, "1.4.3"),
        "pkexec": bool((view.get("lpe") or {}).get("pkexec")),
    }


def assess(view: dict) -> dict:
    if not view:
        return {"flags": {}, "hits": [], "extras": [], "skipped": [], "checked": len(RULES)}
    flags = _flags(view)
    hits: list[dict] = []
    skipped: list[dict] = []
    for rule in RULES:
        kernel = flags["kernel"]
        if rule.get("below") and not kernel:
            skipped.append({"cve": rule["cve"], "reason": "无内核版本"})
            continue
        if kernel and not _kernel_affected(kernel, rule):
            continue
        missing = [req for req in rule["requires"] if not flags.get(req)]
        if missing:
            continue
        hits.append({
            "cve": rule["cve"],
            "name": rule["name"],
            "sev": rule["sev"],
            "confidence": "heuristic",
            "note": rule["note"],
            "evidence": f"kernel={kernel or '?'} requires={rule['requires']}",
        })
    # 逃逸原语启发式（非 CVE）
    extras: list[dict] = []
    caps = sorted({str(c).upper() for c in ((view.get("capabilities") or {}).get("effective") or [])}
                  & DANGEROUS_CAPS)
    if caps:
        extras.append({"sev": "high", "title": f"危险 capabilities 可用于 LPE 原语：{caps}",
                       "detail": "SYS_MODULE/SYS_ADMIN/NET_ADMIN 等直接提供内核攻击面。",
                       "evidence": f"caps={caps}"})
    if flags["cgroups_v1_writable"] and not flags["sys_admin"]:
        extras.append({"sev": "medium", "title": "cgroups v1 可写（无 SYS_ADMIN 仍为逃逸前置）",
                       "detail": "release_agent/notify_on_release 面需结合其他原语。",
                       "evidence": "cgroups=v1 writable=true"})
    if str((view.get("seccomp") or {}).get("mode", "")).lower() in ("unconfined", "unset", ""):
        extras.append({"sev": "high", "title": "seccomp 未启用（LPE 利用面扩大）",
                       "detail": "无系统调用过滤，内核 CVE 可利用性提高。",
                       "evidence": f"seccomp={(view.get('seccomp') or {}).get('mode', 'unset')}"})
    if flags["userns_host"]:
        extras.append({"sev": "medium", "title": "host user namespace（无 userns 隔离）",
                       "detail": "容器内 root 即宿主映射 root，LPE 后直接宿主权限。",
                       "evidence": "userns=host"})
    return {"flags": flags, "hits": hits, "extras": extras, "skipped": skipped,
            "checked": len(RULES)}


def findings(assessment: dict) -> list[dict]:
    out = []
    for hit in assessment.get("hits", []):
        out.append({
            "sev": hit["sev"],
            "title": f"LPE 面：{hit['cve']} {hit['name']}（heuristic）",
            "detail": f"{hit['note']}；confidence=heuristic；{hit['evidence']}",
            "evidence": hit["evidence"],
            "cve": hit["cve"],
            "confidence": hit["confidence"],
            "mapping": "KubeTrail LPE 检测（16 CVE 表，只判定不利用）",
            "fix": "升级内核/运行时；seccomp + 最小能力 + userns 隔离作为补偿控制",
        })
    for extra in assessment.get("extras", []):
        out.append({**extra, "mapping": "KubeTrail LPE 启发式",
                    "fix": "最小能力集 + RuntimeDefault seccomp + 宿主补丁"})
    return out
