# -*- coding: utf-8 -*-
"""Falco/Tetragon runtime coverage model.

The model does not claim to execute eBPF. It encodes the observable rule
semantics that create blind spots: syscall allow-lists, container-id scoping,
hostPID/hostNetwork enrichment, secondary CNI interfaces, parent-exit sampling
and ring-buffer drop handling.  Each synthetic event carries the fields an
eBPF consumer would see so the gap is replayable.
"""

from __future__ import annotations

import copy
from typing import Any

from .common import finding, hash_payload, summary_json

KEY = "ebpf-runtime-coverage"

DEFAULT_FALCO_SYSCALLS = ("execve",)
DEFAULT_TETRAGON_SYSCALLS = ("execve", "openat")
HARDENED_SYSCALLS = (
    "execve", "execveat", "fexecve", "memfd_create", "setns", "unshare",
    "mount", "ptrace", "io_uring_enter", "io_uring_setup", "clone3", "bpf",
    "connect", "openat2", "process_vm_writev",
)


def _event(cid: str, title: str, category: str, *, type_: str, syscall: str,
           container_id: str = "c-01", comm: str = "bash",
           binary: str = "/bin/sh", args: list[str] | None = None,
           parent_alive: bool = True, duration_ms: int = 500,
           host_ns: bool = False, host_network: bool = False,
           multus: bool = False, ringbuf_dropped: bool = False,
           dest: str = "", dest_port: int = 0, path: str = "",
           host_pid: bool = False, follow_child: bool = True) -> dict:
    return {
        "id": cid, "title": title, "category": category,
        "type": type_, "syscall": syscall, "container_id": container_id,
        "comm": comm, "binary": binary, "args": list(args or []),
        "parent_alive": parent_alive, "duration_ms": duration_ms,
        "host_ns": host_ns, "host_network": host_network, "multus": multus,
        "ringbuf_dropped": ringbuf_dropped, "dest": dest,
        "dest_port": dest_port, "path": path, "host_pid": host_pid,
        "follow_child": follow_child,
    }


def _default_cases() -> list[dict]:
    return [
        _event("ebpf-short-lived-shell", "短生命周期 /bin/sh（父进程先行退出）",
               "short-lived", type_="exec", syscall="execve", parent_alive=False,
               duration_ms=30),
        _event("ebpf-execveat-loader", "execveat 加载器绕过 execve 规则",
               "syscall-filter", type_="exec", syscall="execveat",
               binary="/tmp/.loader", args=["--stage"]),
        _event("ebpf-memfd-exec", "memfd_create + fexecve 无文件执行",
               "syscall-filter", type_="exec", syscall="fexecve",
               binary="memfd:payload", comm="python3"),
        _event("ebpf-nsenter-host", "nsenter 进入 host PID namespace（逃逸后）",
               "post-escape", type_="setns", syscall="setns", container_id="",
               comm="nsenter", host_ns=True, binary="/usr/bin/nsenter"),
        _event("ebpf-unshare-user", "unshare(CLONE_NEWUSER) 提权链",
               "post-escape", type_="unshare", syscall="unshare",
               comm="unshare", host_ns=True),
        _event("ebpf-hostnetwork-shell", "hostNetwork Pod 反连 4444",
               "host-network", type_="connect", syscall="connect",
               comm="bash", host_network=True, dest="203.0.113.10",
               dest_port=4444),
        _event("ebpf-multus-secondary", "Multus 第二接口出站 C2",
               "host-network", type_="connect", syscall="connect",
               comm="python3", multus=True, dest="198.51.100.9", dest_port=8443),
        _event("ebpf-io-uring-read", "io_uring 读取 /etc/shadow",
               "syscall-filter", type_="open", syscall="io_uring_enter",
               path="/etc/shadow", comm="ioring"),
        _event("ebpf-ptrace-inject", "ptrace 注入同节点进程",
               "syscall-filter", type_="ptrace", syscall="ptrace",
               comm="gdb", host_pid=True),
        _event("ebpf-mount-hostpath", "逃逸后 mount 宿主根文件系统",
               "post-escape", type_="mount", syscall="mount", container_id="",
               comm="mount", host_ns=True, path="/dev/sda1"),
        _event("ebpf-clone3-child", "clone3 子进程链未被 followChildren 覆盖",
               "child-process", type_="exec", syscall="clone3",
               comm="kworker", binary="", follow_child=False),
        _event("ebpf-ringbuf-drop", "高负载 ring buffer 丢事件",
               "short-lived", type_="exec", syscall="execve",
               ringbuf_dropped=True, duration_ms=15, parent_alive=False),
        _event("ebpf-hostpid-escape", "hostPID 下容器 ID 被标为 host",
               "container-identity", type_="exec", syscall="execve",
               container_id="host", host_pid=True, comm="sh"),
        _event("ebpf-bpf-load", "容器内加载 eBPF 程序隐藏进程",
               "syscall-filter", type_="bpf", syscall="bpf", comm="loader",
               args=["BPF_PROG_LOAD"]),
    ]


_CASES_CACHE: list[dict] | None = None


def cases() -> list[dict]:
    global _CASES_CACHE
    if _CASES_CACHE is None:
        _CASES_CACHE = _default_cases()
    return copy.deepcopy(_CASES_CACHE)


def _falco(event: dict, hardened: bool) -> tuple[bool, str]:
    if hardened:
        if event["syscall"] in HARDENED_SYSCALLS or event["type"] in (
                "exec", "setns", "unshare", "mount", "ptrace", "bpf", "connect", "open"):
            return True, "expanded-syscall-and-host-context"
        return False, "not-covered"
    if event["ringbuf_dropped"] or event["duration_ms"] < 50:
        return False, "lost-or-short-event"
    if event["host_ns"] or event["host_pid"] or event["container_id"] in ("", "host"):
        return False, "host-context-not-attributed"
    if event["host_network"] or event["multus"] or event["follow_child"] is False:
        return False, "network-or-child-filter"
    if event["syscall"] not in DEFAULT_FALCO_SYSCALLS:
        return False, "syscall-filter"
    if not event["parent_alive"]:
        return False, "parent-exited-before-enrichment"
    return True, "default-rule-match"


def _tetragon(event: dict, hardened: bool) -> tuple[bool, str]:
    if hardened:
        if event["syscall"] in HARDENED_SYSCALLS or event["type"] in (
                "exec", "setns", "unshare", "mount", "ptrace", "bpf", "connect", "open"):
            return True, "expanded-syscall-follow-children"
        return False, "not-covered"
    if event["ringbuf_dropped"]:
        return False, "ringbuf-drop"
    if event["host_ns"] or event["host_pid"] or event["container_id"] in ("", "host"):
        return False, "host-namespace-not-attributed"
    if event["host_network"] or event["multus"]:
        return False, "cni-primary-only"
    if not event["follow_child"]:
        return False, "follow-children-disabled"
    if event["syscall"] not in DEFAULT_TETRAGON_SYSCALLS:
        return False, "syscall-filter"
    if not event["parent_alive"]:
        return False, "parent-exited"
    return True, "default-rule-match"


def evaluate(event: dict, hardened: bool = False) -> dict:
    falco, falco_reason = _falco(event, hardened)
    tetra, tetra_reason = _tetragon(event, hardened)
    return {
        "id": event["id"], "category": event["category"],
        "falco": {"detected": falco, "reason": falco_reason},
        "tetragon": {"detected": tetra, "reason": tetra_reason},
        "detected": falco or tetra,
        "missed_by": [name for name, hit in (("falco", falco), ("tetragon", tetra))
                      if not hit],
    }


def audit(cases_in: list[dict] | None = None) -> dict:
    rows = cases_in if cases_in is not None else cases()
    results = []
    findings = []
    vulnerable_missed = 0
    hardened_missed = 0
    categories: dict[str, int] = {}
    for case in rows:
        vuln = evaluate(case, hardened=False)
        hard = evaluate(case, hardened=True)
        vulnerable_missed += int(not vuln["detected"])
        hardened_missed += int(not hard["detected"])
        categories[case["category"]] = categories.get(case["category"], 0) + 1
        results.append({"id": case["id"], "title": case["title"],
                        "category": case["category"], "event": case,
                        "vulnerable": vuln, "hardened": hard})
        if not vuln["detected"] and hard["detected"]:
            findings.append(finding(
                "high",
                f"eBPF 运行时盲区（{case['category']}）：{case['title']}",
                {"case": case["id"], "category": case["category"],
                 "event": {k: case[k] for k in ("type", "syscall", "container_id",
                                               "host_ns", "host_network", "multus",
                                               "parent_alive", "duration_ms",
                                               "ringbuf_dropped", "follow_child")},
                 "missed_by": vuln["missed_by"],
                 "reasons": {"falco": vuln["falco"]["reason"],
                             "tetragon": vuln["tetragon"]["reason"]},
                 "hardened": {"falco": hard["falco"], "tetragon": hard["tetragon"]}},
                fix="覆盖 execveat/fexecve/memfd/io_uring/ptrace/mount/clone3/bpf；"
                    "逃逸后以 hostPID+namespace 归属而非 container_id 过滤；"
                    "hostNetwork/Multus 纳入 L3/L4 策略；短进程与 ringbuf 丢事件加旁路采集。",
            ))
    return {
        "total": len(rows),
        "vulnerable_missed": vulnerable_missed,
        "hardened_missed": hardened_missed,
        "coverage_gaps": len(categories),
        "categories": categories,
        "results": results,
        "finding_items": findings,
        "results_sha256": hash_payload(results),
        "hardened_details": [r["id"] for r in results if not r["hardened"]["detected"]],
    }


def gap_categories(cases_in: list[dict] | None = None) -> set[str]:
    rows = cases_in if cases_in is not None else cases()
    return {c["category"] for c in rows}


def summary(report: dict) -> str:
    return summary_json("ebpf-runtime-coverage", [], extra={
        "total": report["total"],
        "vulnerable_missed": report["vulnerable_missed"],
        "hardened_missed": report["hardened_missed"],
    })


def load_cases(path) -> list[dict]:
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text(encoding="utf-8"))["cases"]
