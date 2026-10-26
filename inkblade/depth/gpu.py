# -*- coding: utf-8 -*-
"""GPU Operator / NVIDIA configuration depth auditor.

The checks encode the concrete operator values that turn a GPU node into a
shared trust domain: privileged driver/toolkit pods, MIG manager with no
strategy, DCGM exporter reachable without auth/TLS, device-plugin time slicing
and DRA admin access / unbounded device classes.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

from .common import finding, hash_payload, summary_json

KEY = "gpu-operator-depth"

DOMAINS = ("driver", "mig", "dcgm", "device-plugin", "dra", "workload")


def _get(doc: dict, dotted: str, default=None):
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part, default)
    return cur


def _vulnerable_fixture() -> dict:
    return {
        "operator": {
            "version": "25.3.0",
            "driver": {"enabled": True, "privileged": True,
                       "host_mounts": ["/dev/nvidia0", "/run/nvidia", "/sys"],
                       "use_precompiled": False, "version": "1.17.7"},
            "toolkit": {"installed": True, "cdi_enabled": False,
                        "sandbox_workloads": True},
            "default_runtime": "docker",
        },
        "mig": {"enabled": True, "strategy": "none", "manager_enabled": True,
                "device_plugin_mig": False, "profile": "1g.5gb",
                "gpu_model": "H100", "allowed_profiles": ["1g.10gb", "3g.40gb"],
                "partition_tenants": False},
        "dcgm": {"enabled": True, "service_type": "NodePort", "node_port": 30080,
                 "tls": False, "auth": False, "host_network": True,
                 "privileged": True, "host_pid": True,
                 "rbac_cluster_admin": True},
        "device_plugin": {"enabled": True, "share_count": 8,
                          "pass_device_specs": True, "cdi": False,
                          "host_path": True, "mount_propagation": "Bidirectional",
                          "runtime_class": "nvidia"},
        "dra": {"enabled": True, "api_version": "resource.k8s.io/v1",
                "admin_access": True, "device_class": "gpu.example.com/*",
                "node_selector": {}, "claim_template_namespace": "tenant-a",
                "allocation_mode": "Immediate", "cel": "true",
                "prioritized": True},
        "workloads": [
            {"kind": "Pod", "name": "trainer", "privileged": True,
             "host_path": "/dev/nvidia0"},
            {"kind": "Pod", "name": "inference", "privileged": False,
             "host_path": ""},
        ],
    }


def _hardened_fixture() -> dict:
    return {
        "operator": {
            "version": "25.7.2",
            "driver": {"enabled": True, "privileged": False, "host_mounts": [],
                       "use_precompiled": True, "version": "1.17.8"},
            "toolkit": {"installed": True, "cdi_enabled": True,
                        "sandbox_workloads": False},
            "default_runtime": "containerd",
        },
        "mig": {"enabled": True, "strategy": "single", "manager_enabled": True,
                "device_plugin_mig": True, "profile": "1g.10gb",
                "gpu_model": "H100", "allowed_profiles": ["1g.10gb", "3g.40gb"],
                "partition_tenants": True},
        "dcgm": {"enabled": True, "service_type": "ClusterIP", "node_port": 0,
                 "tls": True, "auth": True, "host_network": False,
                 "privileged": False, "host_pid": False,
                 "rbac_cluster_admin": False},
        "device_plugin": {"enabled": True, "share_count": 1,
                          "pass_device_specs": False, "cdi": True,
                          "host_path": False, "mount_propagation": "None",
                          "runtime_class": "nvidia"},
        "dra": {"enabled": True, "api_version": "resource.k8s.io/v1",
                "admin_access": False, "device_class": "gpu.example.com/h100",
                "node_selector": {"nvidia.com/gpu.present": "true"},
                "claim_template_namespace": "", "allocation_mode": "WaitForFirstConsumer",
                "cel": "device.attributes['gpu'].mig == false", "prioritized": False},
        "workloads": [],
    }


def fixture(state: str = "vulnerable") -> dict:
    return _vulnerable_fixture() if state == "vulnerable" else _hardened_fixture()


Check = tuple[str, str, str, str, Callable[[dict], bool]]


def _checks() -> list[Check]:
    return [
        ("driver-privileged", "driver", "critical",
         "driver DaemonSet privileged",
         lambda d: bool(_get(d, "operator.driver.privileged"))),
        ("driver-host-mount", "driver", "high",
         "driver 容器挂载 /dev、/run/nvidia 或 /sys",
         lambda d: any(str(m).startswith(("/dev", "/run/nvidia", "/sys", "/proc"))
                       for m in _get(d, "operator.driver.host_mounts") or [])),
        ("driver-cve-2025-23266", "driver", "critical",
         "GPU Operator/Container Toolkit 版本落在 CVE-2025-23266 区间",
         lambda d: _version_le(_get(d, "operator.version", "0"), "25.3.0")
         or _version_le(_get(d, "operator.driver.version", "0"), "1.17.7")),
        ("toolkit-cdi-disabled", "driver", "high",
         "sandbox workloads 开启但 CDI 关闭，回退到特权挂载",
         lambda d: bool(_get(d, "operator.toolkit.sandbox_workloads"))
         and not bool(_get(d, "operator.toolkit.cdi_enabled"))),
        ("default-runtime-docker", "driver", "medium",
         "operator defaultRuntime=docker 且 CDI 未启用",
         lambda d: str(_get(d, "operator.default_runtime", "")) == "docker"
         and not bool(_get(d, "operator.toolkit.cdi_enabled"))),
        ("mig-strategy-none", "mig", "high",
         "MIG manager 开启但 devicePlugin MIG strategy=none",
         lambda d: bool(_get(d, "mig.manager_enabled"))
         and str(_get(d, "mig.strategy", "")).lower() == "none"),
        ("mig-profile-mismatch", "mig", "high",
         "MIG profile 不在允许列表或 device plugin 未 advertise MIG",
         lambda d: bool(_get(d, "mig.enabled"))
         and (str(_get(d, "mig.profile")) not in (_get(d, "mig.allowed_profiles") or [])
              or not bool(_get(d, "mig.device_plugin_mig")))),
        ("mig-cross-tenant", "mig", "medium",
         "MIG mixed 策略未启用租户分区标记",
         lambda d: str(_get(d, "mig.strategy", "")).lower() == "mixed"
         and not bool(_get(d, "mig.partition_tenants"))),
        ("dcgm-nodeport", "dcgm", "high",
         "DCGM exporter 以 NodePort/LoadBalancer 暴露且无鉴权",
         lambda d: str(_get(d, "dcgm.service_type", "")) in ("NodePort", "LoadBalancer")
         and not bool(_get(d, "dcgm.auth"))),
        ("dcgm-hostnetwork-plain", "dcgm", "high",
         "DCGM hostNetwork 且未启用 TLS",
         lambda d: bool(_get(d, "dcgm.host_network"))
         and not bool(_get(d, "dcgm.tls"))),
        ("dcgm-privileged", "dcgm", "critical",
         "DCGM exporter privileged 或 hostPID",
         lambda d: bool(_get(d, "dcgm.privileged")) or bool(_get(d, "dcgm.host_pid"))),
        ("dcgm-rbac", "dcgm", "high",
         "DCGM ServiceAccount 绑定 cluster-admin",
         lambda d: bool(_get(d, "dcgm.rbac_cluster_admin"))),
        ("device-plugin-share", "device-plugin", "high",
         "device plugin shareCount>1（time slicing 共享显存域）",
         lambda d: int(_get(d, "device_plugin.share_count", 1) or 1) > 1),
        ("device-plugin-hostpath", "device-plugin", "high",
         "device plugin hostPath 挂载或 Bidirectional mount propagation",
         lambda d: bool(_get(d, "device_plugin.host_path"))
         or str(_get(d, "device_plugin.mount_propagation", "")).lower() == "bidirectional"),
        ("dra-admin-access", "dra", "critical",
         "DRA adminAccess=true（设备管理权限进入业务 Pod）",
         lambda d: bool(_get(d, "dra.admin_access"))),
        ("dra-unbounded-selector", "dra", "high",
         "DRA deviceClass 通配或 nodeSelector 为空",
         lambda d: "*" in str(_get(d, "dra.device_class", ""))
         or not (_get(d, "dra.node_selector") or {})),
        ("dra-preallocation", "dra", "high",
         "DRA Immediate 分配 + 租户命名空间 claimTemplate（预占 GPU）",
         lambda d: str(_get(d, "dra.allocation_mode", "")) == "Immediate"
         and bool(_get(d, "dra.claim_template_namespace"))),
        ("dra-cel-true", "dra", "high",
         "DRA CEL 选择器恒真，任意设备可被声明",
         lambda d: str(_get(d, "dra.cel", "")).strip().lower() in ("true", "1")),
        ("workload-privileged", "workload", "critical",
         "业务 GPU Pod privileged",
         lambda d: any(bool(w.get("privileged")) for w in d.get("workloads") or [])),
        ("workload-hostpath", "workload", "high",
         "业务 GPU Pod 直接 hostPath 挂载 /dev/nvidia*",
         lambda d: any(str(w.get("host_path", "")).startswith("/dev")
                       for w in d.get("workloads") or [])),
    ]


def _version_le(value: str, ceiling: str) -> bool:
    import re
    def tup(v):
        nums = [int(x) for x in re.findall(r"\d+", str(v))[:4]]
        return tuple(nums) if nums else (0,)
    a, b = tup(value), tup(ceiling)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) <= b + (0,) * (width - len(b))


def cases() -> list[Check]:
    return _checks()


def audit(snapshot: dict | None = None) -> dict:
    doc = copy.deepcopy(snapshot or _vulnerable_fixture())
    failed: list[dict] = []
    passed: list[str] = []
    for cid, domain, sev, title, predicate in _checks():
        try:
            bad = bool(predicate(doc))
        except Exception:  # noqa: BLE001 - malformed snapshots fail closed as a finding
            bad = True
        if bad:
            failed.append({"id": cid, "domain": domain, "sev": sev, "title": title})
        else:
            passed.append(cid)
    counts: dict[str, int] = {}
    for item in failed:
        counts[item["sev"]] = counts.get(item["sev"], 0) + 1
    findings = [finding(
        item["sev"], f"GPU Operator 配置风险（{item['domain']}）：{item['title']}",
        {"check": item["id"], "domain": item["domain"], "checks": len(_checks()),
         "failed": len(failed), "domains": sorted({c[1] for c in _checks()}),
         "snapshot_sha256": hash_payload(doc)},
        fix="driver/toolkit 去掉 privileged 与宿主挂载并启用 CDI；MIG 开启 strategy 且 profile 与 GPU 匹配；"
            "DCGM 改 ClusterIP+mTLS+鉴权；device plugin shareCount=1；DRA 关闭 adminAccess、收紧 deviceClass/CEL。",
    ) for item in failed]
    return {
        "checks": len(_checks()),
        "failed": len(failed),
        "passed": len(passed),
        "findings": len(failed),
        "severity": counts,
        "domains": sorted({c[1] for c in _checks()}),
        "failed_ids": [f["id"] for f in failed],
        "details": [f["id"] for f in failed],
        "results": failed,
        "finding_items": findings,
        "snapshot_sha256": hash_payload(doc),
    }


def summary(report: dict) -> str:
    return summary_json("gpu-operator-depth", [], extra={
        "checks": report["checks"], "failed": report["failed"],
        "domains": report["domains"],
    })


def load_snapshot(value) -> dict:
    if value is None:
        return fixture("vulnerable")
    if isinstance(value, dict):
        return value
    import json
    from pathlib import Path
    return json.loads(Path(str(value)).read_text(encoding="utf-8"))
