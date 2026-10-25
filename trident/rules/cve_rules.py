# -*- coding: utf-8 -*-
"""由 CVE 情报库生成 Sigma 检测规则（每 CVE/公告 ≥1 条）。

设计：
- HTTP 管理面 → webserver 日志的 URI 选择器；
- 容器/运行时/训练栈 → process_creation 命令行选择器；
- K8s 控制面 → kube-apiserver 审计字段选择器；
- 所有规则带 ``custom.trident-cve`` 与 ATT&CK 标签，monitor 模式，不含利用细节。
"""

from __future__ import annotations

from typing import Any

HTTP_ROUTES = {
    "vllm": ["/v1/models", "/plugins/", "/vllm/", "/metrics"],
    "sglang": ["/pause", "/start_profile", "/update_weights", "/sglang/", "/server_info"],
    "ray": ["/api/jobs", "/log_proxy", "/dashboard"],
    "kuberay": ["/api/jobs", "/dashboard"],
    "litellm": ["/config", "/key/generate", "/user/update", "/prompts/test", "/guardrails/"],
    "dify": ["/console/api", "/code-node", "/remote-files"],
    "open-webui": ["/api/v1/retrieval", "/api/v1/utils/code", "/api/v1/knowledge"],
    "mlflow": ["/api/3.0/mlflow/traces", "/model-versions/create", "/ajax-api"],
    "bmc": ["/redfish/v1", "/ipmi/"],
    "sonic": ["/restconf", "/sonic/", "/sonic/config"],
    "cumulus": ["/nvue/", "/cumulus/"],
    "hami": ["/scheduler/filter", "/scheduler/bind", "/hami/"],
}

PROCESS_PATTERNS = {
    "runc": ["runc init", "runc exec", "/proc/self/fd", "release_agent"],
    "containerd": ["containerd-shim", "abstract socket", "/run/containerd"],
    "kubernetes": ["git clone", "git-repo", "envFrom"],
    "nvidia": ["nvidia-ctk", "update-ldcache", "nvidia-container-runtime-hook", "ldconfig"],
    "megatron": ["load_checkpoint", "torch.load", "dill.loads", "ensemble_classifier"],
    "deepspeed": ["load_checkpoint", "deepspeed", "ds_config", "torch.load"],
    "pytorch": ["torch.load", "weights_only=False", "torchrun"],
    "cgpu": ["libcgpu", "nvidia-smi", "cudaMalloc"],
    "lws": ["LWS_LEADER_ADDRESS", "leaderworkerset"],
}

K8S_RESOURCES = {
    "kubernetes": ["pods", "secrets", "persistentvolumeclaims"],
    "kuberay": ["rayclusters", "rayjobs"],
    "lws": ["leaderworkersets"],
    "hami": ["pods", "nodes"],
}


def _sigma_id(entry: dict) -> str:
    return "sigma-cve-" + entry["id"].lower().replace("_", "-")


def sigma_spec(entry: dict) -> dict:
    component = entry["component"]
    tuning = {
        "zh": "按资产清单收敛 URI/命令行白名单；先 monitor 观察误报，再切阻断",
        "en": "Baseline URI/command-line allowlists per asset inventory; run monitor first, then enforce",
    }
    tags = ["attack.discovery", f"cve.{entry['id'].lower()}"]
    if component in HTTP_ROUTES:
        logsource = {"category": "webserver"}
        detection = {
            "selection": {"cs-uri|contains": HTTP_ROUTES[component]},
            "condition": "selection",
        }
        desc = f"{entry['component_name']} 管理/利用面 URI 访问（{entry['id']}）；monitor 模式，建议结合来源网段与状态码调参"
    elif component in PROCESS_PATTERNS:
        logsource = {"category": "process_creation"}
        detection = {
            "selection": {"CommandLine|contains": PROCESS_PATTERNS[component]},
            "condition": "selection",
        }
        desc = f"{entry['component_name']} 相关进程/命令行行为（{entry['id']}）；需按镜像与训练任务基线白名单"
    else:
        logsource = {"product": "kube-apiserver"}
        detection = {
            "selection": {"objectRef.resource": K8S_RESOURCES.get(component, ["pods"])},
            "condition": "selection",
        }
        desc = f"{entry['component_name']} 控制面对象访问（{entry['id']}）；按 namespace/serviceaccount 白名单"
    return {
        "id": _sigma_id(entry),
        "title": f"CVE 检测：{entry['id']} {entry['component_name']}",
        "description": desc,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["合法运维/训练任务与基线重叠；先 monitor 观察", "资产清单未及时更新"],
        "level": "high" if entry["severity"] in ("critical", "high") else "medium",
        "tags": tags,
        "tuning": tuning,
        "blocks_modules": list(entry["modules"]),
        "cves": [entry["id"]],
    }


def sigma_specs(catalog: dict[str, Any]) -> list[dict]:
    return [sigma_spec(e) for e in catalog.get("entries", [])]
