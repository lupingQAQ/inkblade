# -*- coding: utf-8 -*-
"""实验室部署面快照 fixture 生成器（纯本地文件生成，不访问任何集群）。

生成 lab/defense-deploy/fixtures/<product>-{deployed,degraded,absent}.json：
- deployed：产品已部署（含内核态/健康组件）+ 默认规则集面 → 评估「已部署」态
- degraded：核心组件在、内核态/健康组件缺失 → 评估「降级」态（仅适用部分产品）
- absent：普通集群底噪（含近似产品干扰项）→ 评估「未部署」态（防误报）

修改后重跑：python lab/defense-deploy/gen_fixtures.py
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"

GENERIC = {
    "cluster": "kind-trident",
    "daemonsets": ["kube-system/kube-proxy", "kube-system/coredns"],
    "deployments": ["kube-system/coredns", "train/vllm-server"],
    "pods": ["train/vllm-server-0", "train/ray-worker-1"],
    "images": ["vllm/vllm-openai:latest", "rayproject/ray:2.9"],
    "rules": [],
    "configs": ["kubelet-config", "corefile"],
    "kernel_modules": ["nvml"],
    "agent_status": [],
    "kernel_params": [],
    "crds": ["rayclusters.ray.io"],
    "webhooks": [],
}


def generic(**extra):
    snap = json.loads(json.dumps(GENERIC))
    snap.update(extra)
    return snap


DEPLOYED = {
    "elkeid": {
        "cluster": "kind-trident",
        "daemonsets": ["kube-system/elkeid-agent", "kube-system/elkeid-manager"],
        "deployments": ["elkeid-system/elkeid-server", "elkeid-system/elkeid-web"],
        "images": ["elkeid/elkeid-agent:1.9.7"],
        "rules": ["elkeid-rule-host-2130", "elkeid-rule-container-2398"],
        "configs": ["elkeidup-agent-conf"],
        "kernel_modules": ["elkeid"],
    },
    "agentsmith": {
        "daemonsets": ["kube-system/agentsmith-agent"],
        "images": ["bytedance/agentsmith:latest"],
        "configs": ["agentsmith-agent-cfg"],
        "kernel_modules": ["smith"],
    },
    "veinmind": {
        "pods": ["trident-scan/veinmind-tools-abc12"],
        "images": [
            "chaitin/veinmind-tools:v2.0",
            "veinmind/veinmind-backdoor:v1",
            "veinmind/veinmind-weakpass:v1",
        ],
        "configs": ["veinmind-scanner-cfg"],
    },
    "falco": {
        "daemonsets": ["kube-system/falco"],
        "images": ["falcosecurity/falco:0.37.1"],
        "rules": ["falco_rules.yaml", "falco_rules.local.yaml"],
        "configs": ["/etc/falco/falco.yaml"],
        "kernel_modules": ["falco"],
    },
    "tetragon": {
        "daemonsets": ["kube-system/tetragon"],
        "deployments": ["kube-system/tetragon-operator"],
        "images": ["cilium/tetragon:v1.3.0"],
        "crds": ["tracingpolicies.cilium.io"],
        "configs": ["tetragon-conf"],
        "kernel_params": ["lsm=bpf,integrity"],
    },
    "kubearmor": {
        "daemonsets": ["kube-system/kubearmor"],
        "deployments": ["kubearmor/kubearmor-operator"],
        "images": ["kubearmor/kubearmor:latest"],
        "crds": [
            "kubearmorpolicies.security.kubearmor.com",
            "kubearmorhostpolicies.security.kubearmor.com",
        ],
        "configs": ["kubearmor-file-posture=audit"],
    },
    "admission": {
        "deployments": ["kyverno/kyverno", "gatekeeper-system/gatekeeper-controller-manager"],
        "daemonsets": ["gatekeeper-system/gatekeeper-audit"],
        "images": ["kyverno/kyverno:v1.11.0", "openpolicyagent/gatekeeper:v3.15.0"],
        "crds": ["constrainttemplates.templates.gatekeeper.sh"],
        "webhooks": [
            "kyverno-resource-validating-webhook-cfg",
            "gatekeeper-validating-webhook-configuration",
        ],
        "rules": ["clusterpolicy/disallow-privileged-containers validationFailureAction=Audit"],
        "configs": ["kyverno-config"],
    },
    "imagescan": {
        "pods": ["scanning/trivy-scan-x7", "scanning/grype-scan-99"],
        "images": [
            "aquasecurity/trivy:0.50.0",
            "anchore/grype:v0.74.0",
            "chaitin/veinmind-tools:v2.0",
        ],
        "configs": ["trivy-config", "grype-db-cfg"],
    },
    "hostagent": {
        "daemonsets": ["kube-system/wazuh-agent"],
        "deployments": ["wazuh/wazuh-manager"],
        "images": ["wazuh/wazuh-agent:4.7.0", "osquery/osqueryd:5.9.1"],
        "rules": ["0020-syscheck_rules.xml", "0010-ossec_rules.xml"],
        "configs": ["ossec.conf", "osquery.conf", "osqueryd-packs"],
        "agent_status": ["online"],
    },
    "waf-inference": {
        "deployments": ["waf/safeline-tengine", "waf/coraza-spoa"],
        "images": [
            "chaitin/safeline-ce-waf:latest",
            "corazawaf/coraza-spoa:1.0",
            "owasp/modsecurity:2.9",
        ],
        "ingresses": ["inference/vllm-ingress modsecurity=on"],
        "rules": ["owasp-crs-3.3.2"],
        "configs": ["safeline-detector", "coraza-config"],
    },
    "netobserv": {
        "daemonsets": ["kube-system/cilium"],
        "deployments": [
            "kube-system/hubble-relay",
            "kube-system/hubble-ui",
            "calico-system/calico-typha",
        ],
        "images": ["cilium/hubble-relay:v1.15.0"],
        "configs": ["hubble-flowlogs"],
    },
}

# absent 态：底噪 + 近似产品干扰（防误报）
ABSENT = {
    "elkeid": generic(daemonsets=["kube-system/kube-proxy", "kube-system/falco"]),
    "agentsmith": generic(),
    "veinmind": generic(),
    "falco": generic(daemonsets=["kube-system/kube-proxy", "kube-system/elkeid-agent"]),
    "tetragon": generic(),
    "kubearmor": generic(),
    "admission": generic(),
    "imagescan": generic(),
    "hostagent": generic(),
    "waf-inference": generic(),
    "netobserv": generic(daemonsets=["kube-system/cilium", "kube-system/kube-proxy"]),
}

DEGRADED = {"elkeid", "agentsmith", "falco", "tetragon", "hostagent"}


def degraded_of(product: str) -> dict:
    snap = json.loads(json.dumps(DEPLOYED[product]))
    if product == "falco":
        snap["kernel_modules"] = []
        snap["configs"] = ["falco-no-driver"]
    elif product == "tetragon":
        snap["kernel_params"] = ["lsm=integrity,apparmor"]
    elif product == "hostagent":
        snap["agent_status"] = ["offline"]
    else:  # elkeid / agentsmith：内核模块未加载
        snap["kernel_modules"] = []
    return snap


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for product in DEPLOYED:
        files = {
            "deployed": DEPLOYED[product],
            "absent": ABSENT[product],
        }
        if product in DEGRADED:
            files["degraded"] = degraded_of(product)
        for state, snap in files.items():
            p = FIXTURES / f"{product}-{state}.json"
            p.write_text(json.dumps(snap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print("wrote", p.name)


if __name__ == "__main__":
    main()
