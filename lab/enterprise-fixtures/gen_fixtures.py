# -*- coding: utf-8 -*-
"""生成企业真实感实验夹具（生产形态：混合命名空间 / NetworkPolicy 分区 /
Kyverno+Falco 生效状态 / 平台与租户噪声 / 审计事件洪水）。

产物全部为 **fixture**：用于本地可重复的 FP/FN 评测，不冒充客户生产环境。
真实集群车道的证据仍来自 `reports/samples/real-cluster/`（单节点 k3s/QEMU TCG）。

    python lab/enterprise-fixtures/gen_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.core.yamlish import dump  # noqa: E402

HERE = Path(__file__).resolve().parent
CLUSTERS = HERE / "clusters"
MANIFESTS = HERE / "manifests"
KUBECONFIGS = HERE / "kubeconfigs"

KUBECONFIG_TMPL = """apiVersion: v1
kind: Config
clusters:
- name: {cluster}
  cluster:
    server: https://{cluster}.example.test:6443
contexts:
- name: {context}
  context:
    cluster: {cluster}
    user: {user}
    namespace: ml-inference
current-context: {context}
users:
- name: {user}
  user:
    token: MOCK-{upper}-TOKEN
"""


def pod(ns, name, image, *, privileged=False, host_paths=(), host_network=False,
        host_pid=False, caps=(), sa="default", labels=None, phase="Running",
        pvc_claims=()):
    sc = {"privileged": True} if privileged else {}
    if caps:
        sc["capabilities"] = {"add": list(caps)}
    volumes = [{"name": f"host-{i}", "hostPath": {"path": p}}
               for i, p in enumerate(host_paths)]
    volumes += [{"name": f"pvc-{i}", "persistentVolumeClaim": {"claimName": c}}
                for i, c in enumerate(pvc_claims)]
    return {
        "namespace": ns, "name": name, "labels": labels or {},
        "nodeName": f"{ns}-node-0", "hostNetwork": host_network, "hostPID": host_pid,
        "hostIPC": False, "serviceAccountName": sa, "phase": phase,
        "podIP": "10.42.0.10",
        "containers": [{"name": name, "image": image, "securityContext": sc,
                        "volumeMounts": [], "command": [], "args": []}],
        "volumes": volumes, "tolerations": [],
    }


def node(name, *, gpu=0, provider="aws-eks", version="v1.31.4"):
    labels = {
        "kubernetes.io/hostname": name,
        "node.kubernetes.io/instance-type": "m6i.4xlarge" if gpu else "m6i.2xlarge",
    }
    if provider == "aws-eks":
        labels["eks.amazonaws.com/nodegroup"] = "gpu" if gpu else "system"
    elif provider == "azure-aks":
        labels["kubernetes.azure.com/agentpool"] = "gpu" if gpu else "system"
    cap = {"cpu": "16", "memory": "64Gi", "pods": "110"}
    if gpu:
        cap["nvidia.com/gpu"] = str(gpu)
    return {"name": name, "labels": labels, "capacity": cap, "conditions": ["Ready"]}


def svc(ns, name, typ="ClusterIP", ports=(), external_ips=()):
    return {"namespace": ns, "name": name, "type": typ, "clusterIP": "10.43.0.10",
            "externalIPs": list(external_ips), "selector": {"app": name}, "labels": {},
            "ports": [{"name": f"p{i}", "port": p, "targetPort": p,
                       "nodePort": (30000 + i if typ == "NodePort" else None),
                       "protocol": "TCP"} for i, p in enumerate(ports)]}


def netpol(ns, name="default-deny", *, egress=True):
    return {"namespace": ns, "name": name, "podSelector": {},
            "policyTypes": ["Ingress"] + (["Egress"] if egress else []),
            "ingress": [], "egress": []}


def role(name, rules, ns=None):
    return {"namespace": ns, "name": name, "rules": rules}


def binding(name, role_name, subjects, ns=None, kind="ClusterRole"):
    return {"namespace": ns, "name": name, "role": role_name, "roleKind": kind,
            "subjects": subjects}


def audit(seq, verb, resource, *, ns="", name="", user="system:serviceaccount:ci:ci-runner",
          subresource="", code=200, request_object=None, ts=None):
    ref = {"resource": resource, "name": name, "apiVersion": "v1"}
    if ns:
        ref["namespace"] = ns
    if subresource:
        ref["subresource"] = subresource
    return {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1",
        "auditID": f"fixture-{seq:04d}",
        "stage": "ResponseComplete", "stageTimestamp": ts or f"2026-10-25T10:{seq // 60:02d}:{seq % 60:02d}Z",
        "requestReceivedTimestamp": ts or f"2026-10-25T10:{seq // 60:02d}:{seq % 60:02d}Z",
        "verb": verb, "user": {"username": user},
        "objectRef": ref, "responseStatus": {"code": code},
        "sourceIPs": ["10.0.0.5"], "requestObject": request_object or {},
    }


def east_snapshot():
    pods = [
        pod("kube-system", "aws-node-9k2lp", "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni:v1.18",
            privileged=True, host_paths=["/var/run/docker.sock", "/var/lib/cni"], host_network=True,
            sa="aws-node"),
        pod("kube-system", "kube-proxy-7c9d", "registry.k8s.io/kube-proxy:v1.31.4",
            host_network=True, caps=["NET_ADMIN"], sa="kube-proxy"),
        pod("kube-system", "ebs-csi-node-2x8v", "public.ecr.aws/ebs-csi-driver/aws-ebs-csi-driver:v1.35",
            privileged=True, host_paths=["/var/lib/kubelet", "/dev"], sa="ebs-csi-node"),
        pod("kube-system", "coredns-6d4b75cb6d-x8q2z", "registry.k8s.io/coredns/coredns:v1.11.1",
            sa="coredns", labels={"k8s-app": "kube-dns"}),
        pod("security", "falco-jk2m9", "falcosecurity/falco:0.39.2",
            privileged=True, host_paths=["/proc", "/sys/kernel/debug", "/var/run/docker.sock"],
            host_network=True, sa="falco"),
        pod("security", "kyverno-admission-controller-5b7c", "ghcr.io/kyverno/kyverno:v1.13.2",
            sa="kyverno-admission-controller"),
        pod("monitoring", "node-exporter-h4n2p", "quay.io/prometheus/node-exporter:v1.8.2",
            host_paths=["/proc", "/sys"], host_network=True, sa="node-exporter"),
        pod("monitoring", "prometheus-0", "quay.io/prometheus/prometheus:v2.55.0",
            host_paths=["/var/lib/prometheus"], sa="prometheus", pvc_claims=["prometheus-data"]),
        pod("monitoring", "grafana-7d9f", "grafana/grafana:11.3.0", sa="grafana"),
        pod("ml-training", "pytorchjob-worker-0", "pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime",
            sa="training-operator", labels={"job": "llama-finetune"}),
        pod("ml-training", "checkpoint-writer-0", "alpine:3.20",
            sa="platform-scheduler", pvc_claims=["model-weights-pvc"]),
        pod("ml-training", "ray-head-0", "rayproject/ray:2.40.0-gpu",
            host_network=True, sa="ray-head"),
        pod("ml-inference", "vllm-router-6f7d9", "vllm/vllm-openai:v0.6.4",
            sa="vllm-router", labels={"app": "vllm"}),
        pod("ml-inference", "sglang-engine-0", "lmsysorg/sglang:v0.4.1",
            sa="sglang-engine", labels={"app": "sglang"}),
        pod("ml-inference", "api-gateway-5f8d", "envoyproxy/envoy:v1.31.2",
            sa="api-gateway", labels={"app": "api-gateway"}),
        pod("tenant-a", "jupyter-alice-0", "jupyter/scipy-notebook:2024-10-01",
            sa="tenant-a", labels={"tenant": "a"}),
        pod("tenant-a", "model-copy-job-8x2k", "busybox:1.36",
            privileged=True, host_paths=["/"], sa="tenant-a", labels={"tenant": "a"}),
        pod("tenant-b", "jupyter-bob-0", "jupyter/scipy-notebook:2024-10-01",
            sa="tenant-b", labels={"tenant": "b"}),
        pod("ci", "gitlab-runner-0", "gitlab/gitlab-runner:alpine-v17.5.0", sa="ci-runner"),
        pod("ingress-nginx", "controller-7d8f9", "registry.k8s.io/ingress-nginx/controller:v1.11.3",
            host_network=True, caps=["NET_BIND_SERVICE"], sa="ingress-nginx"),
    ]
    return {
        "source": "fixture", "context": "east-prod", "provider": "aws-eks",
        "k8s_version": "v1.31.4-eks",
        "collected_at": "2026-10-25T10:00:00Z",
        "nodes": [node(f"east-node-{i}", gpu=(8 if i < 4 else 0)) for i in range(8)],
        "pods": pods,
        "services": [
            svc("default", "kubernetes", ports=[443]),
            svc("ml-inference", "vllm-router", "NodePort", ports=[8000]),
            svc("ml-training", "tensorboard", "LoadBalancer", ports=[6006]),
            svc("monitoring", "grafana", ports=[3000]),
            svc("monitoring", "prometheus", ports=[9090]),
            svc("ml-training", "mlflow", "LoadBalancer", ports=[5000]),
            svc("ingress-nginx", "ingress-nginx-controller", "LoadBalancer", ports=[80, 443]),
            svc("tenant-a", "jupyter-alice", "NodePort", ports=[8888]),
        ],
        "networkpolicies": [
            netpol("ml-training"), netpol("ml-inference"), netpol("tenant-a"), netpol("ci"),
        ],
        "roles": [
            role("tenant-a-deployer", [{"apiGroups": [""], "resources": ["roles", "rolebindings"],
                                        "verbs": ["create", "update", "patch"]}], ns="tenant-a"),
            role("read-only-auditor", [{"apiGroups": [""], "resources": ["pods", "services"],
                                        "verbs": ["get", "list"]}], ns="tenant-a"),
        ],
        "rolebindings": [
            binding("tenant-a-deployer-binding", "tenant-a-deployer",
                    [{"kind": "ServiceAccount", "name": "deployer", "namespace": "tenant-a"}],
                    ns="tenant-a", kind="Role"),
        ],
        "clusterroles": [
            role("platform-operator", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
            role("system:controller:node-controller",
                 [{"apiGroups": [""], "resources": ["nodes", "pods"], "verbs": ["*"]}]),
            role("tenant-a-deployer", [{"apiGroups": [""], "resources": ["roles", "rolebindings"],
                                        "verbs": ["create", "update", "patch"]}]),
            role("ml-pipeline-runner", [{"apiGroups": [""], "resources": ["pods", "secrets"],
                                         "verbs": ["create", "get", "list"]}]),
            role("read-only-auditor", [{"apiGroups": [""], "resources": ["pods", "services"],
                                        "verbs": ["get", "list"]}]),
        ],
        "clusterrolebindings": [
            binding("system:masters", "cluster-admin",
                    [{"kind": "Group", "name": "system:masters"}]),
            binding("platform-operator-binding", "platform-operator",
                    [{"kind": "ServiceAccount", "name": "platform-operator",
                      "namespace": "ml-platform"}]),
            binding("tenant-a-admin-binding", "cluster-admin",
                    [{"kind": "ServiceAccount", "name": "admin", "namespace": "tenant-a"}]),
            binding("ci-runner-binding", "ml-pipeline-runner",
                    [{"kind": "ServiceAccount", "name": "ci-runner", "namespace": "ci"}]),
        ],
        "ingresses": [
            {"namespace": "ml-inference", "name": "vllm", "host": "llm.east.example.test",
             "path": "/", "service": "vllm-router", "port": 8000},
            {"namespace": "monitoring", "name": "grafana", "host": "grafana.east.example.test",
             "path": "/", "service": "grafana", "port": 3000},
        ],
        "pvs": [
            {"name": "model-weights-pvc", "capacity": {"storage": "2Ti"},
             "claim": "model-weights-pvc", "namespace": "ml-training"},
            {"name": "checkpoint-pvc", "capacity": {"storage": "1Ti"},
             "claim": "checkpoint-pvc", "namespace": "ml-training"},
            {"name": "prometheus-data", "capacity": {"storage": "500Gi"},
             "claim": "prometheus-data", "namespace": "monitoring"},
        ],
        "secrets": [
            {"namespace": "ml-training", "name": "hf-token"},
            {"namespace": "ml-inference", "name": "vllm-api-key"},
            {"namespace": "tenant-a", "name": "alice-token"},
            {"namespace": "tenant-b", "name": "bob-token"},
            {"namespace": "kube-system", "name": "aws-node-token"},
            {"namespace": "security", "name": "falco-webhook"},
        ],
        "cani": [
            {"subject": "system:serviceaccount:ml-training:platform-scheduler",
             "allowed": ["create pods", "get secrets"]},
            {"subject": "system:serviceaccount:tenant-a:tenant-a",
             "allowed": ["get secrets"]},
            {"subject": "system:serviceaccount:ci:ci-runner",
             "allowed": ["create pods/exec"]},
            {"subject": "system:serviceaccount:tenant-a:auditor",
             "allowed": ["get pods"]},
        ],
        "namespaces": ["kube-system", "security", "monitoring", "ml-training",
                       "ml-inference", "tenant-a", "tenant-b", "ci", "ingress-nginx"],
        "defenses": {
            "kyverno": {"policies": [
                {"name": "deny-privileged", "status": "Enforced"},
                {"name": "deny-hostpath", "status": "Enforced"},
                {"name": "require-run-as-nonroot", "status": "Audit"},
                {"name": "restrict-image-registries", "status": "Audit"},
                {"name": "require-resource-limits", "status": "Missing"},
            ]},
            "falco": {"rules": [
                {"name": "Terminal shell in container", "loaded": True},
                {"name": "Read sensitive file untrusted", "loaded": True},
                {"name": "Write below etc", "loaded": True},
                {"name": "Package management launched", "loaded": True},
                {"name": "Contact K8s API Server", "loaded": True},
                {"name": "Detect crypto mining", "loaded": False},
                {"name": "Outbound connection to C2", "loaded": False},
                {"name": "Sensitive mount", "loaded": False},
            ]},
        },
    }


def west_snapshot():
    pods = [
        pod("kube-system", "azure-cni-agent-0", "mcr.microsoft.com/azuremonitor/containerinsights/ciprod:3.1",
            privileged=True, host_paths=["/var/run/containerd/containerd.sock"]),
        pod("kube-system", "coredns-5c7f9", "registry.k8s.io/coredns/coredns:v1.11.1"),
        pod("monitoring", "prometheus-0", "quay.io/prometheus/prometheus:v2.55.0",
            host_paths=["/var/lib/prometheus"]),
        pod("ml-training", "verl-worker-0", "verl/verl:0.3.0-cuda12.4",
            pvc_claims=["model-weights-west"]),
        pod("ml-inference", "triton-0", "nvcr.io/nvidia/tritonserver:24.10-py3", sa="triton"),
        pod("tenant-c", "notebook-carol-0", "jupyter/scipy-notebook:2024-10-01", sa="tenant-c"),
    ]
    return {
        "source": "fixture", "context": "west-prod", "provider": "azure-aks",
        "k8s_version": "v1.30.7-aks",
        "collected_at": "2026-10-25T10:05:00Z",
        "nodes": [node(f"west-node-{i}", gpu=(8 if i < 2 else 0), provider="azure-aks",
                       version="v1.30.7") for i in range(4)],
        "pods": pods,
        "services": [
            svc("default", "kubernetes", ports=[443]),
            svc("ml-inference", "triton", ports=[8000, 8001, 8002]),
            svc("monitoring", "grafana", ports=[3000]),
        ],
        "networkpolicies": [netpol("ml-training"), netpol("ml-inference")],
        "roles": [],
        "rolebindings": [],
        "clusterroles": [
            role("platform-operator", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
            role("read-only-auditor", [{"apiGroups": [""], "resources": ["pods"],
                                        "verbs": ["get", "list"]}]),
        ],
        "clusterrolebindings": [
            binding("system:masters", "cluster-admin",
                    [{"kind": "Group", "name": "system:masters"}]),
            binding("platform-operator-binding", "platform-operator",
                    [{"kind": "ServiceAccount", "name": "platform-operator",
                      "namespace": "ml-platform"}]),
        ],
        "ingresses": [],
        "pvs": [
            {"name": "model-weights-west", "capacity": {"storage": "1Ti"},
             "claim": "model-weights-west", "namespace": "ml-training"},
            {"name": "prometheus-data", "capacity": {"storage": "200Gi"},
             "claim": "prometheus-data", "namespace": "monitoring"},
        ],
        "secrets": [
            {"namespace": "ml-training", "name": "acr-pull"},
            {"namespace": "tenant-c", "name": "carol-token"},
        ],
        "cani": [
            {"subject": "system:serviceaccount:tenant-c:tenant-c", "allowed": ["get secrets"]},
        ],
        "namespaces": ["kube-system", "monitoring", "ml-training", "ml-inference", "tenant-c"],
        "defenses": {
            "kyverno": {"policies": [
                {"name": "deny-privileged", "status": "Enforced"},
                {"name": "require-run-as-nonroot", "status": "Audit"},
                {"name": "restrict-image-registries", "status": "Audit"},
            ]},
            "falco": {"rules": [
                {"name": "Terminal shell in container", "loaded": True},
                {"name": "Read sensitive file untrusted", "loaded": True},
                {"name": "Write below etc", "loaded": True},
                {"name": "Detect crypto mining", "loaded": False},
                {"name": "Outbound connection to C2", "loaded": False},
                {"name": "Sensitive mount", "loaded": False},
            ]},
        },
    }


def audit_events():
    events = []
    seq = 0
    # 180 benign exec sessions by CI (noise; default detector has no CI baseline)
    for i in range(120):
        seq += 1
        events.append(audit(seq, "create", "pods", ns="ci", name=f"build-{i}",
                            subresource="exec", user="system:serviceaccount:ci:ci-runner"))
    # 60 benign denied secret reads by security scanner (noise)
    for i in range(60):
        seq += 1
        events.append(audit(seq, "get", "secrets", ns="tenant-a", name="alice-token",
                            user="system:serviceaccount:security:scanner", code=403))
    # 100 benign secret reads by monitoring (baseline subject)
    for i in range(100):
        seq += 1
        events.append(audit(seq, "get", "secrets", ns="monitoring", name="prometheus-tls",
                            user="system:serviceaccount:monitoring:prometheus"))
    # 60 benign weight PVC pod creations by platform scheduler (baseline subject)
    for i in range(60):
        seq += 1
        events.append(audit(seq, "create", "pods", ns="ml-training", name=f"ckpt-{i}",
                            user="system:serviceaccount:ml-training:platform-scheduler",
                            request_object={"spec": {"volumes": [
                                {"name": "w", "persistentVolumeClaim": {"claimName": "model-weights-pvc"}}]}}))
    # Malicious: cluster-admin binding create
    seq += 1
    events.append(audit(seq, "create", "clusterrolebindings", name="evil-admin",
                        user="alice@example.test",
                        request_object={"roleRef": {"name": "cluster-admin"}}))
    # Malicious: tenant-b exec (not baseline)
    seq += 1
    events.append(audit(seq, "create", "pods", ns="tenant-b", name="jupyter-bob-0",
                        subresource="exec", user="system:serviceaccount:tenant-b:tenant-b"))
    # Malicious: weight PVC patch
    seq += 1
    events.append(audit(seq, "patch", "persistentvolumeclaims", ns="ml-training",
                        name="model-weights-pvc", user="bob@example.test"))
    # Missed risk 1: service account token minting
    seq += 1
    events.append(audit(seq, "create", "serviceaccounts", ns="tenant-b", name="tenant-b",
                        subresource="token", user="system:serviceaccount:tenant-b:tenant-b"))
    # Missed risk 2: port-forward
    seq += 1
    events.append(audit(seq, "create", "pods", ns="tenant-b", name="jupyter-bob-0",
                        subresource="portforward", user="system:serviceaccount:tenant-b:tenant-b"))
    return events


def ground_truth():
    labels = []
    def add(id, scenario, label, module, contains):
        labels.append({"id": id, "scenario": scenario, "label": label,
                       "module": module, "contains": contains})

    # 场景 1：平台组件基线噪声（escape-primitives）
    for name in ("aws-node", "kube-proxy", "ebs-csi-node", "falco", "node-exporter",
                 "prometheus", "ingress-nginx"):
        add(f"benign-platform-{name}", "platform-baseline-noise", "benign",
            "escape-primitives", name)
    add("risk-tenant-a-privileged-copy", "platform-baseline-noise", "risk",
        "escape-primitives", "model-copy-job")
    # 检测器已补齐（escape-primitives 防御验证联动）：占位锚点落位为具体证据锚。
    # risk/benign 判定不变；改动仅是把 "__not_detected__" 占位替换为可命中锚点。
    add("fn-falco-gap", "platform-baseline-noise", "risk",
        "escape-primitives", "Falco 检测缺口")

    # 场景 2：常规 RBAC/网络运维噪声
    for needle in ("platform-operator", "system:controller", "ci-runner"):
        add(f"benign-rbac-{needle}", "rbac-intent-noise", "benign",
            "rbac-mapping", needle)
    for needle in ("kube-system", "monitoring", "security"):
        add(f"benign-netpol-{needle}", "rbac-intent-noise", "benign",
            "network-policy-coverage", needle)
    add("risk-tenant-a-admin", "rbac-intent-noise", "risk", "rbac-mapping", "tenant-a-admin")
    add("risk-tenant-a-deployer", "rbac-intent-noise", "risk", "rbac-mapping", "tenant-a-deployer")
    add("risk-tenant-a-secret", "rbac-intent-noise", "risk", "rbac-mapping", "tenant-a:tenant-a")
    add("risk-platform-scheduler", "rbac-intent-noise", "risk", "rbac-mapping", "platform-scheduler")
    add("risk-tenant-b-netpol", "rbac-intent-noise", "risk", "network-policy-coverage", "tenant-b")
    add("risk-tenant-c-netpol", "rbac-intent-noise", "risk", "network-policy-coverage", "tenant-c")
    # mutable image tag 检测器已存在（rbac-mapping 镜像可变标签盘点），但本夹具
    # 快照中没有任何可变标签镜像证据 → 保留 "__not_detected__"，如实计 FN（不造证据）。
    add("fn-mutable-image", "rbac-intent-noise", "risk", "rbac-mapping", "__not_detected__")

    # 场景 3：审计洪水
    add("risk-audit-clusteradmin", "audit-flood-noise", "risk", "auditlog", "cluster-admin")
    # 锚点精确化：tenant-exec 用「subresource+目标 Pod」复合锚（"tenant-b" 会同时命中
    # sa-token/portforward 发现的主体字段，"pods/exec" 会命中 CI 噪声 exec——复合锚
    # 唯一标识该风险事件）；risk 判定不变。
    add("risk-audit-tenant-exec", "audit-flood-noise", "risk", "auditlog",
        "pods/exec tenant-b/jupyter-bob-0")
    add("risk-audit-weight-pvc", "audit-flood-noise", "risk", "auditlog", "model-weights-pvc")
    # 两条 FN 已补检测器（sa-token-mint / pods-portforward，core/auditlog.py）：
    # 占位锚点落位为检测器产出的资源证据锚。
    add("fn-audit-sa-token", "audit-flood-noise", "risk", "auditlog", "serviceaccounts/token")
    add("fn-audit-portforward", "audit-flood-noise", "risk", "auditlog", "pods/portforward")
    return labels


def manifests():
    kyverno = {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
         "metadata": {"name": name}, "spec": {
             "validationFailureAction": action,
             "rules": [{"name": name, "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
                        "validate": {"message": f"{name} fixture policy",
                                     "pattern": {"spec": {"securityContext": {"runAsNonRoot": True}}}}}]}}
        for name, action in (("deny-privileged", "Enforce"), ("deny-hostpath", "Enforce"),
                             ("require-run-as-nonroot", "Audit"),
                             ("restrict-image-registries", "Audit"),
                             ("require-resource-limits", "Audit"))
    ]}
    falco = {"rules": [
        {"rule": "Terminal shell in container", "enabled": True, "priority": "NOTICE"},
        {"rule": "Read sensitive file untrusted", "enabled": True, "priority": "WARNING"},
        {"rule": "Write below etc", "enabled": True, "priority": "ERROR"},
        {"rule": "Detect crypto mining", "enabled": False, "priority": "ERROR"},
        {"rule": "Outbound connection to C2", "enabled": False, "priority": "CRITICAL"},
        {"rule": "Sensitive mount", "enabled": False, "priority": "WARNING"},
    ]}
    netpols = {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "default-deny", "namespace": ns},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                  "ingress": [], "egress": []}}
        for ns in ("ml-training", "ml-inference", "tenant-a", "ci")
    ]}
    namespaces = {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": ns, "labels": {"inkblade.example/purpose": purpose}}}
        for ns, purpose in (("kube-system", "platform"), ("security", "platform"),
                            ("monitoring", "platform"), ("ml-training", "training"),
                            ("ml-inference", "inference"), ("tenant-a", "tenant"),
                            ("tenant-b", "tenant"), ("ci", "ci"), ("ingress-nginx", "platform"))
    ]}
    (MANIFESTS / "kyverno-policies.yaml").write_text(dump(kyverno), encoding="utf-8")
    (MANIFESTS / "falco-rules.yaml").write_text(dump(falco), encoding="utf-8")
    (MANIFESTS / "network-policies.yaml").write_text(dump(netpols), encoding="utf-8")
    (MANIFESTS / "namespaces.yaml").write_text(dump(namespaces), encoding="utf-8")


README = """# 企业真实感实验夹具（production-shaped fixture）

> **这是 fixture，不是客户生产集群。** 用于本地可重复地测误报/漏报与调优；
> 真实集群证据另见 `reports/samples/real-cluster/`（单节点 k3s/QEMU TCG，无标注，
> 因此不计算 FP/FN）。

## 内容

- `clusters/east-prod.json` / `west-prod.json`：混合命名空间（kube-system/security/
  monitoring/ml-training/ml-inference/tenant-a/tenant-b/tenant-c/ci/ingress-nginx）、
  NetworkPolicy 分区（含未隔离分区）、GPU 节点、PVC/Secret 元数据、RBAC 通配符与
  常规系统绑定、Kyverno/Falco 生效状态。
- `audit-noise.jsonl`：340 条良性审计事件（CI exec、扫描器 403、监控读 Secret、
  平台调度器挂载权重 PVC）+ 5 条标注风险（其中 2 条为当前检测器未覆盖）。
- `ground-truth.json`：逐条 benign/risk 标签（实现不得临时改标签）。
- `kubeconfigs/east.yaml` / `west.yaml`：仅含 `MOCK-*` token 的本地 kubeconfig，
  用于 CLI/多 context 合并演示；不是真实客户凭据。
- `manifests/`：Kyverno/Falco/NetworkPolicy/Namespace 生产形态清单（Kustomize 前置）。
- `gen_fixtures.py`：幂等再生成。

## 明确不声称

- 不声称这些清单已在客户的 EKS/AKS、Calico/Cilium、Kyverno/Falco 版本上实跑；
- 不声称 FP/FN 率可外推到客户环境；Pilot 必须用客户标注样本重测；
- 不把 fixture 结果写成「生产验证」。
"""


def main() -> int:
    CLUSTERS.mkdir(parents=True, exist_ok=True)
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    KUBECONFIGS.mkdir(parents=True, exist_ok=True)
    (KUBECONFIGS / "east.yaml").write_text(
        KUBECONFIG_TMPL.format(cluster="east-cluster", context="east-prod",
                               user="east-user", upper="EAST"), encoding="utf-8")
    (KUBECONFIGS / "west.yaml").write_text(
        KUBECONFIG_TMPL.format(cluster="west-cluster", context="west-prod",
                               user="west-user", upper="WEST"), encoding="utf-8")
    east = east_snapshot()
    west = west_snapshot()
    (CLUSTERS / "east-prod.json").write_text(
        json.dumps(east, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (CLUSTERS / "west-prod.json").write_text(
        json.dumps(west, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    events = audit_events()
    (HERE / "audit-noise.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    (HERE / "ground-truth.json").write_text(
        json.dumps(ground_truth(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifests()
    (HERE / "README.md").write_text(README, encoding="utf-8")
    print(f"fixtures: {CLUSTERS} / {HERE / 'audit-noise.jsonl'} / {MANIFESTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
