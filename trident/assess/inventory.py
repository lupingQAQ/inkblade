# -*- coding: utf-8 -*-
"""只读环境清单采集：kubeconfig → inventory.json（含采集时间与证据来源）。

设计边界
--------
- 在线模式只执行 ``kubectl get`` / ``kubectl auth can-i`` / ``kubectl get --raw``；
  不调用 apply/delete/exec/port-forward，不修改集群。
- 离线模式读取 ``--snapshot``（本模块 schema、K8s 对象快照、pilot 风格 snapshot 均可）；
  所有结论标记 ``source=snapshot:<path>``。
- 采集失败不伪造字段：对应字段留空，``coverage`` 标 false，判定器会输出 unknown
  与补采命令。

清单 schema（``trident-inventory-v1``）是判定器的输入契约，核心字段：
``cluster`` / ``nodes`` / ``pods`` / ``daemonsets`` / ``components`` / ``cni`` /
``gpu`` / ``ray`` / ``kuberay`` / ``lws`` / ``gateway`` / ``ingress`` / ``storage`` /
``cloud`` / ``serviceaccounts`` / ``rbac`` / ``feature_gates`` / ``apiserver`` /
``kubelet`` / ``probes`` / ``facts`` / ``coverage`` / ``collection`` / ``evidence``。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable

SCHEMA = "trident-inventory-v1"

_READ_VERBS = {"get", "auth"}
_CNI_NAMES = ("calico", "cilium", "flannel", "antrea", "canal", "multus",
              "aws-node", "aws-vpc-cni", "azure-cni", "terway", "kube-router",
              "weave", "ovn-kubernetes", "spiderpool")
_GPU_KEYS = ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/i915",
             "nvidia.com/mig-1g.5gb", "nvidia.com/mig-3g.40gb")
_SOCKET_PATHS = ("docker.sock", "containerd.sock", "crio.sock", "kubelet.sock",
                 "containerd/containerd.sock")
_PRODUCT_KEYWORDS = (
    ("kuberay", "kuberay"), ("ray", "ray"), ("leaderworkerset", "lws"),
    ("lws", "lws"), ("vllm", "vllm"), ("sglang", "sglang"), ("triton", "triton"),
    ("litellm", "litellm"), ("higress", "higress"), ("envoy-gateway", "envoy-gateway"),
    ("istio", "istio"), ("gpu-operator", "nvidia"), ("container-toolkit", "nvidia"),
    ("dcgm", "nvidia"), ("nvidia", "nvidia"), ("kserve", "kserve"),
    ("volcano", "volcano"), ("hami", "hami"), ("kueue", "kueue"),
    ("jobset", "jobset"), ("training-operator", "training-operator"),
    ("pytorch", "pytorch"), ("deepspeed", "deepspeed"), ("megatron", "megatron"),
    ("openrlhf", "openrlhf"), ("skyrl", "skyrl"), ("areal", "areal"),
    ("slime", "slime"), ("dify", "dify"), ("open-webui", "open-webui"),
    ("openwebui", "open-webui"), ("mlflow", "mlflow"), ("wandb", "wandb"),
    ("jupyter", "jupyter"), ("calico", "calico"), ("cilium", "cilium"),
    ("flannel", "flannel"), ("ingress-nginx", "ingress-nginx"),
    ("nginx-ingress", "ingress-nginx"), ("traefik", "traefik"),
    ("sonic", "sonic"), ("cumulus", "cumulus"), ("cgpu", "cgpu"),
)
_RBAC_CHECKS = (
    ("create_pods", "create", "pods", True),
    ("get_secrets", "get", "secrets", True),
    ("create_clusterrolebindings", "create", "clusterrolebindings", False),
    ("create_pods_exec", "create", "pods/exec", True),
    ("get_nodes_proxy", "get", "nodes/proxy", False),
    ("create_daemonsets", "create", "daemonsets", True),
    ("create_serviceaccounts_token", "create", "serviceaccounts/token", True),
    ("get_persistentvolumes", "get", "persistentvolumes", False),
)


class InventoryError(ValueError):
    """kubeconfig/snapshot/采集结果非法。"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _items(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict):
        items = doc.get("items")
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
        # pilot 风格 snapshot 直接是 {pods:[...]}
        for key in ("objects", "list"):
            if isinstance(doc.get(key), list):
                return [x for x in doc[key] if isinstance(x, dict)]
    return []


def _list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _image_parts(image: str) -> dict:
    raw = str(image or "").strip()
    if not raw:
        return {"image": "", "repo": "", "tag": "", "digest": "", "version": ""}
    name = raw
    digest = ""
    if "@" in name:
        name, digest = name.split("@", 1)
    tag = ""
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = name.rsplit(":", 1)
    else:
        repo = name
    tag = tag or ""
    version = "" if tag.lower() in ("latest", "main", "master", "dev", "stable",
                                    "edge", "") else tag
    return {"image": raw, "repo": repo, "tag": tag, "digest": digest,
            "version": version}


def classify_component(name: str) -> str:
    text = str(name or "").lower()
    for needle, product in _PRODUCT_KEYWORDS:
        if needle in text:
            return product
    return ""


def _version_tag(tag: str) -> str:
    tag = str(tag or "").strip()
    if not tag or tag.lower() in ("latest", "main", "master", "dev", "stable", "edge"):
        return ""
    return tag


def _env_map(env: Any) -> dict:
    out: dict[str, Any] = {}
    if isinstance(env, dict):
        return dict(env)
    if isinstance(env, list):
        for item in env:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            if "value" in item:
                out[str(name)] = item.get("value")
            elif "valueFrom" in item:
                out[str(name)] = "<valueFrom>"
    return out


def _container_record(c: dict) -> dict:
    sc = c.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    return {
        "name": c.get("name") or "",
        "image": c.get("image") or "",
        "command": list(c.get("command") or []),
        "args": list(c.get("args") or []),
        "env": _env_map(c.get("env")),
        "env_from": list(c.get("envFrom") or []),
        "privileged": bool(sc.get("privileged") or c.get("privileged")),
        "allow_privilege_escalation": sc.get("allowPrivilegeEscalation"),
        "cap_add": list(caps.get("add") or c.get("cap_add") or []),
        "cap_drop": list(caps.get("drop") or []),
        "read_only_root": sc.get("readOnlyRootFilesystem"),
        "run_as_user": sc.get("runAsUser", c.get("run_as_user")),
        "volume_mounts": list(c.get("volumeMounts") or c.get("volume_mounts") or []),
        "ports": list(c.get("ports") or []),
    }


def _volume_records(volumes: Any) -> list[dict]:
    out = []
    for v in _list(volumes):
        if not isinstance(v, dict):
            continue
        hp = v.get("hostPath") or v.get("host_path") or {}
        out.append({
            "name": v.get("name") or "",
            "host_path": hp.get("path") if isinstance(hp, dict) else (hp or None),
            "git_repo": v.get("gitRepo") or v.get("git_repo"),
            "persistent_volume_claim": v.get("persistentVolumeClaim"),
            "config_map": v.get("configMap"),
            "secret": v.get("secret"),
            "empty_dir": v.get("emptyDir"),
        })
    return out


def _node_record(raw: dict, source: str) -> dict:
    meta = raw.get("metadata") or raw
    status = raw.get("status") or {}
    info = status.get("nodeInfo") or raw.get("nodeInfo") or {}
    labels = meta.get("labels") or raw.get("labels") or {}
    annotations = meta.get("annotations") or raw.get("annotations") or {}
    capacity = status.get("capacity") or raw.get("capacity") or {}
    conditions = [c.get("type") for c in status.get("conditions") or []
                  if isinstance(c, dict) and c.get("status") == "True"]
    runtime = str(info.get("containerRuntimeVersion") or raw.get("containerRuntime")
                  or raw.get("container_runtime") or "")
    runtime_type, _, runtime_ver = runtime.partition("://")
    runc = str(raw.get("runc") or annotations.get("runc.version")
               or labels.get("runc.version") or "")
    gpu = raw.get("gpu") if isinstance(raw.get("gpu"), dict) else {}
    driver = str(gpu.get("driver_version") or "")
    if not driver:
        major = labels.get("nvidia.com/cuda.driver.major")
        minor = labels.get("nvidia.com/cuda.driver.minor")
        if major:
            driver = f"{major}.{minor}" if minor else str(major)
    gpu_count = 0
    for key in _GPU_KEYS:
        try:
            gpu_count += int(float(capacity.get(key) or 0))
        except (TypeError, ValueError):
            pass
    return {
        "name": meta.get("name") or raw.get("name") or "",
        "os": str(info.get("operatingSystem") or raw.get("os") or ""),
        "os_image": str(info.get("osImage") or raw.get("os_image") or ""),
        "kernel": str(info.get("kernelVersion") or raw.get("kernel")
                      or raw.get("kernel_version") or ""),
        "arch": str(info.get("architecture") or raw.get("arch") or ""),
        "kubelet": str(info.get("kubeletVersion") or raw.get("kubelet") or ""),
        "container_runtime": runtime,
        "runtime_type": runtime_type.lower(),
        "runtime_version": runtime_ver,
        "containerd": (runtime_ver if runtime_type.lower() == "containerd" else
                       str(raw.get("containerd") or "")),
        "runc": runc,
        "runc_present": bool(runc or any(
            str(h.get("name") or "").lower() == "runc"
            for h in (status.get("runtimeHandlers") or []) if isinstance(h, dict))),
        "runtime_handlers": [str(h.get("name") or "") for h in
                             (status.get("runtimeHandlers") or []) if isinstance(h, dict)],
        "cni": str(raw.get("cni") or ""),
        "cni_version": str(raw.get("cni_version") or ""),
        "cgroups_version": str(raw.get("cgroups_version") or raw.get("cgroups") or ""),
        "provider_id": str(raw.get("providerID") or (raw.get("spec") or {}).get("providerID") or ""),
        "capacity": capacity,
        "gpu": {**gpu, "count": gpu_count, "driver_version": driver,
                "product": str(raw.get("gpu_product") or labels.get("nvidia.com/gpu.product") or "")},
        "labels": labels,
        "annotations": annotations,
        "conditions": conditions,
        "source": source,
    }


def _pod_record(raw: dict, source: str) -> dict:
    meta = raw.get("metadata") or raw
    spec = raw.get("spec") or raw
    status = raw.get("status") or {}
    containers = [_container_record(c) for c in _list(spec.get("containers") or raw.get("containers"))]
    volumes = _volume_records(spec.get("volumes") or raw.get("volumes"))
    host_paths = [v.get("host_path") for v in volumes if v.get("host_path")]
    runtime_sockets = [p for p in host_paths
                       if any(s in str(p) for s in _SOCKET_PATHS)]
    automount = spec.get("automountServiceAccountToken",
                         raw.get("automountServiceAccountToken",
                                 raw.get("automount_service_account_token")))
    return {
        "namespace": meta.get("namespace") or raw.get("namespace") or "default",
        "name": meta.get("name") or raw.get("name") or "",
        "phase": status.get("phase") or raw.get("phase") or "",
        "node": spec.get("nodeName") or raw.get("nodeName") or raw.get("node") or "",
        "labels": meta.get("labels") or raw.get("labels") or {},
        "annotations": meta.get("annotations") or {},
        "service_account": spec.get("serviceAccountName") or raw.get("serviceAccount")
                           or raw.get("service_account_name") or "",
        "automount_sa_token": automount,
        "host_network": bool(spec.get("hostNetwork", raw.get("hostNetwork"))),
        "host_pid": bool(spec.get("hostPID", raw.get("hostPID"))),
        "host_ipc": bool(spec.get("hostIPC", raw.get("hostIPC"))),
        "containers": containers,
        "volumes": volumes,
        "host_paths": host_paths,
        "runtime_socket_mounts": runtime_sockets,
        "git_repo_volumes": [v for v in volumes if v.get("git_repo")],
        "tolerations": list(spec.get("tolerations") or []),
        "source": source,
    }


def _workload_record(raw: dict, source: str, kind: str) -> dict:
    meta = raw.get("metadata") or raw
    spec = raw.get("spec") or {}
    template = ((spec.get("template") or {}).get("spec")) or raw.get("template") or spec
    containers = [_container_record(c) for c in _list(template.get("containers"))]
    volumes = _volume_records(template.get("volumes"))
    host_paths = [v.get("host_path") for v in volumes if v.get("host_path")]
    return {
        "kind": kind,
        "namespace": meta.get("namespace") or raw.get("namespace") or "default",
        "name": meta.get("name") or raw.get("name") or "",
        "containers": containers,
        "volumes": volumes,
        "host_paths": host_paths,
        "service_account": template.get("serviceAccountName") or "",
        "host_network": bool(template.get("hostNetwork")),
        "host_pid": bool(template.get("hostPID")),
        "host_ipc": bool(template.get("hostIPC")),
        "source": source,
    }


def _component_records(workloads: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for w in workloads:
        for c in w.get("containers") or []:
            image = _image_parts(c.get("image"))
            product = classify_component(f"{image['repo']} {c.get('name')} {w.get('name')}")
            key = (w.get("kind"), w.get("namespace"), w.get("name"), c.get("name"),
                   image["image"])
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "kind": w.get("kind"),
                "namespace": w.get("namespace"),
                "name": w.get("name"),
                "container": c.get("name"),
                "image": image["image"],
                "repo": image["repo"],
                "tag": image["tag"],
                "digest": image["digest"],
                "version": _version_tag(image["version"]),
                "product": product,
                "source": w.get("source") or "",
            })
    return out


def _parse_flags(args: Iterable[str]) -> dict:
    out: dict[str, str] = {}
    args = list(args or [])
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg.startswith("--"):
            if "=" in arg:
                key, val = arg.split("=", 1)
                out[key] = val
            elif i + 1 < len(args) and not str(args[i + 1]).startswith("--"):
                out[arg] = str(args[i + 1])
                i += 1
            else:
                out[arg] = "true"
        i += 1
    return out


def _feature_gates(metrics: str) -> dict:
    out: dict[str, bool] = {}
    pattern = re.compile(
        r'kubernetes_feature_enabled\{[^}]*name="([^"]+)"[^}]*\}\s+(\d+)')
    for m in pattern.finditer(metrics or ""):
        out[m.group(1)] = m.group(2) not in ("0", "")
    return out


def _provider_from_nodes(nodes: list[dict]) -> str:
    text = " ".join(str(n.get("provider_id") or "") for n in nodes).lower()
    for needle, provider in (("aws://", "aws"), ("azure://", "azure"), ("gce://", "gcp"),
                             ("alicloud://", "aliyun"), ("tencentcloud://", "tencent"),
                             ("openstack://", "openstack"), ("ibm://", "ibm"),
                             ("vsphere://", "vsphere"), ("oci://", "oci")):
        if needle in text:
            return provider
    return ""


def _sa_identity_hints(sas: list[dict]) -> list[str]:
    hints: list[str] = []
    for sa in sas:
        ann = sa.get("annotations") or {}
        for key in ("eks.amazonaws.com/role-arn",
                    "iam.gke.io/gcp-service-account",
                    "azure.workload.identity/client-id",
                    "aliyun.workload.identity/role-arn",
                    "tencent.cloud/role-arn"):
            if key in ann:
                hints.append(f"{sa.get('namespace')}/{sa.get('name')}:{key}={ann[key]}")
    return sorted(set(hints))


def _assemble(*, source: dict, nodes: list[dict], pods: list[dict], daemonsets: list[dict],
              namespaces: list[str], crds: list[dict], serviceaccounts: list[dict],
              storageclasses: list[dict], csidrivers: list[dict], pvs: list[dict],
              pvcs: list[dict], ingressclasses: list[dict], ingresses: list[dict],
              gatewayclasses: list[dict], gateways: list[dict], rbac: dict,
              apiserver_flags: dict, kubelet_config: dict, feature_gates: dict,
              metrics_ok: bool, bmc: list[dict], switches: list[dict],
              probes: dict, coverage: dict, collection: dict,
              collected_at: str = "") -> dict:
    workloads = list(pods) + list(daemonsets)
    components = _component_records(workloads)
    cni = {}
    for c in components:
        if c.get("product") in _CNI_NAMES:
            cni = {"name": c["product"], "version": c.get("version") or "",
                   "source": c.get("source") or ""}
            break
    if not cni:
        # k3s 等发行版可能把 flannel 编译进进程，没有 CNI Pod；用节点注解佐证。
        for n in nodes:
            text = " ".join(f"{k}={v}" for k, v in (n.get("labels") or {}).items()) + " " + \
                   " ".join(f"{k}={v}" for k, v in (n.get("annotations") or {}).items())
            low = text.lower()
            found = next((name for name in _CNI_NAMES if name in low), "")
            if found:
                cni = {"name": found, "version": "",
                       "source": "kubectl get nodes -o json（node annotations）",
                       "detail": "CNI 由节点注解识别，版本未暴露"}
                break
    gpu_components = [c for c in components if c.get("product") == "nvidia"]
    gpu_operator = next((c for c in gpu_components
                         if "gpu-operator" in str(c.get("repo", "")).lower()
                         or "gpu-operator" in str(c.get("name", "")).lower()), None)
    toolkit = next((c for c in gpu_components
                    if "container-toolkit" in str(c.get("repo", "")).lower()
                    or "toolkit" in str(c.get("name", "")).lower()), None)
    driver = next((str((n.get("gpu") or {}).get("driver_version") or "") for n in nodes
                   if (n.get("gpu") or {}).get("driver_version")), "")
    gpu = {
        "nodes": [n.get("name") for n in nodes if (n.get("gpu") or {}).get("count")],
        "operator": ({"name": gpu_operator.get("name"), "version": gpu_operator.get("version"),
                      "source": gpu_operator.get("source")} if gpu_operator else {}),
        "toolkit": ({"name": toolkit.get("name"), "version": toolkit.get("version"),
                     "source": toolkit.get("source")} if toolkit else {}),
        "driver_version": driver,
        "source": source.get("label") or "",
    }
    ray_components = [c for c in components if c.get("product") == "ray"]
    kuberay_components = [c for c in components if c.get("product") == "kuberay"]
    lws_components = [c for c in components if c.get("product") == "lws"]
    ray = {"versions": sorted({c["version"] for c in ray_components if c.get("version")}),
           "pods": [c.get("name") for c in ray_components],
           "crd": any("ray.io" in str(c.get("group") or "") for c in crds),
           "source": source.get("label") or ""}
    kuberay = {"versions": sorted({c["version"] for c in kuberay_components if c.get("version")}),
               "crd": any("ray.io" in str(c.get("group") or "") for c in crds),
               "source": source.get("label") or ""}
    lws = {"versions": sorted({c["version"] for c in lws_components if c.get("version")}),
           "crd": any("leaderworkerset" in str(c.get("group") or "").lower() for c in crds),
           "source": source.get("label") or ""}
    ingress_components = [c for c in components
                          if c.get("product") in ("ingress-nginx", "traefik")]
    gateway_components = [c for c in components
                          if c.get("product") in ("higress", "envoy-gateway", "istio")]
    ingress = {"controllers": [{k: c.get(k) for k in ("name", "namespace", "product",
                                                      "version", "image", "source")}
                               for c in ingress_components],
               "classes": [str(c.get("name") or "") for c in ingressclasses],
               "ingresses": len(ingresses), "source": source.get("label") or ""}
    gateway = {"components": [{k: c.get(k) for k in ("name", "namespace", "product",
                                                     "version", "image", "source")}
                              for c in gateway_components],
               "classes": [str(c.get("name") or "") for c in gatewayclasses],
               "gateways": [str(c.get("name") or "") for c in gateways],
               "crd": any("gateway.networking.k8s.io" in str(c.get("group") or "") for c in crds),
               "source": source.get("label") or ""}
    storage = {"classes": [{k: c.get(k) for k in ("name", "provisioner", "reclaim_policy")}
                           for c in storageclasses],
               "csi_drivers": [str(c.get("name") or "") for c in csidrivers],
               "pvs": len(pvs), "pvcs": len(pvcs), "source": source.get("label") or ""}
    provider = _provider_from_nodes(nodes) or str((source or {}).get("provider") or "")
    cloud = {"provider": provider, "identity_hints": _sa_identity_hints(serviceaccounts),
             "imds_reachable": probes.get("imds_reachable") if isinstance(probes, dict) else None,
             "source": source.get("label") or ""}
    cd = {c.get("name") for c in crds}
    facts: dict[str, Any] = {}
    fact_sources: dict[str, str] = {}

    def fact(name: str, value: Any, src: str) -> None:
        if value is None and name in facts:
            return
        facts[name] = value
        fact_sources[name] = src

    fact("cluster.version", (source or {}).get("version") or "", str(source.get("label") or ""))
    fact("node.kernel", [n.get("kernel") for n in nodes if n.get("kernel")],
         str((nodes[0].get("source") if nodes else source.get("label")) or ""))
    fact("node.os", [n.get("os") for n in nodes if n.get("os")],
         str((nodes[0].get("source") if nodes else source.get("label")) or ""))
    fact("cloud.provider", provider, str(source.get("label") or ""))
    if coverage.get("pods"):
        fact("workloads.privileged", any(c.get("privileged") for w in workloads
                                         for c in w.get("containers") or []),
             "kubectl get pods -A -o json")
        fact("workloads.host_path", any(w.get("host_paths") for w in workloads),
             "kubectl get pods -A -o json")
        fact("workloads.host_network", any(w.get("host_network") for w in workloads),
             "kubectl get pods -A -o json")
        fact("workloads.host_pid", any(w.get("host_pid") for w in workloads),
             "kubectl get pods -A -o json")
        fact("workloads.host_ipc", any(w.get("host_ipc") for w in workloads),
             "kubectl get pods -A -o json")
        fact("workloads.runtime_socket", any(w.get("runtime_socket_mounts")
                                             for w in workloads),
             "kubectl get pods -A -o json")
        fact("workloads.cap_sys_admin", any("SYS_ADMIN" in {str(x).upper() for x in
                                                           (c.get("cap_add") or [])}
                                            for w in workloads
                                            for c in w.get("containers") or []),
             "kubectl get pods -A -o json")
        auto = False
        for w in pods:
            val = w.get("automount_sa_token")
            if val is True:
                auto = True
            elif val is None and coverage.get("serviceaccounts", True):
                auto = True
        fact("workloads.automount_sa_token", auto,
             "kubectl get pods,serviceaccounts -A -o json")
    if feature_gates:
        for name, enabled in feature_gates.items():
            fact(f"feature_gates.{name}", enabled, "kubectl get --raw /metrics")
    if apiserver_flags:
        anon = apiserver_flags.get("--anonymous-auth")
        authz = str(apiserver_flags.get("--authorization-mode") or "")
        auth_disabled = None
        if anon is not None:
            auth_disabled = str(anon).lower() in ("true", "1", "yes")
        if "AlwaysAllow" in authz:
            auth_disabled = True
        fact("apiserver.anonymous_auth",
             (str(anon).lower() in ("true", "1", "yes")) if anon is not None else None,
             "kubectl get pods -n kube-system -l component=kube-apiserver -o json")
        fact("apiserver.authorization_mode", authz,
             "kubectl get pods -n kube-system -l component=kube-apiserver -o json")
        fact("apiserver.auth_disabled", auth_disabled,
             "kubectl get pods -n kube-system -l component=kube-apiserver -o json")
        adm = str(apiserver_flags.get("--enable-admission-plugins") or "")
        fact("apiserver.serviceaccount_admission",
             ("ServiceAccount" in adm) if adm else None,
             "kubectl get pods -n kube-system -l component=kube-apiserver -o json")
    if kubelet_config:
        ro = kubelet_config.get("readOnlyPort", kubelet_config.get("read_only_port"))
        anon = ((kubelet_config.get("authentication") or {}).get("anonymous") or {}).get("enabled")
        fact("kubelet.read_only_port", ro,
             "kubectl get --raw /api/v1/nodes/<node>/proxy/configz")
        fact("kubelet.anonymous_auth", anon,
             "kubectl get --raw /api/v1/nodes/<node>/proxy/configz")
    for key, val in (rbac or {}).items():
        fact(f"rbac.{key}", val, "kubectl auth can-i")
    if driver:
        fact("gpu.driver_version", driver, str(source.get("label") or ""))
    if any((n.get("runc_present") for n in nodes)):
        fact("node.runc_present", True,
             str((nodes[0].get("source") if nodes else source.get("label")) or ""))
    elif nodes:
        fact("node.runc_present", False,
             str(nodes[0].get("source") or source.get("label") or ""))
    if gpu_operator:
        fact("gpu.operator_version", gpu_operator.get("version"),
             str(gpu_operator.get("source") or ""))
    if toolkit:
        fact("gpu.toolkit_version", toolkit.get("version"),
             str(toolkit.get("source") or ""))
    if cni.get("name"):
        fact("cni.name", cni.get("name"), str(cni.get("source") or ""))
        fact("cni.version", cni.get("version"), str(cni.get("source") or ""))
    evidence = [
        {"field": k, "value": v, "source": fact_sources.get(k) or source.get("label") or ""}
        for k, v in facts.items() if not str(k).startswith("feature_gates.")
    ]
    if feature_gates:
        evidence.append({"field": "feature_gates", "value": len(feature_gates),
                         "source": "kubectl get --raw /metrics"})
    return {
        "schema": SCHEMA,
        "collected_at": collected_at or now_iso(),
        "source": source,
        "cluster": {
            "name": str((source or {}).get("cluster") or ""),
            "version": str((source or {}).get("version") or ""),
            "provider": provider,
            "server": str((source or {}).get("server") or ""),
            "node_count": len(nodes),
            "source": str(source.get("label") or ""),
        },
        "nodes": nodes,
        "namespaces": sorted({str(n) for n in namespaces if n}),
        "pods": pods,
        "daemonsets": daemonsets,
        "components": components,
        "serviceaccounts": serviceaccounts,
        "crds": crds,
        "cni": cni,
        "ingress": ingress,
        "gateway": gateway,
        "gpu": gpu,
        "ray": ray,
        "kuberay": kuberay,
        "lws": lws,
        "storage": storage,
        "cloud": cloud,
        "bmc": bmc,
        "switches": switches,
        "rbac": rbac,
        "feature_gates": feature_gates,
        "apiserver": {"flags": apiserver_flags,
                       "anonymous_auth": facts.get("apiserver.anonymous_auth"),
                       "authorization_mode": apiserver_flags.get("--authorization-mode"),
                       "source": "kubectl get pods -n kube-system"},
        "kubelet": {"read_only_port": facts.get("kubelet.read_only_port"),
                    "anonymous_auth": facts.get("kubelet.anonymous_auth"),
                    "config": kubelet_config,
                    "source": "kubectl get --raw /api/v1/nodes/<node>/proxy/configz"},
        "probes": probes or {},
        "facts": facts,
        "fact_sources": fact_sources,
        "coverage": coverage,
        "collection": collection,
        "evidence": evidence,
        "_crds_names": sorted(str(x) for x in cd if x),
    }


# ====================================================================== live kubectl


class KubectlReader:
    """只读 kubectl 调用器。命令白名单：get / auth can-i。"""

    def __init__(self, kubectl: str | list[str] = "kubectl", *,
                 kubeconfig: str | Path | None = None, context: str | None = None,
                 timeout: int = 30,
                 runner: Callable[[list[str], int], Any] | None = None):
        self.kubectl = [kubectl] if isinstance(kubectl, str) else list(kubectl)
        self.kubeconfig = str(kubeconfig) if kubeconfig else ""
        self.context = str(context) if context else ""
        self.timeout = int(timeout)
        self.runner = runner or self._default_runner
        self.calls: list[dict] = []

    @staticmethod
    def _default_runner(argv: list[str], timeout: int):
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)

    def _argv(self, args: list[str]) -> list[str]:
        if not args or args[0] not in _READ_VERBS:
            raise InventoryError(f"只读采集拒绝非白名单命令：{args[:2]}")
        if args[0] == "auth" and (len(args) < 2 or args[1] != "can-i"):
            raise InventoryError(f"auth 仅允许 can-i：{args[:3]}")
        cmd = list(self.kubectl)
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        if self.context:
            cmd += ["--context", self.context]
        return cmd + list(args)

    def call(self, args: list[str]) -> SimpleNamespace:
        argv = self._argv(args)
        started = time.time()
        try:
            proc = self.runner(argv, self.timeout)
        except subprocess.TimeoutExpired as exc:
            self.calls.append({"argv": argv[1:], "rc": -1, "ms": round(
                (time.time() - started) * 1000, 1), "error": "timeout"})
            raise InventoryError(f"kubectl {' '.join(args)} 超时（{self.timeout}s）") from exc
        rc = int(getattr(proc, "returncode", 1))
        call = {"argv": argv[1:], "rc": rc,
                "ms": round((time.time() - started) * 1000, 1)}
        self.calls.append(call)
        return proc

    def get_json(self, *args: str) -> Any:
        args = list(args)
        if "--raw" in args:
            proc = self.call(args)
        else:
            proc = self.call(args + ["-o", "json"])
        if int(getattr(proc, "returncode", 1)) != 0:
            raise InventoryError(str(getattr(proc, "stderr", "") or "kubectl 调用失败")[:400])
        raw = str(getattr(proc, "stdout", "") or "{}")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise InventoryError(f"kubectl {' '.join(args)} 输出非 JSON") from exc

    def get_raw(self, path: str) -> str:
        proc = self.call(["get", "--raw", path])
        if int(getattr(proc, "returncode", 1)) != 0:
            raise InventoryError(str(getattr(proc, "stderr", "") or "kubectl get --raw 失败")[:400])
        return str(getattr(proc, "stdout", "") or "")

    def can_i(self, verb: str, resource: str, *, all_namespaces: bool = False) -> bool | None:
        args = ["auth", "can-i", verb, resource]
        if all_namespaces:
            args.append("--all-namespaces")
        proc = self.call(args)
        if int(getattr(proc, "returncode", 1)) != 0:
            return None
        text = str(getattr(proc, "stdout", "") or "").strip().lower()
        if text.startswith("yes"):
            return True
        if text.startswith("no"):
            return False
        return None


def _resolve_kubeconfig(path: str | Path | None) -> Path:
    if path:
        p = Path(path)
        if not p.is_file():
            raise InventoryError(f"kubeconfig 不存在：{p}")
        return p
    env = os.environ.get("KUBECONFIG")
    if env:
        for part in env.split(os.pathsep):
            p = Path(part).expanduser()
            if p.is_file():
                return p
    p = Path.home() / ".kube" / "config"
    if p.is_file():
        return p
    raise InventoryError("找不到 kubeconfig：请用 --kubeconfig 指定，或在离线模式使用 --snapshot")


def _kubeconfig_meta(path: Path) -> dict:
    """极简读取 current-context / server（不解析完整 YAML，不读凭据内容）。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    current = ""
    server = ""
    m = re.search(r"(?m)^\s*current-context:\s*[\"']?([^\"'\s#]+)", text)
    if m:
        current = m.group(1)
    m = re.search(r"(?m)^\s*server:\s*[\"']?([^\"'\s#]+)", text)
    if m:
        server = m.group(1)
    return {"context": current, "server": server, "cluster": current}


def _fetch(reader: KubectlReader, commands: list[dict], errors: list[dict],
           *args: str, optional: bool = False, raw: bool = False) -> Any:
    started = time.time()
    try:
        data = reader.get_raw(args[-1]) if raw else reader.get_json(*args)
        return data
    except (InventoryError, OSError) as exc:
        errors.append({"command": "kubectl " + " ".join(args),
                       "optional": bool(optional), "error": str(exc)[:400]})
        return None


def collect_inventory(*, kubeconfig: str | Path | None = None, context: str | None = None,
                      kubectl: str | list[str] = "kubectl", timeout: int = 30,
                      runner: Callable[[list[str], int], Any] | None = None,
                      probes: dict | None = None,
                      collect_kubelet_config: bool = True) -> dict:
    """从 kubeconfig 只读采集环境清单（kubectl get / auth can-i）。"""
    kc = _resolve_kubeconfig(kubeconfig)
    kc_meta = _kubeconfig_meta(kc)
    reader = KubectlReader(kubectl, kubeconfig=kc, context=context, timeout=timeout,
                           runner=runner)
    commands: list[dict] = []
    errors: list[dict] = []
    version_doc = _fetch(reader, commands, errors, "get", "--raw", "/version", raw=True)
    version = ""
    if isinstance(version_doc, str):
        try:
            version_doc = json.loads(version_doc or "{}")
        except ValueError:
            version_doc = {}
    if isinstance(version_doc, dict):
        version = str(version_doc.get("gitVersion") or version_doc.get("version") or "")
    nodes_doc = _fetch(reader, commands, errors, "get", "nodes")
    namespaces_doc = _fetch(reader, commands, errors, "get", "namespaces")
    pods_doc = _fetch(reader, commands, errors, "get", "pods", "--all-namespaces")
    ds_doc = _fetch(reader, commands, errors, "get", "daemonsets", "--all-namespaces")
    crd_doc = _fetch(reader, commands, errors, "get", "customresourcedefinitions",
                     optional=True)
    sa_doc = _fetch(reader, commands, errors, "get", "serviceaccounts",
                    "--all-namespaces", optional=True)
    sc_doc = _fetch(reader, commands, errors, "get", "storageclasses", optional=True)
    csi_doc = _fetch(reader, commands, errors, "get", "csidrivers", optional=True)
    pv_doc = _fetch(reader, commands, errors, "get", "persistentvolumes", optional=True)
    pvc_doc = _fetch(reader, commands, errors, "get", "persistentvolumeclaims",
                     "--all-namespaces", optional=True)
    ingclass_doc = _fetch(reader, commands, errors, "get", "ingressclasses", optional=True)
    ing_doc = _fetch(reader, commands, errors, "get", "ingresses",
                     "--all-namespaces", optional=True)
    gwclass_doc = _fetch(reader, commands, errors, "get", "gatewayclasses",
                         optional=True)
    gw_doc = _fetch(reader, commands, errors, "get", "gateways", "--all-namespaces",
                    optional=True)
    node_items = _items(nodes_doc)
    if nodes_doc is not None and not node_items and isinstance(nodes_doc, dict):
        node_items = [nodes_doc]
    pod_items = _items(pods_doc)
    ds_items = _items(ds_doc)
    src_nodes = "kubectl get nodes -o json"
    src_pods = "kubectl get pods --all-namespaces -o json"
    src_ds = "kubectl get daemonsets --all-namespaces -o json"
    nodes = [_node_record(n, src_nodes) for n in node_items]
    pods = [_pod_record(p, src_pods) for p in pod_items]
    daemonsets = [_workload_record(d, src_ds, "DaemonSet") for d in ds_items]
    namespaces = [str((n.get("metadata") or {}).get("name") or n.get("name") or "")
                  for n in _items(namespaces_doc)] or \
                 [str(n.get("name") or "") for n in _items(namespaces_doc)]
    crds = []
    for c in _items(crd_doc):
        meta, spec = c.get("metadata") or {}, c.get("spec") or {}
        crds.append({"name": meta.get("name") or c.get("name") or "",
                     "group": spec.get("group") or c.get("group") or "",
                     "kind": spec.get("names", {}).get("kind") if isinstance(
                         spec.get("names"), dict) else c.get("kind") or "",
                     "source": "kubectl get crd -o json"})
    serviceaccounts = []
    for sa in _items(sa_doc):
        meta = sa.get("metadata") or {}
        serviceaccounts.append({
            "namespace": meta.get("namespace") or sa.get("namespace") or "default",
            "name": meta.get("name") or sa.get("name") or "",
            "annotations": meta.get("annotations") or {},
            "automount_service_account_token": sa.get("automountServiceAccountToken"),
            "source": "kubectl get serviceaccounts -A -o json",
        })
    storageclasses = [{"name": (x.get("metadata") or {}).get("name") or x.get("name") or "",
                       "provisioner": x.get("provisioner") or (x.get("spec") or {}).get("provisioner"),
                       "reclaim_policy": x.get("reclaimPolicy")
                       or (x.get("spec") or {}).get("reclaimPolicy")}
                      for x in _items(sc_doc)]
    csidrivers = [{"name": (x.get("metadata") or {}).get("name") or x.get("name") or "",
                   "driver": (x.get("spec") or {}).get("driver")}
                  for x in _items(csi_doc)]
    pvs = _items(pv_doc)
    pvcs = _items(pvc_doc)
    ingressclasses = _items(ingclass_doc)
    ingresses = _items(ing_doc)
    gatewayclasses = _items(gwclass_doc)
    gateways = _items(gw_doc)
    rbac: dict[str, bool | None] = {}
    for key, verb, resource, all_ns in _RBAC_CHECKS:
        try:
            rbac[key] = reader.can_i(verb, resource, all_namespaces=all_ns)
        except (InventoryError, OSError):
            rbac[key] = None
    # API Server 静态 Pod 参数（托管集群通常不可见 → 留空，判定为 unknown）
    apiserver_flags: dict[str, str] = {}
    for pod in pods:
        name = str(pod.get("name") or "")
        if "kube-apiserver" not in name and "apiserver" not in name:
            continue
        for c in pod.get("containers") or []:
            if "apiserver" in str(c.get("name") or "") or "apiserver" in str(c.get("image") or ""):
                apiserver_flags.update(_parse_flags(c.get("args") or []))
        if apiserver_flags:
            break
    # kubelet configz（best-effort；失败记 optional，不伪造 readOnlyPort）
    kubelet_config: dict = {}
    kubelet_ok = False
    if collect_kubelet_config:
        for node in nodes:
            node_name = str(node.get("name") or "")
            if not node_name:
                continue
            try:
                raw = reader.get_raw(f"/api/v1/nodes/{node_name}/proxy/configz")
                doc = json.loads(raw or "{}")
                cfg = doc.get("kubeletconfig") or doc.get("kubeletConfig") or doc
                if isinstance(cfg, dict) and cfg:
                    kubelet_config = cfg
                    kubelet_ok = True
                    break
            except (InventoryError, OSError, ValueError) as exc:
                errors.append({"command": f"kubectl get --raw /api/v1/nodes/{node_name}/proxy/configz",
                               "optional": True, "error": str(exc)[:300]})
    feature_gates: dict = {}
    metrics_ok = False
    try:
        metrics = reader.get_raw("/metrics")
        feature_gates = _feature_gates(metrics)
        metrics_ok = True
    except (InventoryError, OSError) as exc:
        errors.append({"command": "kubectl get --raw /metrics", "optional": True,
                       "error": str(exc)[:300]})
    coverage = {
        "nodes": nodes_doc is not None,
        "pods": pods_doc is not None,
        "daemonsets": ds_doc is not None,
        "crds": crd_doc is not None,
        "serviceaccounts": sa_doc is not None,
        "storage": sc_doc is not None and pv_doc is not None,
        "ingress": ing_doc is not None,
        "gateway": gw_doc is not None,
        "rbac": any(v is not None for v in rbac.values()),
        "kubelet_config": kubelet_ok,
        "apiserver_flags": bool(apiserver_flags),
        "metrics": metrics_ok,
        "components": pods_doc is not None or ds_doc is not None,
        "components_complete": pods_doc is not None and ds_doc is not None,
        "hardware": False,
    }
    source = {
        "mode": "live-kubectl",
        "label": "live-kubectl",
        "kubeconfig": str(kc),
        "context": context or kc_meta.get("context") or "",
        "kubectl": reader.kubectl[0] if reader.kubectl else "kubectl",
        "cluster": kc_meta.get("cluster") or "",
        "version": version,
        "server": kc_meta.get("server") or "",
    }
    collection = {
        "read_only": True,
        "allowed_verbs": ["get", "auth can-i"],
        "commands": reader.calls,
        "errors": errors,
        "started_at": now_iso(),
    }
    inv = _assemble(
        source=source, nodes=nodes, pods=pods, daemonsets=daemonsets,
        namespaces=namespaces, crds=crds, serviceaccounts=serviceaccounts,
        storageclasses=storageclasses, csidrivers=csidrivers, pvs=pvs, pvcs=pvcs,
        ingressclasses=ingressclasses, ingresses=ingresses,
        gatewayclasses=gatewayclasses, gateways=gateways, rbac=rbac,
        apiserver_flags=apiserver_flags, kubelet_config=kubelet_config,
        feature_gates=feature_gates, metrics_ok=metrics_ok, bmc=[], switches=[],
        probes=probes or {}, coverage=coverage, collection=collection,
    )
    if not nodes_doc and not version:
        raise InventoryError(
            "kubectl 采集失败：节点与 /version 均不可读。"
            + ("；".join(e["error"] for e in errors[:3]) if errors else "")
        )
    inv["collection"]["finished_at"] = now_iso()
    return normalize_inventory(inv)


# ====================================================================== snapshot / file


def _raw_version(raw: dict) -> str:
    cluster = raw.get("cluster") or {}
    if isinstance(cluster, dict) and cluster.get("version"):
        return str(cluster["version"])
    for key in ("k8s_version", "kubernetes_version", "version"):
        if isinstance(raw.get(key), str) and raw.get(key):
            return str(raw[key])
    apiserver = raw.get("apiserver") or {}
    if isinstance(apiserver, dict) and apiserver.get("version"):
        return str(apiserver["version"])
    return ""


def inventory_from_snapshot(raw: dict, source_path: str = "", probes: dict | None = None) -> dict:
    """把 K8s 对象快照 / pilot snapshot / 简化夹具归一为 inventory。"""
    if not isinstance(raw, dict):
        raise InventoryError("snapshot 根节点必须是 object")
    if isinstance(raw.get("snapshot"), dict):
        raw = raw["snapshot"]
    label = f"snapshot:{source_path}" if source_path else "snapshot"
    nodes_raw = raw.get("nodes")
    pods_raw = raw.get("pods")
    ds_raw = raw.get("daemonsets") or raw.get("daemon_sets")
    node_items = _items(nodes_raw) if isinstance(nodes_raw, (dict, list)) else []
    if isinstance(nodes_raw, dict) and not node_items and nodes_raw.get("name"):
        node_items = [nodes_raw]
    pod_items = _items(pods_raw) if isinstance(pods_raw, (dict, list)) else []
    ds_items = _items(ds_raw) if isinstance(ds_raw, (dict, list)) else []
    nodes = [_node_record(n, label) for n in node_items]
    pods = [_pod_record(p, label) for p in pod_items]
    daemonsets = [_workload_record(d, label, "DaemonSet") for d in ds_items]
    namespaces = raw.get("namespaces") or []
    if namespaces and isinstance(namespaces[0], dict):
        namespaces = [(n.get("metadata") or {}).get("name") or n.get("name") for n in namespaces]
    crds = []
    for c in _items(raw.get("crds") or raw.get("customresourcedefinitions")):
        meta = c.get("metadata") or {}
        spec = c.get("spec") or {}
        crds.append({"name": meta.get("name") or c.get("name") or "",
                     "group": spec.get("group") or c.get("group") or "",
                     "kind": (spec.get("names") or {}).get("kind") if isinstance(
                         spec.get("names"), dict) else c.get("kind") or "",
                     "source": label})
    serviceaccounts = []
    for sa in _items(raw.get("serviceaccounts") or raw.get("service_accounts")):
        meta = sa.get("metadata") or {}
        serviceaccounts.append({"namespace": meta.get("namespace") or sa.get("namespace") or "default",
                                "name": meta.get("name") or sa.get("name") or "",
                                "annotations": meta.get("annotations") or sa.get("annotations") or {},
                                "automount_service_account_token":
                                    sa.get("automountServiceAccountToken",
                                           sa.get("automount_service_account_token")),
                                "source": label})
    storageclasses = [{"name": (x.get("metadata") or {}).get("name") or x.get("name") or "",
                       "provisioner": x.get("provisioner") or (x.get("spec") or {}).get("provisioner"),
                       "reclaim_policy": x.get("reclaimPolicy")
                       or (x.get("spec") or {}).get("reclaimPolicy")}
                      for x in _items(raw.get("storageclasses"))]
    csidrivers = [{"name": (x.get("metadata") or {}).get("name") or x.get("name") or "",
                   "driver": (x.get("spec") or {}).get("driver")}
                  for x in _items(raw.get("csidrivers"))]
    pvs = _items(raw.get("pvs") or raw.get("persistentvolumes"))
    pvcs = _items(raw.get("pvcs") or raw.get("persistentvolumeclaims"))
    ingressclasses = _items(raw.get("ingressclasses"))
    ingresses = _items(raw.get("ingresses"))
    gatewayclasses = _items(raw.get("gatewayclasses"))
    gateways = _items(raw.get("gateways"))
    rbac: dict[str, bool | None] = {}
    cani = raw.get("cani") or []
    if isinstance(cani, list):
        allowed: set[str] = set()
        for item in cani:
            if isinstance(item, str):
                allowed.add(item.lower())
            elif isinstance(item, dict):
                for val in item.get("allowed") or []:
                    allowed.add(str(val).lower())
        for key, verb, resource, _ in _RBAC_CHECKS:
            target = f"{verb} {resource}".lower()
            rbac[key] = True if target in allowed or "*" in allowed else None
    apiserver_flags = dict((raw.get("apiserver") or {}).get("flags") or {})
    kubelet_config = dict((raw.get("kubelet") or {}).get("config") or {})
    if raw.get("kubelet", {}).get("read_only_port") is not None:
        kubelet_config.setdefault("readOnlyPort", raw["kubelet"]["read_only_port"])
    feature_gates = dict(raw.get("feature_gates") or {})
    coverage = {
        "nodes": nodes_raw is not None,
        "pods": pods_raw is not None,
        "daemonsets": ds_raw is not None,
        "crds": raw.get("crds") is not None,
        "serviceaccounts": raw.get("serviceaccounts") is not None,
        "storage": raw.get("storageclasses") is not None,
        "ingress": raw.get("ingresses") is not None,
        "gateway": raw.get("gatewayclasses") is not None,
        "rbac": bool(rbac),
        "kubelet_config": bool(kubelet_config),
        "apiserver_flags": bool(apiserver_flags),
        "metrics": bool(feature_gates),
        "components": pods_raw is not None or ds_raw is not None,
        "components_complete": pods_raw is not None and ds_raw is not None,
        "hardware": "bmc" in raw or "switches" in raw,
    }
    source = {
        "mode": "snapshot",
        "label": label,
        "path": source_path,
        "cluster": str((raw.get("cluster") or {}).get("name") or ""),
        "version": _raw_version(raw),
        "server": "",
        "provider": str((raw.get("cluster") or {}).get("provider") or ""),
    }
    inv = _assemble(
        source=source, nodes=nodes, pods=pods, daemonsets=daemonsets,
        namespaces=[str(x) for x in (namespaces or [])], crds=crds,
        serviceaccounts=serviceaccounts, storageclasses=storageclasses,
        csidrivers=csidrivers, pvs=pvs, pvcs=pvcs,
        ingressclasses=ingressclasses, ingresses=ingresses,
        gatewayclasses=gatewayclasses, gateways=gateways, rbac=rbac,
        apiserver_flags=apiserver_flags, kubelet_config=kubelet_config,
        feature_gates=feature_gates, metrics_ok=bool(feature_gates),
        bmc=[x for x in _list(raw.get("bmc")) if isinstance(x, dict)],
        switches=[x for x in _list(raw.get("switches")) if isinstance(x, dict)],
        probes=probes or raw.get("probes") or {}, coverage=coverage,
        collection={"read_only": True, "mode": "snapshot",
                    "source_path": source_path, "commands": [], "errors": [],
                    "started_at": now_iso(), "finished_at": now_iso()},
        collected_at=str(raw.get("collected_at") or now_iso()),
    )
    if raw.get("products"):
        inv["products"] = raw["products"]
    if raw.get("probes") and probes:
        inv["probes"] = {**raw.get("probes", {}), **probes}
    return normalize_inventory(inv)


def normalize_inventory(raw: dict | None) -> dict:
    """补齐 inventory schema 的默认结构；保留已有 facts/coverage/evidence。"""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise InventoryError("inventory 根节点必须是 object")
    # 识别原始 K8s 快照并转换
    if raw.get("schema") != SCHEMA and (
            ("nodes" in raw and ("pods" in raw or "services" in raw)
             and not isinstance(raw.get("facts"), dict))
            or ("kubelet" in raw and "apiserver" not in raw and "snapshot" in raw)
    ):
        return inventory_from_snapshot(raw)
    out = dict(raw)
    out["schema"] = SCHEMA
    if "collected_at" not in out:
        out["collected_at"] = now_iso() if raw else ""
    out.setdefault("source", {"mode": "file", "label": "inventory"})
    out.setdefault("cluster", {})
    for key in ("nodes", "namespaces", "pods", "daemonsets", "components",
                "serviceaccounts", "crds", "bmc", "switches"):
        out[key] = list(out.get(key) or [])
    for key in ("cni", "ingress", "gateway", "gpu", "ray", "kuberay", "lws",
                "storage", "cloud", "rbac", "feature_gates", "apiserver", "kubelet",
                "probes", "facts", "fact_sources", "coverage", "collection"):
        if not isinstance(out.get(key), dict):
            out[key] = {}
    out["coverage"].setdefault("components", bool(out["pods"] or out["daemonsets"]))
    out["coverage"].setdefault("components_complete",
                               bool(out["coverage"].get("pods")
                                    and out["coverage"].get("daemonsets")))
    out["coverage"].setdefault("hardware", bool(out["bmc"] or out["switches"]))
    if not out.get("evidence"):
        out["evidence"] = []
    return out


def load_inventory(path: str | Path) -> dict:
    """读取 inventory / K8s 快照文件（支持目录：优先 inventory.json）。"""
    p = Path(path)
    if p.is_dir():
        candidate = p / "inventory.json"
        if candidate.is_file():
            p = candidate
        else:
            files = sorted(x for x in p.glob("*.json")
                           if x.name not in ("ground-truth.json", "defenses.json"))
            if not files:
                raise InventoryError(f"目录中没有 JSON 快照：{p}")
            p = files[0]
    if not p.is_file():
        raise InventoryError(f"inventory 不存在：{p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise InventoryError(f"{p}: JSON 非法：{exc}") from exc
    if not isinstance(raw, dict):
        raise InventoryError(f"{p}: 根节点不是 object")
    # 带 snapshot 包装的 pilot 文件
    if isinstance(raw.get("snapshot"), dict):
        raw = raw["snapshot"]
        inv = inventory_from_snapshot(raw, str(p))
    elif raw.get("schema") == SCHEMA:
        inv = normalize_inventory(raw)
    else:
        inv = inventory_from_snapshot(raw, str(p))
    inv["path"] = str(p)
    return inv


def save_inventory(inventory: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    inventory["path"] = str(p)
    p.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def load_probes(path: str | Path | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise InventoryError(f"probes 文件不存在：{p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise InventoryError(f"{p}: JSON 非法：{exc}") from exc
    if not isinstance(raw, dict):
        raise InventoryError(f"{p}: probes 根节点必须是 object")
    return raw


def merge_probes(inventory: dict, probes: dict, *, source: str = "") -> dict:
    inv = normalize_inventory(inventory)
    if not probes:
        return inv
    merged = dict(inv.get("probes") or {})
    merged.update(probes)
    inv["probes"] = merged
    label = f"probes:{source}" if source else "probes"
    if isinstance(inv.get("source"), dict):
        inv["source"].setdefault("probes", label)
    for key, val in probes.items():
        inv["evidence"].append({"field": f"probes.{key}", "value": val, "source": label})
        inv.setdefault("fact_sources", {})[f"probes.{key}"] = label
        inv.setdefault("facts", {})[f"probes.{key}"] = val
        if key == "imds_reachable":
            inv.setdefault("cloud", {})["imds_reachable"] = val
    return inv


def default_inventory_path(home: str | Path | None = None) -> Path | None:
    """自动发现 inventory.json：显式 home → reports/assess → 当前目录。"""
    roots = []
    if home:
        roots.append(Path(home))
    roots.append(Path("."))
    for root in roots:
        for rel in ("inventory.json", "reports/assess/inventory.json",
                    "assess/inventory.json"):
            p = root / rel
            if p.is_file():
                return p
    return None


def inventory_summary(inv: dict) -> dict:
    return {
        "schema": inv.get("schema"),
        "path": inv.get("path") or "",
        "collected_at": inv.get("collected_at") or "",
        "source": inv.get("source"),
        "cluster": inv.get("cluster") or {},
        "counts": {
            "nodes": len(inv.get("nodes") or []),
            "pods": len(inv.get("pods") or []),
            "daemonsets": len(inv.get("daemonsets") or []),
            "components": len(inv.get("components") or []),
            "crds": len(inv.get("crds") or []),
            "serviceaccounts": len(inv.get("serviceaccounts") or []),
            "evidence": len(inv.get("evidence") or []),
        },
        "coverage": inv.get("coverage") or {},
        "errors": len((inv.get("collection") or {}).get("errors") or []),
    }
