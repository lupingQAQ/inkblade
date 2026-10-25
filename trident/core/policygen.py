# -*- coding: utf-8 -*-
"""规则目标生成（CM-25/26/27/28）：Tetragon / KubeArmor / Kyverno CEL+verifyImages /
存量资源 background 合规覆盖矩阵。

- 输入是 finding/控制目标，输出是**声明式策略文档**（dict；可用 ``to_yaml`` 渲染）；
- 不依赖集群、不执行策略；所有字段来自本仓独立编写的模板；
- Tetragon：sys_execve + matchBinaries + Post 动作；
- KubeArmor：file/network/capabilities 三类 LSM 阻断语义；
- Kyverno：CEL 校验（runAsNonRoot/privileged/hostPath）+ verifyImages（keyless）；
- background：把策略匹配到存量对象，输出 covered/gaps 矩阵（CM-28）。
"""

from __future__ import annotations

from typing import Any

from .yamlish import dump as yaml_dump


def tetragon_policy(name: str = "trident-shell-exec", *,
                    binary_values: list[str] | None = None, namespace: str = "",
                    action: str = "Post") -> dict:
    if action not in ("Post", "Signal", "Override", "NoOp"):
        raise ValueError(f"未知 Tetragon action {action!r}")
    values = binary_values or ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    doc = {
        "apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicy",
        "metadata": {"name": name, **({"namespace": namespace} if namespace else {})},
        "spec": {"kprobes": [{
            "call": "sys_execve", "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{"matchBinaries": [{"operator": "In", "values": values}],
                           "matchActions": [{"action": action}]}],
        }]},
    }
    return doc


def kubearmor_policy(name: str = "trident-deny-shell", *, namespace: str = "default",
                     match_labels: dict | None = None, file_paths: list[str] | None = None,
                     network_protocols: list[str] | None = None,
                     capabilities: list[str] | None = None,
                     action: str = "Block", severity: int = 5) -> dict:
    if action not in ("Block", "Audit", "Allow"):
        raise ValueError(f"未知 KubeArmor action {action!r}")
    spec: dict[str, Any] = {
        "selector": {"matchLabels": dict(match_labels or {"app": "ml-workload"})},
        "action": action, "severity": max(1, min(int(severity), 10)),
    }
    if file_paths:
        spec["file"] = {"matchPaths": list(file_paths)}
    if network_protocols:
        spec["network"] = {"matchProtocols": [{"protocol": p} for p in network_protocols]}
    if capabilities:
        spec["capabilities"] = {"matchCapabilities": [{"capability": c} for c in capabilities]}
    if not any(k in spec for k in ("file", "network", "capabilities")):
        spec["file"] = {"matchPaths": ["/bin/sh", "/bin/bash"]}
    return {"apiVersion": "security.kubearmor.com/v1", "kind": "KubeArmorPolicy",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def kyverno_policy(name: str = "trident-pod-hardening", *,
                   cel_expressions: list[str] | None = None,
                   image_references: list[str] | None = None,
                   attestor_subject: str = "https://kubernetes.io/namespaces/*/serviceaccounts/*",
                   attestor_issuer: str = "https://token.actions.githubusercontent.com") -> dict:
    expressions = cel_expressions or [
        "object.spec.containers.all(c, c.securityContext.runAsNonRoot == true)",
        "object.spec.containers.all(c, !has(c.securityContext.privileged) || c.securityContext.privileged == false)",
        "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))",
    ]
    rules = [{
        "name": "require-pod-hardening",
        "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
        "validate": {"cel": {"expressions": expressions}},
    }]
    rules.append({
        "name": "verify-images",
        "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
        "verifyImages": [{
            "imageReferences": list(image_references or ["registry.local/*"]),
            "attestors": [{"entries": [{"keyless": {"subject": attestor_subject,
                                                    "issuer": attestor_issuer}}]}],
        }],
    })
    return {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
            "metadata": {"name": name}, "spec": {"rules": rules}}


def background_coverage(objects: list[dict], policies: list[dict]) -> dict:
    """策略 × 存量对象覆盖矩阵；gaps=未命中任何策略的对象。"""
    matrix = []
    for obj in objects or []:
        kind = str(obj.get("kind") or "")
        ns = str(obj.get("namespace") or "")
        labels = obj.get("labels") or {}
        matched = []
        for pol in policies or []:
            kinds = pol.get("kinds") or []
            if kinds and "*" not in kinds and kind not in kinds:
                continue
            nss = pol.get("namespaces") or []
            if nss and ns not in nss:
                continue
            need = pol.get("labels") or {}
            if any(labels.get(k) != v for k, v in need.items()):
                continue
            matched.append(pol.get("id") or pol.get("name") or "policy")
        matrix.append({"kind": kind, "name": obj.get("name", ""), "namespace": ns,
                       "labels": labels, "covered_by": matched,
                       "covered": bool(matched)})
    gaps = [m for m in matrix if not m["covered"]]
    return {"objects": len(matrix), "policies": len(policies or []),
            "covered": len(matrix) - len(gaps), "gap_count": len(gaps),
            "matrix": matrix, "gaps": gaps,
            "ratio": round((len(matrix) - len(gaps)) / len(matrix), 3) if matrix else 0.0}


def generate_all(findings: list[dict] | None = None, *,
                 namespace: str = "default") -> dict:
    findings = findings or []
    names = sorted({str(f.get("step_key") or "").replace("-", "")[:24] for f in findings
                    if f.get("step_key")})
    suffix = ("-" + names[0]) if names else ""
    tetragon = tetragon_policy(f"trident-shell-exec{suffix}"[:63], namespace=namespace)
    kubearmor = kubearmor_policy(f"trident-deny-shell{suffix}"[:63], namespace=namespace)
    kyverno = kyverno_policy(f"trident-pod-hardening{suffix}"[:63])
    coverage = background_coverage(
        [{"kind": "Pod", "name": "ml-training-0", "namespace": namespace,
          "labels": {"app": "ml-workload"}},
         {"kind": "Pod", "name": "unlabelled-0", "namespace": namespace, "labels": {}},
         {"kind": "Deployment", "name": "ml-api", "namespace": namespace,
          "labels": {"app": "ml-workload"}}],
        [{"id": "kubearmor-shell", "kinds": ["Pod"], "namespaces": [namespace],
          "labels": {"app": "ml-workload"}},
         {"id": "tetragon-exec", "kinds": ["Pod"], "namespaces": [namespace]}])
    return {"tetragon": tetragon, "kubearmor": kubearmor, "kyverno": kyverno,
            "coverage": coverage, "generated_from_findings": len(findings)}


def to_yaml(doc: dict) -> str:
    return yaml_dump(doc)
