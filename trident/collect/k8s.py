# -*- coding: utf-8 -*-
"""Read-only Kubernetes inventory collection.

Only ``kubectl get`` is ever issued.  No create/apply/patch/delete/exec/
port-forward verbs exist in this module, and the command is built as an argv
list (never ``shell=True``).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

# (kubectl resource, namespaced?)
RESOURCES: tuple[tuple[str, bool], ...] = (
    ("nodes", False),
    ("namespaces", False),
    ("pods", True),
    ("deployments", True),
    ("daemonsets", True),
    ("statefulsets", True),
    ("jobs", True),
    ("cronjobs", True),
    ("services", True),
    ("serviceaccounts", True),
    ("roles", True),
    ("clusterroles", False),
    ("rolebindings", True),
    ("clusterrolebindings", False),
    ("networkpolicies", True),
    ("persistentvolumes", False),
    ("persistentvolumeclaims", True),
    ("storageclasses", False),
    ("csidrivers", False),
    ("apiservices", False),
    ("validatingwebhookconfigurations", False),
    ("mutatingwebhookconfigurations", False),
    ("runtimeclasses", False),
    ("ingresses", True),
    ("rayclusters.ray.io", True),
    ("rayjobs.ray.io", True),
    ("leaderworkersets.leaderworkerset.x-k8s.io", True),
    ("pytorchjobs.kubeflow.org", True),
    ("inferenceservices.serving.kserve.io", True),
    ("servingruntimes.serving.kserve.io", True),
    ("horizontalpodautoscalers.autoscaling", True),
)

# Immutable read-only contract used by tests and reviewers.
ALLOWED_VERBS = frozenset({"get"})


def _kubectl_base(kubectl: str, kubeconfig: str | None, context: str | None,
                  request_timeout: str) -> list[str]:
    cmd = [kubectl]
    if kubeconfig:
        cmd += ["--kubeconfig", str(kubeconfig)]
    if context:
        cmd += ["--context", str(context)]
    cmd += ["--request-timeout", request_timeout]
    return cmd


def _flatten(item: dict, resource: str) -> dict:
    metadata = item.get("metadata") or {}
    spec = item.get("spec") or {}
    status = item.get("status") or {}
    template = (((spec.get("template") or {}).get("spec")) or {})
    containers = template.get("containers") or spec.get("containers") or []
    images = sorted({str(c.get("image")) for c in containers
                     if isinstance(c, dict) and c.get("image")})
    labels = metadata.get("labels") or {}
    annotations = metadata.get("annotations") or {}
    return {
        "resource": resource,
        "apiVersion": item.get("apiVersion", ""),
        "kind": item.get("kind", ""),
        "namespace": metadata.get("namespace", ""),
        "name": metadata.get("name", ""),
        "labels": {str(k): str(v) for k, v in labels.items()},
        "annotations": {str(k): str(v) for k, v in annotations.items()},
        "hostNetwork": bool(template.get("hostNetwork") or spec.get("hostNetwork")),
        "runtimeClassName": template.get("runtimeClassName") or spec.get("runtimeClassName") or "",
        "serviceAccountName": template.get("serviceAccountName") or spec.get("serviceAccountName") or "",
        "nodeName": spec.get("nodeName") or "",
        "images": images,
        "status": status.get("phase") or status.get("ready") or "",
        "capacity": status.get("capacity") or {},
        "nodeInfo": status.get("nodeInfo") or {},
        "source": "collection:k8s",
    }


def collect(kubeconfig: str | None = None, context: str | None = None,
            kubectl: str = "kubectl", timeout: int = 45,
            request_timeout: str = "20s") -> dict:
    """Collect a read-only snapshot.  Returns ``schema``-stable JSON."""
    errors: list[str] = []
    objects: list[dict] = []
    resources: list[dict] = []
    base = _kubectl_base(kubectl, kubeconfig, context, request_timeout)
    for resource, namespaced in RESOURCES:
        cmd = base + ["get", resource]
        if namespaced:
            cmd.append("--all-namespaces")
        cmd += ["--output=json"]
        assert "get" in cmd[:5] and not any(v in cmd for v in ("apply", "delete", "exec", "patch"))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{resource}: {type(exc).__name__}: {exc}")
            resources.append({"resource": resource, "status": "unavailable"})
            continue
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip().splitlines()
            errors.append(f"{resource}: rc={proc.returncode} {msg[-1] if msg else ''}")
            resources.append({"resource": resource, "status": "unavailable",
                              "error": msg[-1] if msg else ""})
            continue
        try:
            doc = json.loads(proc.stdout or "{}")
        except ValueError as exc:
            errors.append(f"{resource}: invalid JSON: {exc}")
            resources.append({"resource": resource, "status": "unavailable"})
            continue
        items = doc.get("items")
        if items is None:
            items = [doc] if doc.get("kind") else []
        kept = 0
        for item in items:
            if isinstance(item, dict):
                objects.append(_flatten(item, resource))
                kept += 1
        resources.append({"resource": resource, "status": "ok", "items": kept})
    ok = sum(1 for r in resources if r["status"] == "ok")
    status = "ok" if ok == len(resources) else ("unavailable" if ok == 0 else "partial")
    return {
        "schema": "trident-k8s-collection-v1",
        "status": status,
        "verb": "get",
        "allowed_verbs": sorted(ALLOWED_VERBS),
        "kubectl": kubectl,
        "context": context or "",
        "objects": objects,
        "resources": resources,
        "errors": errors[:50],
    }
