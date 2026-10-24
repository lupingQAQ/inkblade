"""Collect a real Trident recon snapshot from a live Kubernetes API.

The recon modules consume a normalized dict (``params.snapshot``) with keys such
as ``pods``/``services``/``networkpolicies``/``clusterroles``. This script builds
that dict from ``kubectl get -o json`` against a *real* cluster (here: single-node
k3s under QEMU TCG) instead of the static fixtures in lab/fixtures/recon.

    python lab/qemu-k3s/collect_snapshot.py \
        --kubectl lab/qemu-k3s/kubectl.exe \
        --kubeconfig lab/qemu-k3s/out/k3s.yaml \
        --out reports/samples/real-cluster/snapshot.json

Everything is read-only (``kubectl get``); no cluster mutation.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _kubectl(kubectl: str, kubeconfig: str, *args: str) -> dict:
    cmd = [kubectl]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    cmd += list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"kubectl {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _items(doc: dict) -> list[dict]:
    return doc.get("items", []) if isinstance(doc, dict) else []


def normalize_pods(doc: dict) -> list[dict]:
    pods = []
    for p in _items(doc):
        meta, spec, status = p.get("metadata", {}), p.get("spec", {}), p.get("status", {})
        containers = []
        for c in spec.get("containers", []):
            containers.append({
                "name": c.get("name"),
                "image": c.get("image"),
                "securityContext": c.get("securityContext", {}),
                "volumeMounts": c.get("volumeMounts", []),
                "command": c.get("command", []),
                "args": c.get("args", []),
            })
        vols = []
        for v in spec.get("volumes", []):
            vols.append({"name": v.get("name"), "hostPath": v.get("hostPath"),
                         "configMap": v.get("configMap"), "secret": v.get("secret"),
                         "emptyDir": v.get("emptyDir"), "persistentVolumeClaim": v.get("persistentVolumeClaim")})
        pods.append({
            "namespace": meta.get("namespace", "default"),
            "name": meta.get("name"),
            "labels": meta.get("labels", {}),
            "nodeName": spec.get("nodeName"),
            "hostNetwork": bool(spec.get("hostNetwork")),
            "hostPID": bool(spec.get("hostPID")),
            "hostIPC": bool(spec.get("hostIPC")),
            "serviceAccountName": spec.get("serviceAccountName"),
            "phase": status.get("phase"),
            "podIP": status.get("podIP"),
            "containers": containers,
            "volumes": vols,
            "tolerations": spec.get("tolerations", []),
        })
    return pods


def normalize_services(doc: dict) -> list[dict]:
    out = []
    for s in _items(doc):
        meta, spec = s.get("metadata", {}), s.get("spec", {})
        out.append({
            "namespace": meta.get("namespace", "default"),
            "name": meta.get("name"),
            "type": spec.get("type", "ClusterIP"),
            "clusterIP": spec.get("clusterIP"),
            "externalIPs": spec.get("externalIPs") or [],
            "selector": spec.get("selector") or {},
            "labels": meta.get("labels", {}),
            "ports": [
                {"name": p.get("name"), "port": p.get("port"), "targetPort": p.get("targetPort"),
                 "nodePort": p.get("nodePort"), "protocol": p.get("protocol", "TCP")}
                for p in spec.get("ports", [])
            ],
        })
    return out


def normalize_netpols(doc: dict) -> list[dict]:
    out = []
    for n in _items(doc):
        meta, spec = n.get("metadata", {}), n.get("spec", {})
        out.append({
            "namespace": meta.get("namespace", "default"),
            "name": meta.get("name"),
            "podSelector": spec.get("podSelector") or {},
            "policyTypes": spec.get("policyTypes", []),
            "ingress": spec.get("ingress") or [],
            "egress": spec.get("egress") or [],
        })
    return out


def normalize_roles(doc: dict, cluster_scoped: bool) -> list[dict]:
    out = []
    for r in _items(doc):
        meta = r.get("metadata", {})
        out.append({
            "namespace": None if cluster_scoped else meta.get("namespace", "default"),
            "name": meta.get("name"),
            "rules": r.get("rules", []),
        })
    return out


def normalize_bindings(doc: dict, cluster_scoped: bool) -> list[dict]:
    out = []
    for b in _items(doc):
        meta, ref = b.get("metadata", {}), b.get("roleRef", {})
        out.append({
            "namespace": None if cluster_scoped else meta.get("namespace", "default"),
            "name": meta.get("name"),
            "role": ref.get("name"),
            "roleKind": ref.get("kind"),
            "subjects": b.get("subjects", []),
        })
    return out


def normalize_ingresses(doc: dict) -> list[dict]:
    out = []
    for ing in _items(doc):
        meta, spec = ing.get("metadata", {}), ing.get("spec", {})
        for rule in spec.get("rules", []) or [{"host": None}]:
            for path in rule.get("http", {}).get("paths", []) or [{}]:
                svc = path.get("backend", {}).get("service", {})
                out.append({
                    "namespace": meta.get("namespace", "default"),
                    "name": meta.get("name"),
                    "host": rule.get("host") or "*",
                    "path": path.get("path", "/"),
                    "service": svc.get("name"),
                    "port": (svc.get("port") or {}).get("number"),
                })
    return out


def normalize_nodes(doc: dict) -> list[dict]:
    out = []
    for n in _items(doc):
        meta, status = n.get("metadata", {}), n.get("status", {})
        out.append({
            "name": meta.get("name"),
            "labels": meta.get("labels", {}),
            "capacity": status.get("capacity", {}),
            "conditions": [c.get("type") for c in status.get("conditions", []) if c.get("status") == "True"],
        })
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="build a Trident recon snapshot from a live cluster")
    ap.add_argument("--kubectl", default="kubectl")
    ap.add_argument("--kubeconfig", default="")
    ap.add_argument("--namespace", default="", help="limit namespaced objects to one namespace (default: all)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    ns = ["-n", args.namespace] if args.namespace else ["--all-namespaces"]
    get = lambda *a: _kubectl(args.kubectl, args.kubeconfig, "get", *a, "-o", "json")  # noqa: E731

    snapshot = {
        "source": "live-kubectl",
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "context": "k3s-single-node-qemu-tcg",
        "pods": normalize_pods(get("pods", *ns)),
        "services": normalize_services(get("services", *ns)),
        "networkpolicies": normalize_netpols(get("networkpolicies", *ns)),
        "roles": normalize_roles(get("roles", *ns), cluster_scoped=False),
        "rolebindings": normalize_bindings(get("rolebindings", *ns), cluster_scoped=False),
        "clusterroles": normalize_roles(get("clusterroles"), cluster_scoped=True),
        "clusterrolebindings": normalize_bindings(get("clusterrolebindings"), cluster_scoped=True),
        "ingresses": normalize_ingresses(get("ingresses", *ns)),
        "nodes": normalize_nodes(get("nodes")),
        "serviceaccounts": [
            {"namespace": i.get("metadata", {}).get("namespace", "default"),
             "name": i.get("metadata", {}).get("name"),
             "secrets": [s.get("name") for s in i.get("secrets", [])]}
            for i in _items(get("serviceaccounts", *ns))
        ],
        "cani": [],
        "provenance": {
            "tool": "kubectl",
            "note": "each section comes from `kubectl get <resource> -o json`; no fixtures were merged",
        },
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, ensure_ascii=False, indent=1), encoding="utf-8")
    counts = {k: len(v) for k, v in snapshot.items() if isinstance(v, list)}
    print(f"[snapshot] wrote {out} :: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
