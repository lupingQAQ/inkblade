#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Native Rust-probe verification for every template (Linux guest over SSH).

Transport: ``ssh root@guest /tmp/inkblade-probe run --stdio`` (authenticated
framed protocol). The controller lowers each canonical template, runs it in
``vulnerable`` and ``fixed`` mock states, folds evidence, and writes
``reports/probe-coverage/evidence.json`` with ``runtime=rust``.

The guest is the QEMU TCG Alpine lab (see docs/REAL-CLUSTER-VERIFICATION.md);
the mock HTTP range runs on the host and is reached at 10.0.2.2.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lab"))

from inkblade.tpl.lower import compile_template, fold_result
from inkblade.tpl.schema import load_template
from lab.probe_native import KEY, PORT, SSHProbe, ssh_run
from lab.template_range import Range

MODULES = ROOT / "inkblade" / "modules"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"
NATIVE = ROOT / "reports" / "probe-coverage" / "evidence-native.json"
BINARY = "/tmp/inkblade-probe"
BINARY_SHA = "7348deb0368c4d85d1cb2daef80a1dbe1c1f331c97544326b5b27aaf304f5f21"
SOURCE_COMMIT = "bb58f9f"

RICH = {
    "version": "0.6.9", "deployed": True, "ok": True, "found": True,
    "mode": "vulnerable", "marker": "INKBLADE-BENIGN", "tenant": "tenant-b",
    "items": [{"name": "lab-item", "kind": "Pod", "namespace": "default"}],
    "pods": [{"metadata": {"name": "lab-pod", "namespace": "default"},
              "spec": {"containers": [{"image": "lab:1", "env": []}],
                       "hostNetwork": True, "volumes": [{"hostPath": {"path": "/"}}]},
              "status": {"phase": "Running"}, "name": "lab-pod", "namespace": "default"}],
    "nodes": [{"name": "node-1", "kubelet": {"anonymousAuth": True,
                                             "authorizationMode": "AlwaysAllow",
                                             "readOnlyPort": 10255}, "status": "Ready"}],
    "roles": [{"name": "lab-role", "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
    "clusterroles": [{"name": "lab-cluster-role", "rules": [{"verbs": ["escalate"],
                                                            "resources": ["roles"]}]}],
    "clusterrolebindings": [{"name": "lab-binding", "roleRef": {"name": "cluster-admin"}}],
    "daemonsets": [{"name": "nvidia-driver", "namespace": "gpu-operator",
                    "privileged": True, "hostPath": ["/dev"], "image": "nvidia/driver",
                    "serviceAccount": "gpu-operator"},
                   {"name": "calico-node", "namespace": "kube-system",
                    "privileged": True, "hostPath": ["/opt/cni/bin"]}],
    "deployments": [{"name": "argocd-server", "namespace": "argocd",
                     "clusterAdmin": True, "secretRead": True}],
    "secrets": [{"name": "regcred", "namespace": "default",
                 "type": "kubernetes.io/dockerconfigjson", "keys": ["auth"]}],
    "services": [{"name": "lab-svc", "namespace": "default", "type": "NodePort"}],
    "certificatesigningrequests": [{"name": "lab-csr", "status": "Pending",
                                    "subject": {"organization": ["system:masters"],
                                                "commonName": "system:admin"}}],
    "etcd": [{"name": "etcd-0", "tls": False, "clientCertAuth": False}],
    "kubelets": [{"node": "node-1", "port": 10250, "anonymousAuth": True}],
    "apiservices": [{"name": "v1beta1.lab", "insecureSkipTLSVerify": True, "service": None}],
    "customresourcedefinitions": [{"name": "rayclusters.ray.io", "conversion": {
        "strategy": "Webhook", "webhook": {"clientConfig": {"caBundle": ""}}}}],
    "mutatingwebhookconfigurations": [{"name": "policy", "failurePolicy": "Ignore",
                                       "clientConfig": {"url": "http://insecure"},
                                       "namespaceSelector": None}],
    "rules": [{"id": "lab-rule", "enabled": True}],
    "kernel_modules": ["elkeid", "smith", "falco"],
    "agent_status": ["online"],
    "products": ["falco", "tetragon", "kubearmor", "kyverno"],
    "checks": [{"id": "lab-check", "status": "fail"}],
    "upstreams": [{"provider": "openai", "api_key": "sk-live-abcdef123456",
                   "api_base": "http://upstream.mock/v1"}],
    "master_key": "sk-master", "scope": "global", "enforced": False,
    "bucket_by": "x-forwarded-for", "hit": True, "entry": {"tenant": "tenant-b"},
    "entries": [{"tenant": "tenant-b", "prompt": "card 4111 1111 1111 1111",
                 "authorization": "Bearer MOCK-tenant-b-key"}],
    "training": {"world_size": 512},
}

PRIVESC_FIXTURE = {
    "rbac-escalate-verb": "rbac.json", "rbac-bind-verb": "rbac.json",
    "impersonate-abuse": "rbac.json", "sa-token-request": "rbac.json",
    "csr-approve": "rbac.json", "admission-webhook-write": "admission.json",
    "apiservice-hijack": "admission.json", "crd-conversion-webhook": "admission.json",
    "kubelet-10250-exec": "node.json", "etcd-direct-access": "node.json",
    "image-pull-secret-theft": "credentials.json", "gitops-secret-read": "platform.json",
    "gpu-operator-driver-escape": "platform.json", "cni-plugin-exec": "platform.json",
    "csi-node-plugin-escape": "platform.json",
}


def _sha(value) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_guest(remote: str, text: str) -> None:
    proc = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes",
                           "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR",
                           "-i", KEY, "-p", str(PORT), "root@127.0.0.1",
                           f"cat > {remote}"], input=text.encode("utf-8"),
                          capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:300])


def _guest_path(host_path: str) -> str:
    text = str(host_path).replace("\\", "/")
    marker = "lab/fixtures"
    if marker in text:
        return "/tmp/inkblade-fx/lab/fixtures" + text.split(marker, 1)[1]
    marker = "lab/defense-deploy"
    if marker in text:
        return "/tmp/inkblade-fx/lab/defense-deploy" + text.split(marker, 1)[1]
    return "/tmp/inkblade-fx/rich.json"


def _defense(product: str, state: str) -> str:
    path = f"/tmp/inkblade-fx/lab/defense-deploy/fixtures/{product}-{state}.json"
    return path


def _params(template: dict, key: str, target: str, state: str) -> dict:
    params: dict = {"mode": "probe-only"}
    rich = "rich.json" if state == "vulnerable" else "empty.json"
    for name, spec in (template.get("inputs") or {}).items():
        source = str(spec.get("from") or "")
        if "target" in source or name == "target":
            params[name] = target
            continue
        if name == "deploy_snapshot" or "deploy_snapshot" in source:
            product = key.replace("defense-bypass-", "")
            desired = "deployed" if state == "vulnerable" else "absent"
            params[name] = _defense(product, desired)
            continue
        if key in PRIVESC_FIXTURE and name in ("fixture", "snapshot"):
            params[name] = f"/tmp/inkblade-fx/lab/fixtures/privesc/{PRIVESC_FIXTURE[key]}"
            continue
        params[name] = f"/tmp/inkblade-fx/{rich}"
    return params


def _scenarios() -> dict:
    return {"vulnerable": {"*": {"status": 200, "json": RICH}},
            "fixed": {"*": {"status": 403, "json": {"error": "denied"}}}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keys", nargs="*", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--base-url", default="", help="guest-reachable target URL")
    args = parser.parse_args()

    # guest fixtures
    _write_guest("/tmp/inkblade-fx/rich.json", json.dumps(RICH, ensure_ascii=False))
    _write_guest("/tmp/inkblade-fx/empty.json", "{}")
    print("guest fixtures ready", flush=True)

    scenarios = _scenarios()
    range_obj = Range(scenarios, host="127.0.0.1").start()
    target = args.base_url or f"http://10.0.2.2:{range_obj._http.server_address[1]}"
    print("target", target, "binary", BINARY_SHA[:12], flush=True)
    probe = SSHProbe()
    entries: dict = {}
    failures: list[str] = []
    modules = sorted(p for p in MODULES.iterdir()
                     if p.is_dir() and (p / "template.json").is_file())
    if args.keys:
        modules = [p for p in modules if p.name in args.keys]
    if args.limit:
        modules = modules[: args.limit]
    started = time.time()
    try:
        range_obj.set_profile("vulnerable")
        for index, module_dir in enumerate(modules, 1):
            key = module_dir.name
            raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
            if str(raw.get("execution") or "template") != "template":
                continue
            try:
                template = load_template(module_dir, module_meta=raw)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{key}: template load: {exc}")
                continue
            results = {}
            error = ""
            for state in ("vulnerable", "fixed"):
                range_obj.set_profile(state)
                params = _params(template, key, target, state)
                try:
                    results[state] = probe.run(template, params,
                                               {"marker": "INKBLADE-LAB"})
                except Exception as exc:  # noqa: BLE001
                    error = f"{state}: {type(exc).__name__}: {str(exc)[:400]}"
                    results[state] = None
            positive = results.get("vulnerable") or {}
            negative = results.get("fixed") or {}
            ok = bool(positive) and positive.get("status") != "error"
            compilation = None
            try:
                compilation = compile_template(template, _params(template, key, target, "vulnerable"),
                                               {"marker": "INKBLADE-LAB"})
            except Exception:
                pass
            entries[key] = {
                "tested": ok,
                "mode": "vulnerable/fixed",
                "runtime": "rust",
                "binary_sha256": BINARY_SHA,
                "source_commit": SOURCE_COMMIT,
                "findings_positive": len((positive or {}).get("findings") or []),
                "findings_negative": len((negative or {}).get("findings") or []),
                "steps": len((positive or {}).get("steps") or []),
                "native_ready": bool(compilation and compilation.native_ready),
                "evidence": _sha({"positive": positive, "negative": negative}),
                "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "note": "native probe over SSH (QEMU TCG Alpine guest)",
                "error": error,
            }
            if key.startswith("defense-bypass-"):
                for artifact in (positive or {}).get("artifacts") or []:
                    if str(artifact.get("name", "")).endswith("-matrix.json"):
                        try:
                            matrix = json.loads(artifact.get("text") or "{}")
                            entries[key]["defense_matrix"] = {
                                "detected": len(matrix.get("detected") or []),
                                "blindspots": len(matrix.get("blindspots") or []),
                                "hardening": len(matrix.get("hardening") or []),
                            }
                        except ValueError:
                            pass
            if not ok:
                failures.append(f"{key}: {error or positive.get('error')}")
            if index % 10 == 0 or index == len(modules):
                print(f"progress {index}/{len(modules)} elapsed={int(time.time()-started)}s "
                      f"failures={len(failures)}", flush=True)
    finally:
        range_obj.stop()

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    try:
        doc = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = {"schema": "inkblade-probe-coverage-evidence-v1", "entries": {}}
    doc.setdefault("entries", {}).update(entries)
    doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc["native_runtime"] = {
        "binary": BINARY, "sha256": BINARY_SHA, "source_commit": SOURCE_COMMIT,
        "transport": "ssh stdio framed protocol", "target": target,
        "tested_at": doc["updated_at"],
    }
    EVIDENCE.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    NATIVE.write_text(json.dumps({"schema": "inkblade-native-evidence-v1",
                                  "binary_sha256": BINARY_SHA,
                                  "source_commit": SOURCE_COMMIT,
                                  "entries": entries, "failures": failures},
                                 ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    print(f"done tested={sum(1 for e in entries.values() if e['tested'])}/{len(entries)} "
          f"failures={len(failures)} in {int(time.time()-started)}s")
    for failure in failures[:20]:
        print("FAIL", failure)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
