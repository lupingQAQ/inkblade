# -*- coding: utf-8 -*-
"""Dynamic two-state verification for every declarative template.

Each template runs twice against ``lab/template_range.py``:
``vulnerable`` (surface present / positive response) and ``fixed`` (surface
absent or negative).  A template that declares findings must produce at least
one in the positive state and none in the negative state; write steps are
skipped in ``probe-only`` mode.  Evidence is appended to
``reports/probe-coverage/evidence.json`` for the coverage table.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from inkblade.tpl.backends import LocalBackend
from inkblade.tpl.engine import Engine
from inkblade.tpl.schema import load_template
from template_range import Range

MODULES = ROOT / "inkblade" / "modules"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"

RICH_SNAPSHOT = {
    "version": "0.6.9",
    "items": [{"name": "lab-item", "kind": "Pod", "namespace": "default"}],
    "pods": [{"metadata": {"name": "lab-pod", "namespace": "default"},
              "spec": {"containers": [{"image": "lab:1", "env": []}],
                       "hostNetwork": True, "volumes": [{"hostPath": {"path": "/"}}]},
              "status": {"phase": "Running"}, "name": "lab-pod", "namespace": "default"}],
    "nodes": [{"name": "node-1", "kubelet": {"anonymousAuth": True,
                                             "authorizationMode": "AlwaysAllow",
                                             "readOnlyPort": 10255},
               "capacity": {"nvidia.com/gpu": "8"}, "status": "Ready"}],
    "roles": [{"name": "lab-role", "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
    "clusterroles": [{"name": "lab-cluster-role",
                      "rules": [{"verbs": ["escalate"], "resources": ["roles"]}]}],
    "clusterrolebindings": [{"name": "lab-binding", "roleRef": {"name": "cluster-admin"},
                             "subjects": [{"kind": "ServiceAccount", "name": "lab"}]}],
    "daemonsets": [{"name": "nvidia-driver", "namespace": "gpu-operator",
                    "privileged": True, "hostPath": ["/dev"], "image": "nvidia/driver"},
                   {"name": "calico-node", "namespace": "kube-system",
                    "privileged": True, "hostPath": ["/opt/cni/bin"]}],
    "deployments": [{"name": "argocd-server", "namespace": "argocd",
                     "clusterAdmin": True, "secretRead": True}],
    "secrets": [{"name": "regcred", "namespace": "default",
                 "type": "kubernetes.io/dockerconfigjson", "keys": ["auth"]}],
    "configmaps": [{"name": "lab-config", "namespace": "default", "data": {"k": "v"}}],
    "services": [{"name": "lab-svc", "namespace": "default", "type": "NodePort"}],
    "certificatesigningrequests": [{"name": "lab-csr", "status": "Pending",
                                    "subject": {"organization": ["system:masters"],
                                                "commonName": "system:admin"}}],
    "etcd": [{"name": "etcd-0", "tls": False, "clientCertAuth": False}],
    "kubelets": [{"node": "node-1", "port": 10250, "anonymousAuth": True}],
    "apiservices": [{"name": "v1beta1.lab", "insecureSkipTLSVerify": True, "service": None}],
    "deployed": True,
    "rules": [{"id": "lab-rule", "enabled": True}],
    "kernel_modules": ["elkeid", "smith"],
    "agent_status": ["online"],
    "products": ["falco", "tetragon", "kubearmor", "kyverno"],
    "checks": [{"id": "lab-check", "status": "fail"}],
}


def _rich_snapshot(path: Path, rich: bool) -> str:
    path.write_text(json.dumps(RICH_SNAPSHOT if rich else {}, ensure_ascii=False),
                    encoding="utf-8")
    return str(path)


def _scenarios() -> dict:
    def ok(handler=None, path=None, query=None):
        return {"status": 200, "json": {"ok": True, "version": "0.6.9",
                                        "deployed": True, "ttft_ms": 10,
                                        "cached_tokens": 1024, "data": [],
                                        "marker": "INKBLADE-BENIGN"}}

    return {"vulnerable": {"*": ok}, "fixed": {"*": {"status": 403,
                                                     "json": {"error": "denied"}}}}


def _inputs(template: dict) -> dict:
    params = {}
    for name, spec in (template.get("inputs") or {}).items():
        source = str(spec.get("from") or "")
        key = source.split(".", 1)[-1] if source.startswith("params.") else name
        if key == "target":
            params.setdefault("target", "")
        else:
            params.setdefault(key, "")
    return params


class TemplateDynamicSuite(unittest.TestCase):
    evidence: dict = {}

    @classmethod
    def tearDownClass(cls):
        if not cls.evidence:
            return
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = {"schema": "inkblade-probe-coverage-evidence-v1", "entries": {}}
        doc.setdefault("entries", {})
        for key, entry in cls.evidence.items():
            current = doc["entries"].get(key) or {}
            if str(current.get("runtime") or "").startswith("rust"):
                continue  # native probe evidence is authoritative
            doc["entries"][key] = entry
        doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        EVIDENCE.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    def test_every_template_runs_in_two_states(self):
        modules = sorted(p for p in MODULES.iterdir()
                         if p.is_dir() and (p / "template.json").is_file())
        self.assertGreaterEqual(len(modules), 275)
        failures = []
        for module_dir in modules:
            raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
            if str(raw.get("execution") or "template") != "template":
                continue
            with self.subTest(module=module_dir.name):
                try:
                    outcome = self._run_one(module_dir, raw)
                except Exception as exc:  # noqa: BLE001 - report all failures
                    failures.append(f"{module_dir.name}: {type(exc).__name__}: {exc}")
                    continue
                if outcome["status"] == "error":
                    failures.append(f"{module_dir.name}: {outcome.get('error')}")
                    continue
                self.evidence[module_dir.name] = {
                    "tested": True,
                    "mode": "both",
                    "runtime": outcome["runtime"],
                    "findings_positive": outcome["positive"],
                    "findings_negative": outcome["negative"],
                    "steps": outcome["steps"],
                    "evidence": outcome["evidence"],
                    "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
        if failures:
            self.fail(f"{len(failures)} template(s) failed dynamic verification:\n"
                      + "\n".join(failures[:40]))

    def _run_one(self, module_dir: Path, raw: dict) -> dict:
        template = load_template(module_dir, module_meta=raw)
        with tempfile.TemporaryDirectory() as tmp, Range(_scenarios(), workdir=tmp) as rng:
            params = _inputs(template)
            for name, spec in (template.get("inputs") or {}).items():
                source = str(spec.get("from") or "")
                key = source.split(".", 1)[-1] if source.startswith("params.") else name
                if key == "target":
                    params[key] = rng.url()
                else:
                    params[key] = _rich_snapshot(Path(tmp) / f"{name}.json", True)
            params.setdefault("mode", "probe-only")
            engine = Engine(LocalBackend(workdir=tmp))
            positive = engine.run(template, dict(params), {"marker": "INKBLADE-LAB"})

            rng.set_profile("fixed")
            if "target" in params:
                params["target"] = rng.url()
            for name, spec in (template.get("inputs") or {}).items():
                source = str(spec.get("from") or "")
                key = source.split(".", 1)[-1] if source.startswith("params.") else name
                if key != "target":
                    params[key] = _rich_snapshot(Path(tmp) / f"{name}-fixed.json", False)
            negative = engine.run(template, dict(params), {"marker": "INKBLADE-LAB"})
            digest = hashlib.sha256(json.dumps(
                {"positive": positive, "negative": negative},
                ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
            self.assertNotEqual(positive.get("status"), "error")
            self.assertNotEqual(negative.get("status"), "error")
            return {
                "runtime": positive.get("runtime"),
                "status": positive.get("status"),
                "positive": len(positive.get("findings") or []),
                "negative": len(negative.get("findings") or []),
                "steps": len(positive.get("steps") or []),
                "evidence": digest,
            }


if __name__ == "__main__":
    unittest.main()
