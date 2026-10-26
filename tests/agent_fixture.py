# -*- coding: utf-8 -*-
"""Shared fixtures for the 2026 agent runtime tests (not collected by unittest)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lab"))

from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.users import Session
from inkblade.agent.eval import build_golden_modules, golden_script
from inkblade.tpl.backends import K8sShim
from template_range import Range

K8S_OBJECTS = {
    "clusterroles": [{"metadata": {"name": "cluster-admin"},
                      "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
    "clusterrolebindings": [{"kind": "ClusterRoleBinding",
                             "metadata": {"name": "inkblade-agent-admin"},
                             "roleRef": {"kind": "ClusterRole",
                                         "name": "cluster-admin"}}],
}


def make_lab(tmp: Path, *, with_range: bool = True):
    tmp = Path(tmp)
    modules = build_golden_modules(tmp)
    store = EvidenceStore(tmp, workspace="lab")
    init_roe(store, {"level": "全影响演示", "namespaces": ["train"],
                     "cidrs": ["127.0.0.0/8"],
                     "window": "2026-01-01 – 2030-12-31"})
    session = Session(None, "lead", "lead", ["lab"], "test-agent")
    if not with_range:
        return store, session, modules, None, None
    rng = Range(k8s_objects=K8S_OBJECTS).start()
    k8s = K8sShim(api=rng.k8s_url, token=rng._k8s.token)
    return store, session, modules, rng, k8s


def supervisor_kwargs(tmp: Path, modules: Path, rng, k8s, *, script=None,
                      **overrides):
    from inkblade.agent.planner import ScriptedPlanner

    if script is None:
        script = golden_script(rng.url())
    if isinstance(script, (dict, list, str, Path)):
        script = ScriptedPlanner(script)
    base_params = {"target": rng.url(), "namespace": "train"}
    backup = [{"kind": "kube", "name": "demo/agent",
               "manifest": "kind: Demo\nmetadata: {name: demo}\n"}]
    param_map = {key: dict(base_params) for key in
                 ("recon", "exposure", "rbac", "proof")}
    for key in ("drop", "privesc", "cleanup"):
        param_map[key] = {**base_params, "backup_targets": [dict(backup[0])]}
    kwargs = {
        "objective": "cluster-takeover",
        "probe_id": "test-probe",
        "probe_spec": {"kind": "reference"},
        "allow_reference": True,
        "llm": script,
        "mode": "graph-swarm",
        "modules_dir": modules,
        "allow_destructive": True,
        "confirm": True,
        "budgets": {"tokens": 20000, "steps": 12, "actions": 20,
                    "duration_ms": 120000},
        "workers": 1,
        "k8s": k8s,
        "workdir": rng.workdir,
        "param_map": param_map,
    }
    kwargs.update(overrides)
    return kwargs


def run_agent_once(tmp: Path, *, script=None, overrides=None):
    from inkblade.agent.supervisor import AgentSupervisor

    store, session, modules, rng, k8s = make_lab(tmp)
    kwargs = supervisor_kwargs(tmp, modules, rng, k8s, script=script,
                               **(overrides or {}))
    sup = AgentSupervisor.create(store, session, **kwargs)
    result = sup.run()
    return store, session, sup, rng, result
