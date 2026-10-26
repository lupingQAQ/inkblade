# -*- coding: utf-8 -*-
"""Evaluation harness (CyberGym/AgentDojo-style task, success, budget metrics).

Modes compared:

* ``deterministic`` — fixed objective stages, no LLM (degraded baseline).
* ``supervisor`` — scripted/LLM supervisor with FIFO single-worker control.
* ``graph-swarm`` — graph frontier + bounded role workers.

The golden suite runs on the mock probe range with the explicit reference
runtime; it is a regression harness, not a production score.  Every metric is
also recorded per intent in the durable journal.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..core.evidence import EvidenceStore
from ..core.roe import init_roe
from ..core.users import Session
from .objectives import get_objective, objective_keys
from .planner import DeterministicPlanner, ScriptedPlanner
from .probes import build_probe_session
from .supervisor import AgentSupervisor

EVAL_SCHEMA = "inkblade-agent-eval/1"
MODES = ("deterministic", "supervisor", "graph-swarm")


@dataclass
class EvalTask:
    id: str
    objective: str
    script: list[dict] | dict | Callable[[dict], dict]
    module_map: dict[str, str] = field(default_factory=dict)
    workers: int = 2
    budgets: dict = field(default_factory=lambda: {
        "tokens": 20000, "steps": 12, "actions": 20, "duration_ms": 900000})
    expected_success: bool = True
    description: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "objective": self.objective, "workers": self.workers,
                "budgets": dict(self.budgets), "expected_success": self.expected_success,
                "description": self.description}


def _module(root: Path, key: str, *, writes: bool, steps: list[dict],
            findings: list[dict], artifacts: list[dict] | None = None) -> None:
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {"key": key, "name": {"zh": key, "en": key}, "series": "权限链",
            "description": "agent eval lab module", "min_level": "利用验证",
            "writes": bool(writes), "requires": []}
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    tpl = {"schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
           "meta": {"name": {"zh": key, "en": key}, "series": "权限链",
                    "min_level": "利用验证", "writes": bool(writes), "requires": []},
           "steps": steps, "findings": findings,
           "artifacts": artifacts or []}
    if writes:
        tpl["modes"] = {"probe_only": True, "backup_write": True,
                        "requires_backup": True}
    (d / "template.json").write_text(json.dumps(tpl, ensure_ascii=False), encoding="utf-8")


def build_golden_modules(root: Path) -> Path:
    """Create the 8-stage cluster-takeover lab module set under ``root/modules``."""
    _module(root, "lab-recon", writes=False, steps=[
        {"id": "health", "op": "http", "method": "GET",
         "url": "{{params.target}}/healthz", "save": "health"}],
        findings=[{"id": "f", "sev": "info", "title": "recon-ok: healthz reachable",
                   "when": "steps.health.status == 200"}],
        artifacts=[{"name": "health.json", "from": "steps.health.json"}])
    _module(root, "lab-exposure", writes=False, steps=[
        {"id": "models", "op": "http", "method": "GET",
         "url": "{{params.target}}/v1/models", "save": "models"}],
        findings=[{"id": "f", "sev": "high", "title": "model registry exposed",
                   "when": "steps.models.status == 200"}],
        artifacts=[{"name": "models.json", "from": "steps.models.json"}])
    _module(root, "lab-rbac", writes=False, steps=[
        {"id": "roles", "op": "k8s", "verb": "list",
         "api_version": "rbac.authorization.k8s.io/v1", "resource": "clusterroles",
         "namespace": "", "save": "roles"}],
        findings=[{"id": "f", "sev": "critical", "title": "wildcard clusterrole",
                   "when": "len(steps.roles.json.items) > 0"}],
        artifacts=[{"name": "roles.json", "from": "steps.roles.json"}])
    _module(root, "lab-drop", writes=True, steps=[
        {"id": "create", "op": "k8s", "verb": "create", "api_version": "v1",
         "resource": "configmaps", "namespace": "train", "write": True,
         "body": {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "inkblade-probe"}}, "save": "create"}],
        findings=[{"id": "f", "sev": "high", "title": "probe deployed: foothold marker",
                   "when": "steps.create.ok == true"}],
        artifacts=[{"name": "create.json", "from": "steps.create.json"}])
    _module(root, "lab-privesc", writes=True, steps=[
        {"id": "bind", "op": "k8s", "verb": "create",
         "api_version": "rbac.authorization.k8s.io/v1",
         "resource": "clusterrolebindings", "namespace": "", "write": True,
         "body": {"apiVersion": "rbac.authorization.k8s.io/v1",
                  "kind": "ClusterRoleBinding",
                  "metadata": {"name": "inkblade-agent-admin"},
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                              "kind": "ClusterRole", "name": "cluster-admin"},
                  "subjects": [{"kind": "ServiceAccount", "name": "agent",
                                "namespace": "train"}]}, "save": "bind"}],
        findings=[{"id": "f", "sev": "critical",
                   "title": "privilege escalation: cluster-admin rolebinding created",
                   "when": "steps.bind.ok == true"}],
        artifacts=[{"name": "bind.json", "from": "steps.bind.json"}])
    _module(root, "lab-proof", writes=False, steps=[
        {"id": "proof", "op": "k8s", "verb": "get",
         "api_version": "rbac.authorization.k8s.io/v1",
         "resource": "clusterrolebindings", "namespace": "",
         "name": "inkblade-agent-admin", "save": "proof"}],
        findings=[{"id": "f", "sev": "critical",
                   "title": "takeover proof: cluster-admin binding readable",
                   "when": "steps.proof.ok == true"}],
        artifacts=[{"name": "proof.json", "from": "steps.proof.json"}])
    _module(root, "lab-cleanup", writes=True, steps=[
        {"id": "delete", "op": "k8s", "verb": "delete",
         "api_version": "rbac.authorization.k8s.io/v1",
         "resource": "clusterrolebindings", "namespace": "",
         "name": "inkblade-agent-admin", "write": True, "save": "delete"}],
        findings=[{"id": "f", "sev": "info", "title": "cleanup: rolebinding deleted",
                   "when": "steps.delete.ok == true"}],
        artifacts=[{"name": "delete.json", "from": "steps.delete.json"}])
    return root / "modules"


def _intent(role: str, module: str, target: str, *, writes: bool = False,
            cleanup: bool = False, probe: bool = True) -> dict:
    params: dict[str, Any] = {"target": target, "namespace": "train"}
    if writes:
        params["backup_targets"] = [{
            "kind": "kube", "name": f"demo/{module}",
            "manifest": "kind: Demo\nmetadata: {name: demo}\n"}]
    return {"role": role, "module": module, "params": params, "priority": 8,
            "writes": writes, "cleanup": cleanup, "probe": probe,
            "expected_evidence": ["probe evidence"]}


def golden_script(target: str) -> dict:
    return {"responses": [
        {"decision": "propose_intents", "rationale": "建立可达性/资产事实",
         "intents": [_intent("recon", "lab-recon", target)]},
        {"decision": "propose_intents", "rationale": "枚举暴露面",
         "intents": [_intent("recon", "lab-exposure", target)]},
        {"decision": "propose_intents", "rationale": "枚举 RBAC 面",
         "intents": [_intent("recon", "lab-rbac", target)]},
        {"decision": "propose_intents", "rationale": "投放可回滚探针对象",
         "intents": [_intent("exploit", "lab-drop", target, writes=True)]},
        {"decision": "propose_intents", "rationale": "利用 RBAC 提权",
         "intents": [_intent("exploit", "lab-privesc", target, writes=True)]},
        {"decision": "propose_intents", "rationale": "独立验证夺权证明",
         "intents": [_intent("verify", "lab-proof", target)]},
        {"decision": "propose_intents", "rationale": "产出报告",
         "intents": [{"role": "report", "module": "agent-report", "params": {},
                      "priority": 5, "probe": False}]},
        {"decision": "propose_intents", "rationale": "清理演示对象",
         "intents": [_intent("exploit", "lab-cleanup", target, writes=True,
                             cleanup=True)]},
        {"decision": "stop", "rationale": "objective satisfied"},
    ]}


def golden_task(workers: int = 2) -> EvalTask:
    return EvalTask(
        id="golden-cluster-takeover", objective="cluster-takeover",
        script=lambda state: {"decision": "stop", "rationale": "placeholder"},
        module_map={"recon": "lab-recon", "exposure": "lab-exposure",
                    "rbac": "lab-rbac", "drop": "lab-drop",
                    "privesc": "lab-privesc", "proof": "lab-proof",
                    "report": "agent-report", "cleanup": "lab-cleanup"},
        workers=workers,
        description="8-stage graph chain on the mock range",
    )


class EvalHarness:
    def __init__(self, root: str | Path, *, workdir: str | Path | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.workdir = Path(workdir) if workdir else self.root

    def run_task(self, mode: str, task: EvalTask, *,
                 script_target: str | None = None) -> dict:
        if mode not in MODES:
            raise ValueError(f"未知 eval mode: {mode}")
        from lab.template_range import Range

        started = time.time()
        tmp = Path(tempfile.mkdtemp(prefix=f"agent-eval-{mode}-", dir=str(self.workdir)))
        build_golden_modules(tmp)
        store = EvidenceStore(tmp, workspace=f"eval-{mode}")
        init_roe(store, {"level": "全影响演示", "namespaces": ["train"],
                         "cidrs": ["127.0.0.0/8"],
                         "window": "2026-01-01 – 2030-12-31"})
        session = Session(None, "lead", "lead", [f"eval-{mode}"], "agent-eval")
        rng = Range(k8s_objects={
            "clusterroles": [{"metadata": {"name": "cluster-admin"},
                              "rules": [{"verbs": ["*"], "resources": ["*"]}]}],
            "clusterrolebindings": [{"kind": "ClusterRoleBinding",
                                     "metadata": {"name": "inkblade-agent-admin"},
                                     "roleRef": {"kind": "ClusterRole",
                                                 "name": "cluster-admin"}}],
        }).start()
        try:
            from inkblade.tpl.backends import K8sShim

            k8s = K8sShim(api=rng.k8s_url, token=rng._k8s.token)
            target = rng.url()
            if mode == "deterministic":
                base_params = {"target": target, "namespace": "train"}
                param_map = {key: dict(base_params) for key in
                             ("recon", "exposure", "rbac", "proof")}
                backup = [{"kind": "kube", "name": "demo/agent",
                           "manifest": "kind: Demo\nmetadata: {name: demo}\n"}]
                for key in ("drop", "privesc", "cleanup"):
                    param_map[key] = {**base_params,
                                      "backup_targets": [dict(backup[0])]}
                planner = DeterministicPlanner(
                    get_objective(task.objective), module_map=task.module_map,
                    param_map=param_map)
            else:
                script = golden_script(target) if task.id.startswith("golden") \
                    else task.script
                planner = ScriptedPlanner(script)
                base_params = {"target": target, "namespace": "train"}
                param_map = {key: dict(base_params) for key in
                             ("recon", "exposure", "rbac", "proof")}
                backup = [{"kind": "kube", "name": "demo/agent",
                           "manifest": "kind: Demo\nmetadata: {name: demo}\n"}]
                for key in ("drop", "privesc", "cleanup"):
                    param_map[key] = {**base_params,
                                      "backup_targets": [dict(backup[0])]}
            sup = AgentSupervisor.create(
                store, session, objective=task.objective, probe_id="eval-probe",
                probe_spec={"kind": "reference"}, allow_reference=True,
                llm=planner, mode=mode, modules_dir=tmp / "modules",
                allow_destructive=True, confirm=True, budgets=task.budgets,
                workers=1 if mode != "graph-swarm" else task.workers,
                k8s=k8s, workdir=rng.workdir, module_map=task.module_map,
                param_map=param_map)
            summary = sup.run()
            metrics = dict(summary.get("metrics") or {})
            metrics["success"] = bool(summary.get("success"))
            metrics["success_rate"] = 1.0 if summary.get("success") else 0.0
            metrics["expected_success"] = bool(task.expected_success)
            return {
                "schema": EVAL_SCHEMA, "mode": mode, "task": task.as_dict(),
                "ok": bool(summary.get("success")) == bool(task.expected_success),
                "metrics": metrics, "summary": summary,
                "duration_ms": int((time.time() - started) * 1000),
                "run_id": summary.get("run_id"),
            }
        finally:
            rng.stop()

    def compare(self, tasks: list[EvalTask] | None = None,
                modes: tuple[str, ...] = MODES) -> dict:
        tasks = tasks or [golden_task()]
        results = []
        for task in tasks:
            for mode in modes:
                results.append(self.run_task(mode, task))
        per_mode: dict[str, dict] = {}
        for mode in modes:
            rows = [r for r in results if r["mode"] == mode]
            per_mode[mode] = {
                "tasks": len(rows),
                "successes": sum(1 for r in rows if r["metrics"]["success"]),
                "success_rate": round(sum(1 for r in rows if r["metrics"]["success"]) /
                                      max(1, len(rows)), 4),
                "mean_steps": round(sum(r["metrics"].get("steps", 0) for r in rows) /
                                    max(1, len(rows)), 2),
                "mean_tokens": round(sum(r["metrics"].get("tokens", 0) for r in rows) /
                                     max(1, len(rows)), 2),
                "mean_evidence_coverage": round(
                    sum(r["metrics"].get("evidence_coverage", 0) for r in rows) /
                    max(1, len(rows)), 4),
                "interventions": sum(r["metrics"].get("interventions", 0) for r in rows),
            }
        return {
            "schema": EVAL_SCHEMA, "generated_at": time.time(),
            "modes": list(modes), "tasks": [t.as_dict() for t in tasks],
            "per_mode": per_mode, "results": results,
        }


def run_cli_eval(store: EvidenceStore, *, suite: str = "golden",
                 modes: str = "deterministic,supervisor,graph-swarm",
                 out: str | None = None) -> dict:
    root = Path(store.root) / "reports" / "agent-eval"
    harness = EvalHarness(root)
    tasks = [golden_task()] if suite in ("golden", "golden-cluster-takeover") else [golden_task()]
    mode_list = tuple(m.strip() for m in str(modes).split(",") if m.strip())
    report = harness.compare(tasks, mode_list)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
        report["out"] = str(path)
    return report
