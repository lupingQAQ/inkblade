# -*- coding: utf-8 -*-
"""Machine-checkable objectives for the agent graph.

An objective is not a prose prompt.  It is a set of required confirmed facts,
required role/tag intents and an evidence rule; :meth:`Objective.evaluate`
returns a deterministic pass/fail vector used by the scheduler, eval harness
and CLI status.  A fact without probe evidence can never satisfy a requirement.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from .graph import PlanGraph, severity_rank


class ObjectiveError(ValueError):
    """Unknown objective or invalid stage."""


@dataclass(frozen=True)
class FactRequirement:
    fact_kind: str
    severity: str = "info"
    min_count: int = 1
    label: str = ""

    def as_dict(self) -> dict:
        return {"fact_kind": self.fact_kind, "severity": self.severity,
                "min_count": self.min_count, "label": self.label or self.fact_kind}


@dataclass(frozen=True)
class PlanStage:
    key: str
    role: str
    module_key: str
    priority: int = 5
    writes: bool = False
    cleanup: bool = False
    probe: bool = True
    requires_facts: tuple[str, ...] = ()
    requires_intents: tuple[str, ...] = ()
    params: dict = field(default_factory=dict)
    expected_evidence: tuple[str, ...] = ()
    rationale: str = ""

    def as_dict(self) -> dict:
        return {
            "key": self.key, "role": self.role, "module_key": self.module_key,
            "priority": self.priority, "writes": self.writes, "cleanup": self.cleanup,
            "probe": self.probe, "requires_facts": list(self.requires_facts),
            "requires_intents": list(self.requires_intents),
            "params": copy.deepcopy(self.params),
            "expected_evidence": list(self.expected_evidence),
            "rationale": self.rationale,
        }


@dataclass
class Objective:
    key: str
    title: str
    goal: str
    required_facts: tuple[FactRequirement, ...]
    allow_writes: bool = False
    require_report: bool = False
    require_cleanup: bool = False
    stages: tuple[PlanStage, ...] = ()
    default_params: dict = field(default_factory=dict)

    # ------------------------------------------------------------ checks
    def evaluate(self, graph: PlanGraph) -> dict:
        checks: list[dict] = []
        for req in self.required_facts:
            need = severity_rank(req.severity)
            hits = [f for f in graph.confirmed_facts(fact_kind=req.fact_kind)
                    if severity_rank(f.get("severity")) >= need and f.get("evidence")]
            ok = len(hits) >= max(1, int(req.min_count))
            checks.append({
                "id": f"fact:{req.fact_kind}", "ok": ok,
                "detail": (f"{len(hits)}/{max(1, int(req.min_count))} 个 {req.fact_kind} "
                           f">= {req.severity} 且带证据"),
                "evidence": [f["id"] for f in hits],
            })
        if self.require_report:
            reports = [i for i in graph.intents(status="done", role="report")]
            checks.append({"id": "intent:report", "ok": bool(reports),
                           "detail": "报告 worker 已产出报告",
                           "evidence": [i["id"] for i in reports]})
        if self.require_cleanup:
            cleanups = [i for i in graph.intents(status="done") if i.get("cleanup")]
            checks.append({"id": "intent:cleanup", "ok": bool(cleanups),
                           "detail": "清理动作已执行并留证",
                           "evidence": [i["id"] for i in cleanups]})
        confirmed = graph.confirmed_facts()
        backed = [f for f in confirmed if f.get("evidence")]
        checks.append({
            "id": "evidence:coverage", "ok": len(backed) == len(confirmed),
            "detail": f"{len(backed)}/{len(confirmed)} 个 confirmed fact 带证据",
            "evidence": [],
        })
        if not self.allow_writes:
            writes = [i for i in graph.intents() if i.get("writes")
                      and i.get("status") in ("done", "claimed", "open")]
            checks.append({"id": "policy:read-only", "ok": not writes,
                           "detail": "read-only objective 不允许写动作",
                           "evidence": [i["id"] for i in writes]})
        return {
            "objective": self.key, "title": self.title,
            "success": all(c["ok"] for c in checks),
            "checks": checks,
            "missing": [c["id"] for c in checks if not c["ok"]],
            "summary": graph.summary(),
        }

    def success(self, graph: PlanGraph) -> bool:
        return bool(self.evaluate(graph)["success"])

    # ------------------------------------------------------------ deterministic plan
    def _stage_requirements(self, graph: PlanGraph, stage: PlanStage) -> list[str] | None:
        req_ids: list[str] = []
        for kind in stage.requires_facts:
            hits = [f for f in graph.confirmed_facts(fact_kind=kind) if f.get("evidence")]
            if not hits:
                return None
            req_ids.append(hits[-1]["id"])
        for role in stage.requires_intents:
            hits = [i for i in graph.intents(status="done", role=role)]
            if not hits:
                return None
            req_ids.append(hits[-1]["id"])
        return list(dict.fromkeys(req_ids))

    def next_stage(self, graph: PlanGraph, *, module_map: dict[str, str] | None = None,
                   param_map: dict[str, dict] | None = None) -> dict | None:
        """Return the next deterministic stage that is ready and not done."""
        done_modules = {i["module"] for i in graph.intents(status="done")}
        open_modules = {i["module"] for i in graph.intents() if i["status"] in
                        ("open", "claimed")}
        mapping = dict(module_map or {})
        params_map = dict(param_map or {})
        produced = {
            "recon": "asset", "exposure": "exposure", "rbac": "rbac",
            "drop": "foothold", "privesc": "privesc", "proof": "takeover-proof",
            "model-access": "model-access", "checkpoint-write": "checkpoint-write",
            "poison-proof": "weight-poison-proof", "data-reach": "data-reachable",
            "secret-read": "secret-read", "exfil-proof": "exfil-proof",
        }
        for stage in self.stages:
            module = mapping.get(stage.module_key, stage.module_key)
            if module in done_modules or module in open_modules:
                continue
            fact_kind = produced.get(stage.key)
            if fact_kind and graph.has_confirmed(fact_kind=fact_kind):
                continue
            req_ids = self._stage_requirements(graph, stage)
            if req_ids is None:
                continue
            params = {**self.default_params, **copy.deepcopy(stage.params),
                      **copy.deepcopy(params_map.get(stage.module_key, {}))}
            return {
                "stage": stage.key, "role": stage.role, "module": module,
                "params": params, "priority": stage.priority,
                "writes": stage.writes, "cleanup": stage.cleanup,
                "probe": stage.probe, "requires": req_ids,
                "expected_evidence": list(stage.expected_evidence),
                "rationale": stage.rationale or f"deterministic stage {stage.key}",
            }
        return None

    def as_dict(self) -> dict:
        return {
            "key": self.key, "title": self.title, "goal": self.goal,
            "allow_writes": self.allow_writes, "require_report": self.require_report,
            "require_cleanup": self.require_cleanup,
            "required_facts": [r.as_dict() for r in self.required_facts],
            "stages": [s.as_dict() for s in self.stages],
            "default_params": copy.deepcopy(self.default_params),
        }


_CLUSTER_STAGES = (
    PlanStage("recon", "recon", "recon", priority=9,
              expected_evidence=("reachable endpoint", "asset fingerprint"),
              rationale="先建立可达性与资产事实，后续意图只依赖已确认事实"),
    PlanStage("exposure", "recon", "exposure", priority=9,
              requires_facts=("asset",),
              expected_evidence=("served API surface", "model/registry exposure"),
              rationale="在已确认资产上枚举暴露面，不猜测目标"),
    PlanStage("rbac", "recon", "rbac", priority=8,
              requires_facts=("exposure",),
              expected_evidence=("RBAC bindings", "privileged role surface"),
              rationale="从暴露面推进到集群权限面，保留只读约束"),
    PlanStage("drop", "exploit", "drop", priority=8, writes=True,
              requires_facts=("rbac",),
              expected_evidence=("probe artifact deployed", "foothold marker"),
              rationale="在备份闸门满足后投放可回滚的探针演示对象"),
    PlanStage("privesc", "exploit", "privesc", priority=9, writes=True,
              requires_facts=("foothold",),
              expected_evidence=("role binding created", "escalation proof"),
              rationale="用已确认的 RBAC 能力提权，写面必须有备份回执"),
    PlanStage("proof", "verify", "proof", priority=10,
              requires_facts=("privesc",),
              expected_evidence=("cluster-admin binding readable", "takeover proof"),
              rationale="独立验证夺权结果，证据门控通过后才能 confirmed"),
    PlanStage("report", "report", "report", priority=5, probe=False,
              requires_facts=("takeover-proof",),
              expected_evidence=("report artifact",),
              rationale="报告 worker 只读图与证据，不执行探针"),
    PlanStage("cleanup", "exploit", "cleanup", priority=10, writes=True, cleanup=True,
              requires_facts=("takeover-proof",), requires_intents=("report",),
              expected_evidence=("binding deleted", "cleanup receipt"),
              rationale="清理演示对象，保留回滚与审计证据"),
)

_WEIGHT_STAGES = (
    PlanStage("recon", "recon", "recon", priority=9,
              expected_evidence=("model serving surface",)),
    PlanStage("model-access", "recon", "exposure", priority=9,
              requires_facts=("asset",), expected_evidence=("write-capable model path",)),
    PlanStage("checkpoint-write", "exploit", "drop", priority=8, writes=True,
              requires_facts=("model-access",), expected_evidence=("checkpoint write",)),
    PlanStage("poison-proof", "verify", "proof", priority=10,
              requires_facts=("checkpoint-write",), expected_evidence=("poisoned weight proof",)),
    PlanStage("report", "report", "report", priority=5, probe=False,
              requires_facts=("weight-poison-proof",)),
    PlanStage("cleanup", "exploit", "cleanup", priority=10, writes=True, cleanup=True,
              requires_facts=("weight-poison-proof",), requires_intents=("report",)),
)

_DATA_STAGES = (
    PlanStage("recon", "recon", "recon", priority=9, expected_evidence=("dataset surface",)),
    PlanStage("data-reach", "recon", "exposure", priority=9,
              requires_facts=("asset",), expected_evidence=("dataset endpoint",)),
    PlanStage("secret-read", "exploit", "rbac", priority=8,
              requires_facts=("data-reachable",), expected_evidence=("secret readable",)),
    PlanStage("exfil-proof", "verify", "proof", priority=10,
              requires_facts=("secret-read",), expected_evidence=("exfil sample hash",)),
    PlanStage("report", "report", "report", priority=5, probe=False,
              requires_facts=("exfil-proof",)),
    PlanStage("cleanup", "exploit", "cleanup", priority=10, writes=True, cleanup=True,
              requires_facts=("exfil-proof",), requires_intents=("report",)),
)

_RECON_STAGES = (
    PlanStage("recon", "recon", "recon", priority=9, expected_evidence=("asset",)),
    PlanStage("exposure", "recon", "exposure", priority=9,
              requires_facts=("asset",), expected_evidence=("exposure",)),
    PlanStage("rbac", "recon", "rbac", priority=8,
              requires_facts=("exposure",), expected_evidence=("RBAC map",)),
    PlanStage("report", "report", "report", priority=5, probe=False,
              requires_facts=("rbac",), expected_evidence=("recon report",)),
)

OBJECTIVES: dict[str, Objective] = {
    "cluster-takeover": Objective(
        key="cluster-takeover", title="ML 集群夺权",
        goal="从可达 LLM/控制面推进到 cluster-admin，留下可复核证据并清理演示对象",
        required_facts=(
            FactRequirement("exposure", "medium", label="暴露的模型/控制面"),
            FactRequirement("foothold", "medium", label="探针立足点"),
            FactRequirement("privesc", "high", label="提权到高权角色"),
            FactRequirement("takeover-proof", "critical", label="夺权证明"),
        ),
        allow_writes=True, require_report=True, require_cleanup=True,
        stages=_CLUSTER_STAGES,
    ),
    "weight-poisoning": Objective(
        key="weight-poisoning", title="模型权重投毒",
        goal="证明可写模型/checkpoint 路径并留下投毒验证证据，随后清理",
        required_facts=(
            FactRequirement("model-access", "high", label="模型写路径"),
            FactRequirement("checkpoint-write", "high", label="checkpoint 写入"),
            FactRequirement("weight-poison-proof", "critical", label="投毒验证"),
        ),
        allow_writes=True, require_report=True, require_cleanup=True,
        stages=_WEIGHT_STAGES,
    ),
    "data-exfiltration": Objective(
        key="data-exfiltration", title="训练数据/凭据外泄",
        goal="证明可读敏感数据并用哈希样本留证，随后清理",
        required_facts=(
            FactRequirement("data-reachable", "medium", label="数据面可达"),
            FactRequirement("secret-read", "high", label="敏感对象可读"),
            FactRequirement("exfil-proof", "critical", label="外泄样本哈希"),
        ),
        allow_writes=True, require_report=True, require_cleanup=True,
        stages=_DATA_STAGES,
    ),
    "read-only-recon": Objective(
        key="read-only-recon", title="只读侦察",
        goal="枚举资产、暴露面与 RBAC 面，不产生任何写动作",
        required_facts=(
            FactRequirement("asset", "info", label="资产"),
            FactRequirement("exposure", "medium", label="暴露面"),
            FactRequirement("rbac", "medium", label="权限面"),
        ),
        allow_writes=False, require_report=True, require_cleanup=False,
        stages=_RECON_STAGES,
    ),
}


def get_objective(key: str) -> Objective:
    try:
        return OBJECTIVES[str(key)]
    except KeyError as exc:
        raise ObjectiveError(f"未知 objective: {key!r}；可选 {sorted(OBJECTIVES)}") from exc


def objective_keys() -> list[str]:
    return sorted(OBJECTIVES)


def evaluate_objective(key: str, graph: PlanGraph) -> dict:
    return get_objective(key).evaluate(graph)


def stage_module_map(objective: str, mapping: dict[str, str] | None = None) -> dict[str, str]:
    """Return a complete stage→module map, defaulting to deterministic keys."""
    obj = get_objective(objective)
    out = {s.module_key: s.module_key for s in obj.stages}
    out.update({str(k): str(v) for k, v in (mapping or {}).items()})
    return out
