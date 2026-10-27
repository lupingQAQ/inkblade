# -*- coding: utf-8 -*-
"""Normalise probe evidence into facts, assets, capabilities and failures.

The observer consumes the deterministic evidence store, never the raw model
output.  A finding is promoted to a confirmed fact only when the run has a
probe archive with a SHA-256 in the ``evidence`` table.  Failure observations
carry a machine-readable reason (probe unavailable, backup gate, scope, etc.).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from ..core import defense_policy
from ..tpl.probe import ProbeFailed, ProbeUnavailable
from .graph import PlanGraph, severity_rank

_CAPABILITY_MARKERS = (
    "escalate", "bind", "impersonate", "create serviceaccounts/token",
    "cluster-admin", "clusteradmin", "exec", "secrets", "delete", "patch",
    "impersonate", "approve", "sign", "nodes/proxy", "pods/exec",
)


class ObservationError(RuntimeError):
    """Probe evidence missing or malformed; the intent must not be confirmed."""


@dataclass
class Observation:
    intent: str
    module: str
    role: str
    ok: bool
    evidence: list[dict] = field(default_factory=list)
    facts: list[dict] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    reachability: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    summary: str = ""
    runtime: str = ""
    run: str = ""

    @property
    def evidence_ids(self) -> list[str]:
        return [e["id"] for e in self.evidence]

    def to_dict(self) -> dict:
        return {
            "intent": self.intent, "module": self.module, "role": self.role,
            "ok": self.ok, "evidence": [dict(e) for e in self.evidence],
            "facts": [dict(f) for f in self.facts], "assets": list(self.assets),
            "capabilities": list(self.capabilities),
            "reachability": list(self.reachability),
            "failures": list(self.failures), "summary": self.summary,
            "runtime": self.runtime, "run": self.run,
        }


def _sha_or_empty(text: str) -> str:
    text = str(text or "")
    return text if re.fullmatch(r"[a-f0-9]{64}", text) else ""


def _target_of(params: dict) -> str:
    for key in ("target", "host", "url", "endpoint", "base_url", "target_url"):
        value = (params or {}).get(key)
        if value:
            return str(value)
    return ""


def _infer_kind(intent: dict, title: str, detail: str) -> str:
    title_text = str(title or "").lower()
    detail_text = str(detail or "").lower()
    module = str(intent.get("module") or "").lower()

    def has(words: tuple[str, ...], text: str) -> bool:
        return any(word in text for word in words)

    # Facts are classified from the finding title first.  Write-module evidence
    # detail contains PoC/rollback prose; it must not reclassify a foothold or
    # privesc finding as "cleanup".
    if has(("takeover-proof", "takeover proof", "夺权证明", "proof: cluster-admin",
            "cluster-admin binding readable"), title_text):
        return "takeover-proof"
    if has(("cleanup", "cleaned", "deleted", "removed", "rollback", "清理"), title_text):
        return "cleanup"
    if has(("foothold", "probe deployed", "probe artifact", "marker deployed", "立足",
            "投放"), title_text):
        return "foothold"
    if has(("privesc", "privilege escalation", "escalat", "提权"), title_text):
        return "privesc"
    if has(("rbac", "clusterrole", "rolebinding", "wildcard", "can-i", "serviceaccount",
            "tokenrequest"), title_text):
        return "rbac"
    if has(("model", "/v1/models", "registry", "served", "模型"), title_text):
        return "exposure"
    if has(("exposed", "exposure", "暴露"), title_text):
        return "exposure"
    if has(("checkpoint", "weight", "权重"), title_text):
        if has(("write", "poison", "投毒"), title_text):
            return "weight-poison-proof" if "proof" in title_text else "checkpoint-write"
        return "model-access"
    if has(("secret", "credential", "凭据", "敏感"), title_text):
        return "secret-read" if "read" in title_text or "可读" in title_text else "data-reachable"
    if has(("exfil", "sample", "外泄"), title_text):
        return "exfil-proof"
    if has(("recon", "health", "reachable", "asset", "资产"), title_text):
        return "asset"
    # Fallbacks: detail then module name.
    if has(("takeover proof", "夺权证明"), detail_text):
        return "takeover-proof"
    if has(("foothold", "立足", "投放"), detail_text):
        return "foothold"
    if has(("privilege escalation", "提权"), detail_text):
        return "privesc"
    if "exposure" in module:
        return "exposure"
    if "rbac" in module or "role" in module:
        return "rbac"
    if "cleanup" in module:
        return "cleanup"
    if "proof" in module:
        return "takeover-proof"
    return "finding"


def _capabilities(text: str) -> list[str]:
    low = str(text or "").lower()
    return sorted({marker for marker in _CAPABILITY_MARKERS if marker in low})


def _finding_rows(run, module: str) -> list[dict]:
    rows = run.query(
        "SELECT step_key, severity, title, detail, evidence_path FROM findings"
        " WHERE run=? AND step_key=? ORDER BY id", (run.name, module))
    keys = ("step_key", "severity", "title", "detail", "evidence_path")
    return [dict(zip(keys, row)) for row in rows]


def _evidence_rows(run, step_id: int) -> list[dict]:
    rows = run.query(
        "SELECT path, sha256, kind FROM evidence WHERE step_id=? ORDER BY id",
        (int(step_id),))
    return [{"path": row[0], "sha256": row[1], "kind": row[2]} for row in rows]


def _probe_runtime(run, step_id: int) -> str:
    rows = run.query("SELECT value FROM env WHERE step_id=? AND key='probe_runtime'",
                     (int(step_id),))
    return str(rows[0][0]) if rows else ""


def normalize_run(run, intent: dict, *, step_rowid: int | None = None,
                  step_archive: str = "") -> Observation:
    """Read one deterministic run and build an evidence-gated observation."""
    module = str(intent.get("module") or "")
    step_id = int(step_rowid or 0)
    if not step_id:
        rows = run.query("SELECT id, archive FROM steps ORDER BY id DESC LIMIT 1")
        if not rows:
            raise ObservationError(f"intent {intent.get('id')} 没有步骤证据")
        step_id, step_archive = int(rows[0][0]), str(rows[0][1] or step_archive)
    evidence_rows = _evidence_rows(run, step_id)
    if not evidence_rows:
        raise ObservationError(
            f"intent {intent.get('id')} 的步骤没有 evidence 行；拒绝无证据确认")
    runtime = _probe_runtime(run, step_id)
    evidence = []
    for row in evidence_rows:
        digest = _sha_or_empty(row.get("sha256"))
        if not digest:
            raise ObservationError(
                f"intent {intent.get('id')} 的 evidence 缺 sha256；拒绝无证据确认")
        evidence.append({
            "sha256": digest, "run": run.name, "step": module,
            "archive": row.get("path") or step_archive, "source": "probe",
            "runtime": runtime, "summary": f"probe archive {row.get('kind') or 'archive'}",
        })
    findings = _finding_rows(run, module)
    target = _target_of(intent.get("params") or {})
    assets = ([{"kind": "service", "id": target, "address": target}] if target else [])
    reachability = ([{"target": target, "reachable": True,
                      "evidence": evidence[0]["sha256"][:16]}] if target else [])
    caps: set[str] = set()
    facts: list[dict] = []
    for finding in findings:
        text = f"{finding.get('title', '')} {finding.get('detail', '')}"
        caps.update(_capabilities(text))
        fact_kind = _infer_kind(intent, finding.get("title", ""),
                                finding.get("detail", ""))
        facts.append({
            "claim": finding.get("title") or module,
            "status": "confirmed" if evidence else "hypothesis",
            "fact_kind": fact_kind,
            "severity": finding.get("severity") or "info",
            "evidence": [e["sha256"] for e in evidence],
            "source_intent": intent.get("id", ""),
            "attrs": {
                "module": module, "detail": finding.get("detail", ""),
                "step": module, "target": target,
            },
        })
    # A collect step carries the raw security posture.  The observer turns it
    # into `defense:<product>` facts so the scheduler can require a bypass
    # variant before any exploit/privesc intent is claimed.
    params = intent.get("params") or {}
    posture = params.get("security_posture") or params.get("posture")
    if isinstance(posture, dict) and posture:
        refs = [e["sha256"] for e in evidence]
        facts.extend(defense_policy.defense_facts(
            posture, refs, source_intent=str(intent.get("id") or "")))
    if not facts:
        facts.append({
            "claim": f"{module}: probe completed without a finding",
            "status": "hypothesis", "fact_kind": "observation",
            "severity": "info", "evidence": [e["sha256"] for e in evidence],
            "source_intent": intent.get("id", ""),
            "attrs": {"module": module, "target": target},
        })
    summary = f"{module}: {len(findings)} finding(s), {len(evidence)} evidence ref(s)"
    return Observation(intent=str(intent.get("id") or ""), module=module,
                       role=str(intent.get("role") or ""), ok=True,
                       evidence=evidence, facts=facts, assets=assets,
                       capabilities=sorted(caps), reachability=reachability,
                       summary=summary, runtime=runtime, run=run.name)


def failure_observation(intent: dict, exc: BaseException) -> Observation:
    kind = "probe-error"
    if isinstance(exc, ProbeUnavailable):
        kind = "probe-unavailable"
    elif isinstance(exc, ProbeFailed):
        kind = "probe-failed"
    elif type(exc).__name__ == "BackupGateRefused":
        kind = "backup-gate"
    elif type(exc).__name__ == "ExecutionLocked":
        kind = "roe-locked"
    elif "timeout" in str(exc).lower():
        kind = "timeout"
    return Observation(
        intent=str(intent.get("id") or ""), module=str(intent.get("module") or ""),
        role=str(intent.get("role") or ""), ok=False,
        failures=[{"kind": kind, "reason": f"{type(exc).__name__}: {exc}"}],
        summary=f"{intent.get('module')}: {kind}: {exc}",
    )


def apply_observation(graph: PlanGraph, observation: Observation,
                      *, key_prefix: str = "") -> dict:
    """Persist observation evidence/facts into the graph; return ids."""
    evidence_ids: list[str] = []
    by_sha: dict[str, str] = {}
    for ref in observation.evidence:
        node = graph.add_evidence(ref["sha256"], run=ref.get("run", ""),
                                  step=ref.get("step", ""),
                                  archive=ref.get("archive", ""),
                                  source=ref.get("source", "probe"),
                                  runtime=ref.get("runtime", ""),
                                  summary=ref.get("summary", ""))
        evidence_ids.append(node["id"])
        by_sha[str(node.get("sha256") or "")] = node["id"]
    fact_ids: list[str] = []
    for fact in observation.facts:
        evidence: list[str] = []
        for ref in fact.get("evidence") or []:
            if ref in evidence_ids:
                evidence.append(ref)
            elif ref in by_sha:
                evidence.append(by_sha[ref])
        if fact.get("status") == "confirmed" and not evidence:
            continue
        node = graph.add_fact(fact.get("claim", ""), status=fact.get("status", "hypothesis"),
                              evidence=evidence, kind=fact.get("fact_kind", "finding"),
                              severity=fact.get("severity", "info"),
                              source_intent=fact.get("source_intent", ""),
                              attrs=fact.get("attrs") or {})
        fact_ids.append(node["id"])
    return {"evidence": evidence_ids, "facts": fact_ids}


def evidence_digest(observation: Observation) -> str:
    import json

    raw = json.dumps(observation.to_dict(), ensure_ascii=False, sort_keys=True,
                     default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
