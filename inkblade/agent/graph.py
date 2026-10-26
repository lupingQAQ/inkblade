# -*- coding: utf-8 -*-
"""Fact / Intent / Hint graph with causal edges and evidence gating.

The graph is the only shared planning state.  It is deliberately *not* a task
list: facts are observations backed by probe evidence, intents are unknowns to
resolve, and hints are human/agent priors.  A fact cannot become ``confirmed``
without at least one evidence reference whose SHA-256 came from a probe result.
Intents become ready only when every ``requires`` node is satisfied; the
scheduler then chooses from the frontier by priority and cost.
"""
from __future__ import annotations

import copy
import hashlib
import re
import time
from typing import Any, Iterable

GRAPH_SCHEMA = "inkblade-agent-graph/1"
NODE_KINDS = ("fact", "intent", "hint", "evidence")
RELATIONS = ("requires", "supports", "contradicts", "derived_from", "produced_by")
ROLES = ("recon", "exploit", "verify", "report")
INTENT_STATUSES = ("open", "claimed", "done", "failed", "blocked", "skipped")
FACT_STATUSES = ("hypothesis", "confirmed", "refuted")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class GraphError(ValueError):
    """Invalid graph operation."""


class EvidenceRequired(GraphError):
    """A fact/intent was promoted without probe evidence."""


def severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(str(value or "info").lower(), 0)


def _digest(value: Any) -> str:
    raw = repr(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class PlanGraph:
    """Minimal blackboard with evidence-gated promotion and frontier queries."""

    def __init__(self, *, objective: str = ""):
        self.objective = objective
        self._nodes: dict[str, dict] = {}
        self._edges: list[dict] = []
        self._edge_set: set[tuple[str, str, str]] = set()
        self._counter: dict[str, int] = {}
        self._created = 0

    # ------------------------------------------------------------ ids
    def _next_id(self, prefix: str) -> str:
        n = int(self._counter.get(prefix, 0)) + 1
        self._counter[prefix] = n
        return f"{prefix}-{n}"

    def _touch(self) -> int:
        self._created += 1
        return self._created

    # ------------------------------------------------------------ evidence
    def add_evidence(self, sha256: str, *, run: str = "", step: str = "",
                     archive: str = "", source: str = "probe",
                     runtime: str = "", summary: str = "",
                     evidence_id: str | None = None) -> dict:
        digest = str(sha256 or "").lower()
        if not _SHA256_RE.match(digest):
            raise EvidenceRequired("evidence sha256 必须是 64 位十六进制")
        if source != "probe":
            raise EvidenceRequired("evidence source 必须是 probe（不接受模型自述）")
        for node in self._nodes.values():
            if node["kind"] == "evidence" and node.get("sha256") == digest \
                    and node.get("step") == step:
                return copy.deepcopy(node)
        eid = evidence_id or f"ev-{digest[:16]}"
        suffix = 1
        base = eid
        while eid in self._nodes:
            suffix += 1
            eid = f"{base}-{suffix}"
        node = {
            "id": eid, "kind": "evidence", "sha256": digest, "run": str(run),
            "step": str(step), "archive": str(archive), "source": source,
            "runtime": str(runtime), "summary": str(summary),
            "created_seq": self._touch(),
        }
        self._nodes[eid] = node
        return copy.deepcopy(node)

    def evidence_ids(self) -> list[str]:
        return [n["id"] for n in self._nodes.values() if n["kind"] == "evidence"]

    # ------------------------------------------------------------ facts
    def add_fact(self, claim: str, *, status: str = "hypothesis",
                 evidence: Iterable[str] | None = None, kind: str = "finding",
                 severity: str = "info", source_intent: str = "",
                 attrs: dict | None = None, fact_id: str | None = None) -> dict:
        if status not in FACT_STATUSES:
            raise GraphError(f"非法 fact 状态: {status!r}")
        ev_ids = list(dict.fromkeys(str(e) for e in (evidence or [])))
        if status == "confirmed":
            if not ev_ids:
                raise EvidenceRequired(f"fact {claim!r} 无证据，不能 confirmed")
            for eid in ev_ids:
                node = self._nodes.get(eid)
                if node is None or node.get("kind") != "evidence":
                    raise EvidenceRequired(f"fact {claim!r} 引用了不存在的证据 {eid}")
                if not _SHA256_RE.match(str(node.get("sha256") or "")):
                    raise EvidenceRequired(f"证据 {eid} 缺少 sha256")
        fid = fact_id or self._next_id("fact")
        node = {
            "id": fid, "kind": "fact", "claim": str(claim), "fact_kind": str(kind),
            "status": status, "evidence": ev_ids,
            "severity": severity if severity in SEVERITIES else "info",
            "source_intent": str(source_intent), "attrs": dict(attrs or {}),
            "created_seq": self._touch(),
        }
        if fid in self._nodes:
            raise GraphError(f"fact 已存在: {fid}")
        self._nodes[fid] = node
        for eid in ev_ids:
            self.add_edge(fid, eid, "derived_from")
        return copy.deepcopy(node)

    def confirm_fact(self, fact_id: str, evidence: Iterable[str]) -> dict:
        node = self._node(fact_id, "fact")
        ev_ids = list(dict.fromkeys(str(e) for e in evidence))
        if not ev_ids:
            raise EvidenceRequired("confirm_fact 需要 probe 证据")
        for eid in ev_ids:
            self._node(eid, "evidence")
        node["status"] = "confirmed"
        node["evidence"] = list(dict.fromkeys([*node.get("evidence", []), *ev_ids]))
        for eid in ev_ids:
            self.add_edge(fact_id, eid, "derived_from")
        return copy.deepcopy(node)

    def refute_fact(self, fact_id: str, reason: str = "") -> dict:
        node = self._node(fact_id, "fact")
        node["status"] = "refuted"
        node["refute_reason"] = str(reason)
        return copy.deepcopy(node)

    def facts(self, *, status: str | None = None, fact_kind: str | None = None) -> list[dict]:
        out = []
        for node in self._nodes.values():
            if node["kind"] != "fact":
                continue
            if status and node.get("status") != status:
                continue
            if fact_kind and node.get("fact_kind") != fact_kind:
                continue
            out.append(copy.deepcopy(node))
        return sorted(out, key=lambda n: n.get("created_seq", 0))

    def confirmed_facts(self, *, fact_kind: str | None = None) -> list[dict]:
        return self.facts(status="confirmed", fact_kind=fact_kind)

    def has_confirmed(self, *, fact_kind: str, min_severity: str = "info",
                      min_count: int = 1) -> bool:
        need = severity_rank(min_severity)
        hits = [f for f in self.confirmed_facts(fact_kind=fact_kind)
                if severity_rank(f.get("severity")) >= need and f.get("evidence")]
        return len(hits) >= max(1, int(min_count))

    # ------------------------------------------------------------ intents
    def add_intent(self, role: str, module: str, params: dict | None = None, *,
                   priority: int = 5, cost_tokens: int = 100,
                   requires: Iterable[str] | None = None,
                   produces: Iterable[str] | None = None,
                   success: str = "", writes: bool = False,
                   cleanup: bool = False, max_attempts: int = 2,
                   rationale: str = "", expected_evidence: Iterable[str] | None = None,
                   probe: bool = True, intent_id: str | None = None,
                   tags: Iterable[str] | None = None) -> dict:
        if role not in ROLES:
            raise GraphError(f"未知角色: {role!r}（仅 {ROLES}）")
        if not str(module or "").strip():
            raise GraphError("intent 缺 module")
        req_ids = [str(r) for r in (requires or [])]
        for rid in req_ids:
            if rid not in self._nodes:
                raise GraphError(f"intent 依赖不存在的节点: {rid}")
        iid = intent_id or self._next_id("intent")
        if iid in self._nodes:
            raise GraphError(f"intent 已存在: {iid}")
        node = {
            "id": iid, "kind": "intent", "role": role, "module": str(module),
            "params": dict(params or {}), "priority": int(priority),
            "cost_tokens": max(0, int(cost_tokens)), "status": "open",
            "requires": req_ids, "produces": [str(p) for p in (produces or [])],
            "success": str(success), "writes": bool(writes), "cleanup": bool(cleanup),
            "probe": bool(probe), "max_attempts": max(1, int(max_attempts)),
            "attempts": 0, "lease_owner": "", "lease_until": 0.0,
            "next_attempt_at": 0.0, "last_error": "",
            "rationale": str(rationale),
            "expected_evidence": [str(e) for e in (expected_evidence or [])],
            "tags": [str(t) for t in (tags or [])],
            "result": None, "evidence": [],
            "created_seq": self._touch(),
        }
        self._nodes[iid] = node
        for rid in req_ids:
            self.add_edge(iid, rid, "requires")
        return copy.deepcopy(node)

    def intents(self, *, status: str | None = None,
                role: str | None = None) -> list[dict]:
        out = []
        for node in self._nodes.values():
            if node["kind"] != "intent":
                continue
            if status and node.get("status") != status:
                continue
            if role and node.get("role") != role:
                continue
            out.append(copy.deepcopy(node))
        return sorted(out, key=lambda n: (n.get("priority", 0), -n.get("created_seq", 0)))

    def _requirements_met(self, intent: dict) -> bool:
        for rid in intent.get("requires") or []:
            dep = self._nodes.get(rid)
            if dep is None:
                return False
            if dep["kind"] == "fact" and dep.get("status") != "confirmed":
                return False
            if dep["kind"] == "intent" and dep.get("status") != "done":
                return False
            if dep["kind"] == "evidence" and not dep.get("sha256"):
                return False
        return True

    def frontier(self, *, now: float | None = None, memory=None,
                 include_claimed: bool = False) -> list[dict]:
        """Ready intents ordered by priority, then cost, then creation order."""
        ts = time.time() if now is None else float(now)
        ready: list[dict] = []
        for node in self._nodes.values():
            if node["kind"] != "intent":
                continue
            status = node.get("status")
            if status not in ("open", "claimed"):
                continue
            if status == "claimed" and not include_claimed:
                continue
            if float(node.get("next_attempt_at") or 0) > ts:
                continue
            if not self._requirements_met(node):
                continue
            ready.append(copy.deepcopy(node))
        scored = []
        for node in ready:
            bonus, reason = (0.0, "")
            if memory is not None:
                try:
                    bonus, reason = memory.priority_adjustment(node, self)
                except Exception:  # memory is an optimisation, never a gate
                    bonus, reason = 0.0, ""
            score = float(node.get("priority", 0)) + float(bonus)
            scored.append((score, -float(node.get("cost_tokens", 0)),
                           -int(node.get("created_seq", 0)), node["id"], node, reason))
        scored.sort(key=lambda row: (-row[0], -row[1], -row[2], row[3]))
        out = []
        for _, _, _, _, node, reason in scored:
            if reason:
                node["priority_reason"] = reason
            out.append(node)
        return out

    def claim(self, intent_id: str, owner: str, *, lease_seconds: float = 60.0,
              now: float | None = None) -> dict:
        node = self._node(intent_id, "intent")
        ts = time.time() if now is None else float(now)
        if node["status"] not in ("open", "claimed"):
            raise GraphError(f"intent {intent_id} 状态 {node['status']} 不可认领")
        if node["status"] == "claimed" and float(node.get("lease_until") or 0) > ts:
            raise GraphError(f"intent {intent_id} 仍被 {node.get('lease_owner')} 持有")
        if not self._requirements_met(node):
            raise GraphError(f"intent {intent_id} 依赖未满足")
        node["status"] = "claimed"
        node["lease_owner"] = str(owner)
        node["lease_until"] = ts + max(1.0, float(lease_seconds))
        return copy.deepcopy(node)

    def heartbeat(self, intent_id: str, *, lease_seconds: float = 60.0,
                  now: float | None = None) -> dict:
        node = self._node(intent_id, "intent")
        if node["status"] != "claimed":
            raise GraphError(f"intent {intent_id} 未被认领")
        ts = time.time() if now is None else float(now)
        node["lease_until"] = ts + max(1.0, float(lease_seconds))
        return copy.deepcopy(node)

    def complete(self, intent_id: str, *, evidence: Iterable[str] | None = None,
                 result: dict | None = None) -> dict:
        node = self._node(intent_id, "intent")
        if node["status"] not in ("claimed", "open"):
            raise GraphError(f"intent {intent_id} 状态 {node['status']} 不可完成")
        ev_ids = list(dict.fromkeys(str(e) for e in (evidence or [])))
        if node.get("probe", True) and not ev_ids:
            raise EvidenceRequired(f"intent {intent_id} 是探针动作，无证据不得 done")
        for eid in ev_ids:
            self._node(eid, "evidence")
        node["status"] = "done"
        node["evidence"] = ev_ids
        node["result"] = dict(result or {})
        node["lease_owner"] = ""
        node["lease_until"] = 0.0
        for eid in ev_ids:
            self.add_edge(intent_id, eid, "produced_by")
        return copy.deepcopy(node)

    def fail(self, intent_id: str, reason: str, *, retryable: bool = True,
             now: float | None = None, backoff_seconds: float = 0.0) -> dict:
        node = self._node(intent_id, "intent")
        node["attempts"] = int(node.get("attempts", 0)) + 1
        node["last_error"] = str(reason)
        node["lease_owner"] = ""
        node["lease_until"] = 0.0
        ts = time.time() if now is None else float(now)
        if retryable and node["attempts"] < int(node.get("max_attempts", 2)):
            node["status"] = "open"
            node["next_attempt_at"] = ts + max(0.0, float(backoff_seconds))
        else:
            node["status"] = "failed"
        return copy.deepcopy(node)

    def block(self, intent_id: str, reason: str) -> dict:
        node = self._node(intent_id, "intent")
        node["status"] = "blocked"
        node["last_error"] = str(reason)
        node["lease_owner"] = ""
        node["lease_until"] = 0.0
        return copy.deepcopy(node)

    def reclaim_expired(self, *, now: float | None = None,
                        backoff_seconds: float = 0.0) -> list[dict]:
        ts = time.time() if now is None else float(now)
        reclaimed = []
        for node in list(self._nodes.values()):
            if node["kind"] != "intent" or node["status"] != "claimed":
                continue
            if float(node.get("lease_until") or 0) > ts:
                continue
            node["attempts"] = int(node.get("attempts", 0)) + 1
            node["last_error"] = "lease-expired"
            node["lease_owner"] = ""
            node["lease_until"] = 0.0
            if node["attempts"] < int(node.get("max_attempts", 2)):
                node["status"] = "open"
                node["next_attempt_at"] = ts + max(0.0, float(backoff_seconds))
            else:
                node["status"] = "failed"
            reclaimed.append(copy.deepcopy(node))
        return reclaimed

    # ------------------------------------------------------------ hints
    def add_hint(self, text: str, *, source: str = "human", priority: int = 5,
                 created_by: str = "lead", hint_id: str | None = None) -> dict:
        text = str(text or "").strip()
        if not text:
            raise GraphError("hint 不能为空")
        hid = hint_id or self._next_id("hint")
        if hid in self._nodes:
            raise GraphError(f"hint 已存在: {hid}")
        node = {"id": hid, "kind": "hint", "text": text, "source": str(source),
                "priority": int(priority), "created_by": str(created_by),
                "created_seq": self._touch()}
        self._nodes[hid] = node
        return copy.deepcopy(node)

    def hints(self) -> list[dict]:
        return sorted((copy.deepcopy(n) for n in self._nodes.values()
                       if n["kind"] == "hint"), key=lambda n: n.get("created_seq", 0))

    # ------------------------------------------------------------ edges
    def add_edge(self, src: str, dst: str, relation: str) -> dict:
        if relation not in RELATIONS:
            raise GraphError(f"未知边关系: {relation!r}")
        if src not in self._nodes or dst not in self._nodes:
            raise GraphError(f"边端点不存在: {src} -> {dst}")
        key = (src, dst, relation)
        if key in self._edge_set:
            return {"src": src, "dst": dst, "relation": relation}
        edge = {"src": src, "dst": dst, "relation": relation}
        self._edges.append(edge)
        self._edge_set.add(key)
        return dict(edge)

    def edges(self) -> list[dict]:
        return copy.deepcopy(self._edges)

    def _node(self, node_id: str, kind: str | None = None) -> dict:
        node = self._nodes.get(str(node_id))
        if node is None:
            raise GraphError(f"未知节点: {node_id}")
        if kind and node["kind"] != kind:
            raise GraphError(f"节点 {node_id} 是 {node['kind']}，不是 {kind}")
        return node

    def node(self, node_id: str) -> dict:
        """Public copy of a node (used to emit replayable events after folding)."""
        return copy.deepcopy(self._node(node_id))

    # ------------------------------------------------------------ metrics
    def evidence_coverage(self) -> float:
        confirmed = self.confirmed_facts()
        if not confirmed:
            return 0.0
        backed = sum(1 for f in confirmed if f.get("evidence"))
        return round(backed / len(confirmed), 4)

    def summary(self, *, memory=None, now: float | None = None) -> dict:
        facts = self.facts()
        intents = self.intents()
        counts = {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "facts": len(facts),
            "confirmed_facts": sum(1 for f in facts if f["status"] == "confirmed"),
            "hypotheses": sum(1 for f in facts if f["status"] == "hypothesis"),
            "intents": len(intents),
            "intent_done": sum(1 for i in intents if i["status"] == "done"),
            "intent_failed": sum(1 for i in intents if i["status"] == "failed"),
            "intent_blocked": sum(1 for i in intents if i["status"] == "blocked"),
            "evidence": len(self.evidence_ids()),
            "hints": len(self.hints()),
            "evidence_coverage": self.evidence_coverage(),
        }
        return {
            **counts,
            "objective": self.objective,
            "frontier": [i["id"] for i in self.frontier(now=now, memory=memory)],
            "confirmed": [
                {"id": f["id"], "kind": f["fact_kind"], "severity": f["severity"],
                 "claim": f["claim"], "evidence": f["evidence"]}
                for f in facts if f["status"] == "confirmed"
            ],
        }

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict:
        return {
            "schema": GRAPH_SCHEMA,
            "objective": self.objective,
            "counter": dict(self._counter),
            "created": self._created,
            "nodes": [copy.deepcopy(self._nodes[k]) for k in
                      sorted(self._nodes, key=lambda x: self._nodes[x].get("created_seq", 0))],
            "edges": copy.deepcopy(self._edges),
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "PlanGraph":
        if not isinstance(doc, dict) or doc.get("schema") != GRAPH_SCHEMA:
            raise GraphError("不是 inkblade-agent-graph/1 文档")
        graph = cls(objective=str(doc.get("objective") or ""))
        graph._counter = {str(k): int(v) for k, v in (doc.get("counter") or {}).items()}
        graph._created = int(doc.get("created") or 0)
        for node in doc.get("nodes") or []:
            if not isinstance(node, dict) or "id" not in node or "kind" not in node:
                raise GraphError("图节点非法")
            graph._nodes[str(node["id"])] = copy.deepcopy(node)
        for edge in doc.get("edges") or []:
            key = (str(edge.get("src")), str(edge.get("dst")), str(edge.get("relation")))
            graph._edge_set.add(key)
            graph._edges.append({"src": key[0], "dst": key[1], "relation": key[2]})
        return graph

    # ------------------------------------------------------------ event folding
    def apply_event(self, event: dict) -> None:
        """Replay one runtime event into the graph (idempotent for duplicates)."""
        kind = str(event.get("kind") or "")
        payload = event.get("payload") or {}
        if kind == "graph.evidence.added":
            node = payload.get("evidence") or {}
            try:
                self.add_evidence(node.get("sha256", ""), run=node.get("run", ""),
                                  step=node.get("step", ""), archive=node.get("archive", ""),
                                  source=node.get("source", "probe"),
                                  runtime=node.get("runtime", ""),
                                  summary=node.get("summary", ""),
                                  evidence_id=node.get("id"))
            except EvidenceRequired:
                pass
        elif kind == "graph.fact.added":
            node = payload.get("fact") or {}
            try:
                self.add_fact(node.get("claim", ""), status=node.get("status", "hypothesis"),
                              evidence=node.get("evidence") or [],
                              kind=node.get("fact_kind", "finding"),
                              severity=node.get("severity", "info"),
                              source_intent=node.get("source_intent", ""),
                              attrs=node.get("attrs") or {},
                              fact_id=node.get("id"))
            except (GraphError, EvidenceRequired):
                pass
        elif kind == "graph.intent.added":
            node = payload.get("intent") or {}
            try:
                self.add_intent(node.get("role", "recon"), node.get("module", ""),
                                node.get("params") or {},
                                priority=node.get("priority", 5),
                                cost_tokens=node.get("cost_tokens", 100),
                                requires=node.get("requires") or [],
                                produces=node.get("produces") or [],
                                success=node.get("success", ""),
                                writes=node.get("writes", False),
                                cleanup=node.get("cleanup", False),
                                max_attempts=node.get("max_attempts", 2),
                                rationale=node.get("rationale", ""),
                                expected_evidence=node.get("expected_evidence") or [],
                                probe=node.get("probe", True),
                                intent_id=node.get("id"),
                                tags=node.get("tags") or [])
            except GraphError:
                pass
        elif kind == "graph.hint.added":
            node = payload.get("hint") or {}
            try:
                self.add_hint(node.get("text", ""), source=node.get("source", "human"),
                              priority=node.get("priority", 5),
                              created_by=node.get("created_by", "lead"),
                              hint_id=node.get("id"))
            except GraphError:
                pass
        elif kind == "graph.edge.added":
            edge = payload.get("edge") or {}
            try:
                self.add_edge(edge.get("src", ""), edge.get("dst", ""),
                              edge.get("relation", ""))
            except GraphError:
                pass
        elif kind == "intent.claimed":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["status"] = "claimed"
                node["lease_owner"] = str(payload.get("owner") or "")
                node["lease_until"] = float(payload.get("lease_until") or 0)
        elif kind == "intent.heartbeat":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["lease_until"] = float(payload.get("lease_until") or 0)
        elif kind == "intent.completed":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["status"] = "done"
                node["evidence"] = list(payload.get("evidence") or [])
                node["result"] = copy.deepcopy(payload.get("result") or {})
                node["lease_owner"] = ""
                node["lease_until"] = 0.0
        elif kind == "intent.failed":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["status"] = "failed" if not payload.get("retryable") else "open"
                node["attempts"] = int(payload.get("attempts") or node.get("attempts", 0))
                node["last_error"] = str(payload.get("reason") or "")
                node["next_attempt_at"] = float(payload.get("next_attempt_at") or 0)
        elif kind == "intent.blocked":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["status"] = "blocked"
                node["last_error"] = str(payload.get("reason") or "")
        elif kind == "intent.reclaimed":
            node = self._nodes.get(str(payload.get("intent") or ""))
            if node and node["kind"] == "intent":
                node["status"] = "open" if payload.get("retryable", True) else "failed"
                node["attempts"] = int(payload.get("attempts") or node.get("attempts", 0))
                node["lease_owner"] = ""
                node["lease_until"] = 0.0
                node["next_attempt_at"] = float(payload.get("next_attempt_at") or 0)


def replay_graph(events: Iterable[dict], *, objective: str = "") -> PlanGraph:
    graph = PlanGraph(objective=objective)
    for event in events:
        graph.apply_event(event)
    return graph
