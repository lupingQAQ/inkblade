# -*- coding: utf-8 -*-
"""Coverage graph and machine-checkable closure for the agent runtime.

The planner graph (:mod:`inkblade.agent.graph`) records *why* an action was
selected.  The coverage graph records *what the action covered*:

* assets / services / identities discovered in each cluster;
* reachable and permission edges between them;
* probes that were registered and their baseline ``collect``;
* the probe/read-only checks that touched each asset and the templates used.

Closure is a four-part vector; a run may not be reported as complete until all
four hold **and** the objective itself succeeds:

1. every reachable asset has at least one probe or read-only check;
2. every exploitable permission edge has been attempted, with ``success``
   evidence or a reason for ``failed`` / ``blocked``;
3. every probe is registered and has one completed baseline ``collect``;
4. there is no unhandled planner frontier / unresolved intent.

The proof is written as ``coverage-proof.json``; the Markdown rendering is the
human review surface.  The module also contains thin adapters used by the
supervisor: :class:`CoverageScheduler` prioritises uncovered refs and
:class:`ClosureGatedObjective` refuses success until the closure vector holds.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Any, Iterable

from .graph import PlanGraph
from .scheduler import TaskScheduler

COVERAGE_SCHEMA = "inkblade-agent-coverage/1"
PROOF_SCHEMA = "inkblade-coverage-proof/1"
NODE_KINDS = ("asset", "service", "identity", "probe")
RELATIONS = ("reachable", "exposes", "can", "runs-as", "member-of")
CHECK_MODES = ("probe", "read-only")
ATTEMPT_OUTCOMES = ("success", "failed", "blocked")
STOP_REASONS = ("closed", "frontier-open", "budget-exhausted", "operator-stop",
                "objective-unmet", "policy-refused", "no-probes", "dry-run",
                "error")
PROBE_STATUSES = ("pending", "registered", "ready", "degraded", "failed")

_ASSET_KINDS = ("workload", "node", "api-server", "service", "dataset", "bucket",
                "registry", "other")


class CoverageError(ValueError):
    """Invalid coverage graph operation."""


class CoverageEvidenceRequired(CoverageError):
    """A success/check was recorded without the evidence it requires."""


class CoverageLoopError(CoverageError):
    """A probe parent chain would form a loop."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _checks(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return [str(item) for item in value if str(item or "")]


def budget_exhausted(budget: Any) -> bool:
    """True when any capped budget dimension is fully spent."""
    if budget is None:
        return False
    limits = getattr(budget, "limits", {}) or {}
    spent = getattr(budget, "spent", {}) or {}
    for kind, limit in limits.items():
        try:
            limit = int(limit)
            used = int(spent.get(kind, 0))
        except (TypeError, ValueError):
            continue
        if limit and used >= limit:
            return True
    return False


def stop_reason_for_status(status: str) -> str:
    """Map a supervisor status onto the proof stop_reason vocabulary."""
    return {
        "success": "closed",
        "coverage-gap": "frontier-open",
        "budget-exceeded": "budget-exhausted",
        "stopped": "operator-stop",
        "policy-refused": "policy-refused",
        "dry-run": "dry-run",
        "failed": "objective-unmet",
        "paused": "frontier-open",
    }.get(str(status or ""), "error")


class CoverageGraph:
    """Assets, services, identities, probes and coverage edges for one run."""

    def __init__(self, *, objective: str = "", run_id: str = ""):
        self.objective = str(objective or "")
        self.run_id = str(run_id or "")
        self._nodes: dict[str, dict] = {}
        self._edges: dict[str, dict] = {}
        self._edge_index: dict[tuple, str] = {}
        self._counter: dict[str, int] = {}
        self._created = 0
        self._frontier_items: list[dict] = []

    # ------------------------------------------------------------ ids
    def _next_id(self, prefix: str) -> str:
        n = int(self._counter.get(prefix, 0)) + 1
        self._counter[prefix] = n
        return f"{prefix}-{n}"

    def _touch(self) -> int:
        self._created += 1
        return self._created

    @staticmethod
    def probe_ref(cluster_id: str, probe_id: str) -> str:
        """Stable coverage node id for a probe (``probe:<cluster>/<probe>``)."""
        raw = str(probe_id or "").strip()
        if not raw:
            raise CoverageError("probe_id 不能为空")
        if raw.startswith("probe:"):
            return raw
        cluster = str(cluster_id or "").strip()
        return f"probe:{cluster}/{raw}" if cluster else f"probe:{raw}"

    @staticmethod
    def _split_ref(ref: str) -> tuple[str, str]:
        raw = str(ref or "")
        if not raw.startswith("probe:"):
            raise CoverageError(f"不是 probe 引用: {ref!r}")
        rest = raw[len("probe:"):]
        if "/" in rest:
            cluster, probe = rest.split("/", 1)
            return cluster, probe
        return "", rest

    # ------------------------------------------------------------ assets
    def add_asset(self, asset_id: str, *, cluster_id: str = "", kind: str = "workload",
                  name: str = "", namespace: str = "", address: str = "",
                  reachable: bool = True, attrs: dict | None = None) -> dict:
        aid = str(asset_id or "").strip()
        if not aid:
            raise CoverageError("asset_id 不能为空")
        if kind not in _ASSET_KINDS:
            raise CoverageError(f"未知 asset kind: {kind!r}（{_ASSET_KINDS}）")
        node = self._nodes.get(aid)
        if node is not None and node.get("kind") != "asset":
            raise CoverageError(f"{aid} 已是 {node.get('kind')}，不能再作为 asset")
        if node is None:
            node = {
                "id": aid, "kind": "asset", "created_seq": self._touch(),
                "checks": [], "templates": [], "attrs": {},
            }
            self._nodes[aid] = node
        node.update({
            "asset_kind": str(kind), "cluster_id": str(cluster_id),
            "name": str(name or aid), "namespace": str(namespace),
            "address": str(address), "reachable": bool(reachable),
        })
        node["attrs"].update(dict(attrs or {}))
        return self._view_node(node)

    def add_service(self, service_id: str, *, cluster_id: str = "", asset_id: str = "",
                    name: str = "", namespace: str = "", port: int | None = None,
                    protocol: str = "tcp", address: str = "",
                    reachable: bool = True, attrs: dict | None = None) -> dict:
        sid = str(service_id or "").strip()
        if not sid:
            raise CoverageError("service_id 不能为空")
        node = self._nodes.get(sid)
        if node is not None and node.get("kind") != "service":
            raise CoverageError(f"{sid} 已是 {node.get('kind')}，不能再作为 service")
        if node is None:
            node = {
                "id": sid, "kind": "service", "created_seq": self._touch(),
                "checks": [], "templates": [], "attrs": {},
            }
            self._nodes[sid] = node
        node.update({
            "cluster_id": str(cluster_id), "name": str(name or sid),
            "namespace": str(namespace), "port": int(port) if port else None,
            "protocol": str(protocol), "address": str(address),
            "reachable": bool(reachable),
        })
        node["attrs"].update(dict(attrs or {}))
        if asset_id:
            self._node(asset_id, "asset")
            self.add_edge(asset_id, sid, "exposes")
        return self._view_node(node)

    def add_identity(self, identity_id: str, *, cluster_id: str = "", name: str = "",
                     namespace: str = "", kind: str = "serviceaccount",
                     attrs: dict | None = None) -> dict:
        iid = str(identity_id or "").strip()
        if not iid:
            raise CoverageError("identity_id 不能为空")
        node = self._nodes.get(iid)
        if node is not None and node.get("kind") != "identity":
            raise CoverageError(f"{iid} 已是 {node.get('kind')}，不能再作为 identity")
        if node is None:
            node = {
                "id": iid, "kind": "identity", "created_seq": self._touch(),
                "checks": [], "templates": [], "attrs": {},
            }
            self._nodes[iid] = node
        node.update({
            "identity_kind": str(kind), "cluster_id": str(cluster_id),
            "name": str(name or iid), "namespace": str(namespace),
        })
        node["attrs"].update(dict(attrs or {}))
        return self._view_node(node)

    # ------------------------------------------------------------ edges
    @staticmethod
    def _edge_key(src: str, dst: str, relation: str,
                  attrs: dict | None = None) -> tuple:
        """Permission edges are unique per subject/object/verb/resource/scope."""
        key: tuple = (str(src), str(dst), str(relation))
        if str(relation) == "can":
            data = attrs or {}
            key += (str(data.get("verb") or ""), str(data.get("resource") or ""),
                    str(data.get("scope") or ""))
        return key

    def add_edge(self, src: str, dst: str, relation: str, *, exploitable: bool = False,
                 edge_id: str | None = None, attrs: dict | None = None) -> dict:
        if relation not in RELATIONS:
            raise CoverageError(f"未知覆盖边关系: {relation!r}（{RELATIONS}）")
        self._node(src)
        self._node(dst)
        key = self._edge_key(src, dst, relation, attrs)
        existing = self._edge_index.get(key)
        if existing:
            edge = self._edges[existing]
            edge["exploitable"] = bool(edge.get("exploitable")) or bool(exploitable)
            edge["attrs"].update(dict(attrs or {}))
            return copy.deepcopy(edge)
        if edge_id and edge_id in self._edges:
            raise CoverageError(f"edge id 已存在: {edge_id}")
        eid = str(edge_id or self._next_id("edge"))
        edge = {
            "id": eid, "src": str(src), "dst": str(dst), "relation": str(relation),
            "exploitable": bool(exploitable), "attempts": [],
            "attrs": dict(attrs or {}), "created_seq": self._touch(),
        }
        self._edges[eid] = edge
        self._edge_index[key] = eid
        return copy.deepcopy(edge)

    def add_permission(self, subject_id: str, object_id: str, *, verb: str,
                       resource: str, scope: str = "", exploitable: bool = True,
                       edge_id: str | None = None, attrs: dict | None = None) -> dict:
        merged = {"verb": str(verb), "resource": str(resource), "scope": str(scope)}
        merged.update(dict(attrs or {}))
        return self.add_edge(subject_id, object_id, "can", exploitable=exploitable,
                             edge_id=edge_id, attrs=merged)

    def add_reachable(self, src: str, dst: str, *, via: str = "",
                      edge_id: str | None = None, attrs: dict | None = None) -> dict:
        merged = {"via": str(via)}
        merged.update(dict(attrs or {}))
        return self.add_edge(src, dst, "reachable", exploitable=False,
                             edge_id=edge_id, attrs=merged)

    # ------------------------------------------------------------ probes
    def register_probe(self, probe_id: str, *, cluster_id: str = "",
                       parent_id: str = "", transport: str = "probe",
                       registered: bool = True, attrs: dict | None = None) -> dict:
        raw = str(probe_id or "").strip()
        if not raw:
            raise CoverageError("probe_id 不能为空")
        if raw.startswith("probe:"):
            node_id = raw
            cluster, pid = self._split_ref(raw)
            cluster = str(cluster_id or cluster)
        else:
            pid = raw
            cluster = str(cluster_id or "")
            node_id = self.probe_ref(cluster, pid)
        parent_ref = ""
        if parent_id:
            parent_ref = str(parent_id)
            if not parent_ref.startswith("probe:"):
                parent_ref = self.probe_ref(cluster, parent_ref)
        node = self._nodes.get(node_id)
        if node is not None:
            if node.get("kind") != "probe":
                raise CoverageError(f"{node_id} 已是 {node.get('kind')}，不是 probe")
            if node.get("parent_id") and parent_ref and node["parent_id"] != parent_ref:
                raise CoverageError(f"probe {node_id} 已有父探针 {node['parent_id']}")
            if parent_ref and parent_ref != node_id:
                self._assert_probe_acyclic(node_id, parent_ref)
            duplicate = True
            if parent_ref:
                node["parent_id"] = parent_ref
            if registered:
                node["registered"] = True
            node["transport"] = str(transport or node.get("transport") or "probe")
            node["attrs"].update(dict(attrs or {}))
        else:
            duplicate = False
            if parent_ref:
                self._node(parent_ref, "probe")
                self._assert_probe_acyclic(node_id, parent_ref)
            node = {
                "id": node_id, "kind": "probe", "probe_id": pid,
                "cluster_id": cluster, "parent_id": parent_ref,
                "transport": str(transport or "probe"),
                "registered": bool(registered),
                "status": "registered" if registered else "pending",
                "baseline": {}, "checks": [], "templates": [],
                "attrs": dict(attrs or {}), "created_seq": self._touch(),
            }
            self._nodes[node_id] = node
        if registered:
            node["status"] = "registered" if not node.get("baseline") else node["status"]
        view = self._view_node(node)
        view["duplicate"] = duplicate
        return view

    def _assert_probe_acyclic(self, node_id: str, parent_ref: str) -> None:
        seen: set[str] = set()
        current = parent_ref
        while current:
            if current == node_id:
                raise CoverageLoopError(
                    f"探针父链成环: {node_id} -> {parent_ref}")
            if current in seen:
                raise CoverageLoopError(f"探针父链已存在环: {current}")
            seen.add(current)
            parent = self._nodes.get(current)
            if parent is None:
                raise CoverageError(f"父探针不存在: {current}")
            if parent.get("kind") != "probe":
                raise CoverageError(f"父探针 {current} 不是 probe")
            current = str(parent.get("parent_id") or "")

    def mark_baseline(self, probe_id: str, *, ok: bool = True, evidence: Any = "",
                      detail: str = "", command: str = "collect",
                      latency_ms: int | None = None) -> dict:
        node = self._probe_node(probe_id)
        if not node.get("registered"):
            raise CoverageEvidenceRequired(
                f"probe {node['id']} 未注册，不能记录 baseline collect")
        refs = _checks(evidence)
        if ok and not refs:
            raise CoverageEvidenceRequired("baseline collect 成功需要证据引用")
        if not ok and not str(detail or "").strip():
            raise CoverageEvidenceRequired("baseline collect 失败需要原因")
        node["baseline"] = {
            "ok": bool(ok), "evidence": refs, "detail": str(detail),
            "command": str(command), "latency_ms": int(latency_ms or 0),
            "ts": time.time(),
        }
        node["status"] = "ready" if ok else "degraded"
        return self._view_node(node)

    # ------------------------------------------------------------ checks
    def mark_check(self, asset_id: str, *, probe_id: str = "", module: str = "",
                   mode: str = "probe", ok: bool = True, evidence: Any = None,
                   detail: str = "", template: str = "") -> dict:
        node = self._node(asset_id)
        if node.get("kind") not in ("asset", "service"):
            raise CoverageError(f"{asset_id} 不是 asset/service，不能记录检查")
        if mode not in CHECK_MODES:
            raise CoverageError(f"未知检查模式: {mode!r}（{CHECK_MODES}）")
        probe_ref = ""
        if mode == "probe":
            if not str(probe_id or "").strip():
                raise CoverageEvidenceRequired("probe 检查必须引用已注册探针")
            probe = self._probe_node(probe_id)
            if not probe.get("registered"):
                raise CoverageEvidenceRequired(
                    f"probe {probe['id']} 未注册，不能作为检查来源")
            probe_ref = probe["id"]
        refs = _checks(evidence)
        if ok and not refs:
            raise CoverageEvidenceRequired("成功的覆盖检查需要证据引用")
        if not ok and not str(detail or "").strip():
            raise CoverageEvidenceRequired("失败的覆盖检查需要原因")
        key = str(template or module or mode)
        record = {
            "probe_id": probe_ref, "module": str(module), "mode": str(mode),
            "ok": bool(ok), "evidence": refs, "detail": str(detail),
            "template": key, "ts": time.time(),
        }
        node.setdefault("checks", []).append(record)
        if key and key not in node.setdefault("templates", []):
            node["templates"].append(key)
        return copy.deepcopy(record)

    def mark_permission_attempt(self, edge_id: str, *, outcome: str, reason: str = "",
                                evidence: Any = "", intent: str = "",
                                detail: str = "") -> dict:
        edge = self._edges.get(str(edge_id))
        if edge is None:
            raise CoverageError(f"未知覆盖边: {edge_id}")
        if edge.get("relation") != "can" or not edge.get("exploitable"):
            raise CoverageError(f"{edge_id} 不是可利用权限边")
        if outcome not in ATTEMPT_OUTCOMES:
            raise CoverageError(f"未知尝试结果: {outcome!r}（{ATTEMPT_OUTCOMES}）")
        refs = _checks(evidence)
        if outcome == "success" and not refs:
            raise CoverageEvidenceRequired("权限边成功尝试需要证据引用")
        if outcome in ("failed", "blocked") and not str(reason or "").strip():
            raise CoverageEvidenceRequired(f"权限边 {outcome} 必须写明原因")
        record = {
            "outcome": str(outcome), "reason": str(reason), "evidence": refs,
            "intent": str(intent), "detail": str(detail), "ts": time.time(),
        }
        edge.setdefault("attempts", []).append(record)
        return copy.deepcopy(record)

    # ------------------------------------------------------------ frontier
    def add_frontier_item(self, kind: str, ref: str, reason: str, *,
                          detail: str = "") -> dict:
        item = {"kind": str(kind), "id": str(ref), "reason": str(reason),
                "detail": str(detail)}
        key = (item["kind"], item["id"], item["reason"])
        for existing in self._frontier_items:
            if (existing["kind"], existing["id"], existing["reason"]) == key:
                return copy.deepcopy(existing)
        self._frontier_items.append(item)
        return copy.deepcopy(item)

    def clear_frontier_item(self, ref: str) -> int:
        before = len(self._frontier_items)
        self._frontier_items = [i for i in self._frontier_items if i["id"] != str(ref)]
        return before - len(self._frontier_items)

    def frontier(self, *, graph: PlanGraph | None = None,
                 include_unknown_frontier: bool = True,
                 include_intents: bool = True) -> list[dict]:
        items: list[dict] = []
        for node in self._nodes.values():
            kind = node.get("kind")
            if kind in ("asset", "service") and node.get("reachable") \
                    and not node.get("checks"):
                items.append({
                    "kind": "asset", "id": node["id"],
                    "reason": "unchecked-reachable-asset",
                    "detail": f"{kind} {node.get('name') or node['id']} 没有检查",
                })
            elif kind == "probe":
                if not node.get("registered"):
                    items.append({
                        "kind": "probe", "id": node["id"],
                        "reason": "probe-not-registered",
                        "detail": "探针已发现但未注册",
                    })
                elif not node.get("baseline"):
                    items.append({
                        "kind": "probe", "id": node["id"],
                        "reason": "baseline-collect-missing",
                        "detail": "未完成基线 collect",
                    })
                elif not node.get("baseline", {}).get("ok"):
                    items.append({
                        "kind": "probe", "id": node["id"],
                        "reason": "baseline-collect-failed",
                        "detail": str(node.get("baseline", {}).get("detail") or ""),
                    })
        for edge in self._edges.values():
            if edge.get("relation") == "can" and edge.get("exploitable") \
                    and not edge.get("attempts"):
                attrs = edge.get("attrs") or {}
                items.append({
                    "kind": "permission", "id": edge["id"],
                    "reason": "unattempted-exploitable-edge",
                    "detail": f"{attrs.get('verb') or '?'} "
                              f"{attrs.get('resource') or '?'}",
                })
        items.extend(copy.deepcopy(self._frontier_items))
        if graph is not None and include_intents:
            for intent in graph.intents():
                if intent.get("status") not in ("open", "claimed"):
                    continue
                reason = "unhandled-frontier"
                if intent.get("status") == "open" and not graph.frontier(
                        now=time.time() + 10 ** 9, include_claimed=True):
                    reason = "unroutable-intent"
                items.append({
                    "kind": "intent", "id": intent["id"], "reason": reason,
                    "detail": f"{intent.get('role')}/{intent.get('module')} "
                              f"status={intent.get('status')}",
                })
        elif graph is None and include_unknown_frontier:
            items.append({
                "kind": "frontier", "id": "*", "reason": "frontier-unavailable",
                "detail": "未提供 planner 图，无法证明 frontier 为空",
            })
        dedup: dict[tuple[str, str, str], dict] = {}
        for item in items:
            key = (item["kind"], item["id"], item["reason"])
            dedup[key] = item
        return sorted(dedup.values(), key=lambda i: (i["kind"], i["id"], i["reason"]))

    # ------------------------------------------------------------ metrics
    def _asset_nodes(self) -> list[dict]:
        return [n for n in self._nodes.values()
                if n.get("kind") in ("asset", "service")]

    def _probe_nodes(self) -> list[dict]:
        return [n for n in self._nodes.values() if n.get("kind") == "probe"]

    def _exploitable_edges(self) -> list[dict]:
        return [e for e in self._edges.values()
                if e.get("relation") == "can" and e.get("exploitable")]

    def coverage(self) -> dict:
        assets = self._asset_nodes()
        reachable = [n for n in assets if n.get("reachable")]
        checked = [n for n in assets if n.get("checks")]
        templates = sorted({t for n in assets for t in n.get("templates") or []})
        probes = self._probe_nodes()
        registered = [p for p in probes if p.get("registered")]
        baselined = [p for p in probes
                     if p.get("registered") and p.get("baseline", {}).get("ok")]
        permissions = self._exploitable_edges()
        attempted = [e for e in permissions if e.get("attempts")]
        return {
            "assets": len(assets),
            "reachable_assets": len(reachable),
            "checked_assets": len(checked),
            "asset_coverage": round(len(checked) / len(reachable), 4) if reachable else 1.0,
            "services": sum(1 for n in assets if n.get("kind") == "service"),
            "identities": sum(1 for n in self._nodes.values()
                              if n.get("kind") == "identity"),
            "permission_edges": len(permissions),
            "attempted_permission_edges": len(attempted),
            "permission_coverage": round(len(attempted) / len(permissions), 4)
            if permissions else 1.0,
            "probes": len(probes),
            "registered_probes": len(registered),
            "baselined_probes": len(baselined),
            "probe_coverage": round(len(baselined) / len(probes), 4) if probes else 1.0,
            "checks": sum(len(n.get("checks") or []) for n in assets),
            "templates_checked": len(templates),
            "templates": templates,
            "frontier": len(self.frontier(include_unknown_frontier=False,
                                          include_intents=False)),
        }

    # ------------------------------------------------------------ evaluation
    def evaluate(self, *, graph: PlanGraph | None = None, objective: Any = None,
                 budget: Any = None, stop_reason: str = "") -> dict:
        if isinstance(objective, str) and objective:
            from .objectives import get_objective

            objective = get_objective(objective)
        if getattr(objective, "coverage", None) is self:
            objective = None
        items = self.frontier(graph=graph)
        asset_gaps = [i for i in items if i["kind"] == "asset"]
        permission_gaps = [i for i in items if i["kind"] == "permission"]
        probe_gaps = [i for i in items if i["kind"] == "probe"]
        frontier_gaps = [i for i in items
                         if i["kind"] in ("intent", "frontier", "blocker")]
        cov = self.coverage()
        criteria = [
            {
                "id": "coverage:assets", "ok": not asset_gaps,
                "detail": f"{cov['checked_assets']}/{cov['reachable_assets']} "
                          f"个可达资产已有 probe/只读检查",
                "gaps": asset_gaps,
            },
            {
                "id": "coverage:permissions", "ok": not permission_gaps,
                "detail": f"{cov['attempted_permission_edges']}/"
                          f"{cov['permission_edges']} 条可利用权限边已尝试",
                "gaps": permission_gaps,
            },
            {
                "id": "coverage:probes", "ok": not probe_gaps,
                "detail": f"{cov['baselined_probes']}/{cov['probes']} 个探针已注册"
                          f"并完成基线 collect",
                "gaps": probe_gaps,
            },
            {
                "id": "coverage:frontier", "ok": not frontier_gaps,
                "detail": f"{len(frontier_gaps)} 个未处理 frontier/未收敛意图",
                "gaps": frontier_gaps,
            },
        ]
        closed = all(c["ok"] for c in criteria)
        objective_success = None
        if objective is not None and graph is not None:
            try:
                objective_success = bool(objective.success(graph))
            except Exception:  # objective is a gate, never a crash source
                objective_success = False
        if stop_reason:
            reason = str(stop_reason)
            if reason not in STOP_REASONS:
                reason = stop_reason_for_status(reason)
        elif budget_exhausted(budget):
            reason = "budget-exhausted"
        elif closed and objective_success is not False:
            reason = "closed"
        elif objective_success is False:
            reason = "objective-unmet"
        elif not self._probe_nodes() and items:
            reason = "no-probes"
        else:
            reason = "frontier-open"
        if reason not in STOP_REASONS:
            reason = "error"
        return {
            "closed": closed,
            "success": closed and objective_success is not False,
            "objective_success": objective_success,
            "criteria": criteria,
            "gaps": items,
            "coverage": cov,
            "stop_reason": reason,
            "budget_exhausted": budget_exhausted(budget),
        }

    # ------------------------------------------------------------ proof
    def proof(self, *, graph: PlanGraph | None = None, objective: Any = None,
              budget: Any = None, run_id: str = "",
              stop_reason: str = "") -> dict:
        evaluation = self.evaluate(graph=graph, objective=objective,
                                   budget=budget, stop_reason=stop_reason)
        reason = evaluation["stop_reason"]
        nodes = [self._view_node(n) for n in
                 sorted(self._nodes.values(), key=lambda x: x.get("created_seq", 0))]
        edges = [self._view_edge(e) for e in
                 sorted(self._edges.values(), key=lambda x: x.get("created_seq", 0))]
        gap_counts: dict[str, int] = {}
        for gap in evaluation["gaps"]:
            gap_counts[gap["reason"]] = gap_counts.get(gap["reason"], 0) + 1
        objective_key = ""
        if isinstance(objective, str):
            objective_key = objective
        elif objective is not None:
            objective_key = str(getattr(objective, "key", "") or self.objective)
        return {
            "schema": PROOF_SCHEMA,
            "generated_at": time.time(),
            "run_id": str(run_id or self.run_id),
            "objective": objective_key or self.objective,
            "closed": bool(evaluation["closed"]),
            "success": bool(evaluation["success"]),
            "objective_success": evaluation["objective_success"],
            "stop_reason": reason,
            "criteria": evaluation["criteria"],
            "coverage": evaluation["coverage"],
            "gaps": evaluation["gaps"],
            "gap_counts": gap_counts,
            "budget": budget.to_dict() if hasattr(budget, "to_dict") else None,
            "nodes": nodes,
            "edges": edges,
            "state": self.to_dict(),
        }

    def write_proof(self, path: str | Path, *, proof: dict | None = None,
                    graph: PlanGraph | None = None, objective: Any = None,
                    budget: Any = None, run_id: str = "",
                    stop_reason: str = "") -> dict:
        doc = proof if proof is not None else self.proof(
            graph=graph, objective=objective, budget=budget, run_id=run_id,
            stop_reason=stop_reason)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(_json_safe(doc), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(target)
        return doc

    @classmethod
    def from_proof(cls, doc: dict) -> "CoverageGraph":
        state = (doc or {}).get("state")
        if not isinstance(state, dict):
            raise CoverageError("coverage proof 缺少 state，无法恢复")
        return cls.from_dict(state)

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict:
        return {
            "schema": COVERAGE_SCHEMA,
            "objective": self.objective,
            "run_id": self.run_id,
            "counter": dict(self._counter),
            "created": self._created,
            "nodes": [copy.deepcopy(n) for n in
                      sorted(self._nodes.values(),
                             key=lambda x: x.get("created_seq", 0))],
            "edges": [copy.deepcopy(e) for e in
                      sorted(self._edges.values(),
                             key=lambda x: x.get("created_seq", 0))],
            "frontier_items": copy.deepcopy(self._frontier_items),
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "CoverageGraph":
        if not isinstance(doc, dict) or doc.get("schema") != COVERAGE_SCHEMA:
            raise CoverageError("不是 inkblade-agent-coverage/1 文档")
        graph = cls(objective=str(doc.get("objective") or ""),
                    run_id=str(doc.get("run_id") or ""))
        graph._counter = {str(k): int(v) for k, v in (doc.get("counter") or {}).items()}
        graph._created = int(doc.get("created") or 0)
        for node in doc.get("nodes") or []:
            if not isinstance(node, dict) or not node.get("id") or not node.get("kind"):
                raise CoverageError("覆盖图节点非法")
            graph._nodes[str(node["id"])] = copy.deepcopy(node)
        for edge in doc.get("edges") or []:
            if not isinstance(edge, dict) or "id" not in edge:
                raise CoverageError("覆盖图边非法")
            graph._edges[str(edge["id"])] = copy.deepcopy(edge)
            graph._edge_index[graph._edge_key(
                edge.get("src"), edge.get("dst"), edge.get("relation"),
                edge.get("attrs") or {})] = str(edge["id"])
        graph._frontier_items = [copy.deepcopy(i) for i in
                                 doc.get("frontier_items") or [] if isinstance(i, dict)]
        return graph

    # ------------------------------------------------------------ views
    def node(self, node_id: str) -> dict:
        return self._view_node(self._node(node_id))

    def nodes(self, *, kind: str | None = None) -> list[dict]:
        return [self._view_node(n) for n in sorted(
            self._nodes.values(), key=lambda x: x.get("created_seq", 0))
            if not kind or n.get("kind") == kind]

    def edges(self, *, relation: str | None = None) -> list[dict]:
        return [self._view_edge(e) for e in sorted(
            self._edges.values(), key=lambda x: x.get("created_seq", 0))
            if not relation or e.get("relation") == relation]

    def has_node(self, node_id: str) -> bool:
        return str(node_id) in self._nodes

    def _node(self, node_id: str, kind: str | None = None) -> dict:
        node = self._nodes.get(str(node_id))
        if node is None:
            raise CoverageError(f"未知覆盖节点: {node_id}")
        if kind and node.get("kind") != kind:
            raise CoverageError(f"{node_id} 是 {node.get('kind')}，不是 {kind}")
        return node

    def _probe_node(self, probe_id: str) -> dict:
        raw = str(probe_id or "").strip()
        node = self._nodes.get(raw)
        if node is not None and node.get("kind") == "probe":
            return node
        hits = [n for n in self._probe_nodes() if n.get("probe_id") == raw]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise CoverageError(f"未知 probe: {probe_id!r}")
        raise CoverageError(f"probe id 有歧义，请使用 cluster/probe 引用: {probe_id!r}")

    @staticmethod
    def _view_node(node: dict) -> dict:
        view = copy.deepcopy(node)
        checks = view.get("checks") or []
        view["checked"] = bool(checks)
        view["check_count"] = len(checks)
        view["check_ok"] = any(bool(c.get("ok")) for c in checks)
        view["baseline_ok"] = bool((view.get("baseline") or {}).get("ok"))
        return view

    @staticmethod
    def _view_edge(edge: dict) -> dict:
        view = copy.deepcopy(edge)
        attempts = view.get("attempts") or []
        view["attempted"] = bool(attempts)
        view["attempt_count"] = len(attempts)
        view["last_outcome"] = attempts[-1].get("outcome") if attempts else ""
        return view

    # ------------------------------------------------------------ intent hints
    @staticmethod
    def intent_refs(intent: dict) -> list[str]:
        refs: list[str] = []
        for tag in intent.get("tags") or []:
            tag = str(tag)
            if tag.startswith("coverage:"):
                refs.append(tag.split(":", 1)[1])
        params = intent.get("params") or {}
        for key in ("coverage", "coverage_refs"):
            value = params.get(key)
            if isinstance(value, str):
                refs.append(value)
            elif isinstance(value, (list, tuple)):
                refs.extend(str(v) for v in value)
        return list(dict.fromkeys(r for r in refs if r))

    def intent_priority(self, intent: dict) -> int:
        """Bonus used by :class:`CoverageScheduler` (100 = uncovered ref)."""
        refs = self.intent_refs(intent)
        if not refs:
            return 0
        open_items = self.frontier(include_unknown_frontier=False,
                                   include_intents=False)
        open_ids = {i["id"] for i in open_items}
        return 100 if any(ref in open_ids for ref in refs) else 0


# --------------------------------------------------------------------------
# Scheduler / objective integration
# --------------------------------------------------------------------------
class CoverageScheduler(TaskScheduler):
    """TaskScheduler that puts intents covering open coverage refs first."""

    def __init__(self, graph: PlanGraph, budget, runtime=None, *, coverage=None,
                 **kwargs):
        super().__init__(graph, budget, runtime, **kwargs)
        self.coverage = coverage

    @classmethod
    def from_scheduler(cls, other: TaskScheduler,
                       coverage: CoverageGraph) -> "CoverageScheduler":
        kwargs = {
            "memory": other.memory, "policy": other.policy, "mode": other.mode,
            "max_attempts": other.max_attempts, "lease_seconds": other.lease_seconds,
            "retry_backoff": other.retry_backoff, "clock": other._clock,
        }
        if hasattr(other, "defense_gate"):
            kwargs["defense_gate"] = other.defense_gate
        scheduler = cls(other.graph, other.budget, other.runtime,
                        coverage=coverage, **kwargs)
        scheduler.status = other.status
        scheduler._tripped = bool(getattr(other, "_tripped", False))
        return scheduler

    def _ordered(self, now: float) -> list[dict]:
        frontier = super()._ordered(now)
        if self.coverage is not None:
            # Stable: within uncovered/covered groups keep priority/cost order.
            frontier.sort(key=lambda n: -int(self.coverage.intent_priority(n)))
        return frontier

    def state(self) -> dict:
        view = super().state()
        if self.coverage is not None:
            view["coverage"] = self.coverage.coverage()
            view["coverage_gaps"] = self.coverage.frontier(graph=self.graph)
        return view


class ClosureGatedObjective:
    """Objective proxy that appends the coverage closure gate."""

    def __init__(self, objective: Any, coverage: CoverageGraph):
        self._objective = objective
        self.coverage = coverage

    def evaluate(self, graph: PlanGraph) -> dict:
        evaluate = getattr(self._objective, "evaluate")
        try:
            return evaluate(graph, coverage=self.coverage)
        except TypeError:
            result = evaluate(graph)
            closure = self.coverage.evaluate(graph=graph)
            result = dict(result)
            result.setdefault("checks", []).append({
                "id": "coverage:closure", "ok": closure["closed"],
                "detail": f"覆盖闭包缺口 {len(closure['gaps'])} 个",
                "gaps": closure["gaps"],
            })
            result["missing"] = [c["id"] for c in result["checks"] if not c["ok"]]
            result["success"] = not result["missing"]
            return result

    def success(self, graph: PlanGraph) -> bool:
        return bool(self.evaluate(graph)["success"])

    def __getattr__(self, name: str) -> Any:
        return getattr(self._objective, name)


def attach_coverage(supervisor: Any, coverage: CoverageGraph) -> Any:
    """Attach closure gating to an existing AgentSupervisor instance."""
    if not isinstance(coverage, CoverageGraph):
        raise CoverageError("coverage 必须是 CoverageGraph")
    base = getattr(supervisor, "_base_objective", None)
    if base is None:
        base = supervisor.objective
        supervisor._base_objective = base
    supervisor.coverage = coverage
    supervisor.objective = ClosureGatedObjective(base, coverage)
    scheduler = getattr(supervisor, "scheduler", None)
    if scheduler is not None:
        if isinstance(scheduler, CoverageScheduler):
            scheduler.coverage = coverage
        else:
            supervisor.scheduler = CoverageScheduler.from_scheduler(scheduler, coverage)
    coverage.objective = coverage.objective or str(getattr(base, "key", "") or "")
    coverage.run_id = coverage.run_id or str(getattr(supervisor.runtime, "run_id", ""))
    return supervisor


def coverage_from_graph(graph: PlanGraph, *, cluster_id: str = "",
                        objective: str = "") -> CoverageGraph:
    """Best-effort materialisation of confirmed facts into coverage nodes.

    Facts with ``attrs.target`` become assets with a read-only check (the fact is
    probe-backed, so the observation did touch the asset).  Facts carrying
    ``attrs.verb``/``attrs.resource`` or ``attrs.permission`` additionally become
    exploitable permission edges; they remain unattempted until the caller marks
    an attempt, which keeps the closure honest.
    """
    coverage = CoverageGraph(objective=objective or graph.objective)
    for fact in graph.facts(status="confirmed"):
        attrs = fact.get("attrs") or {}
        target = str(attrs.get("target") or "").strip()
        evidence = [e for e in fact.get("evidence") or [] if e]
        cid = str(attrs.get("cluster_id") or cluster_id or "")
        if target:
            cluster = cid or "graph"
            if not coverage.has_node(target):
                coverage.add_asset(target, cluster_id=cluster, kind="workload",
                                   name=target, address=target,
                                   attrs={"source": "graph-fact"})
            if evidence and not (coverage._nodes[target].get("checks")):
                coverage.mark_check(target, mode="read-only", ok=True,
                                    evidence=evidence,
                                    module=str(attrs.get("module") or ""),
                                    template=str(attrs.get("step") or
                                                 attrs.get("module") or "fact"))
        subject = str(attrs.get("subject") or "").strip()
        verb = str(attrs.get("verb") or "").strip()
        resource = str(attrs.get("resource") or "").strip()
        if subject and (verb or resource):
            if not coverage.has_node(subject):
                coverage.add_identity(
                    subject, cluster_id=cid or "graph", name=subject,
                    namespace=str(attrs.get("namespace") or ""))
            obj = target or str(attrs.get("object") or resource or subject)
            if not coverage.has_node(obj):
                coverage.add_asset(obj, cluster_id=cid or "graph", kind="other",
                                   name=obj)
            coverage.add_permission(subject, obj, verb=verb or "?",
                                     resource=resource or "?",
                                     scope=str(attrs.get("scope") or ""),
                                     exploitable=bool(attrs.get("exploitable", True)))
    return coverage


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------
def _md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in row]
        out.append("| " + " | ".join(cells) + " |")
    return out


def render_markdown(proof: dict, *, title: str = "覆盖闭包证明") -> str:
    """Render a coverage proof for human review (deterministic order)."""
    cov = proof.get("coverage") or {}
    lines = [f"# {title}", ""]
    lines.append(f"- schema: `{proof.get('schema', '')}`")
    lines.append(f"- run: `{proof.get('run_id', '') or '-'}`")
    lines.append(f"- objective: `{proof.get('objective', '') or '-'}`")
    lines.append(f"- stop_reason: `{proof.get('stop_reason', '')}`")
    lines.append(f"- closed: `{bool(proof.get('closed'))}`")
    lines.append(f"- success: `{bool(proof.get('success'))}`")
    lines.append("")
    lines.append("## 1. 四条闭包判据")
    lines.append("")
    rows = []
    for check in proof.get("criteria") or []:
        rows.append(["PASS" if check.get("ok") else "GAP", check.get("id", ""),
                     check.get("detail", ""), len(check.get("gaps") or [])])
    lines.extend(_md_table(["状态", "判据", "说明", "缺口"], rows))
    lines.append("")
    lines.append("## 2. 覆盖计数")
    lines.append("")
    rows = [
        ["可达资产", cov.get("reachable_assets", 0), cov.get("checked_assets", 0),
         cov.get("asset_coverage", 0)],
        ["可利用权限边", cov.get("permission_edges", 0),
         cov.get("attempted_permission_edges", 0),
         cov.get("permission_coverage", 0)],
        ["探针", cov.get("probes", 0), cov.get("baselined_probes", 0),
         cov.get("probe_coverage", 0)],
    ]
    lines.extend(_md_table(["对象", "总数", "已覆盖", "比例"], rows))
    lines.append("")
    lines.append(f"- 已检测模板: {cov.get('templates_checked', 0)}"
                 f"（{', '.join(cov.get('templates') or []) or '无'}）")
    lines.append("")
    lines.append("## 3. 缺口清单")
    lines.append("")
    gaps = proof.get("gaps") or []
    if not gaps:
        lines.append("无。所有可达资产、可利用权限边、探针基线与 frontier 均已处理。")
    else:
        rows = [[g.get("kind", ""), g.get("id", ""), g.get("reason", ""),
                 g.get("detail", "")] for g in gaps]
        lines.extend(_md_table(["类型", "对象", "原因", "说明"], rows))
    lines.append("")
    lines.append("## 4. 覆盖图节点")
    lines.append("")
    nodes = proof.get("nodes") or []
    if not nodes:
        lines.append("无。")
    else:
        rows = []
        for node in nodes:
            rows.append([
                node.get("id", ""), node.get("kind", ""),
                node.get("cluster_id", ""), node.get("name", ""),
                "yes" if node.get("checked") else "no",
                "yes" if node.get("baseline_ok") else
                ("-" if node.get("kind") != "probe" else "no"),
            ])
        lines.extend(_md_table(["id", "类型", "集群", "名称", "已检查", "基线"],
                               rows))
    lines.append("")
    lines.append("## 5. 覆盖图边")
    lines.append("")
    edges = proof.get("edges") or []
    if not edges:
        lines.append("无。")
    else:
        rows = [[e.get("id", ""), e.get("src", ""), e.get("relation", ""),
                 e.get("dst", ""), "yes" if e.get("exploitable") else "no",
                 e.get("last_outcome", "") or "-"] for e in edges]
        lines.extend(_md_table(["id", "源", "关系", "目标", "可利用", "尝试"],
                               rows))
    lines.append("")
    lines.append("## 证据 / 限制")
    lines.append("")
    lines.append("- 本文件由 `coverage-proof.json` 确定性渲染；JSON 是机器判据，"
                 "Markdown 只供人工复核。")
    lines.append("- `closed` 只表示四条判据成立；是否成功还必须由 objective 证据门控"
                 "共同判定（`success`）。")
    lines.append("- 覆盖检查与权限尝试必须带证据引用；失败/阻断必须带原因，缺一不计数。")
    lines.append("- 未提供 planner 图时判据四无法证明，会输出 `frontier-unavailable`。")
    lines.append("- 覆盖闭包证明的是“已声明的可达面被处理”，不是“不存在未发现资产”；"
                 "资产发现本身的遗漏不在本证明范围内。")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Supervisor adapter
# --------------------------------------------------------------------------
from .supervisor import AgentSupervisor  # noqa: E402  (avoids a cycle at import top)


class CoverageSupervisor(AgentSupervisor):
    """AgentSupervisor that enforces the coverage closure gate.

    ``create`` / ``load`` accept ``coverage=CoverageGraph(...)``.  Plain
    ``AgentSupervisor`` remains unchanged; this subclass is the opt-in
    integration point used by ``inkblade agent run --coverage``.
    """

    coverage: CoverageGraph | None = None

    @classmethod
    def create(cls, store, session, *, coverage: CoverageGraph | None = None,
               **kwargs):
        supervisor = super().create(store, session, **kwargs)
        if coverage is not None:
            attach_coverage(supervisor, coverage)
        return supervisor

    @classmethod
    def load(cls, store, run_id: str | None = None, *,
             coverage: CoverageGraph | None = None, **kwargs):
        supervisor = super().load(store, run_id, **kwargs)
        if coverage is None:
            path = Path(supervisor.runtime.dir) / "coverage-proof.json"
            if path.is_file():
                try:
                    coverage = CoverageGraph.from_proof(
                        json.loads(path.read_text(encoding="utf-8")))
                except (ValueError, CoverageError):
                    coverage = None
        if coverage is not None:
            attach_coverage(supervisor, coverage)
        return supervisor

    # ------------------------------------------------------------ status
    def _status(self, *, forced: str = "") -> str:
        status = super()._status(forced=forced)
        if status != "failed" or self.coverage is None:
            return status
        base = getattr(self, "_base_objective", None)
        if base is None:
            return status
        try:
            objective_ok = bool(base.success(self.graph))
        except Exception:  # noqa: BLE001 - objective gate
            objective_ok = False
        if not objective_ok:
            return status
        closure = self.coverage.evaluate(graph=self.graph)
        return "failed" if closure["closed"] else "coverage-gap"

    # ------------------------------------------------------------ views
    def state(self) -> dict:
        view = super().state()
        if self.coverage is not None:
            evaluation = self.coverage.evaluate(graph=self.graph)
            view["coverage"] = evaluation["coverage"]
            view["coverage_criteria"] = evaluation["criteria"]
            view["coverage_gaps"] = evaluation["gaps"]
            view["coverage_closed"] = evaluation["closed"]
        return view

    def coverage_proof(self) -> dict | None:
        if self.coverage is None:
            return None
        return self.coverage.proof(
            graph=self.graph, objective=getattr(self, "_base_objective", None),
            budget=self.scheduler.budget, run_id=self.runtime.run_id)

    # ------------------------------------------------------------ finalize
    def _finalize(self, *, status: str = "", reason: str = "") -> dict:
        summary = super()._finalize(status=status, reason=reason)
        if self.coverage is None:
            return summary
        final_status = str(summary.get("status") or "")
        proof = self.coverage.proof(
            graph=self.graph, objective=getattr(self, "_base_objective", None),
            budget=self.scheduler.budget, run_id=self.runtime.run_id,
            stop_reason=stop_reason_for_status(final_status))
        path = Path(self.runtime.dir) / "coverage-proof.json"
        self.coverage.write_proof(path, proof=proof)
        summary["coverage"] = proof
        summary["coverage_path"] = str(path)
        summary["coverage_closed"] = bool(proof["closed"])
        summary["gaps"] = proof["gaps"]
        if final_status == "budget-exceeded":
            summary["coverage_gaps"] = proof["gaps"]
        (Path(self.runtime.dir) / "summary.json").write_text(
            json.dumps(_json_safe(summary), ensure_ascii=False, indent=2),
            encoding="utf-8")
        self.runtime.emit("coverage.proof", {
            "closed": bool(proof["closed"]), "stop_reason": proof["stop_reason"],
            "gaps": proof["gaps"], "path": str(path),
            "coverage": proof["coverage"],
            "summary": f"coverage {'closed' if proof['closed'] else 'open'}: "
                       f"{len(proof['gaps'])} gap(s), {proof['stop_reason']}",
        }, actor="supervisor")
        return summary


__all__ = [
    "COVERAGE_SCHEMA", "PROOF_SCHEMA", "CoverageError", "CoverageEvidenceRequired",
    "CoverageLoopError", "CoverageGraph", "CoverageScheduler",
    "ClosureGatedObjective", "CoverageSupervisor", "attach_coverage",
    "coverage_from_graph", "render_markdown", "budget_exhausted",
    "stop_reason_for_status",
]
