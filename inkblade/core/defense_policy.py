# -*- coding: utf-8 -*-
"""Defense-aware bypass policy engine (agent execution path).

The engine turns a ``probe collect`` security posture into ``defense:<product>``
facts, then selects a *benign* bypass technique per product from the primitives
implemented by the Rust probe.  Selection is risk/success ranked:

    score = success_rate * (1 - detection_risk)

If a detected product has no implemented primitive, the engine stops and reports
``该产品/规则下不可绕过`` instead of sending an offensive intent that the product
is known to catch.  Every selected technique is recorded by ``technique_id`` so
the scheduler event log and the evidence archive are auditable.

This module is deliberately side-effect free except for
:func:`apply_posture`, which only writes to an explicit ``PlanGraph``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "inkblade-defense-policy/1"
FACT_PREFIX = "defense:"

# --------------------------------------------------------------------------
# Technique catalog — one entry per Rust primitive in probe/src/bypass.rs
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    primitive: str
    products: tuple[str, ...]
    risk: float
    success: float
    requires: tuple[str, ...] = ()
    notes: str = ""
    benign: bool = True

    @property
    def score(self) -> float:
        """Ranking heuristic, not an exploit probability."""
        return round(max(0.0, min(1.0, self.success)) *
                     (1.0 - max(0.0, min(1.0, self.risk))), 4)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "primitive": self.primitive,
            "products": list(self.products), "risk": self.risk,
            "success": self.success, "score": self.score,
            "requires": list(self.requires), "notes": self.notes,
            "benign": self.benign,
        }


TECHNIQUES: dict[str, Technique] = {
    "namespace-scope-evasion": Technique(
        "namespace-scope-evasion", "命名空间/标签作用域规避",
        "namespace-scope-evasion", ("admission", "kubearmor"), 0.05, 0.95,
        requires=("admission_policy_scope",),
        notes="默认 ns 在 Kyverno matchConditions 之外；实测 default 可建特权 Pod",
    ),
    "fileless-memfd-exec": Technique(
        "fileless-memfd-exec", "memfd 无文件执行",
        "fileless-memfd-exec", ("falco", "elkeid", "agentsmith", "tetragon",
                                "kubearmor", "hostagent"), 0.45, 0.55,
        requires=("exec",),
        notes="memfd_create + /proc/self/fd exec；无落盘可执行文件",
    ),
    "existing-binary-exec": Technique(
        "existing-binary-exec", "既有解释器执行",
        "existing-binary-exec", ("falco", "elkeid", "agentsmith", "tetragon",
                                  "kubearmor", "hostagent"), 0.55, 0.45,
        requires=("exec",),
        notes="复用镜像内 /bin/sh 或 busybox；不新增/改名二进制",
    ),
    "path-evasion": Technique(
        "path-evasion", "监控路径规避",
        "path-evasion", ("falco", "elkeid", "agentsmith", "tetragon",
                          "kubearmor", "hostagent"), 0.15, 0.75,
        requires=("writable_workspace",),
        notes="从 /dev/shm、/tmp、/run 等候选目录避开 HIDS monitored set",
    ),
    "command-split-env-clean": Technique(
        "command-split-env-clean", "命令拆分 + 环境清理",
        "command-split-env-clean", ("falco", "elkeid", "agentsmith", "tetragon",
                                     "kubearmor", "hostagent"), 0.30, 0.60,
        requires=("exec",),
        notes="逐行短命令、env_clear；规避整条命令签名与敏感环境变量",
    ),
    "sa-permission-selection": Technique(
        "sa-permission-selection", "SA/权限选择",
        "sa-permission-selection", ("admission", "falco", "kubearmor"), 0.10, 0.85,
        requires=("service_account_token",),
        notes="SSAR 检查 pods/exec 并记录可用 SA；不提升权限，只选择已授权主体",
    ),
}

# Product -> techniques that are meaningful for that product.  Empty tuple means
# "no implemented primitive for this product" → policy stops.
PRODUCT_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "admission": ("namespace-scope-evasion", "sa-permission-selection"),
    "falco": ("fileless-memfd-exec", "existing-binary-exec", "path-evasion",
              "command-split-env-clean"),
    "elkeid": ("fileless-memfd-exec", "existing-binary-exec", "path-evasion",
               "command-split-env-clean"),
    "agentsmith": ("fileless-memfd-exec", "existing-binary-exec", "path-evasion",
                   "command-split-env-clean"),
    "kubearmor": ("namespace-scope-evasion", "existing-binary-exec", "path-evasion"),
    "tetragon": ("fileless-memfd-exec", "existing-binary-exec", "path-evasion",
                 "command-split-env-clean"),
    "hostagent": ("path-evasion", "command-split-env-clean"),
    # Scanners / network observability / WAF do not run in the pod exec path;
    # there is no honest primitive that avoids them at execution time.
    "imagescan": (),
    "veinmind": (),
    "waf-inference": (),
    "netobserv": (),
}

PRODUCT_ALIASES = {
    "kyverno": "admission",
    "gatekeeper": "admission",
    "trivy": "imagescan",
    "grype": "imagescan",
    "veinmind": "imagescan",
    "wazuh": "hostagent",
    "ossec": "hostagent",
    "osquery": "hostagent",
    "modsecurity": "waf-inference",
    "coraza": "waf-inference",
    "safeline": "waf-inference",
    "hubble": "netobserv",
    "typha": "netobserv",
    "calico": "netobserv",
}

PRODUCT_DISPLAY = {
    "admission": "准入策略(Kyverno/Gatekeeper)",
    "falco": "Falco",
    "elkeid": "Elkeid HIDS",
    "agentsmith": "AgentSmith-HIDS",
    "kubearmor": "KubeArmor",
    "tetragon": "Tetragon",
    "hostagent": "主机代理(Wazuh/Osquery)",
    "imagescan": "镜像扫描(Trivy/grype/veinmind)",
    "waf-inference": "WAF(ModSecurity/Coraza/雷池)",
    "netobserv": "网络可视化(Hubble/Calico flows)",
}

OFFENSIVE_KEYWORDS = (
    "exploit", "privesc", "privilege", "lateral", "escape", "takeover",
    "bypass", "credential", "persistence", "c2", "payload", "shell",
)


def normalize_product(product: str) -> str:
    key = str(product or "").strip().lower()
    return PRODUCT_ALIASES.get(key, key)


# --------------------------------------------------------------------------
# Posture → detected products
# --------------------------------------------------------------------------
@dataclass
class DetectedDefense:
    product: str
    display: str = ""
    version: str = ""
    evidence: list[str] = field(default_factory=list)
    sensor: dict = field(default_factory=dict)
    ruleset: dict | None = None
    policies: list[str] = field(default_factory=list)
    namespace: str = ""
    source: str = "probe.collect"

    def as_dict(self) -> dict:
        return {
            "product": self.product, "display": self.display or PRODUCT_DISPLAY.get(
                self.product, self.product),
            "version": self.version, "evidence": list(self.evidence),
            "sensor": dict(self.sensor), "ruleset": self.ruleset,
            "policies": list(self.policies), "namespace": self.namespace,
            "source": self.source,
        }


def _merge_detected(store: dict[str, DetectedDefense], item: DetectedDefense) -> None:
    current = store.get(item.product)
    if current is None:
        store[item.product] = item
        return
    for ev in item.evidence:
        if ev and ev not in current.evidence:
            current.evidence.append(ev)
    if item.version and not current.version:
        current.version = item.version
    if item.sensor and not current.sensor:
        current.sensor = item.sensor
    if item.ruleset and not current.ruleset:
        current.ruleset = item.ruleset
    for policy in item.policies:
        if policy and policy not in current.policies:
            current.policies.append(policy)
    if item.namespace and not current.namespace:
        current.namespace = item.namespace


def parse_posture(posture: Mapping[str, Any] | None) -> list[DetectedDefense]:
    """Parse ``probe collect`` security_posture into normalized products.

    Accepts both the structured ``products`` array emitted by the Rust probe and
    the raw process/module/dir/admission sections (so an older snapshot or a
    hand-built fixture still works).
    """
    if not isinstance(posture, Mapping):
        return []
    found: dict[str, DetectedDefense] = {}
    namespace = str(posture.get("namespace") or "")

    for entry in posture.get("products") or []:
        if isinstance(entry, str):
            key = normalize_product(entry)
            if key:
                _merge_detected(found, DetectedDefense(
                    product=key, display=PRODUCT_DISPLAY.get(key, key),
                    namespace=namespace))
            continue
        if not isinstance(entry, Mapping):
            continue
        raw_key = str(entry.get("product") or "")
        key = normalize_product(raw_key)
        if not key:
            continue
        rulesets = entry.get("rulesets") or []
        ruleset = rulesets[0] if isinstance(rulesets, list) and rulesets else None
        sensor = entry.get("sensor") if isinstance(entry.get("sensor"), Mapping) else {}
        _merge_detected(found, DetectedDefense(
            product=key,
            display=str(entry.get("display") or PRODUCT_DISPLAY.get(key, key)),
            version=str(entry.get("version") or ""),
            evidence=[str(v) for v in entry.get("evidence") or [] if str(v)],
            sensor=dict(sensor),
            ruleset=ruleset if isinstance(ruleset, dict) else None,
            namespace=namespace,
        ))

    # Raw processes (list of strings or {comm, cmdline, matched}).
    process_tokens = {
        "falco": ("falco",), "kyverno": ("kyverno",),
        "elkeid": ("elkeid", "olehid"),
        "agentsmith": ("agentsmith", "smith-agent", "smithd"),
        "kubearmor": ("kubearmor",), "tetragon": ("tetragon",),
        "hostagent": ("wazuh", "ossec", "osquery"),
        "imagescan": ("trivy", "grype", "syft"),
        "waf-inference": ("modsecurity", "coraza", "safeline"),
        "netobserv": ("hubble", "typha"),
    }
    for row in posture.get("processes") or []:
        text = ""
        if isinstance(row, str):
            text = row
        elif isinstance(row, Mapping):
            matched = row.get("matched") or []
            for key in matched:
                norm = normalize_product(str(key))
                if norm:
                    _merge_detected(found, DetectedDefense(
                        product=norm, display=PRODUCT_DISPLAY.get(norm, norm),
                        evidence=[f"process:{row.get('comm') or row.get('pid') or '?'}"],
                        namespace=namespace))
            text = f"{row.get('comm') or ''} {row.get('cmdline') or ''}"
        low = text.lower()
        for product, tokens in process_tokens.items():
            if any(token in low for token in tokens):
                _merge_detected(found, DetectedDefense(
                    product=normalize_product(product),
                    display=PRODUCT_DISPLAY.get(normalize_product(product), product),
                    evidence=[f"process:{text.strip()[:120]}"], namespace=namespace))

    for module in posture.get("kernel_modules") or []:
        name = str(module or "").lower()
        for product, needles in {
            "falco": ("falco",), "elkeid": ("elkeid", "olehid"),
            "agentsmith": ("smith",), "kubearmor": ("kubearmor",),
            "tetragon": ("tetragon",),
        }.items():
            if any(needle in name for needle in needles):
                _merge_detected(found, DetectedDefense(
                    product=product, display=PRODUCT_DISPLAY.get(product, product),
                    evidence=[f"kernel_module:{name}"], namespace=namespace))

    for row in posture.get("agent_dirs") or []:
        if not isinstance(row, Mapping) or not row.get("present"):
            continue
        product = normalize_product(str(row.get("product") or ""))
        if not product:
            continue
        _merge_detected(found, DetectedDefense(
            product=product, display=PRODUCT_DISPLAY.get(product, product),
            evidence=[f"dir:{row.get('path')}"], namespace=namespace))

    admission = posture.get("admission")
    if isinstance(admission, Mapping):
        for group in ("kyverno", "gatekeeper"):
            block = admission.get(group)
            if not isinstance(block, Mapping):
                continue
            items = block.get("items") or []
            policies = [str(item.get("name")) for item in items
                        if isinstance(item, Mapping) and item.get("name")]
            if block.get("available") or policies:
                _merge_detected(found, DetectedDefense(
                    product="admission", display=PRODUCT_DISPLAY["admission"],
                    evidence=[f"admission:{group}:{len(policies)}"],
                    policies=policies, namespace=namespace))

    for row in posture.get("rulesets") or []:
        if not isinstance(row, Mapping):
            continue
        product = normalize_product(str(row.get("product") or ""))
        if not product:
            continue
        _merge_detected(found, DetectedDefense(
            product=product, display=PRODUCT_DISPLAY.get(product, product),
            evidence=[f"ruleset:{row.get('path')}"], ruleset=dict(row),
            namespace=namespace))

    for row in posture.get("pods") or []:
        if not isinstance(row, Mapping):
            continue
        images = [str(image) for image in row.get("images") or []]
        for image in images:
            low = image.lower()
            for product, tokens in process_tokens.items():
                if any(token in low for token in tokens):
                    norm = normalize_product(product)
                    _merge_detected(found, DetectedDefense(
                        product=norm, display=PRODUCT_DISPLAY.get(norm, norm),
                        version=image, evidence=[f"image:{image}"],
                        namespace=namespace))

    return sorted(found.values(), key=lambda item: item.product)


def defense_facts(items: Sequence[DetectedDefense] | Mapping[str, Any] | None,
                  evidence_ids: Iterable[str] = (),
                  source_intent: str = "") -> list[dict]:
    """Build graph facts with the required ``defense:<product>`` claim."""
    if isinstance(items, Mapping):
        detected = parse_posture(items)
    else:
        detected = list(items or [])
    evidence = [str(e) for e in evidence_ids if e]
    out: list[dict] = []
    for item in detected:
        attrs = {
            "product": item.product,
            "display": item.display or PRODUCT_DISPLAY.get(item.product, item.product),
            "version": item.version,
            "sensor": dict(item.sensor),
            "ruleset": item.ruleset,
            "policies": list(item.policies),
            "namespace": item.namespace,
            "evidence": list(item.evidence),
            "source": item.source,
            "available_techniques": list(PRODUCT_TECHNIQUES.get(item.product, ())),
        }
        out.append({
            "claim": f"{FACT_PREFIX}{item.product}",
            "status": "confirmed" if evidence else "hypothesis",
            "fact_kind": "defense",
            "severity": "info",
            "evidence": list(evidence),
            "source_intent": str(source_intent),
            "attrs": attrs,
        })
    return out


def apply_posture(graph, posture: Mapping[str, Any], evidence_sha256: str,
                  *, source_intent: str = "", summary: str = "") -> dict:
    """Persist one collect archive as evidence plus ``defense:<product>`` facts."""
    ev = graph.add_evidence(
        evidence_sha256, run="", step="probe.collect", archive="security_posture.json",
        source="probe", runtime="rust", summary=summary or "probe collect security_posture")
    facts = defense_facts(posture, [ev["id"]], source_intent=source_intent)
    ids: list[str] = []
    for fact in facts:
        node = graph.add_fact(
            fact["claim"], status=fact["status"], evidence=fact["evidence"],
            kind=fact["fact_kind"], severity=fact["severity"],
            source_intent=fact["source_intent"], attrs=fact["attrs"])
        ids.append(node["id"])
    return {
        "evidence": ev["id"], "facts": ids,
        "products": [fact["claim"][len(FACT_PREFIX):] for fact in facts],
    }


def detected_from_graph(graph) -> list[DetectedDefense]:
    out: dict[str, DetectedDefense] = {}
    if graph is None:
        return []
    try:
        facts = graph.facts(fact_kind="defense")
    except TypeError:  # older graph signature
        facts = [f for f in graph.facts() if f.get("fact_kind") == "defense"]
    for fact in facts:
        claim = str(fact.get("claim") or "")
        if not claim.startswith(FACT_PREFIX):
            continue
        product = normalize_product(claim[len(FACT_PREFIX):])
        if not product:
            continue
        attrs = fact.get("attrs") or {}
        _merge_detected(out, DetectedDefense(
            product=product,
            display=str(attrs.get("display") or PRODUCT_DISPLAY.get(product, product)),
            version=str(attrs.get("version") or ""),
            evidence=[str(v) for v in attrs.get("evidence") or []],
            sensor=dict(attrs.get("sensor") or {}),
            ruleset=attrs.get("ruleset") if isinstance(attrs.get("ruleset"), dict) else None,
            policies=[str(v) for v in attrs.get("policies") or []],
            namespace=str(attrs.get("namespace") or ""),
            source=str(attrs.get("source") or "graph"),
        ))
    return sorted(out.values(), key=lambda item: item.product)


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------
def select_technique(product: str, available: Sequence[str] | None = None
                     ) -> Technique | None:
    """Pick the highest risk-adjusted technique for one product."""
    key = normalize_product(product)
    ids = list(available if available is not None else PRODUCT_TECHNIQUES.get(key, ()))
    candidates = [TECHNIQUES[tid] for tid in ids if tid in TECHNIQUES]
    if not candidates:
        return None
    candidates.sort(key=lambda tech: (-tech.score, tech.risk, tech.id))
    return candidates[0]


def plan_bypass(product: str, available: Sequence[str] | None = None,
                *, action: str = "") -> dict:
    """Return a selected technique or an explicit stop/no-technique report."""
    key = normalize_product(product)
    ids = list(available if available is not None else PRODUCT_TECHNIQUES.get(key, ()))
    tech = select_technique(key, ids)
    if tech is None:
        return {
            "schema": SCHEMA, "status": "no-technique", "stop": True,
            "product": key, "display": PRODUCT_DISPLAY.get(key, key),
            "action": str(action), "technique": None,
            "available": ids,
            "reason": (f"该产品/规则下不可绕过：{PRODUCT_DISPLAY.get(key, key)} "
                       f"没有已实现的执行期原语（available={ids}）"),
            "benign_only": True,
        }
    return {
        "schema": SCHEMA, "status": "selected", "stop": False,
        "product": key, "display": PRODUCT_DISPLAY.get(key, key),
        "action": str(action), "technique": tech.as_dict(),
        "available": ids,
        "reason": (f"{PRODUCT_DISPLAY.get(key, key)} → {tech.id} "
                   f"(score={tech.score}, risk={tech.risk}, success={tech.success})"),
        "benign_only": True,
    }


def bypass_params(tech: Technique | str, *, script: str = "", workdir: str = "",
                  monitored_paths: Sequence[str] = (), target: Mapping[str, Any] | None = None,
                  techniques: Sequence[str] | None = None, extra: Mapping[str, Any] | None = None
                  ) -> dict:
    """Build the ``params["bypass"]`` object carried by a probe task."""
    item = TECHNIQUES[tech] if isinstance(tech, str) else tech
    selected = list(techniques or [item.id])
    plan: dict[str, Any] = {"techniques": selected, "clean_env": True, "benign": True}
    if script:
        plan["script"] = script
    if workdir:
        plan["workdir"] = workdir
    if monitored_paths:
        plan["monitored_paths"] = list(monitored_paths)
    if target:
        plan["target"] = dict(target)
    for key, value in (extra or {}).items():
        plan[key] = value
    return {
        "technique_id": item.id,
        "techniques": selected,
        "product": item.products[0] if item.products else "",
        "primitive": item.primitive,
        "risk": item.risk, "success": item.success, "score": item.score,
        "benign": True, "plan": plan,
    }


# --------------------------------------------------------------------------
# Scheduler gate
# --------------------------------------------------------------------------
@dataclass
class GateDecision:
    allow: bool
    kind: str = ""
    reason: str = ""
    status: str = ""
    products: list[str] = field(default_factory=list)
    technique_id: str = ""
    product: str = ""
    stop: bool = False
    available: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allow": self.allow, "kind": self.kind, "reason": self.reason,
            "status": self.status, "products": list(self.products),
            "technique_id": self.technique_id, "product": self.product,
            "stop": self.stop, "available": list(self.available),
        }


def is_offensive_intent(intent: Mapping[str, Any]) -> bool:
    role = str(intent.get("role") or "").lower()
    if role == "exploit":
        return True
    if role in ("recon", "report", "verify"):
        return False
    module = str(intent.get("module") or "").lower()
    tags = " ".join(str(tag) for tag in intent.get("tags") or []).lower()
    blob = f"{module} {tags}"
    if str(intent.get("role") or "").lower() in ("exploit",):
        return True
    return any(keyword in blob for keyword in OFFENSIVE_KEYWORDS)


class DefenseGate:
    """Refuse offensive intents unless they carry a valid bypass variant."""

    def __init__(self, graph=None, *, products: Sequence[DetectedDefense] | None = None,
                 require_for=("exploit",)):
        self.graph = graph
        self._products = list(products or [])
        self.require_for = tuple(require_for)

    def detected(self, graph=None) -> list[DetectedDefense]:
        if self._products:
            return list(self._products)
        return detected_from_graph(graph if graph is not None else self.graph)

    def check_intent(self, intent: Mapping[str, Any], graph=None) -> GateDecision:
        products = self.detected(graph)
        if not products:
            return GateDecision(True, status="no-defense-detected")
        if not is_offensive_intent(intent):
            return GateDecision(True, status="non-offensive-intent",
                                products=[p.product for p in products])
        params = intent.get("params") or {}
        bypass = params.get("bypass") or params.get("defense_bypass") or {}
        if isinstance(bypass, str):
            bypass = {"technique_id": bypass}
        if not isinstance(bypass, Mapping):
            bypass = {}
        names = [p.product for p in products]
        available: list[str] = []
        for product in products:
            for tid in PRODUCT_TECHNIQUES.get(product.product, ()):
                if tid in TECHNIQUES and tid not in available:
                    available.append(tid)
        if not available:
            return GateDecision(
                False, kind="NoBypassTechnique", stop=True,
                status="no-technique",
                reason=(f"检测到防护产品 {names}，但该产品/规则下不可绕过"
                        f"（无已实现原语）；拒绝硬闯"),
                products=names)
        requested = str(bypass.get("technique_id") or "").strip()
        if not requested and isinstance(bypass.get("techniques"), list) and bypass["techniques"]:
            requested = str(bypass["techniques"][0])
        if not requested:
            return GateDecision(
                False, kind="DefenseBypassRequired", status="bypass-required",
                reason=(f"检测到防护产品 {names}；攻击性 intent 必须携带 bypass "
                        f"technique_id（可选 {available}）"),
                products=names, available=available)
        if requested not in TECHNIQUES:
            return GateDecision(
                False, kind="DefenseTechniqueUnknown", status="technique-unknown",
                reason=f"未知 bypass technique {requested!r}（可选 {available}）",
                products=names, available=available)
        if requested not in available:
            tech = TECHNIQUES[requested]
            return GateDecision(
                False, kind="DefenseTechniqueMismatch", status="technique-unavailable",
                reason=(f"technique {requested} 不适用于检测到的产品 {names}"
                        f"（其产品域={list(tech.products)}）"),
                products=names, available=available, technique_id=requested)
        tech = TECHNIQUES[requested]
        product = normalize_product(str(bypass.get("product") or ""))
        if not product:
            relevant = [p.product for p in products if p.product in tech.products]
            product = relevant[0] if relevant else tech.products[0]
        return GateDecision(
            True, kind="DefenseBypassSelected", status="bypass-selected",
            reason=(f"使用 bypass {requested} 规避 {product} "
                    f"(score={tech.score})"),
            products=names, technique_id=requested, product=product,
            available=available)


def record_bypass(observation_attrs: Mapping[str, Any], *,
                  detected: Sequence[DetectedDefense] | Sequence[str],
                  technique_id: str, alerts: Sequence[Mapping[str, Any]] = (),
                  denials: Sequence[Mapping[str, Any]] = ()) -> dict:
    """Shape the evidence block required of a bypass execution.

    The record always carries the three required fields: detected product,
    selected technique and observed alerts/denials.  An empty alert list is
    meaningful only together with the log source and capture window.
    """
    products = [item.product if isinstance(item, DetectedDefense) else normalize_product(item)
                for item in detected]
    return {
        "schema": "inkblade-defense-bypass-evidence/1",
        "detected_products": products,
        "technique_id": technique_id,
        "alerts": [dict(alert) for alert in alerts],
        "denials": [dict(denial) for denial in denials],
        "alert_count": len(alerts),
        "denial_count": len(denials),
        "benign_only": True,
        "observation": dict(observation_attrs),
        "honest": True,
    }


def refusal_report(product: str, available: Sequence[str] | None = None,
                   action: str = "") -> dict:
    """Machine-readable stop object for a product with no primitive."""
    plan = plan_bypass(product, available, action=action)
    return {
        "schema": SCHEMA, "stop": True,
        "status": "policy-refused" if plan["status"] == "no-technique" else plan["status"],
        "product": plan["product"], "technique_id": "",
        "reason": plan["reason"], "available": plan["available"],
        "benign_only": True,
    }


def catalog() -> list[dict]:
    return [TECHNIQUES[tid].as_dict() for tid in sorted(TECHNIQUES)]


def summary() -> dict:
    return {
        "schema": SCHEMA,
        "techniques": len(TECHNIQUES),
        "products": {product: len(ids) for product, ids in sorted(PRODUCT_TECHNIQUES.items())},
        "stopped_products": [product for product, ids in PRODUCT_TECHNIQUES.items() if not ids],
        "ranking": "score = success * (1 - risk)",
    }


def load_posture(path: str) -> dict:
    """Read a collect JSON file (tolerates the old {snapshot:{...}} wrapper)."""
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    if isinstance(doc, dict) and isinstance(doc.get("security_posture"), dict):
        return doc["security_posture"]
    if isinstance(doc, dict) and isinstance(doc.get("snapshot"), dict):
        return load_posture_any(doc["snapshot"])
    return doc


def load_posture_any(value: Any) -> dict:
    if isinstance(value, dict) and isinstance(value.get("security_posture"), dict):
        return value["security_posture"]
    return value if isinstance(value, dict) else {}

# --------------------------------------------------------------------------
# Alert observation parsing (Falco stdout / Kyverno admission log)
# --------------------------------------------------------------------------
_FALCO_LINE = re.compile(
    r"^(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?):\s+"
    r"(?P<priority>Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug)\s+"
    r"(?P<message>.+)$",
    re.MULTILINE,
)
_FALCO_FIELD = re.compile(r"(?:^|\s)([a-z_][a-z0-9_]*)=((?:[^=]|\s(?!\w+=))*?)(?=\s+[a-z_][a-z0-9_]*=|$)")
_KYVERNO_DENIAL = re.compile(
    r'admission webhook "(?P<webhook>[^"]+)" denied[^:]*:\s*(?P<body>.+)')
_KYVERNO_POLICY = re.compile(r"Policy\s+(?P<policy>[\w.-]+)\s+failed:\s*(?P<message>.+)")

ALERT_RULE_TECHNIQUES = {
    "executing binary not part of base image": ("existing-binary-exec", "fileless-memfd-exec"),
    "terminal shell in container": ("existing-binary-exec", "fileless-memfd-exec"),
    "privileged container started": ("namespace-scope-evasion",),
    "write below etc": ("path-evasion",),
    "write below binary dir": ("path-evasion",),
    "contact k8s api server from container": ("sa-permission-selection",),
    "unexpected connection to k8s api server from container": ("sa-permission-selection",),
    "drop and execute new binary in container": ("fileless-memfd-exec",),
}


def _parse_fields(text: str) -> dict:
    fields = {}
    for match in _FALCO_FIELD.finditer(text):
        key = match.group(1)
        value = match.group(2).strip()
        if key and key not in fields:
            fields[key] = value[:512]
    return fields


def parse_falco_alerts(text: str) -> list[dict]:
    alerts: list[dict] = []
    for match in _FALCO_LINE.finditer(str(text or "")):
        message = match.group("message").strip()
        rule, _, detail = message.partition("|")
        rule = rule.strip()
        if not rule:
            continue
        alert = {
            "source": "falco",
            "time": match.group("time"),
            "priority": match.group("priority"),
            "rule": rule,
            "detail": detail.strip()[:2048],
            "fields": _parse_fields(detail),
            "raw": match.group(0)[:2048],
        }
        alerts.append(alert)
    return alerts


def parse_kyverno_denials(text: str) -> list[dict]:
    denials: list[dict] = []
    for line in str(text or "").splitlines():
        match = _KYVERNO_DENIAL.search(line)
        if not match:
            continue
        body = match.group("body").strip()
        policy = ""
        message = body
        pm = _KYVERNO_POLICY.search(body)
        if pm:
            policy = pm.group("policy")
            message = pm.group("message").strip()
        denials.append({
            "source": "kyverno",
            "webhook": match.group("webhook"),
            "policy": policy,
            "message": message[:2048],
            "raw": line.strip()[:2048],
        })
    return denials


def attribute_alerts(alerts: Sequence[Mapping[str, Any]]) -> list[dict]:
    """Attach the technique family each observed alert would have caught."""
    out = []
    for alert in alerts:
        rule = str(alert.get("rule") or "").strip().lower()
        matched: list[str] = []
        for needle, techniques in ALERT_RULE_TECHNIQUES.items():
            if needle in rule:
                matched = list(techniques)
                break
        out.append({**dict(alert), "technique_ids": matched})
    return out


def parse_product_logs(falco_text: str = "", kyverno_text: str = "") -> dict:
    alerts = parse_falco_alerts(falco_text)
    denials = parse_kyverno_denials(kyverno_text)
    return {
        "alerts": alerts,
        "denials": denials,
        "alert_rules": sorted({alert["rule"] for alert in alerts}),
        "denied_policies": sorted({denial["policy"] for denial in denials if denial.get("policy")}),
        "alert_count": len(alerts),
        "denial_count": len(denials),
    }
