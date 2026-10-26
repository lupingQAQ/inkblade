# -*- coding: utf-8 -*-
"""Kyverno/Gatekeeper admission semantics research engine.

The engine is intentionally small but models the differences that matter in
real bypasses: Audit/dryrun modes, namespace/label exemptions, mutation order,
subresources, init/ephemeral containers, cluster scope and CRD version
conversion.  It returns a trace so every admitted attack has a replayable
reason, not just a hard-coded verdict.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .common import finding, hash_payload, summary_json

KEY = "admission-policy-semantics"

SENSITIVE_PATHS = ("/var/run", "/var/lib", "/etc", "/dev", "/proc", "/sys",
                   "/boot", "/root", "/")


def _pod(name: str = "workload", ns: str = "default", *, privileged=False,
         init_priv=False, eph_priv=False, labels=None, host_network=False,
         host_path=None, image="registry.local/train:1.0", command=None,
         run_as_root=False, caps=None) -> dict:
    labels = dict(labels or {})
    container = {
        "name": "main",
        "image": image,
        "securityContext": {"privileged": bool(privileged),
                            "allowPrivilegeEscalation": bool(privileged)},
    }
    if caps:
        container["securityContext"]["capabilities"] = {"add": list(caps)}
    if run_as_root:
        container["securityContext"]["runAsUser"] = 0
        container["securityContext"]["runAsNonRoot"] = False
    obj = {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {"containers": [container]},
    }
    if init_priv:
        obj["spec"]["initContainers"] = [{
            "name": "init", "image": image,
            "securityContext": {"privileged": True},
        }]
    if eph_priv:
        obj["spec"]["ephemeralContainers"] = [{
            "name": "debug", "image": image,
            "securityContext": {"privileged": True},
        }]
    if host_network:
        obj["spec"]["hostNetwork"] = True
    if host_path:
        obj["spec"]["volumes"] = [{"name": "host", "hostPath": {"path": host_path}}]
    if command:
        obj["command"] = list(command)
    return obj


def _policy(engine: str, action: str, checks: list[str], *, name="policy",
            scope="containers", namespaces=None, subresources=None,
            label_selector=None, exclude_namespaces=None, exclude_labels=None,
            mutate_labels=None, preconditions=None, api_versions=None,
            cluster_scope=False, namespace_labels=None, exempt_images=None,
            allow_images=None, require_labels=None) -> dict:
    policy: dict[str, Any] = {
        "name": name, "engine": engine, "action": action,
        "match": {}, "validate": {"checks": list(checks), "scope": scope},
    }
    match = policy["match"]
    if namespaces is not None:
        match["namespaces"] = list(namespaces)
    if subresources is not None:
        match["subresources"] = list(subresources)
    if label_selector is not None:
        match["labelSelector"] = dict(label_selector)
    if api_versions is not None:
        match["apiVersions"] = list(api_versions)
    if cluster_scope:
        match["scope"] = "Cluster"
    if namespace_labels is not None:
        match["namespaceLabels"] = dict(namespace_labels)
    if exclude_namespaces:
        policy["exclude"] = {"namespaces": list(exclude_namespaces)}
    if exclude_labels:
        policy.setdefault("exclude", {})["labels"] = dict(exclude_labels)
    if mutate_labels:
        policy["mutate"] = {"labels": dict(mutate_labels)}
    if preconditions:
        policy["preconditions"] = list(preconditions)
    if exempt_images is not None:
        policy["exemptImages"] = list(exempt_images)
    if allow_images is not None:
        policy["allowImages"] = list(allow_images)
    if require_labels is not None:
        policy["requireLabels"] = list(require_labels)
    return policy


def _case(cid: str, engine: str, mechanism: str, title: str, request: dict,
          obj: dict, vulnerable: list[dict], hardened: list[dict], **extra) -> dict:
    return {
        "id": cid, "engine": engine, "mechanism": mechanism, "title": title,
        "request": request, "object": obj,
        "vulnerable_policies": vulnerable, "hardened_policies": hardened,
        **extra,
    }


def _req(namespace="default", operation="CREATE", kind="Pod", subresource="",
         api_version="v1", cluster_scoped=False) -> dict:
    return {"namespace": namespace, "operation": operation, "kind": kind,
            "subresource": subresource, "apiVersion": api_version,
            "cluster_scoped": cluster_scoped}


def _default_cases() -> list[dict]:
    cases: list[dict] = []

    # 1. Kyverno Audit: violation recorded but object admitted.
    p_audit = _policy("kyverno", "Audit", ["privileged"], name="deny-privileged")
    p_enforce = _policy("kyverno", "Enforce", ["privileged"], name="deny-privileged")
    cases.append(_case(
        "kyv-audit-privileged", "kyverno", "audit-mode",
        "Kyverno validationFailureAction=Audit 对 privileged Pod 只告警",
        _req(), _pod(privileged=True), [p_audit], [p_enforce]))

    # 2. Excluded namespace.
    p_excl = _policy("kyverno", "Enforce", ["privileged"], exclude_namespaces=["kube-system"])
    p_no_excl = _policy("kyverno", "Enforce", ["privileged"])
    cases.append(_case(
        "kyv-excluded-namespace", "kyverno", "exemption",
        "exclude.resources.namespaces 将 kube-system 排除在 privileged 校验之外",
        _req(namespace="kube-system"), _pod(ns="kube-system", privileged=True),
        [p_excl], [p_no_excl]))

    # 3. Exempt label chosen by the workload author.
    p_label = _policy("kyverno", "Enforce", ["privileged"],
                      exclude_labels={"policy-exempt": "true"})
    p_label_hard = _policy("kyverno", "Enforce", ["privileged"],
                           exclude_labels={"policy-exempt": "security-approved"})
    cases.append(_case(
        "kyv-exempt-label", "kyverno", "exemption",
        "工作负载可自填 policy-exempt=true 命中 exclude.labels",
        _req(), _pod(privileged=True, labels={"policy-exempt": "true"}),
        [p_label], [p_label_hard]))

    # 4. initContainers not covered by containers-only rule.
    p_containers = _policy("kyverno", "Enforce", ["privileged"], scope="containers")
    p_all = _policy("kyverno", "Enforce", ["privileged"], scope="all")
    cases.append(_case(
        "kyv-init-container", "kyverno", "init-container",
        "校验 rule 仅遍历 containers，initContainers.privileged 逃逸",
        _req(), _pod(init_priv=True), [p_containers], [p_all]))

    # 5. Ephemeral containers subresource not matched.
    p_no_sub = _policy("kyverno", "Enforce", ["privileged"], scope="containers")
    p_eph = _policy("kyverno", "Enforce", ["privileged"], scope="all",
                    subresources=["ephemeralcontainers"])
    cases.append(_case(
        "kyv-ephemeral-subresource", "kyverno", "ephemeral-container",
        "pods/ephemeralcontainers 子资源未被主资源规则匹配，debug 容器 privileged",
        _req(operation="UPDATE", subresource="ephemeralcontainers"),
        _pod(eph_priv=True), [p_no_sub], [p_eph]))

    # 6. pods/exec subresource not matched.
    p_no_exec = _policy("kyverno", "Enforce", ["exec_shell"], scope="containers")
    p_exec = _policy("kyverno", "Enforce", ["exec_shell"], scope="containers",
                     subresources=["exec"])
    cases.append(_case(
        "kyv-exec-subresource", "kyverno", "subresource",
        "pods/exec 不在规则 match 内，交互式 shell 未被阻断",
        _req(operation="CONNECT", subresource="exec"),
        _pod(command=["/bin/sh"]), [p_no_exec], [p_exec]))

    # 7. Mutation adds an exempt label before validation.
    p_mutate_exempt = _policy("kyverno", "Enforce", ["privileged"],
                              exclude_labels={"policy-exempt": "true"})
    p_mutator = _policy("kyverno", "Mutate", [], mutate_labels={"policy-exempt": "true"})
    p_mutator_hard = _policy("kyverno", "Mutate", [], mutate_labels={"team": "platform"})
    cases.append(_case(
        "kyv-mutation-order", "kyverno", "mutation-order",
        "mutating policy 先写入 exempt 标签，validating policy 随后跳过",
        _req(), _pod(privileged=True), [p_mutator, p_mutate_exempt],
        [p_mutator_hard, p_label_hard]))

    # 8. Precondition for UPDATE lets CREATE through.
    p_pre = _policy("kyverno", "Enforce", ["privileged"],
                    preconditions=[{"field": "request.operation", "op": "Equals",
                                    "value": "UPDATE"}])
    p_pre_hard = _policy("kyverno", "Enforce", ["privileged"],
                         preconditions=[{"field": "request.operation", "op": "In",
                                         "value": ["CREATE", "UPDATE"]}])
    cases.append(_case(
        "kyv-precondition-create", "kyverno", "precondition",
        "precondition 仅覆盖 UPDATE，CREATE 路径不校验 privileged",
        _req(operation="CREATE"), _pod(privileged=True), [p_pre], [p_pre_hard]))

    # 9. CRD version mismatch (v1beta1 rule vs v1 object).
    p_beta = _policy("kyverno", "Enforce", ["privileged"],
                     api_versions=["example.com/v1beta1"])
    p_v1 = _policy("kyverno", "Enforce", ["privileged"],
                   api_versions=["example.com/v1beta1", "example.com/v1"])
    cases.append(_case(
        "kyv-crd-version", "kyverno", "crd-conversion",
        "规则匹配 v1beta1，CRD conversion 后以 v1 提交则规则不命中",
        _req(kind="TrainingJob", api_version="example.com/v1"),
        _pod(name="job", privileged=True), [p_beta], [p_v1]))

    # 10. Cluster-scoped CRD bypasses namespaced policy.
    p_ns = _policy("kyverno", "Enforce", ["privileged"], namespaces=["default"])
    p_cluster = _policy("kyverno", "Enforce", ["privileged"], namespaces=["*"],
                        cluster_scope=True)
    cases.append(_case(
        "kyv-cluster-scope", "kyverno", "scope",
        "namespaced 规则不匹配 cluster-scoped CRD，privileged 工作负载放行",
        _req(kind="ClusterTrainingJob", api_version="example.com/v1",
             cluster_scoped=True), _pod(name="cj", privileged=True),
        [p_ns], [p_cluster]))

    # 11. Gatekeeper dryrun.
    g_dry = _policy("gatekeeper", "dryrun", ["privileged"], name="K8sDenyPrivileged")
    g_deny = _policy("gatekeeper", "deny", ["privileged"], name="K8sDenyPrivileged")
    cases.append(_case(
        "gk-dryrun", "gatekeeper", "dryrun",
        "Constraint enforcementAction=dryrun 只写入审计，不拒绝",
        _req(), _pod(privileged=True), [g_dry], [g_deny]))

    # 12. Gatekeeper warn.
    g_warn = _policy("gatekeeper", "warn", ["privileged"])
    cases.append(_case(
        "gk-warn", "gatekeeper", "audit-mode",
        "Constraint enforcementAction=warn 仅返回 warning，仍准入",
        _req(), _pod(privileged=True), [g_warn], [g_deny]))

    # 13. excludedNamespaces.
    g_excl = _policy("gatekeeper", "deny", ["privileged"],
                     exclude_namespaces=["kube-system"])
    cases.append(_case(
        "gk-excluded-namespace", "gatekeeper", "exemption",
        "Constraint excludedNamespaces 将 kube-system 排除",
        _req(namespace="kube-system"), _pod(ns="kube-system", privileged=True),
        [g_excl], [g_deny]))

    # 14. labelSelector evaluated after a mutator removes the label.
    g_sel = _policy("gatekeeper", "deny", ["privileged"],
                    label_selector={"security": "high"})
    g_strip = _policy("gatekeeper", "Mutate", [], mutate_labels={"security": "low"})
    g_sel_hard = _policy("gatekeeper", "deny", ["privileged"])
    cases.append(_case(
        "gk-labelselector-mutation", "gatekeeper", "mutation-order",
        "constraint 依赖 labelSelector，mutator 将 security 改写为 low 后不再匹配",
        _req(), _pod(privileged=True, labels={"security": "high"}),
        [g_strip, g_sel], [g_strip, g_sel_hard]))

    # 15. pods/exec subresource.
    g_no_exec = _policy("gatekeeper", "deny", ["exec_shell"])
    g_exec = _policy("gatekeeper", "deny", ["exec_shell"], subresources=["exec"])
    cases.append(_case(
        "gk-exec-subresource", "gatekeeper", "subresource",
        "Constraint 未声明 subresources，pods/exec 不被评估",
        _req(operation="CONNECT", subresource="exec"), _pod(command=["/bin/bash"]),
        [g_no_exec], [g_exec]))

    # 16. CRD version.
    g_beta = _policy("gatekeeper", "deny", ["privileged"],
                     api_versions=["example.com/v1beta1"])
    g_v1 = _policy("gatekeeper", "deny", ["privileged"],
                   api_versions=["example.com/v1"])
    cases.append(_case(
        "gk-crd-version", "gatekeeper", "crd-conversion",
        "Constraint 只匹配 v1beta1，conversion webhook 后提交 v1 即漏过",
        _req(kind="TrainingJob", api_version="example.com/v1"),
        _pod(privileged=True), [g_beta], [g_v1]))

    # 17. scope mismatch.
    g_ns = _policy("gatekeeper", "deny", ["privileged"], namespaces=["*"])
    g_cluster = _policy("gatekeeper", "deny", ["privileged"], namespaces=["*"],
                        cluster_scope=True)
    cases.append(_case(
        "gk-scope-cluster", "gatekeeper", "scope",
        "Constraint scope=Namespaced 对 cluster-scoped 资源不生效",
        _req(kind="ClusterTrainingJob", api_version="example.com/v1",
             cluster_scoped=True), _pod(name="cj", privileged=True),
        [g_ns], [g_cluster]))

    # 18. Parameter wildcard exempts every image.
    g_param = _policy("gatekeeper", "deny", ["image"])
    g_param["exemptImages"] = ["*"]
    g_param_hard = _policy("gatekeeper", "deny", ["image"])
    g_param_hard["allowImages"] = ["registry.local/"]
    cases.append(_case(
        "gk-param-wildcard", "gatekeeper", "parameter-wildcard",
        "Constraint 参数 exemptImages=[\"*\"] 使任意镜像豁免",
        _req(), _pod(image="evil.example/x:latest"), [g_param], [g_param_hard]))

    # 19. namespaceSelector does not match the target namespace.
    g_ns_sel = _policy("gatekeeper", "deny", ["privileged"],
                       namespace_labels={"policy": "enforced"})
    g_ns_sel_hard = _policy("gatekeeper", "deny", ["privileged"])
    cases.append(_case(
        "gk-namespace-selector", "gatekeeper", "exemption",
        "namespaceSelector 未覆盖新租户命名空间，privileged Pod 放行",
        _req(namespace="tenant-new"), _pod(ns="tenant-new", privileged=True),
        [g_ns_sel], [g_ns_sel_hard], namespace_labels={"team": "tenant-new"}))

    # 20. Gatekeeper containers-only scope misses initContainers.
    g_init = _policy("gatekeeper", "deny", ["privileged"], scope="containers")
    g_init_hard = _policy("gatekeeper", "deny", ["privileged"], scope="all")
    cases.append(_case(
        "gk-init-container", "gatekeeper", "init-container",
        "Constraint 只遍历 containers，initContainers.privileged 逃逸",
        _req(), _pod(init_priv=True), [g_init], [g_init_hard]))

    return cases


_CASES_CACHE: list[dict] | None = None


def cases() -> list[dict]:
    global _CASES_CACHE
    if _CASES_CACHE is None:
        _CASES_CACHE = _default_cases()
    return copy.deepcopy(_CASES_CACHE)


def _get(obj: dict, dotted: str):
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _precondition_ok(policy: dict, obj: dict, request: dict) -> bool:
    for cond in policy.get("preconditions") or []:
        actual = _get({"request": request, "object": obj}, cond.get("field", ""))
        op = str(cond.get("op") or "Equals").lower()
        expected = cond.get("value")
        if op == "equals" and actual != expected:
            return False
        if op == "notequals" and actual == expected:
            return False
        if op == "in" and actual not in (expected or []):
            return False
        if op == "notin" and actual in (expected or []):
            return False
    return True


def _labels_match(labels: dict, selector: dict | None) -> bool:
    for key, value in (selector or {}).items():
        if str(labels.get(key)) != str(value):
            return False
    return True


def _matches(policy: dict, obj: dict, request: dict, *, namespace_labels=None,
             after_mutation=False) -> tuple[bool, str]:
    match = policy.get("match") or {}
    if match.get("kinds") and request.get("kind") not in match["kinds"]:
        return False, "kind"
    if match.get("apiVersions") and request.get("apiVersion") not in match["apiVersions"]:
        return False, "api-version"
    namespaces = match.get("namespaces")
    if namespaces is not None:
        if "*" not in namespaces and request.get("namespace") not in namespaces:
            return False, "namespace"
        if request.get("cluster_scoped") and "*" not in namespaces:
            return False, "cluster-scoped"
    if match.get("scope") == "Cluster" and not request.get("cluster_scoped"):
        return False, "scope-not-cluster"
    if match.get("scope") != "Cluster" and request.get("cluster_scoped"):
        return False, "scope-namespaced"
    operations = match.get("operations")
    if operations and request.get("operation") not in operations:
        return False, "operation"
    subresources = match.get("subresources")
    req_sub = request.get("subresource") or ""
    if subresources is not None:
        if req_sub not in subresources:
            return False, "subresource"
    elif req_sub:
        # A rule without an explicit subresource block only evaluates the
        # primary resource; pods/exec and pods/ephemeralcontainers are skipped.
        return False, "subresource-not-declared"
    selector = match.get("labelSelector")
    if selector and not _labels_match((obj.get("metadata") or {}).get("labels") or {}, selector):
        return False, "label-selector"
    ns_selector = match.get("namespaceLabels")
    if ns_selector and not _labels_match(namespace_labels or {}, ns_selector):
        return False, "namespace-selector"
    if not _precondition_ok(policy, obj, request):
        return False, "precondition"
    exclude = policy.get("exclude") or {}
    if request.get("namespace") in (exclude.get("namespaces") or []):
        return False, "excluded-namespace"
    labels = (obj.get("metadata") or {}).get("labels") or {}
    exclude_labels = exclude.get("labels")
    if exclude_labels and _labels_match(labels, exclude_labels):
        return False, "excluded-label"
    return True, "matched"


def _containers(obj: dict, scope: str) -> list[dict]:
    spec = obj.get("spec") or {}
    if scope == "initContainers":
        return list(spec.get("initContainers") or [])
    if scope == "ephemeralContainers":
        return list(spec.get("ephemeralContainers") or [])
    if scope == "all":
        return (list(spec.get("containers") or []) + list(spec.get("initContainers") or []) +
                list(spec.get("ephemeralContainers") or []))
    return list(spec.get("containers") or [])


def _violations(policy: dict, obj: dict, request: dict) -> list[str]:
    validate = policy.get("validate") or {}
    scope = validate.get("scope") or "containers"
    containers = _containers(obj, scope)
    checks = validate.get("checks") or []
    found: list[str] = []
    for check in checks:
        if check == "privileged":
            if any((c.get("securityContext") or {}).get("privileged") for c in containers):
                found.append("privileged")
        elif check == "hostNetwork":
            if (obj.get("spec") or {}).get("hostNetwork"):
                found.append("hostNetwork")
        elif check == "hostPath":
            for volume in (obj.get("spec") or {}).get("volumes") or []:
                path = str(((volume or {}).get("hostPath") or {}).get("path") or "")
                if path and any(path == p or path.startswith(p.rstrip("/") + "/")
                                for p in SENSITIVE_PATHS):
                    found.append("hostPath")
                    break
        elif check == "image":
            allow = policy.get("allowImages") or []
            exempt = policy.get("exemptImages") or []
            if "*" not in exempt:
                bad = [c.get("image", "") for c in containers
                       if not any(str(c.get("image", "")).startswith(a) for a in allow)
                       and not any(_glob(str(c.get("image", "")), e) for e in exempt)]
                if bad:
                    found.append("image")
        elif check == "exec_shell":
            if (request.get("subresource") or "") == "exec":
                cmd = [str(x) for x in obj.get("command") or []]
                if any(x in ("/bin/sh", "/bin/bash", "sh", "bash") for x in cmd):
                    found.append("exec_shell")
        elif check == "capabilities":
            for c in containers:
                caps = ((c.get("securityContext") or {}).get("capabilities") or {}).get("add") or []
                if "SYS_ADMIN" in caps or "NET_ADMIN" in caps:
                    found.append("capabilities")
                    break
        elif check == "runAsRoot":
            for c in containers:
                ctx = c.get("securityContext") or {}
                if ctx.get("runAsUser") == 0 or ctx.get("runAsNonRoot") is False:
                    found.append("runAsRoot")
                    break
        elif check == "labels":
            labels = (obj.get("metadata") or {}).get("labels") or {}
            if any(key not in labels for key in policy.get("requireLabels") or []):
                found.append("labels")
    return sorted(set(found))


def _glob(value: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(value, pattern)


def _enforces(policy: dict) -> bool:
    action = str(policy.get("action") or "").lower()
    if policy.get("engine") == "kyverno":
        return action in ("enforce", "deny")
    return action in ("deny", "enforce")


def _enforcement_label(policy: dict) -> str:
    return str(policy.get("action") or ("Enforce" if policy.get("engine") == "kyverno"
                                        else "deny"))


def evaluate_case(case: dict, *, hardened: bool = False) -> dict:
    policies = copy.deepcopy(case["hardened_policies" if hardened else "vulnerable_policies"])
    obj = copy.deepcopy(case["object"])
    request = dict(case["request"])
    namespace_labels = dict(case.get("namespace_labels") or {})
    trace: list[str] = []
    # Mutating admission runs before validating admission.
    for policy in policies:
        mutate = policy.get("mutate") or {}
        if not mutate:
            continue
        matched, reason = _matches(policy, obj, request, namespace_labels=namespace_labels)
        if matched:
            labels = obj.setdefault("metadata", {}).setdefault("labels", {})
            labels.update(mutate.get("labels") or {})
            trace.append(f"mutate:{policy['name']}:{reason}")
        else:
            trace.append(f"mutate-skip:{policy['name']}:{reason}")
    denied_by = None
    violations: list[dict] = []
    for policy in policies:
        if not policy.get("validate") or not (policy.get("validate") or {}).get("checks"):
            continue
        matched, reason = _matches(policy, obj, request, namespace_labels=namespace_labels)
        if not matched:
            trace.append(f"validate-skip:{policy['name']}:{reason}")
            continue
        found = _violations(policy, obj, request)
        if not found:
            trace.append(f"validate-pass:{policy['name']}")
            continue
        action = _enforcement_label(policy)
        item = {"policy": policy["name"], "engine": policy["engine"],
                "action": action, "checks": found}
        violations.append(item)
        if _enforces(policy):
            denied_by = item
            trace.append(f"deny:{policy['name']}:{','.join(found)}")
            break
        trace.append(f"audit-only:{policy['name']}:{','.join(found)}")
    admitted = denied_by is None
    return {
        "id": case["id"],
        "engine": case["engine"],
        "mechanism": case["mechanism"],
        "admitted": admitted,
        "denied_by": denied_by,
        "violations": violations,
        "trace": trace,
        "labels_after_mutation": (obj.get("metadata") or {}).get("labels") or {},
        "result_sha256": hash_payload({"id": case["id"], "hardened": hardened,
                                       "admitted": admitted, "trace": trace}),
    }


def audit(cases_in: list[dict] | None = None) -> dict:
    rows = cases_in if cases_in is not None else cases()
    results: list[dict] = []
    findings: list[dict] = []
    vulnerable_admitted = 0
    hardened_admitted = 0
    for case in rows:
        vuln = evaluate_case(case, hardened=False)
        hard = evaluate_case(case, hardened=True)
        vulnerable_admitted += int(vuln["admitted"])
        hardened_admitted += int(hard["admitted"])
        results.append({"id": case["id"], "engine": case["engine"],
                        "mechanism": case["mechanism"], "title": case["title"],
                        "admitted": vuln["admitted"], "trace": vuln["trace"],
                        "vulnerable": vuln, "hardened": hard})
        if vuln["admitted"] and not hard["admitted"]:
            findings.append(finding(
                "high",
                f"{case['engine']} 准入语义绕过：{case['title']}",
                {"case": case["id"], "mechanism": case["mechanism"],
                 "vulnerable_trace": vuln["trace"],
                 "hardened_trace": hard["trace"],
                 "violations": vuln["violations"]},
                fix="将 Audit/dryrun 提升为 Enforce/deny；删除工作负载可控 exempt 标签与宽泛排除；"
                    "覆盖 init/ephemeral 容器与 exec/ephemeralcontainers 子资源；"
                    "CRD 多版本与 cluster-scoped 资源统一校验；先稳定 mutation 再执行 validation。",
            ))
    return {
        "total": len(rows),
        "vulnerable_admitted": vulnerable_admitted,
        "hardened_admitted": hardened_admitted,
        "findings": len(findings),
        "results": results,
        "finding_items": findings,
        "results_sha256": hash_payload(results),
    }


def summary(report: dict) -> str:
    return summary_json("admission-policy-semantics", [], extra={
        "total": report["total"],
        "vulnerable_admitted": report["vulnerable_admitted"],
        "hardened_admitted": report["hardened_admitted"],
    })


def load_cases(path: Path | str | None = None) -> list[dict]:
    if path is None:
        return cases()
    return json.loads(Path(path).read_text(encoding="utf-8"))["cases"]
