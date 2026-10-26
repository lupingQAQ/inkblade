# -*- coding: utf-8 -*-
"""admission dry-run / fuzz 探测（CM-24）：fuzz-pod 模板 → 准入边界矩阵。

- ``fuzz_pods``：覆盖 8 类高风险 Pod 形态（privileged、hostNetwork、hostPID、hostPath、
  runAsUser 0、CAP_SYS_ADMIN、hostPort、seccomp Unconfined）；
- ``evaluate``：以内置声明式策略（路径 + 操作）判断 deny/allow，完全离线；
- ``probe(submit=fn)``：可注入真实 API Server 的 dry-run 适配器（``fn(pod) ->
  {"allowed": bool, "reason": str}``）；默认不联网、只做离线矩阵；
- 输出“准入边界”与绕过点，供修复建议；不创建任何 Pod、不接触集群。
"""

from __future__ import annotations

import re
from typing import Any, Callable

DEFAULT_POLICIES = [
    {"id": "deny-privileged", "path": "spec.containers.*.securityContext.privileged",
     "op": "truthy", "reason": "privileged 容器可逃逸"},
    {"id": "deny-host-network", "path": "spec.hostNetwork", "op": "truthy",
     "reason": "hostNetwork 绕过网络策略"},
    {"id": "deny-host-pid", "path": "spec.hostPID", "op": "truthy",
     "reason": "hostPID 可观察/注入宿主进程"},
    {"id": "deny-host-path", "path": "spec.volumes.*.hostPath", "op": "exists",
     "reason": "hostPath 可挂载宿主敏感路径"},
    {"id": "deny-root-user", "path": "spec.containers.*.securityContext.runAsUser",
     "op": "equals", "value": 0, "reason": "以 root 运行"},
    {"id": "deny-sys-admin", "path": "spec.containers.*.securityContext.capabilities.add",
     "op": "contains", "value": "SYS_ADMIN", "reason": "CAP_SYS_ADMIN 高危"},
    {"id": "deny-host-port", "path": "spec.containers.*.ports.*.hostPort", "op": "exists",
     "reason": "hostPort 暴露节点端口"},
    {"id": "deny-unconfined-seccomp", "path": "spec.containers.*.securityContext.seccompProfile.type",
     "op": "equals", "value": "Unconfined", "reason": "seccomp 未限制"},
]


def fuzz_pods() -> list[dict]:
    base = {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "trident-fuzz", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "registry.local/app:1",
                                     "securityContext": {"runAsUser": 1000,
                                                         "runAsNonRoot": True,
                                                         "allowPrivilegeEscalation": False}}]}}
    pods = []

    def add(pid: str, patch: Callable[[dict], None], *, expect: str):
        import copy

        pod = copy.deepcopy(base)
        pod["metadata"]["name"] = f"trident-fuzz-{pid}"
        patch(pod)
        pod["id"] = pid
        pod["expect"] = expect
        pods.append(pod)

    def container(pod):
        return pod["spec"]["containers"][0]

    add("privileged", lambda p: container(p)["securityContext"].update(privileged=True),
        expect="deny")
    add("host-network", lambda p: p["spec"].update(hostNetwork=True), expect="deny")
    add("host-pid", lambda p: p["spec"].update(hostPID=True), expect="deny")
    add("host-path", lambda p: p["spec"].update(
        volumes=[{"name": "host", "hostPath": {"path": "/var/run/docker.sock"}}]), expect="deny")
    add("root-user", lambda p: container(p)["securityContext"].update(runAsUser=0),
        expect="deny")
    add("sys-admin", lambda p: container(p)["securityContext"].update(
        capabilities={"add": ["SYS_ADMIN"]}), expect="deny")
    add("host-port", lambda p: container(p).update(
        ports=[{"containerPort": 8080, "hostPort": 8080}]), expect="deny")
    add("unconfined", lambda p: container(p)["securityContext"].update(
        seccompProfile={"type": "Unconfined"}), expect="deny")
    return pods


def _get_all(obj: Any, path: str) -> list[Any]:
    parts = [p for p in path.split(".") if p]
    cur = [obj]
    for part in parts:
        nxt = []
        for item in cur:
            if part == "*":
                if isinstance(item, list):
                    nxt.extend(item)
                elif isinstance(item, dict):
                    nxt.extend(item.values())
            elif isinstance(item, list):
                try:
                    nxt.append(item[int(part)])
                except (ValueError, IndexError):
                    continue
            elif isinstance(item, dict) and part in item:
                nxt.append(item[part])
        cur = nxt
    return cur


def _match(values: list[Any], policy: dict) -> bool:
    op = policy.get("op")
    if op == "exists":
        return bool(values)
    if op == "truthy":
        return any(bool(v) for v in values)
    if op == "equals":
        return any(v == policy.get("value") for v in values)
    if op == "contains":
        want = policy.get("value")
        return any(isinstance(v, list) and want in v for v in values) or \
            any(isinstance(v, str) and want in v for v in values)
    if op == "regex":
        return any(re.search(str(policy.get("value")), str(v)) for v in values)
    return False


def evaluate(pod: dict, policies: list[dict] | None = None) -> dict:
    policies = DEFAULT_POLICIES if policies is None else policies
    matched = []
    for policy in policies:
        values = _get_all(pod, str(policy.get("path") or ""))
        if _match(values, policy):
            matched.append({"id": policy.get("id"), "reason": policy.get("reason", ""),
                             "path": policy.get("path")})
    return {"pod": pod.get("id") or pod.get("metadata", {}).get("name", ""),
            "decision": "deny" if matched else "allow",
            "matched": matched, "ok": (not matched) == (pod.get("expect") == "allow")}


def probe(pods: list[dict] | None = None, policies: list[dict] | None = None,
          submit: Callable[[dict], dict] | None = None) -> dict:
    pods = pods or fuzz_pods()
    policies = DEFAULT_POLICIES if policies is None else policies
    rows = []
    for pod in pods:
        offline = evaluate(pod, policies)
        row = {"pod": offline["pod"], "expect": pod.get("expect", ""),
               "decision": offline["decision"], "matched": offline["matched"],
               "mode": "offline"}
        if submit is not None:
            try:
                res = submit(pod)
                row.update({"decision": "allow" if res.get("allowed") else "deny",
                            "reason": res.get("reason", ""), "mode": "api-dry-run"})
            except Exception as exc:
                row.update({"decision": "error", "reason": f"{type(exc).__name__}: {exc}",
                            "mode": "api-dry-run"})
        row["ok"] = row["decision"] == pod.get("expect")
        rows.append(row)
    boundary = [r for r in rows if r["decision"] == "allow"]
    return {"pods": len(rows), "policies": len(policies), "rows": rows,
            "allowed": len(boundary), "denied": sum(1 for r in rows if r["decision"] == "deny"),
            "gaps": [r["pod"] for r in rows if r["expect"] == "deny" and r["decision"] == "allow"],
            "mode": "api-dry-run" if submit else "offline"}


def render_md(result: dict) -> str:
    lines = ["# Admission dry-run 矩阵", "",
             f"- Pod 模板 {result.get('pods')}；策略 {result.get('policies')}；"
             f"允许 {result.get('allowed')}；拒绝 {result.get('denied')}", "",
             "| Pod | 期望 | 结果 | 匹配策略 | 模式 |", "|---|---|---|---|---|"]
    for r in result.get("rows", []):
        lines.append(f"| {r['pod']} | {r.get('expect')} | {r['decision']} | "
                     f"{', '.join(m.get('id', '') for m in r.get('matched', [])) or '—'} | {r.get('mode')} |")
    return "\n".join(lines) + "\n"
