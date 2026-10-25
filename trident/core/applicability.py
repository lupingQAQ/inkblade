# -*- coding: utf-8 -*-
"""CVE 适用性判定：版本区间 × 前置条件 × 当前环境实测证据。

三件套
------
1. 版本区间：每条 CVE 声明受影响产品与区间（``version_range`` / ``affected``），
   用环境清单里的实测版本判定命中 / 不命中 / 信息不足。
2. 前置条件：结构化 ``conditions``（and/or/not、命名条件、快照字段、主动探测结果）。
   条件评估器可插拔：``register_condition`` 注册后即可在目录里引用。
3. 实测证据：每个判定都携带 ``field``（清单字段）与 ``source``（kubectl / snapshot /
   probe / catalog），并输出补采建议。

四态语义（诚实性约束）
----------------------
- ``applicable``：版本命中且全部前置条件为真。
- ``blocked``：版本命中但至少一个前置条件为假（列缺失条件）。
- ``not-applicable``：版本明确不命中，或组件在完整扫描中确认未部署。
- ``unknown``：版本/条件/探测信息不足。**unknown 永不自动升级为 applicable。**

目录兼容
--------
``trident/core/cve-catalog.json`` 是本仓库的权威目录；本模块也接受
``cves`` / ``entries`` / ``items`` 等外层键、``affected`` 字符串或列表、
``version_range``、``affected_versions`` 等常见写法。缺少结构化 conditions 时，
会把 ``exploit_conditions`` 自由文本按保守映射编译为可验证条件；不能映射的
条款记为 unknown，而不是默认满足。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = "trident-cve-assessment-v1"
CATALOG_SCHEMA = "trident-cve-catalog-v1"

STATE_APPLICABLE = "applicable"
STATE_BLOCKED = "blocked"
STATE_NOT_APPLICABLE = "not-applicable"
STATE_UNKNOWN = "unknown"
STATES = (STATE_APPLICABLE, STATE_BLOCKED, STATE_NOT_APPLICABLE, STATE_UNKNOWN)

STATE_LABELS = {
    STATE_APPLICABLE: ("适用", "applicable"),
    STATE_BLOCKED: ("前置不满足", "blocked"),
    STATE_NOT_APPLICABLE: ("不适用", "not applicable"),
    STATE_UNKNOWN: ("信息不足", "unknown"),
}

STATE_ORDER = {STATE_APPLICABLE: 0, STATE_UNKNOWN: 1, STATE_BLOCKED: 2,
               STATE_NOT_APPLICABLE: 3}

_CVE_RE = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})",
                     re.I)
_VERSION_RE = re.compile(
    r"^[vV]?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+([0-9A-Za-z][0-9A-Za-z.-]*))?$"
)
_VERSION_SEARCH_RE = re.compile(
    r"(?<![\w.])[vV]?(\d+(?:\.\d+)+|\d+)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+([0-9A-Za-z][0-9A-Za-z.-]*))?"
)
_CLAUSE_RE = re.compile(
    r"^\s*(<=|>=|!=|==|=|<|>|~|\^)?\s*[vV]?(\d+(?:\.\d+)*(?:\.(?:x|X|\*))?)\s*$"
)
_RANGE_SPLIT_RE = re.compile(r"\s+(?=(?:<=|>=|!=|==|=|<|>))")


class ApplicabilityError(ValueError):
    """目录/清单/条件表达式非法。"""


class ApplicabilityBlocked(RuntimeError):
    """模块被 CVE 适用性闸门拒绝（与授权/备份闸门同为 91）。"""

    exit_code = 91


# ====================================================================== 版本


@dataclass(frozen=True)
class Version:
    nums: tuple[int, ...]
    pre: str = ""

    @property
    def rank(self) -> int:
        """rc/alpha/beta/pre/dev 低于正式版；厂商后缀（+k3s/-k3s）按正式版处理。"""
        low = self.pre.lower()
        if low.startswith(("rc", "alpha", "beta", "pre", "dev")):
            return 0
        return 1


def parse_version(text: Any) -> Version | None:
    """从 ``v1.36.5+k3s1`` / ``containerd://2.3.4-k3s1.36`` / ``1.1.11`` 提取版本。"""
    if text is None:
        return None
    raw = str(text).strip()
    if not raw:
        return None
    m = _VERSION_RE.match(raw)
    if not m:
        m = _VERSION_SEARCH_RE.search(raw)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    return Version(nums, (m.group(2) or "").strip())


def _cmp_version(a: Version, b: Version) -> int:
    width = max(len(a.nums), len(b.nums))
    aa = a.nums + (0,) * (width - len(a.nums))
    bb = b.nums + (0,) * (width - len(b.nums))
    if aa != bb:
        return -1 if aa < bb else 1
    if a.rank != b.rank:
        return -1 if a.rank < b.rank else 1
    if a.rank == 0 and a.pre.lower() != b.pre.lower():
        return -1 if a.pre.lower() < b.pre.lower() else 1
    return 0


def compare_versions(a: Any, b: Any) -> int:
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        raise ApplicabilityError(f"无法解析版本：{a!r} / {b!r}")
    return _cmp_version(va, vb)


def _parse_range_clause(clause: str, observed: Version) -> bool:
    text = clause.strip()
    if not text:
        return True
    if text in ("*", "any", "all", "ANY", "ALL"):
        return True
    if text.lower() in ("none", "never"):
        return False
    m = _CLAUSE_RE.match(text)
    if not m:
        raise ApplicabilityError(f"无法解析版本区间片段：{clause!r}")
    op = m.group(1) or "=="
    raw = m.group(2)
    if raw.endswith((".x", ".X", ".*")):
        base = raw[:-2]
        ref = parse_version(base)
        if ref is None:
            raise ApplicabilityError(f"无法解析版本区间片段：{clause!r}")
        width = len(ref.nums)
        width = max(width, 1)
        pad = observed.nums + (0,) * max(0, width - len(observed.nums))
        return pad[:width] == ref.nums[:width]
    ref = parse_version(raw)
    if ref is None:
        raise ApplicabilityError(f"无法解析版本区间片段：{clause!r}")
    width = max(len(observed.nums), len(ref.nums))
    obs = observed.nums + (0,) * (width - len(observed.nums))
    r = ref.nums + (0,) * (width - len(ref.nums))
    if op in ("==", "="):
        return _cmp_version(observed, ref) == 0
    if op == "!=":
        return _cmp_version(observed, ref) != 0
    if op == "<":
        return _cmp_version(observed, ref) < 0
    if op == "<=":
        return _cmp_version(observed, ref) <= 0
    if op == ">":
        return _cmp_version(observed, ref) > 0
    if op == ">=":
        return _cmp_version(observed, ref) >= 0
    if op == "^":
        # ^1.2.3 -> >=1.2.3,<2.0.0 ; ^0.2.3 -> <0.3.0
        upper = list(r)
        idx = 0
        while idx < len(upper) - 1 and upper[idx] == 0:
            idx += 1
        upper[idx] += 1
        for j in range(idx + 1, len(upper)):
            upper[j] = 0
        return _cmp_version(observed, ref) >= 0 and obs < tuple(upper)
    if op == "~":
        # ~1.2.3 -> >=1.2.3,<1.3.0
        upper = list(r[:2]) if len(r) >= 2 else list(r)
        if len(upper) < 2:
            upper = [r[0] + 1, 0]
        else:
            upper[1] += 1
        return _cmp_version(observed, ref) >= 0 and obs < tuple(upper)
    raise ApplicabilityError(f"未知版本运算符：{op!r}")


def version_in_range(observed: Any, spec: Any) -> bool:
    """判断 observed 是否落入 spec（支持 ``<1.2``、``>=1.0,<1.2``、``1.0 - 1.2``、``||``）。"""
    if spec is None:
        return True
    if isinstance(spec, (list, tuple, set)):
        return any(version_in_range(observed, s) for s in spec)
    if str(observed).strip() in ("*", "any", "all", "ANY", "ALL"):
        return True
    vo = parse_version(observed)
    if vo is None:
        raise ApplicabilityError(f"无法解析观测版本：{observed!r}")
    text = str(spec).strip()
    if not text:
        return True
    if text in ("*", "any", "all", "ANY", "ALL"):
        return True
    # 1.0.0 - 1.2.0（含端点），避免把 1.0.0-rc1 误拆
    hyphen = re.match(r"^\s*([vV]?\d+(?:\.\d+)*)\s+-\s+([vV]?\d+(?:\.\d+)*)\s*$", text)
    if hyphen:
        return (compare_versions(observed, hyphen.group(1)) >= 0
                and compare_versions(observed, hyphen.group(2)) <= 0)
    alternatives = [a.strip() for a in text.split("||") if a.strip()]
    if len(alternatives) > 1:
        return any(version_in_range(observed, a) for a in alternatives)
    # 逗号 / 空格分隔的 AND 片段
    parts: list[str] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts.extend(p for p in _RANGE_SPLIT_RE.split(chunk) if p.strip())
    return all(_parse_range_clause(p, vo) for p in parts)


# ====================================================================== 条件


@dataclass
class ConditionResult:
    value: bool | None
    label: str = ""
    evidence: list[dict] = field(default_factory=list)
    collect: list[dict] = field(default_factory=list)
    reason: str = ""

    @property
    def status(self) -> str:
        if self.value is True:
            return "true"
        if self.value is False:
            return "false"
        return "unknown"


@dataclass
class ConditionContext:
    inventory: dict
    products: dict
    probes: dict
    component: str = ""

    @property
    def facts(self) -> dict:
        return self.inventory.get("facts") or {}


ConditionFn = Callable[[ConditionContext, Any], ConditionResult]
_CONDITION_REGISTRY: dict[str, ConditionFn] = {}


def register_condition(name: str, fn: ConditionFn) -> None:
    """注册/覆盖条件评估器（插件入口）。"""
    key = str(name).strip().lower().replace("-", "_")
    if not key:
        raise ApplicabilityError("条件名不能为空")
    _CONDITION_REGISTRY[key] = fn


def condition_names() -> list[str]:
    return sorted(_CONDITION_REGISTRY)


def _ev(field_name: str, value: Any, source: str, detail: str = "") -> dict:
    out = {"field": field_name, "value": value, "source": source}
    if detail:
        out["detail"] = detail
    return out


def _collect(field_name: str, why: str, command: str = "") -> dict:
    out = {"field": field_name, "why": why}
    if command:
        out["command"] = command
    return out


def _source(inventory: dict, default: str = "inventory") -> str:
    src = inventory.get("source")
    if isinstance(src, dict):
        return str(src.get("label") or src.get("mode") or default)
    return str(src or default)


def _coverage(inventory: dict, key: str) -> bool:
    return bool((inventory.get("coverage") or {}).get(key))


def _pod_list(inventory: dict) -> list[dict]:
    return list(inventory.get("pods") or [])


def _fact(inventory: dict, name: str, default=None):
    facts = inventory.get("facts") or {}
    if name in facts:
        return facts[name]
    return default


def _fact_source(inventory: dict, name: str) -> str:
    return str(((inventory.get("fact_sources") or {}).get(name))
               or _source(inventory))


def _cond_result(value: bool | None, label: str, *, field_name: str = "",
                 observed: Any = None, source: str = "", detail: str = "",
                 collect: list[dict] | None = None, reason: str = "") -> ConditionResult:
    evidence = []
    if field_name:
        evidence.append(_ev(field_name, observed, source, detail))
    return ConditionResult(value, label, evidence, collect or [], reason)


def _unknown(label: str, *, field_name: str, why: str, command: str = "",
             observed: Any = None, source: str = "") -> ConditionResult:
    return ConditionResult(
        None, label,
        [_ev(field_name, observed, source, why)] if field_name else [],
        [_collect(field_name, why, command)],
        why,
    )


def _bool_from_fact(ctx: ConditionContext, name: str, label: str,
                    collect: dict) -> ConditionResult:
    value = _fact(ctx.inventory, name)
    src = _fact_source(ctx.inventory, name)
    if value is None:
        return ConditionResult(None, label,
                               [_ev(name, None, src, "清单未提供该字段")],
                               [collect], "字段缺失")
    return _cond_result(bool(value), label, field_name=name, observed=value, source=src)


def _pods_scanned(ctx: ConditionContext) -> bool:
    return _coverage(ctx.inventory, "pods")


def _components_for(inventory: dict, product: str) -> list[dict]:
    want = canonical_product(product)
    out = []
    for c in inventory.get("components") or []:
        cname = c.get("product") or c.get("name") or c.get("image") or ""
        if canonical_product(cname) == want:
            out.append(c)
    return out


# ---------------------------------------------------------------- named evaluators

def _cond_privileged(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.privileged", "存在特权容器",
        _collect("workloads.privileged",
                 "读取所有 Pod 的 securityContext.privileged",
                 "kubectl get pods -A -o json"),
    )


def _cond_hostpath(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.host_path", "存在 hostPath 挂载",
        _collect("workloads.host_path", "读取所有 Pod 的 spec.volumes[].hostPath",
                 "kubectl get pods -A -o json"),
    )


def _cond_host_network(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.host_network", "存在 hostNetwork 工作负载",
        _collect("workloads.host_network", "读取所有 Pod 的 spec.hostNetwork",
                 "kubectl get pods -A -o json"),
    )


def _cond_host_pid(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.host_pid", "存在 hostPID 工作负载",
        _collect("workloads.host_pid", "读取所有 Pod 的 spec.hostPID",
                 "kubectl get pods -A -o json"),
    )


def _cond_host_ipc(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.host_ipc", "存在 hostIPC 工作负载",
        _collect("workloads.host_ipc", "读取所有 Pod 的 spec.hostIPC",
                 "kubectl get pods -A -o json"),
    )


def _cond_automount(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.automount_sa_token", "ServiceAccount token 自动挂载",
        _collect("workloads.automount_sa_token",
                 "读取 Pod spec.automountServiceAccountToken 与 SA 默认值",
                 "kubectl get pods,serviceaccounts -A -o json"),
    )


def _cond_runtime_socket(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.runtime_socket", "挂载容器运行时 socket",
        _collect("workloads.runtime_socket",
                 "检查 hostPath 是否含 docker.sock / containerd.sock / crio.sock",
                 "kubectl get pods -A -o json"),
    )


def _cond_sys_admin(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "workloads.cap_sys_admin", "容器具备 SYS_ADMIN",
        _collect("workloads.cap_sys_admin",
                 "读取 securityContext.capabilities.add",
                 "kubectl get pods -A -o json"),
    )


def _cond_auth_disabled(ctx: ConditionContext, node: Any) -> ConditionResult:
    """API Server 匿名/AlwaysAllow；组件面则读取 probes.component_auth。"""
    comp = (ctx.component or "").strip().lower()
    probes = ctx.probes or {}
    if comp and comp not in ("kubernetes", "k8s", "apiserver", "api-server", "kube-apiserver"):
        per = probes.get("component_auth") or {}
        if isinstance(per, dict) and comp in per:
            val = per[comp]
            if isinstance(val, dict):
                val = val.get("auth_disabled", val.get("anonymous", val.get("enabled")))
            return _cond_result(bool(val), f"{comp} 未启用认证",
                                field_name=f"probes.component_auth.{comp}",
                                observed=val, source=f"probe:component_auth.{comp}")
        for c in _components_for(ctx.inventory, comp):
            if "auth_disabled" in c:
                return _cond_result(bool(c["auth_disabled"]), f"{comp} 未启用认证",
                                    field_name=f"components[{c.get('name')}].auth_disabled",
                                    observed=c["auth_disabled"], source=str(c.get("source") or ""))
        return _unknown(
            f"{comp} 认证配置",
            field_name=f"probes.component_auth.{comp}",
            why="目录要求组件未启用认证，但清单没有该组件的认证探测结果",
            command=f"在授权范围内检查 {comp} 的启动参数/env/管理端口；或通过 --probes 提供 "
                    f'{{"component_auth": {{"{comp}": true}}}}',
            source="probe/catalog",
        )
    value = _fact(ctx.inventory, "apiserver.auth_disabled")
    src = _fact_source(ctx.inventory, "apiserver.auth_disabled")
    if value is not None:
        return _cond_result(bool(value), "API Server 未启用认证",
                            field_name="apiserver.auth_disabled", observed=value, source=src)
    if isinstance(probes.get("auth_disabled"), bool):
        return _cond_result(probes["auth_disabled"], "API Server 未启用认证",
                            field_name="probes.auth_disabled",
                            observed=probes["auth_disabled"], source="probe:auth_disabled")
    return _unknown(
        "API Server 认证配置",
        field_name="apiserver.auth_disabled",
        why="未能从静态 Pod 参数或 kubelet configz 判断 --anonymous-auth / AlwaysAllow",
        command="kubectl get pods -n kube-system -l component=kube-apiserver -o json "
                "（读取 args 中的 --anonymous-auth / --authorization-mode）；"
                "托管集群查云审计/认证配置；或 --probes 提供 {\"auth_disabled\": true/false}",
        source="catalog.preconditions",
    )


def _cond_imds(ctx: ConditionContext, node: Any) -> ConditionResult:
    probes = ctx.probes or {}
    value = probes.get("imds_reachable", (ctx.inventory.get("cloud") or {}).get("imds_reachable"))
    src = "probe:imds_reachable" if "imds_reachable" in probes else _source(ctx.inventory)
    if value is None:
        return _unknown(
            "云元数据服务可达",
            field_name="cloud.imds_reachable",
            why="未执行/未提供 IMDS 主动探测；仅凭版本不能判定可窃取云身份",
            command="在授权 Pod 内只读探测 http://169.254.169.254/latest/meta-data/ "
                    "（AWS）或对应云厂商元数据端点；或用 --probes 提供结果",
            source="catalog.preconditions",
        )
    return _cond_result(bool(value), "云元数据服务可达",
                        field_name="cloud.imds_reachable", observed=value, source=src)


def _cond_network_reachable(ctx: ConditionContext, node: Any) -> ConditionResult:
    probes = ctx.probes or {}
    value = probes.get("network_reachable")
    if isinstance(value, dict):
        key = canonical_product(ctx.component or "")
        if key in value:
            value = value[key]
    if value is None:
        return _unknown(
            "网络可达",
            field_name="probes.network_reachable",
            why="目录要求管理面/服务端口可达，但清单未包含主动网络探测结果",
            command="在授权范围内对组件 Service/NodePort/Ingress 做 TCP/HTTP 只读探测；"
                    "或 --probes 提供 {\"network_reachable\": true/false}",
            source="catalog.preconditions",
        )
    return _cond_result(bool(value), "网络可达",
                        field_name="probes.network_reachable", observed=value,
                        source="probe:network_reachable")


def _cond_kubelet_readonly(ctx: ConditionContext, node: Any) -> ConditionResult:
    value = _fact(ctx.inventory, "kubelet.read_only_port")
    src = _fact_source(ctx.inventory, "kubelet.read_only_port")
    if value is None:
        return _unknown(
            "kubelet 只读端口",
            field_name="kubelet.read_only_port",
            why="未读取 kubelet configz，无法判断 readOnlyPort=10255 是否开启",
            command="kubectl get --raw /api/v1/nodes/<node>/proxy/configz "
                    "（读取 kubeletconfig.readOnlyPort）；或 snapshot 提供 kubelet.read_only_port",
            source="catalog.preconditions",
        )
    try:
        enabled = int(value) > 0
    except (TypeError, ValueError):
        enabled = bool(value)
    return _cond_result(enabled, "kubelet 只读端口开启",
                        field_name="kubelet.read_only_port", observed=value, source=src)


def _cond_feature_gate(ctx: ConditionContext, node: Any) -> ConditionResult:
    gate = ""
    expected = True
    if isinstance(node, dict):
        gate = str(node.get("name") or node.get("gate") or node.get("value") or "")
        expected = bool(node.get("enabled", node.get("equals", True)))
    elif isinstance(node, str):
        gate = node
    if not gate:
        return _unknown("feature gate", field_name="feature_gates",
                        why="条件未指定 gate 名称", source="catalog.preconditions")
    value = _fact(ctx.inventory, f"feature_gates.{gate}")
    src = _fact_source(ctx.inventory, f"feature_gates.{gate}")
    if value is None:
        return _unknown(
            f"feature gate {gate}",
            field_name=f"feature_gates.{gate}",
            why="未采集 /metrics 的 kubernetes_feature_enabled",
            command="kubectl get --raw /metrics | findstr kubernetes_feature_enabled",
            source="catalog.preconditions",
        )
    return _cond_result(bool(value) == expected, f"feature gate {gate}",
                        field_name=f"feature_gates.{gate}", observed=value, source=src)


def _cond_flag(ctx: ConditionContext, node: Any) -> ConditionResult:
    name = ""
    expected: Any = None
    if isinstance(node, dict):
        name = str(node.get("name") or node.get("flag") or "")
        expected = node.get("equals", node.get("value"))
    elif isinstance(node, str):
        name = node
    flags = (ctx.inventory.get("apiserver") or {}).get("flags") or {}
    if not name:
        return _unknown("控制面 flag", field_name="apiserver.flags",
                        why="条件未指定 flag 名称", source="catalog.preconditions")
    key = name if name.startswith("--") else f"--{name}"
    if key not in flags:
        return _unknown(
            f"控制面 flag {key}",
            field_name=f"apiserver.flags[{key}]",
            why="未采集到 API Server 静态 Pod 参数",
            command="kubectl get pods -n kube-system -l component=kube-apiserver -o json",
            source="catalog.preconditions",
        )
    actual = flags[key]
    ok = True if expected is None else str(actual).lower() == str(expected).lower()
    return _cond_result(ok, f"控制面 flag {key}",
                        field_name=f"apiserver.flags[{key}]", observed=actual,
                        source="kubectl get pods -n kube-system -l component=kube-apiserver")


def _cond_env(ctx: ConditionContext, node: Any) -> ConditionResult:
    name = ""
    expected: Any = None
    if isinstance(node, dict):
        name = str(node.get("name") or node.get("env") or "")
        expected = node.get("equals", node.get("value"))
    elif isinstance(node, str):
        name = node
    if not name:
        return _unknown("环境变量", field_name="pods[*].env",
                        why="条件未指定 env 名称", source="catalog.preconditions")
    found = []
    for pod in _pod_list(ctx.inventory):
        for c in pod.get("containers") or []:
            env = c.get("env") or {}
            if isinstance(env, dict) and name in env:
                found.append({"pod": f"{pod.get('namespace')}/{pod.get('name')}",
                              "value": env[name]})
            elif isinstance(env, list):
                for item in env:
                    if isinstance(item, dict) and item.get("name") == name:
                        found.append({"pod": f"{pod.get('namespace')}/{pod.get('name')}",
                                      "value": item.get("value")})
    if found:
        if expected is None:
            return ConditionResult(True, f"env {name} 存在",
                                   [_ev(f"pods[*].containers[*].env[{name}]",
                                        found[0]["value"], "kubectl get pods -A -o json",
                                        f"命中 {len(found)} 个容器")])
        ok = str(found[0]["value"]).lower() == str(expected).lower()
        return ConditionResult(ok, f"env {name}={expected}",
                               [_ev(f"pods[*].containers[*].env[{name}]",
                                    found[0]["value"], "kubectl get pods -A -o json")])
    if _pods_scanned(ctx):
        return ConditionResult(False, f"env {name} 不存在",
                               [_ev("pods[*].containers[*].env", None,
                                    "kubectl get pods -A -o json", "完整扫描未发现")])
    return _unknown("环境变量", field_name="pods[*].env",
                    why="Pod 清单未采集完整", command="kubectl get pods -A -o json",
                    source="catalog.preconditions")


def _cond_os(ctx: ConditionContext, node: Any) -> ConditionResult:
    want = str(node.get("value") if isinstance(node, dict) else node or "").lower()
    nodes = ctx.inventory.get("nodes") or []
    if not nodes:
        return _unknown("节点操作系统", field_name="nodes[*].os",
                        why="节点清单为空", command="kubectl get nodes -o json",
                        source="catalog.preconditions")
    hit = [n for n in nodes if want and want in str(n.get("os") or n.get("os_image") or "").lower()]
    src = str((hit[0].get("source") if hit else nodes[0].get("source")) or _source(ctx.inventory))
    return ConditionResult(bool(hit), f"节点 OS 含 {want}",
                           [_ev("nodes[*].os", [n.get("os") for n in nodes], src)])


def _cond_present(ctx: ConditionContext, node: Any) -> ConditionResult:
    name = ""
    if isinstance(node, dict):
        name = str(node.get("product") or node.get("name") or node.get("value") or "")
    elif isinstance(node, str):
        name = node
    if not name:
        return _unknown("组件存在", field_name="components", why="条件未指定组件",
                        source="catalog.preconditions")
    want = canonical_product(name)
    info = ctx.products.get(want) or {}
    if info.get("present") is True:
        return ConditionResult(True, f"组件 {name} 已部署",
                               [_ev(f"products.{want}.present", True,
                                    str(info.get("source") or _source(ctx.inventory)))])
    if info.get("present") is False:
        return ConditionResult(False, f"组件 {name} 未部署",
                               [_ev(f"products.{want}.present", False,
                                    str(info.get("source") or _source(ctx.inventory)),
                                    "完整 Pod/DS/CRD 扫描未发现")])
    return _unknown(f"组件 {name}", field_name=f"products.{want}.present",
                    why="清单未完整扫描组件面（Pod/DaemonSet/CRD）",
                    command="kubectl get pods,daemonsets,crd -A -o json",
                    source="catalog.preconditions")


def _cond_runtime(ctx: ConditionContext, node: Any) -> ConditionResult:
    name = ""
    if isinstance(node, dict):
        name = str(node.get("runtime") or node.get("value") or node.get("name") or "")
    elif isinstance(node, str):
        name = node
    name = name.lower()
    nodes = ctx.inventory.get("nodes") or []
    if not nodes:
        return _unknown("节点运行时", field_name="nodes[*].container_runtime",
                        why="节点清单为空", command="kubectl get nodes -o json",
                        source="catalog.preconditions")
    if not name:
        return _unknown("节点运行时", field_name="nodes[*].container_runtime",
                        why="条件未指定运行时", source="catalog.preconditions")
    hits = []
    for n in nodes:
        runtime = str(n.get("container_runtime") or n.get("runtime") or "").lower()
        if name in runtime:
            hits.append(n)
    src = str((hits[0].get("source") if hits else nodes[0].get("source")) or _source(ctx.inventory))
    return ConditionResult(bool(hits), f"节点运行时含 {name}",
                           [_ev("nodes[*].container_runtime",
                                [n.get("container_runtime") for n in nodes], src)])


def _cond_gpu(ctx: ConditionContext, node: Any) -> ConditionResult:
    nodes = ctx.inventory.get("nodes") or []
    gpu = ctx.inventory.get("gpu") or {}
    count = 0
    for n in nodes:
        cap = n.get("capacity") or {}
        for k, v in cap.items():
            if "gpu" in str(k).lower():
                try:
                    count += int(float(v))
                except (TypeError, ValueError):
                    pass
    if count or gpu.get("nodes") or gpu.get("operator") or gpu.get("driver_version"):
        return ConditionResult(True, "存在 GPU 节点/组件",
                               [_ev("nodes[*].capacity", {"gpu": count},
                                    str(gpu.get("source") or _source(ctx.inventory)))])
    if nodes and _coverage(ctx.inventory, "nodes"):
        return ConditionResult(False, "无 GPU 节点",
                               [_ev("nodes[*].capacity", {"gpu": 0},
                                    str(nodes[0].get("source") or _source(ctx.inventory)))])
    return _unknown("GPU 面", field_name="gpu", why="节点清单为空",
                    command="kubectl get nodes -o json", source="catalog.preconditions")


def _cond_cgroups_v1(ctx: ConditionContext, node: Any) -> ConditionResult:
    value = _fact(ctx.inventory, "node.cgroups_version")
    if value is None:
        return _unknown(
            "cgroups v1",
            field_name="node.cgroups_version",
            why="未采集节点 cgroup 版本（configz 通常只给 cgroupDriver）",
            command="在节点只读执行 stat -fc %T /sys/fs/cgroup（cgroup2fs=v2）；"
                    "或 snapshot 提供 nodes[].cgroups_version",
            source="catalog.preconditions",
        )
    return _cond_result(str(value).lower() in ("v1", "1"), "cgroups v1",
                        field_name="node.cgroups_version", observed=value,
                        source=_fact_source(ctx.inventory, "node.cgroups_version"))


def _cond_untrusted(ctx: ConditionContext, node: Any) -> ConditionResult:
    probes = ctx.probes or {}
    value = probes.get("untrusted_artifact")
    if value is None:
        return _unknown(
            "不可信 artifact 可达",
            field_name="probes.untrusted_artifact",
            why="目录要求加载攻击者可控的模型/检查点/脚本，但清单没有 artifact 来源探测",
            command="在授权范围检查模型/检查点/数据来源与信任边界；"
                    "或 --probes 提供 {\"untrusted_artifact\": true/false}",
            source="catalog.preconditions",
        )
    return _cond_result(bool(value), "不可信 artifact 可达",
                        field_name="probes.untrusted_artifact", observed=value,
                        source="probe:untrusted_artifact")


def _cond_attacker(ctx: ConditionContext, node: Any) -> ConditionResult:
    probes = ctx.probes or {}
    value = probes.get("attacker_capability")
    if value is None:
        return _unknown(
            "攻击者入口/权限",
            field_name="probes.attacker_capability",
            why="目录假设攻击者具备某类入口或低权限账号；清单没有该前提的实测结果",
            command="在授权范围验证入口账号/可创建对象/可路由网络；"
                    "或 --probes 提供 {\"attacker_capability\": true/false}",
            source="catalog.preconditions",
        )
    return _cond_result(bool(value), "攻击者入口/权限",
                        field_name="probes.attacker_capability", observed=value,
                        source="probe:attacker_capability")


def _cond_serviceaccount_admission(ctx: ConditionContext, node: Any) -> ConditionResult:
    return _bool_from_fact(
        ctx, "apiserver.serviceaccount_admission", "ServiceAccount admission 启用",
        _collect("apiserver.serviceaccount_admission",
                 "读取 API Server --enable-admission-plugins",
                 "kubectl get pods -n kube-system -l component=kube-apiserver -o json"),
    )


def _cond_oob(ctx: ConditionContext, node: Any) -> ConditionResult:
    devices = list(ctx.inventory.get("bmc") or []) + list(ctx.inventory.get("switches") or [])
    if devices:
        return ConditionResult(True, "BMC/交换机已纳管",
                               [_ev("bmc/switches", len(devices),
                                    str((ctx.inventory.get("source") or {}).get("label")
                                        if isinstance(ctx.inventory.get("source"), dict)
                                        else _source(ctx.inventory)))])
    if _coverage(ctx.inventory, "hardware"):
        return ConditionResult(False, "无 BMC/交换机清单",
                               [_ev("bmc/switches", [], _source(ctx.inventory),
                                    "硬件清单已明确为空")])
    return _unknown(
        "BMC/交换机清单",
        field_name="bmc/switches",
        why="Kubernetes 只读采集不覆盖带外管理面/交换机；未提供硬件清单",
        command="提供 BMC/交换机 CMDB 或只读清单（vendor/model/firmware/url），"
                "或 --snapshot 包含 bmc/switches 字段",
        source="catalog.preconditions",
    )


def _cond_switch_present(ctx: ConditionContext, node: Any) -> ConditionResult:
    switches = ctx.inventory.get("switches") or []
    if switches:
        return ConditionResult(True, "交换机已纳管",
                               [_ev("switches", len(switches), _source(ctx.inventory))])
    if _coverage(ctx.inventory, "hardware"):
        return ConditionResult(False, "无交换机清单",
                               [_ev("switches", [], _source(ctx.inventory), "硬件清单已明确为空")])
    return _unknown(
        "交换机清单",
        field_name="switches",
        why="Kubernetes API 不暴露交换机 OS/版本；未提供硬件清单",
        command="提供交换机只读清单（SONiC/Cumulus/NX-OS 版本、管理面地址）",
        source="catalog.preconditions",
    )


def _cond_true(ctx: ConditionContext, node: Any) -> ConditionResult:
    return ConditionResult(True, "无条件")


def _cond_false(ctx: ConditionContext, node: Any) -> ConditionResult:
    return ConditionResult(False, "恒假")


def _install_default_conditions() -> None:
    mapping = {
        "privileged": _cond_privileged,
        "privileged_pod": _cond_privileged,
        "hostpath": _cond_hostpath,
        "host_path": _cond_hostpath,
        "host_network": _cond_host_network,
        "hostnetwork": _cond_host_network,
        "host_pid": _cond_host_pid,
        "host_ipc": _cond_host_ipc,
        "sa_automount": _cond_automount,
        "automount_sa_token": _cond_automount,
        "runtime_socket": _cond_runtime_socket,
        "cap_sys_admin": _cond_sys_admin,
        "sys_admin": _cond_sys_admin,
        "auth_disabled": _cond_auth_disabled,
        "anonymous_auth": _cond_auth_disabled,
        "imds_reachable": _cond_imds,
        "metadata_reachable": _cond_imds,
        "network_reachable": _cond_network_reachable,
        "reachable": _cond_network_reachable,
        "kubelet_read_only_port": _cond_kubelet_readonly,
        "kubelet_readonly": _cond_kubelet_readonly,
        "feature_gate": _cond_feature_gate,
        "flag": _cond_flag,
        "env": _cond_env,
        "os": _cond_os,
        "component_present": _cond_present,
        "present": _cond_present,
        "runtime": _cond_runtime,
        "runtime_runc": lambda c, n: _cond_runtime(c, "runc"),
        "runtime_containerd": lambda c, n: _cond_runtime(c, "containerd"),
        "kubelet_present": lambda c, n: _cond_present(c, "kubelet"),
        "gpu_present": _cond_gpu,
        "cgroups_v1": _cond_cgroups_v1,
        "untrusted_artifact": _cond_untrusted,
        "attacker_capability": _cond_attacker,
        "serviceaccount_admission": _cond_serviceaccount_admission,
        "oob_device_present": _cond_oob,
        "bmc_present": _cond_oob,
        "switch_present": _cond_switch_present,
        "always": _cond_true,
        "true": _cond_true,
        "false": _cond_false,
    }
    for name, fn in mapping.items():
        register_condition(name, fn)


_install_default_conditions()


# ---------------------------------------------------------------- expression eval


_IDENT_RE = re.compile(r"[A-Za-z0-9_.:\-]+")
_TEXT_TOKEN_RE = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|&&|\|\||!|"
                            r"[A-Za-z0-9_.:\-]+)", re.I)


class _TextParser:
    """条件文本的极小布尔文法：and / or / not / 括号 / 命名条件。"""

    def __init__(self, text: str, ctx: ConditionContext):
        self.text = text
        self.ctx = ctx
        self.tokens: list[str] = []
        pos = 0
        while pos < len(text):
            m = _TEXT_TOKEN_RE.match(text, pos)
            if not m:
                raise ApplicabilityError(f"条件文本无法解析（位置 {pos}）：{text[pos:pos + 16]!r}")
            pos = m.end()
            tok = m.group(1)
            if tok.strip():
                self.tokens.append(tok)
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self):
        tok = self.peek()
        if tok is None:
            raise ApplicabilityError("条件文本意外结束")
        self.i += 1
        return tok

    def parse(self) -> ConditionResult:
        node = self._or()
        if self.peek() is not None:
            raise ApplicabilityError(f"条件文本尾部多余：{self.peek()!r}")
        return node

    def _or(self) -> ConditionResult:
        left = self._and()
        while (self.peek() or "").lower() == "or" or self.peek() == "||":
            self.next()
            right = self._and()
            left = _combine_or(left, right)
        return left

    def _and(self) -> ConditionResult:
        left = self._not()
        while (self.peek() or "").lower() == "and" or self.peek() == "&&":
            self.next()
            right = self._not()
            left = _combine_and(left, right)
        return left

    def _not(self) -> ConditionResult:
        tok = self.peek()
        if tok is not None and (tok.lower() == "not" or tok == "!"):
            self.next()
            return _negate(self._not())
        return self._atom()

    def _atom(self) -> ConditionResult:
        tok = self.next()
        if tok == "(":
            node = self._or()
            if self.next() != ")":
                raise ApplicabilityError("条件文本缺少右括号")
            return node
        return _eval_named(tok, self.ctx)


def _combine_and(a: ConditionResult, b: ConditionResult) -> ConditionResult:
    evidence = a.evidence + b.evidence
    collect = a.collect + b.collect
    parts = [x for x in (a.label, b.label)
             if x and x not in ("all", "any", "clause", "textual", "无条件")]
    label = " and ".join(parts) or "all"
    if a.value is False or b.value is False:
        return ConditionResult(False, label, evidence, collect)
    if a.value is None or b.value is None:
        return ConditionResult(None, label, evidence, collect)
    return ConditionResult(True, label, evidence, collect)


def _combine_or(a: ConditionResult, b: ConditionResult) -> ConditionResult:
    evidence = a.evidence + b.evidence
    collect = a.collect + b.collect
    parts = [x for x in (a.label, b.label)
             if x and x not in ("all", "any", "clause", "textual", "无条件")]
    label = " or ".join(parts) or "any"
    if a.value is True or b.value is True:
        return ConditionResult(True, label, evidence, collect)
    if a.value is None or b.value is None:
        return ConditionResult(None, label, evidence, collect)
    return ConditionResult(False, label, evidence, collect)


def _negate(a: ConditionResult) -> ConditionResult:
    if a.value is None:
        return ConditionResult(None, f"not ({a.label})", a.evidence, a.collect)
    return ConditionResult(not a.value, f"not ({a.label})", a.evidence, a.collect)


def _eval_named(name: str, ctx: ConditionContext, node: Any = None) -> ConditionResult:
    raw = str(name).strip()
    if not raw:
        return _unknown("空条件", field_name="conditions", why="条件名为空",
                        source="catalog.preconditions")
    low = raw.lower()
    # feature_gate:HTTP2 / env:FOO / flag:--anonymous-auth / runtime:runc
    if ":" in raw:
        head, _, tail = raw.partition(":")
        fn = _CONDITION_REGISTRY.get(head.strip().lower().replace("-", "_"))
        if fn is not None:
            arg = tail
            if head.lower().replace("-", "_") == "feature_gate":
                arg = {"name": tail, "enabled": True}
            return fn(ctx, arg)
    fn = _CONDITION_REGISTRY.get(low.replace("-", "_"))
    if fn is None:
        return _unknown(
            f"条件 {raw}",
            field_name="conditions",
            why=f"没有注册名为 {raw!r} 的条件评估器（不会默认视为满足；"
                "可在 trident.core.applicability.register_condition 注册）",
            command="在 trident.core.applicability.register_condition 注册评估器，"
                    "或使用内置条件/结构化表达式",
            source="catalog.preconditions",
        )
    return fn(ctx, node if node is not None else {})


def _compare_values(actual: Any, op: str, expected: Any) -> bool:
    op = op or "=="
    if op in ("exists", "present"):
        return (actual is not None) == bool(expected)
    if actual is None:
        return False
    if op in ("in", "contains"):
        try:
            return expected in actual if op == "in" else actual in expected
        except TypeError:
            return str(actual) in str(expected) if op == "in" else str(expected) in str(actual)
    try:
        if op == "==":
            return actual == expected or str(actual).lower() == str(expected).lower()
        if op == "!=":
            return not (actual == expected or str(actual).lower() == str(expected).lower())
        if op == ">":
            return float(actual) > float(expected)
        if op == ">=":
            return float(actual) >= float(expected)
        if op == "<":
            return float(actual) < float(expected)
        if op == "<=":
            return float(actual) <= float(expected)
    except (TypeError, ValueError):
        return False
    raise ApplicabilityError(f"未知比较运算符 {op!r}")


def _lookup_fact(ctx: ConditionContext, path: str) -> tuple[Any, str]:
    if path in (ctx.inventory.get("facts") or {}):
        return ctx.facts.get(path), _fact_source(ctx.inventory, path)
    cur: Any = ctx.inventory
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None, _source(ctx.inventory)
    return cur, _source(ctx.inventory)


def _version_condition(ctx: ConditionContext, node: dict) -> ConditionResult:
    product = str(node.get("product") or node.get("component") or ctx.component or "")
    spec = node.get("range") or node.get("version_range") or node.get("value") or node.get("versions")
    if spec is None and "operator" in node and "version" in node:
        spec = f"{node['operator']}{node['version']}"
    if not product or spec is None:
        return _unknown("版本条件", field_name="conditions.version",
                        why="版本条件缺少 product/range", source="catalog.preconditions")
    want = canonical_product(product)
    info = ctx.products.get(want) or {}
    versions = list(info.get("versions") or [])
    if not versions:
        return _unknown(
            f"{product} 版本",
            field_name=f"products.{want}.versions",
            why="清单没有该产品版本",
            command=f"提供 {product} 的版本采集（kubectl/镜像 tag/host 只读命令）",
            source="catalog.preconditions",
        )
    evidence = []
    unknown = False
    matched = False
    for v in versions:
        try:
            ok = version_in_range(v.get("value"), spec)
        except ApplicabilityError as exc:
            unknown = True
            evidence.append(_ev(str(v.get("field") or f"products.{want}.versions"),
                                v.get("value"), str(v.get("source") or ""), str(exc)))
            continue
        evidence.append(_ev(str(v.get("field") or f"products.{want}.versions"),
                            v.get("value"), str(v.get("source") or ""),
                            f"区间 {spec} -> {'命中' if ok else '未命中'}"))
        matched = matched or ok
    if matched:
        return ConditionResult(True, f"{product} 版本命中 {spec}", evidence)
    if unknown:
        return ConditionResult(None, f"{product} 版本条件无法解析", evidence)
    return ConditionResult(False, f"{product} 版本不命中 {spec}", evidence)


def _eval_condition(node: Any, ctx: ConditionContext) -> ConditionResult:
    if node is None:
        return ConditionResult(True, "无条件")
    if isinstance(node, bool):
        return ConditionResult(node, "true" if node else "false")
    if isinstance(node, str):
        text = node.strip()
        if not text:
            return ConditionResult(True, "无条件")
        if text.lower() in ("true", "always", "1"):
            return ConditionResult(True, "true")
        if text.lower() in ("false", "never", "0"):
            return ConditionResult(False, "false")
        if text.startswith(("{", "[")):
            try:
                return _eval_condition(json.loads(text), ctx)
            except ValueError:
                pass
        # 含布尔运算符的文本走小解析器；单个命名条件直接查表
        if any(tok in text.lower() for tok in (" and ", " or ", "not ", "&&", "||")) \
                or text.count("(") != text.count(")"):
            return _TextParser(text, ctx).parse()
        return _eval_named(text, ctx)
    if isinstance(node, (list, tuple)):
        result = ConditionResult(True, "all")
        for item in node:
            result = _combine_and(result, _eval_condition(item, ctx))
        return result
    if not isinstance(node, dict):
        return _unknown(f"条件 {node!r}", field_name="conditions",
                        why="不支持的条件节点类型", source="catalog.preconditions")
    keys = {str(k).lower(): v for k, v in node.items()}
    for key in ("all", "and", "all_of"):
        if key in keys:
            items = keys[key]
            items = items if isinstance(items, list) else [items]
            result = ConditionResult(True, "all")
            for item in items:
                result = _combine_and(result, _eval_condition(item, ctx))
            return result
    for key in ("any", "or", "any_of"):
        if key in keys:
            items = keys[key]
            items = items if isinstance(items, list) else [items]
            result = ConditionResult(False, "any")
            for item in items:
                result = _combine_or(result, _eval_condition(item, ctx))
            return result
    if "not" in keys or "none" in keys:
        inner = keys.get("not", keys.get("none"))
        return _negate(_eval_condition(inner, ctx))
    if "version" in keys:
        val = keys["version"]
        if isinstance(val, str):
            return _eval_named(val, ctx)
        return _version_condition(ctx, val if isinstance(val, dict) else {"value": val})
    if "textual" in keys or "text" in keys:
        return _eval_textual(str(keys.get("textual", keys.get("text"))), ctx)
    if "condition" in keys or "name" in keys or "check" in keys:
        name = keys.get("condition", keys.get("name", keys.get("check")))
        if isinstance(name, str):
            return _eval_named(name, ctx, node)
        return _eval_condition(name, ctx)
    if "fact" in keys or "field" in keys:
        path = str(keys.get("fact", keys.get("field")))
        actual, src = _lookup_fact(ctx, path)
        if actual is None and not any(k in keys for k in ("equals", "eq", "is", "value")):
            return _unknown(f"字段 {path}", field_name=path,
                            why="清单未提供该字段", command=f"采集 {path}",
                            source=src)
        expected = keys.get("equals", keys.get("eq", keys.get("is",
                          keys.get("value", keys.get("expected")))))
        op = str(keys.get("op", keys.get("operator",
                     "==" if expected is not None else "exists")))
        return ConditionResult(_compare_values(actual, op, expected),
                               f"{path} {op} {expected}",
                               [_ev(path, actual, src)])
    if "probe" in keys:
        path = str(keys["probe"])
        actual = (ctx.probes or {}).get(path)
        src = f"probe:{path}"
        if actual is None:
            return _unknown(f"探测 {path}", field_name=f"probes.{path}",
                            why="未提供主动探测结果", command=f"执行 {path} 探测或 --probes 提供",
                            source=src)
        expected = keys.get("equals", keys.get("value", True))
        return ConditionResult(_compare_values(actual, str(keys.get("op", "==")), expected),
                               f"probe {path}",
                               [_ev(f"probes.{path}", actual, src)])
    if "env" in keys:
        return _eval_named("env", ctx, {"name": keys["env"],
                                        "equals": keys.get("equals", keys.get("value"))})
    if "flag" in keys:
        return _eval_named("flag", ctx, {"name": keys["flag"],
                                         "equals": keys.get("equals", keys.get("value"))})
    if "feature_gate" in keys:
        return _eval_named("feature_gate", ctx,
                           {"name": keys["feature_gate"],
                            "enabled": keys.get("enabled", keys.get("equals", True))})
    # {"privileged": true} / {"hostpath": false} / {"auth_disabled": true}
    for key, val in node.items():
        low = str(key).lower().replace("-", "_")
        if low in ("source", "note", "notes", "label", "reason"):
            continue
        if low in _CONDITION_REGISTRY:
            res = _eval_named(low, ctx, val if isinstance(val, dict) else {"value": val})
            if isinstance(val, bool):
                return res if res.value == val else _negate(res)
            return res
    return _unknown(f"条件 {sorted(node)}", field_name="conditions",
                    why="未识别的条件结构（不会默认视为满足）",
                    source="catalog.preconditions")


# ---------------------------------------------------------------- 自由文本条件

_CLAUSE_MAP: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"hostnetwork|host network", re.I), "host_network"),
    (re.compile(r"sys_admin|sys admin", re.I), "cap_sys_admin"),
    (re.compile(r"cgroups?\s*v1|cgroup v1", re.I), "cgroups_v1"),
    (re.compile(r"hostpath|host path", re.I), "hostpath"),
    (re.compile(r"privileged|特权", re.I), "privileged"),
    (re.compile(r"未配置\s*api\s*key|未启用[^；;。]*token|未设置[^；;。]*key|"
                r"默认[^；;。]*(key|口令|密码)|弱口令|无鉴权|未认证|未启用认证|未轮换|"
                r"fail[- ]?open|未接[^；;。]*token|未启用\s*ray_auth_mode", re.I),
     "auth_disabled"),
    (re.compile(r"可达|暴露|监听|0\.0\.0\.0|端口|公网|外部|相邻网络|"
                r"ssh\s*管理面|web\s*管理面|dashboard\s*8265|redfish|ipmi", re.I),
     "network_reachable"),
    (re.compile(r"可创建\s*pod|可创建工作流|已认证|低权限用户|任意[^；;。]*用户|"
                r"攻击者可|用户加载|用户运行|可写|可执行", re.I), "attacker_capability"),
    (re.compile(r"恶意镜像|不可信|攻击者构造|恶意[^；;。]*(检查点|配置|脚本|数据)", re.I),
     "untrusted_artifact"),
    (re.compile(r"\bgpu\b|cuda", re.I), "gpu_present"),
    (re.compile(r"\brunc\b", re.I), "runtime_runc"),
    (re.compile(r"\bcontainerd\b", re.I), "runtime_containerd"),
    (re.compile(r"\bkubelet\b", re.I), "kubelet_present"),
    (re.compile(r"\bbmc\b|\bilo\b|\bredfish\b|\bipmi\b", re.I), "oob_device_present"),
    (re.compile(r"\bsonic\b|\bcumulus\b|交换机", re.I), "switch_present"),
    (re.compile(r"serviceaccount admission", re.I), "serviceaccount_admission"),
)


def _map_text_clause(clause: str) -> list[str]:
    names: list[str] = []
    for pattern, name in _CLAUSE_MAP:
        if pattern.search(clause) and name not in names:
            names.append(name)
    # “所有版本/所有 KubeRay 版本/依据模板” 属于描述，不追加可验证条件
    if not names and re.search(r"所有|任意版本|各版本|具体\s*tag|master\s*修复前", clause):
        return ["component_present"]
    return names


def _eval_textual(text: str, ctx: ConditionContext) -> ConditionResult:
    if not str(text or "").strip():
        return ConditionResult(True, "无条件文本")
    clauses = [c.strip() for c in re.split(r"[；;。\n]+", str(text)) if c.strip()]
    results: list[ConditionResult] = []
    for clause in clauses:
        names = _map_text_clause(clause)
        if not names:
            results.append(ConditionResult(
                None,
                f"未映射条件：{clause}",
                [_ev("catalog.exploit_conditions", clause, "cve-catalog",
                     "自由文本条款未能映射为实测字段")],
                [_collect("catalog.conditions",
                          f"把目录条款映射为结构化条件或提供探测：{clause}")],
                "自由文本未映射",
            ))
            continue
        combined = ConditionResult(True, "clause")
        for name in names:
            combined = _combine_and(combined, _eval_named(name, ctx))
        combined.evidence.append(_ev("catalog.exploit_conditions", clause, "cve-catalog"))
        results.append(combined)
    out = ConditionResult(True, "textual")
    for res in results:
        out = _combine_and(out, res)
    return out


# ====================================================================== 目录


_ALIASES = {
    "k8s": "kubernetes",
    "kube": "kubernetes",
    "kube-apiserver": "kubernetes",
    "kubelet": "kubelet",
    "kubernetes-kubelet": "kubelet",
    "linux": "linux-kernel",
    "linux-kernel": "linux-kernel",
    "kernel": "linux-kernel",
    "runc-vulnerability": "runc",
    "containerd.io": "containerd",
    "nvidia-container-toolkit": "nvidia",
    "nvidia-gpu-operator": "nvidia",
    "gpu-operator": "nvidia",
    "nvidia-driver": "nvidia",
    "calico": "calico",
    "cilium": "cilium",
    "flannel": "flannel",
    "ingress-nginx": "ingress-nginx",
    "nginx-ingress": "ingress-nginx",
    "traefik": "traefik",
    "leaderworkerset": "lws",
    "kuberay": "kuberay",
    "ray": "ray",
    "dify": "dify",
    "open-webui": "open-webui",
    "openwebui": "open-webui",
    "wandb": "wandb",
}

_SYSTEM_PRODUCTS = {
    "kubernetes", "kubelet", "runc", "containerd", "linux-kernel", "cni",
    "calico", "cilium", "flannel", "ingress-nginx", "traefik", "kube-apiserver",
    "etcd", "docker", "cri-o", "os",
}
_HARDWARE_PRODUCTS = {"bmc", "sonic", "cumulus", "switch", "ipmi", "redfish"}


def canonical_product(name: str) -> str:
    raw = str(name or "").strip().lower()
    if not raw:
        return ""
    raw = raw.split("@", 1)[0]
    raw = raw.split("://")[-1]
    if "/" in raw:
        raw = raw.rstrip("/").split("/")[-1]
    raw = raw.replace("_", "-")
    raw = _ALIASES.get(raw, raw)
    if raw.startswith("nvidia-container-toolkit"):
        return "nvidia"
    if raw.startswith("gpu-operator"):
        return "nvidia"
    return raw


def _range_text(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (int, float)):
        return [str(raw)]
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            out.extend(_range_text(item))
        return out
    return []


def _compose_dict_range(d: dict) -> list[str]:
    low = {str(k).lower(): v for k, v in d.items()}
    intro = next((low[k] for k in ("introduced", "since", "from", "min", "version_start",
                                   "after") if k in low and low[k] not in (None, "")), None)
    fixed = next((low[k] for k in ("fixed", "fixed_version", "patched", "until", "to",
                                   "max", "version_end", "before") if k in low
                  and low[k] not in (None, "")), None)
    inclusive = bool(low.get("end_inclusive", low.get("max_inclusive",
                          low.get("fixed_inclusive", False))))
    if intro is not None and fixed is not None:
        return [f">={intro},{'<=' if inclusive else '<'}{fixed}"]
    if intro is not None:
        return [f">={intro}"]
    if fixed is not None:
        return [f"{'<=' if inclusive else '<'}{fixed}"]
    clauses = []
    for op, keys in ((">=", ("gte", "ge")), (">", ("gt",)), ("<=", ("lte", "le")),
                     ("<", ("lt",))):
        for key in keys:
            if key in low and low[key] not in (None, ""):
                clauses.append(f"{op}{low[key]}")
                break
    if clauses:
        return [",".join(clauses)]
    return []


def _extract_version_specs(entry: dict, component: str) -> list[dict]:
    specs: list[dict] = []

    def add(product: Any, range_value: Any) -> None:
        prod = canonical_product(product or component)
        for text in _range_text(range_value):
            if not text.strip():
                continue
            specs.append({"product": prod, "range": text.strip(), "raw": text.strip()})

    # 1) 规范化字段：version_range / affected_versions / versions / ranges
    for key in ("version_range", "affected_versions", "versions", "ranges",
                "version_ranges", "affected_version"):
        if key in entry and entry[key] not in (None, ""):
            add(entry.get("component") or entry.get("product"), entry[key])
            break
    if specs:
        return _dedupe_specs(specs)

    # 2) affected 结构化
    raw = entry.get("affected")
    if raw is None:
        raw = entry.get("affects")
    if raw is None and entry.get("fixed"):
        raw = f"<{entry['fixed']}"
    if raw is None:
        return []

    def walk(node: Any, fallback_product: str = "") -> None:
        if node is None:
            return
        if isinstance(node, str):
            text = node.strip()
            if not text:
                return
            # 人类可读 "1.0.0 - 1.1.11" 或 "<1.2" 可直接用；
            # 若只是描述（无运算符/版本号），留给 unknown，不臆造区间。
            if re.search(r"\d", text) and re.search(r"[<>=]|\d+\.\d+", text):
                add(fallback_product or component, text)
            else:
                specs.append({"product": canonical_product(fallback_product or component),
                              "range": "", "raw": text, "unparsed": True})
            return
        if isinstance(node, (list, tuple, set)):
            for item in node:
                walk(item, fallback_product)
            return
        if isinstance(node, dict):
            low = {str(k).lower(): v for k, v in node.items()}
            prod = (low.get("product") or low.get("component") or low.get("package")
                    or low.get("target") or fallback_product or component)
            direct = False
            for key in ("range", "version_range", "ranges", "versions",
                        "affected_versions", "affected"):
                if key in low:
                    add(prod, low[key])
                    direct = True
            composed = _compose_dict_range(node)
            if composed:
                add(prod, composed)
                return
            if direct:
                return
            if any(k in low for k in ("product", "component", "package", "target")):
                return
            # {"runc": "<1.1.12", "containerd": "<1.4.3"} 映射写法
            for key, val in node.items():
                if str(key).lower() in ("source", "note", "notes", "confidence", "match",
                                        "mode", "operator", "version"):
                    continue
                walk(val, str(key))
            return

    walk(raw)
    return _dedupe_specs(specs)


def _dedupe_specs(specs: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for s in specs:
        key = (canonical_product(s.get("product")), str(s.get("range") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _strings(raw: Any) -> list[str]:
    out: list[str] = []
    if raw is None:
        return out
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, dict):
        for key in ("key", "id", "name", "module", "chain", "rule"):
            if key in raw and isinstance(raw[key], str):
                out.append(raw[key])
                break
        return out
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            out.extend(_strings(item))
    return out


def _entry_id(raw: dict) -> str:
    for key in ("cve", "id", "advisory", "cve_id", "CVE"):
        val = raw.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _title(raw: dict, fallback: str) -> Any:
    for key in ("title", "name", "summary"):
        val = raw.get(key)
        if isinstance(val, dict):
            return {"zh": val.get("zh") or val.get("en") or fallback,
                    "en": val.get("en") or val.get("zh") or fallback}
        if isinstance(val, str) and val.strip():
            return val.strip()
    return fallback


def _normalize_entry(raw: dict, index: int, warnings: list[str]) -> dict | None:
    if not isinstance(raw, dict):
        warnings.append(f"entries[{index}] 不是 object，已跳过")
        return None
    eid = _entry_id(raw)
    if not eid:
        warnings.append(f"entries[{index}] 缺 cve/id，已跳过")
        return None
    component = str(raw.get("component") or raw.get("product") or raw.get("package") or "")
    specs = _extract_version_specs(raw, component)
    if not specs:
        warnings.append(f"{eid}: 未能解析受影响版本区间（将判 unknown）")
    raw_conditions = None
    for key in ("conditions", "preconditions", "condition", "requires_env",
                "environment_preconditions"):
        if key in raw and raw[key] not in (None, "", [], {}):
            raw_conditions = raw[key]
            break
    condition_text = str(raw.get("exploit_conditions") or raw.get("precondition_text") or "")
    condition_source = "catalog.conditions"
    if raw_conditions is None and condition_text.strip():
        raw_conditions = {"textual": condition_text}
        condition_source = "catalog.exploit_conditions"
    modules = _strings(raw.get("modules") or raw.get("module") or raw.get("module_keys"))
    chains = _strings(raw.get("chains") or raw.get("chain") or raw.get("chain_keys"))
    rules = _strings(raw.get("rules") or raw.get("rule") or raw.get("rule_keys")
                     or raw.get("detections"))
    sources = _strings(raw.get("sources") or raw.get("source") or raw.get("references")
                       or raw.get("verified_via"))
    return {
        "id": eid,
        "cve": eid,
        "catalog_id": str(raw.get("id") or eid),
        "title": _title(raw, eid),
        "component": component,
        "component_name": str(raw.get("component_name") or component),
        "kind": str(raw.get("kind") or ""),
        "severity": str(raw.get("severity") or "").lower(),
        "cvss": raw.get("cvss"),
        "cvss_vector": str(raw.get("cvss_vector") or ""),
        "affected_text": str(raw.get("affected") or ""),
        "versions": specs,
        "fixed": raw.get("fixed"),
        "fixed_note": str(raw.get("fixed_note") or ""),
        "conditions": raw_conditions,
        "condition_text": condition_text,
        "condition_source": condition_source,
        "modules": modules,
        "chains": chains,
        "rules": rules,
        "sources": sources,
        "requires_hardware": bool(raw.get("requires_hardware")),
        "mockable": bool(raw.get("mockable")),
        "match": str(raw.get("match") or raw.get("match_mode") or "any").lower(),
        "notes": str(raw.get("notes") or ""),
        "raw_index": index,
    }


_CATALOG_CANDIDATES = (
    ("core/cve-catalog.json",),
    ("core/data/cve-catalog.json",),
    ("cve-catalog.json",),
    ("data/cve-catalog.json",),
)


def resolve_catalog_path(path: str | Path | None = None, home: str | Path | None = None) -> Path | None:
    if path:
        p = Path(path)
        if not p.is_file():
            raise ApplicabilityError(f"cve catalog 不存在：{p}")
        return p
    env = os.environ.get("TRIDENT_CVE_CATALOG")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    roots = [Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent]
    if home:
        roots.append(Path(home))
    for root in roots:
        for rel in ("cve-catalog.json", "data/cve-catalog.json",
                    "core/cve-catalog.json"):
            p = root / rel
            if p.is_file():
                return p
    return None


def _normalize_catalog_doc(raw: Any, path: str = "") -> dict:
    warnings: list[str] = []
    if isinstance(raw, list):
        entries_raw = raw
        schema = CATALOG_SCHEMA
        meta: dict = {}
    elif isinstance(raw, dict):
        entries_raw = None
        for key in ("cves", "entries", "items", "vulnerabilities", "records", "advisories"):
            if isinstance(raw.get(key), list):
                entries_raw = raw[key]
                break
        if entries_raw is None:
            raise ApplicabilityError(f"{path or 'catalog'}: 未找到 cves/entries 列表")
        schema = str(raw.get("schema") or CATALOG_SCHEMA)
        meta = {k: v for k, v in raw.items()
                if k not in ("cves", "entries", "items", "vulnerabilities", "records", "advisories")}
    else:
        raise ApplicabilityError(f"{path or 'catalog'}: 根节点不是 object/list")
    entries = []
    for i, e in enumerate(entries_raw):
        norm = _normalize_entry(e, i, warnings)
        if norm is not None:
            entries.append(norm)
    return {
        "schema": schema,
        "path": path,
        "found": True,
        "_normalized": True,
        "verified_at": meta.get("verified_at") or "",
        "method_note": meta.get("method_note") or "",
        "entries": entries,
        "raw_entry_count": len(entries_raw),
        "warnings": warnings,
    }


def load_catalog(path: str | Path | None = None, home: str | Path | None = None,
                 *, link: bool = True) -> dict:
    """读取并规范化 CVE 目录；未落盘时返回 found=False（不报错）。"""
    p = resolve_catalog_path(path, home)
    if p is None:
        return {"schema": CATALOG_SCHEMA, "path": "", "found": False, "entries": [],
                "raw_entry_count": 0, "warnings": ["cve catalog 未落盘"], "verified_at": ""}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ApplicabilityError(f"{p}: JSON 非法：{exc}") from exc
    doc = _normalize_catalog_doc(raw, str(p))
    if link:
        _enrich_links(doc)
    return doc


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _module_cve_map(modules_dir: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    if not modules_dir.is_dir():
        return out
    for d in sorted(p for p in modules_dir.iterdir() if p.is_dir()):
        mf = d / "module.json"
        if not mf.is_file():
            continue
        raw = _read_json(mf)
        if not isinstance(raw, dict):
            continue
        key = str(raw.get("key") or d.name)
        text = " ".join(str(raw.get(k) or "") for k in ("description", "knowledge", "name"))
        ids = {m.group(0).upper() for m in _CVE_RE.finditer(text)}
        # 目录里可能用非 CVE 的 advisory id（GHSA-/HAMI-ADV-...），模块描述常直接写。
        for token in re.findall(r"\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+){2,}\b", text):
            ids.add(token)
        out[key] = ids
    return out


def _enrich_links(catalog: dict) -> None:
    """从链的 cves/步骤模块、规则 blocks_modules、模块描述补齐链/规则键。"""
    root = Path(__file__).resolve().parents[2]
    chains_dir = root / "trident" / "chains"
    rules_dir = root / "trident" / "rules" / "templates"
    modules_dir = root / "trident" / "modules"
    chains_by_cve: dict[str, set[str]] = {}
    chains_by_module: dict[str, set[str]] = {}
    if chains_dir.is_dir():
        for f in sorted(chains_dir.glob("*.json")):
            doc = _read_json(f)
            if not isinstance(doc, dict):
                continue
            cid = str(doc.get("id") or f.stem)
            for cve in _strings(doc.get("cves") or doc.get("cve")):
                chains_by_cve.setdefault(cve.upper(), set()).add(cid)
            for step in doc.get("steps") or []:
                if isinstance(step, dict) and step.get("module"):
                    chains_by_module.setdefault(str(step["module"]), set()).add(cid)
            # objective 阶段也参与模块→链映射
            for stage in ((doc.get("objective") or {}).get("stages") or []):
                if isinstance(stage, dict) and stage.get("module"):
                    chains_by_module.setdefault(str(stage["module"]), set()).add(cid)
    rules_by_module: dict[str, set[str]] = {}
    if rules_dir.is_dir():
        for f in sorted(rules_dir.glob("*.json")):
            doc = _read_json(f)
            if not isinstance(doc, list):
                continue
            kind = f.stem
            for rule in doc:
                if not isinstance(rule, dict):
                    continue
                rid = str(rule.get("id") or "")
                if not rid:
                    continue
                key = f"{kind}:{rid}"
                for mod in _strings(rule.get("blocks_modules")):
                    rules_by_module.setdefault(mod, set()).add(key)
    module_ids = _module_cve_map(modules_dir)
    for entry in catalog.get("entries") or []:
        eid = entry["id"].upper()
        modules = list(entry.get("modules") or [])
        related_modules = set(modules)
        for mod, ids in module_ids.items():
            if eid in ids or entry["id"] in ids:
                related_modules.add(mod)
        if not entry.get("chains"):
            chains: set[str] = set(chains_by_cve.get(eid, set()))
            for mod in related_modules:
                chains |= chains_by_module.get(mod, set())
            entry["chains"] = sorted(chains)
        if not entry.get("rules"):
            rules: set[str] = set()
            for mod in related_modules:
                rules |= rules_by_module.get(mod, set())
            entry["rules"] = sorted(rules)
        if not entry.get("modules"):
            entry["modules"] = sorted(related_modules)


# ====================================================================== 环境清单 → 产品版本


_COMPONENT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("kuberay", "kuberay"),
    ("ray", "ray"),
    ("leaderworkerset", "lws"),
    ("leader-worker-set", "lws"),
    ("lws", "lws"),
    ("vllm", "vllm"),
    ("sglang", "sglang"),
    ("triton", "triton"),
    ("litellm", "litellm"),
    ("higress", "higress"),
    ("envoy-gateway", "envoy-gateway"),
    ("istio", "istio"),
    ("gpu-operator", "nvidia"),
    ("container-toolkit", "nvidia"),
    ("nvidia", "nvidia"),
    ("dcgm", "nvidia"),
    ("kserve", "kserve"),
    ("volcano", "volcano"),
    ("hami", "hami"),
    ("kueue", "kueue"),
    ("jobset", "jobset"),
    ("training-operator", "training-operator"),
    ("pytorch", "pytorch"),
    ("deepspeed", "deepspeed"),
    ("megatron", "megatron"),
    ("openrlhf", "openrlhf"),
    ("skyrl", "skyrl"),
    ("areal", "areal"),
    ("slime", "slime"),
    ("dify", "dify"),
    ("open-webui", "open-webui"),
    ("openwebui", "open-webui"),
    ("wandb", "wandb"),
    ("mlflow", "mlflow"),
    ("jupyter", "jupyter"),
    ("calico", "calico"),
    ("cilium", "cilium"),
    ("flannel", "flannel"),
    ("ingress-nginx", "ingress-nginx"),
    ("nginx-ingress", "ingress-nginx"),
    ("traefik", "traefik"),
    ("sonic", "sonic"),
    ("cumulus", "cumulus"),
    ("cgpu", "cgpu"),
)


def classify_component(name: str) -> str:
    text = str(name or "").lower()
    for needle, product in _COMPONENT_KEYWORDS:
        if needle in text:
            return product
    return canonical_product(text)


def _tag_version(tag: str) -> str:
    tag = str(tag or "").strip()
    if not tag or tag.lower() in ("latest", "main", "master", "dev", "stable", "edge"):
        return ""
    return tag


def _record_version(products: dict, product: str, value: Any, field_name: str,
                    source: str, present: bool = True) -> None:
    key = canonical_product(product)
    if not key:
        return
    rec = products.setdefault(key, {"present": present, "versions": [],
                                    "sources": [], "source": source})
    if present:
        rec["present"] = True
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _record_version(products, product, item, field_name, source, present)
        return
    if value not in (None, ""):
        text = str(value).strip()
        ver = _tag_version(text)
        if ver and parse_version(ver) is not None:
            item = {"value": ver, "field": field_name, "source": source}
            if item not in rec["versions"]:
                rec["versions"].append(item)
    if source and source not in rec["sources"]:
        rec["sources"].append(source)


def derive_products(inventory: dict) -> dict:
    """把环境清单归并为 {product: {present, versions[{value,field,source}]}}。"""
    inv = inventory or {}
    products: dict[str, dict] = {}
    default_source = _source(inv)
    coverage_components = bool((inv.get("coverage") or {}).get(
        "components_complete",
        (inv.get("coverage") or {}).get("components")))

    # 显式 products 优先（snapshot/probe 可直接提供）
    for name, info in (inv.get("products") or {}).items():
        if isinstance(info, dict):
            source = str(info.get("source") or default_source)
            field_name = str(info.get("field") or f"products.{name}")
            present = info.get("present", True)
            rec = products.setdefault(canonical_product(name),
                                      {"present": bool(present), "versions": [],
                                       "sources": [source], "source": source})
            rec["present"] = bool(present)
            raw_versions = info.get("versions") or ([info["version"]] if info.get("version") else [])
            for v in raw_versions:
                if isinstance(v, dict):
                    _record_version(products, name, v.get("value") or v.get("version"),
                                    str(v.get("field") or field_name),
                                    str(v.get("source") or source), bool(present))
                else:
                    _record_version(products, name, v, field_name, source, bool(present))
        else:
            _record_version(products, name, info, f"products.{name}", default_source)

    cluster = inv.get("cluster") or {}
    if cluster.get("version"):
        _record_version(products, "kubernetes", cluster.get("version"), "cluster.version",
                        str(cluster.get("source") or default_source))
    facts = inv.get("facts") or {}
    for fact, product in (("cluster.version", "kubernetes"),
                          ("node.kernel", "linux-kernel"),
                          ("gpu.driver_version", "nvidia-driver"),
                          ("gpu.operator_version", "nvidia"),
                          ("kubelet.version", "kubelet")):
        if facts.get(fact) not in (None, ""):
            _record_version(products, product, facts[fact], fact,
                            _fact_source(inv, fact))

    nodes = list(inv.get("nodes") or [])
    for i, node in enumerate(nodes):
        src = str(node.get("source") or default_source)
        for key, product in (("kubelet", "kubelet"), ("kubelet_version", "kubelet"),
                             ("runc", "runc"), ("containerd", "containerd"),
                             ("kernel", "linux-kernel"), ("kernel_version", "linux-kernel"),
                             ("os", "os")):
            if node.get(key):
                _record_version(products, product, node[key], f"nodes[{i}].{key}", src)
        if node.get("runc_present") and not node.get("runc"):
            # 运行时 handler 证明 runc 存在，但版本未暴露：present=True、versions=[]
            _record_version(products, "runc", "", f"nodes[{i}].runtime_handlers", src,
                            present=True)
        runtime = str(node.get("container_runtime") or node.get("runtime") or "")
        if runtime:
            rtype, _, rver = runtime.partition("://")
            if rtype:
                _record_version(products, rtype, rver or runtime,
                                f"nodes[{i}].container_runtime", src)
        if node.get("cni"):
            _record_version(products, str(node["cni"]), node.get("cni_version"),
                            f"nodes[{i}].cni", src)
        gpu = node.get("gpu") or {}
        if gpu.get("driver_version"):
            _record_version(products, "nvidia-driver", gpu["driver_version"],
                            f"nodes[{i}].gpu.driver_version", src)

    cni = inv.get("cni") or {}
    if cni.get("name"):
        _record_version(products, cni["name"], cni.get("version"), "cni.version",
                        str(cni.get("source") or default_source))
        _record_version(products, "cni", cni.get("version"), "cni.version",
                        str(cni.get("source") or default_source))

    gpu = inv.get("gpu") or {}
    for key in ("operator", "toolkit"):
        info = gpu.get(key)
        if isinstance(info, dict) and (info.get("version") or info.get("present")):
            _record_version(products, "nvidia", info.get("version"),
                            f"gpu.{key}.version",
                            str(info.get("source") or default_source))
    if gpu.get("driver_version"):
        _record_version(products, "nvidia-driver", gpu["driver_version"],
                        "gpu.driver_version", str(gpu.get("source") or default_source))

    for key, product in (("ray", "ray"), ("kuberay", "kuberay"), ("lws", "lws"),
                         ("litellm", "litellm"), ("vllm", "vllm"),
                         ("sglang", "sglang"), ("gateway", "")):
        info = inv.get(key)
        if isinstance(info, dict):
            prod = product or str(info.get("product") or "")
            if prod and (info.get("version") or info.get("versions")
                         or info.get("present") is True):
                _record_version(products, prod, info.get("version"), f"{key}.version",
                                str(info.get("source") or default_source),
                                present=bool(info.get("present", True)))
                for v in info.get("versions") or []:
                    _record_version(products, prod, v, f"{key}.versions",
                                    str(info.get("source") or default_source))

    for i, comp in enumerate(inv.get("components") or []):
        if not isinstance(comp, dict):
            continue
        src = str(comp.get("source") or default_source)
        for name in (comp.get("product"), comp.get("name"), comp.get("image"),
                     comp.get("repo")):
            if not name:
                continue
            product = classify_component(str(name))
            if not product:
                continue
            _record_version(products, product, comp.get("version") or comp.get("tag"),
                            f"components[{i}].version", src)

    # 组件完整扫描但未出现 → 明确“未部署”；系统/硬件产品不适用此推断
    if coverage_components:
        known = set(products)
        inferred_absent = set()
        for entry_product in _COMPONENT_PRODUCTS:
            if entry_product not in known:
                inferred_absent.add(entry_product)
        if "nvidia" not in known and not (inv.get("gpu") or {}).get("nodes"):
            inferred_absent.add("nvidia")
        for product in inferred_absent:
            products[product] = {"present": False, "versions": [], "sources": [],
                                 "source": default_source}

    for key, product in (("bmc", "bmc"), ("switches", "switch")):
        items = inv.get(key)
        if isinstance(items, list) and items:
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                src = str(item.get("source") or default_source)
                prod = canonical_product(item.get("os") or item.get("vendor")
                                         or item.get("product") or product)
                if key == "switches" and prod not in ("sonic", "cumulus"):
                    prod = "switch"
                _record_version(products, prod, item.get("version") or item.get("firmware")
                                or item.get("os_version"), f"{key}[{i}].version", src)
    return products


# 由 catalog 组件名推导的“可判定未部署”产品；不包含系统/硬件/带外面。
_COMPONENT_PRODUCTS = {
    "vllm", "sglang", "ray", "kuberay", "lws", "litellm", "dify", "open-webui",
    "megatron", "deepspeed", "pytorch", "mlflow", "wardb", "wandb", "hami", "cgpu",
    "triton", "higress", "envoy-gateway", "istio", "kserve", "volcano", "kueue",
    "jobset", "training-operator", "openrlhf", "skyrl", "areal", "slime", "jupyter",
}


# ====================================================================== 判定


def _product_collect_hint(product: str) -> dict:
    hints = {
        "runc": _collect("nodes[*].runc", "节点 runc 版本（容器逃逸 CVE 的关键实测依据）",
                         "ssh <node> 'runc --version'（只读）或 crictl info；"
                         "或 snapshot 提供 nodes[].runc"),
        "containerd": _collect("nodes[*].containerd", "containerd 版本",
                               "kubectl get nodes -o json（status.nodeInfo.containerRuntimeVersion）"),
        "kubernetes": _collect("cluster.version", "K8s 版本",
                               "kubectl get --raw /version"),
        "kubelet": _collect("nodes[*].kubelet", "kubelet 版本",
                            "kubectl get nodes -o json（status.nodeInfo.kubeletVersion）"),
        "linux-kernel": _collect("nodes[*].kernel", "节点内核版本",
                                 "kubectl get nodes -o json（status.nodeInfo.kernelVersion）"),
        "nvidia": _collect("gpu.toolkit/operator", "NVIDIA Container Toolkit / GPU Operator 版本",
                           "kubectl get pods,daemonsets -A -o json（镜像 tag）；"
                           "节点 nvidia-ctk --version / nvidia-smi"),
        "bmc": _collect("bmc", "BMC 型号/固件（K8s API 不覆盖）",
                        "提供 BMC CMDB/Redfish 只读清单，或 --snapshot 含 bmc 字段"),
        "sonic": _collect("switches", "SONiC 版本（K8s API 不覆盖）",
                          "提供交换机只读清单，或 --snapshot 含 switches 字段"),
        "cumulus": _collect("switches", "Cumulus/NVUE 版本（K8s API 不覆盖）",
                            "提供交换机只读清单，或 --snapshot 含 switches 字段"),
        "switch": _collect("switches", "交换机清单", "提供交换机只读清单"),
    }
    return hints.get(canonical_product(product), _collect(
        f"products.{canonical_product(product)}.versions",
        f"未采集 {product} 版本",
        f"从镜像 tag / CRD / 组件进程只读采集 {product} 版本",
    ))


def _absent_product(product: str, inventory: dict) -> bool:
    key = canonical_product(product)
    if key in _SYSTEM_PRODUCTS or key in _HARDWARE_PRODUCTS:
        return False
    return key in _COMPONENT_PRODUCTS and bool(
        (inventory.get("coverage") or {}).get(
            "components_complete",
            (inventory.get("coverage") or {}).get("components")))


def _assess_version(entry: dict, products: dict, inventory: dict) -> dict:
    specs = entry.get("versions") or []
    if not specs:
        return {
            "status": "unknown",
            "matched": False,
            "checks": [],
            "missing": [_collect("catalog.version_range",
                                 "目录未声明可解析的受影响版本区间",
                                 "补充 version_range（如 >=1.0.0,<1.2.0）")],
            "reason": "catalog 版本区间缺失",
        }
    checks: list[dict] = []
    statuses: list[str] = []
    for spec in specs:
        product = canonical_product(spec.get("product") or entry.get("component") or "")
        ranges = str(spec.get("range") or "").strip()
        if not ranges:
            checks.append({"product": product, "status": "unknown",
                           "range": spec.get("raw") or "",
                           "detail": "目录提供的是人类可读版本描述，未给出可判定区间",
                           "field": f"products.{product}.versions", "source": "cve-catalog"})
            statuses.append("unknown")
            continue
        info = products.get(product)
        if info is None:
            absent = _absent_product(product, inventory)
            status = "absent" if absent else "unknown"
            statuses.append(status)
            checks.append({
                "product": product, "status": status, "range": ranges,
                "detail": "组件完整扫描未部署" if absent else "清单无该产品版本",
                "field": f"products.{product}.present",
                "source": _source(inventory),
                "collect": [] if absent else [_product_collect_hint(product)],
            })
            continue
        versions = list(info.get("versions") or [])
        if not versions:
            if info.get("present") is False:
                statuses.append("absent")
                checks.append({"product": product, "status": "absent", "range": ranges,
                               "detail": "组件完整扫描未部署",
                               "field": f"products.{product}.present",
                               "source": str(info.get("source") or _source(inventory))})
            else:
                statuses.append("unknown")
                checks.append({
                    "product": product, "status": "unknown", "range": ranges,
                    "detail": "产品已部署但版本未知（无 tag/版本字段）",
                    "field": f"products.{product}.versions",
                    "source": str(info.get("source") or _source(inventory)),
                    "collect": [_product_collect_hint(product)],
                })
            continue
        spec_statuses: list[str] = []
        for v in versions:
            try:
                ok = version_in_range(v.get("value"), ranges)
            except ApplicabilityError as exc:
                spec_statuses.append("unknown")
                checks.append({"product": product, "status": "unknown", "range": ranges,
                               "observed": v.get("value"),
                               "field": str(v.get("field") or f"products.{product}.versions"),
                               "source": str(v.get("source") or ""),
                               "detail": f"版本区间无法解析：{exc}"})
                continue
            spec_statuses.append("match" if ok else "no-match")
            checks.append({"product": product, "status": "match" if ok else "no-match",
                           "range": ranges, "observed": v.get("value"),
                           "field": str(v.get("field") or f"products.{product}.versions"),
                           "source": str(v.get("source") or ""),
                           "detail": f"{v.get('value')} {'∈' if ok else '∉'} {ranges}"})
        if "match" in spec_statuses:
            statuses.append("match")
        elif "unknown" in spec_statuses:
            statuses.append("unknown")
        elif spec_statuses and all(s == "no-match" for s in spec_statuses):
            statuses.append("no-match")
        else:
            statuses.append("unknown")
    mode = entry.get("match") or "any"
    if mode == "all":
        if "no-match" in statuses or "absent" in statuses:
            status = "no-match"
        elif all(s == "match" for s in statuses):
            status = "match"
        else:
            status = "unknown"
    else:
        if "match" in statuses:
            status = "match"
        elif "unknown" in statuses:
            status = "unknown"
        elif statuses and all(s in ("no-match", "absent") for s in statuses):
            status = "no-match"
        else:
            status = "unknown"
    missing = []
    for c in checks:
        if c.get("status") == "unknown":
            missing.extend(c.get("collect") or [])
    return {
        "status": status,
        "matched": status == "match",
        "checks": checks,
        "missing": _dedupe_collect(missing),
        "reason": "",
    }


def _dedupe_collect(items: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("field") or ""), str(item.get("why") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _assess_conditions(entry: dict, inventory: dict, products: dict) -> dict:
    raw = entry.get("conditions")
    if raw is None or raw == [] or raw == {}:
        return {"status": "true", "checks": [], "missing": [],
                "reason": "目录未声明前置条件"}
    ctx = ConditionContext(inventory=inventory, products=products,
                           probes=inventory.get("probes") or {},
                           component=str(entry.get("component") or ""))
    try:
        result = _eval_condition(raw, ctx)
    except ApplicabilityError as exc:
        return {
            "status": "unknown",
            "checks": [{"condition": str(raw), "status": "unknown",
                        "detail": f"条件求值失败：{exc}"}],
            "missing": [_collect("catalog.conditions", "条件表达式无法解析",
                                 "修正目录 conditions 结构")],
            "reason": str(exc),
        }
    checks = []
    for ev in result.evidence:
        checks.append({
            "condition": result.label,
            "status": result.status,
            "field": ev.get("field"),
            "value": ev.get("value"),
            "source": ev.get("source"),
            "detail": ev.get("detail") or "",
        })
    if not checks:
        checks.append({"condition": result.label, "status": result.status,
                       "detail": result.reason or ""})
    if entry.get("condition_text"):
        checks.append({
            "condition": "catalog.exploit_conditions",
            "status": "advisory",
            "field": f"catalog.entries[{entry.get('raw_index')}].exploit_conditions",
            "value": entry["condition_text"],
            "source": "cve-catalog",
            "detail": "目录自由文本前置条件（仅作证据说明，不替代实测）",
        })
    return {
        "status": "true" if result.value is True else
                  "false" if result.value is False else "unknown",
        "checks": checks,
        "missing": _dedupe_collect(result.collect + _false_missing(checks)),
        "reason": result.reason,
    }


def _false_missing(checks: list[dict]) -> list[dict]:
    """blocked 时必须列出缺失前置，而不是只给一个 false。"""
    out = []
    for c in checks:
        if c.get("status") != "false":
            continue
        field_name = str(c.get("field") or "conditions")
        label = str(c.get("condition") or "前置条件")
        out.append(_collect(
            field_name,
            f"前置条件不满足：{label}"
            + (f"（观测 {c.get('value')!r}）" if c.get("value") is not None else ""),
            "按证据修复/调整环境后重跑 assess；或在授权范围补充探测结果",
        ))
    return out


def _state(version_status: str, condition_status: str | None) -> str:
    if version_status in ("no-match", "absent"):
        return STATE_NOT_APPLICABLE
    if version_status != "match":
        return STATE_UNKNOWN
    if condition_status == "false":
        return STATE_BLOCKED
    if condition_status in (None, "true"):
        return STATE_APPLICABLE
    return STATE_UNKNOWN


def _why(entry: dict, state: str, version: dict, conditions: dict) -> dict:
    title = entry.get("title")
    name = title.get("zh") if isinstance(title, dict) else str(title)
    matched = [c for c in version.get("checks") or [] if c.get("status") == "match"]
    bad = [c for c in conditions.get("checks") or [] if c.get("status") == "false"]
    unknown = [c for c in conditions.get("checks") or [] if c.get("status") == "unknown"]
    if state == STATE_APPLICABLE:
        zh = f"版本命中（{len(matched)} 条区间）且前置条件全部满足。"
        en = f"Version matched ({len(matched)} range checks) and all preconditions passed."
    elif state == STATE_BLOCKED:
        labels = "；".join(str(c.get("condition") or c.get("detail") or "") for c in bad[:3])
        zh = f"版本命中，但前置条件不满足：{labels or '见证据'}。"
        en = f"Version matched but preconditions failed: {labels or 'see evidence'}."
    elif state == STATE_NOT_APPLICABLE:
        reasons = []
        for c in version.get("checks") or []:
            if c.get("status") == "no-match":
                reasons.append(f"{c.get('product')} {c.get('observed')} ∉ {c.get('range')}")
            elif c.get("status") == "absent":
                reasons.append(f"{c.get('product')} 未部署")
        reasons = list(dict.fromkeys(reasons))
        zh = "版本不命中或组件未部署：" + ("；".join(reasons[:4]) or "无受影响面") + "。"
        en = "Version not affected / component absent: " + \
             ("; ".join(reasons[:4]) or "no affected surface") + "."
    else:
        reasons = [str(c.get("detail") or c.get("condition") or "") for c in unknown[:3]]
        reasons += [str(c.get("detail") or "") for c in (version.get("checks") or [])
                    if c.get("status") == "unknown"]
        reasons = [r for r in dict.fromkeys(reasons) if r]
        zh = "信息不足，不能判定为适用：" + \
             ("；".join(reasons[:3]) or version.get("reason") or "版本或前置条件未知") + "。"
        en = "Insufficient information; applicable cannot be inferred: " + \
             ("; ".join(reasons[:3]) or version.get("reason") or "version/precondition unknown") + "."
    return {"zh": zh, "en": en, "title": name}


def _assess_entry(entry: dict, products: dict, inventory: dict) -> dict:
    version = _assess_version(entry, products, inventory)
    if version["status"] == "match":
        conditions = _assess_conditions(entry, inventory, products)
    else:
        conditions = {"status": None if version["status"] in ("no-match", "absent") else "unknown",
                      "checks": [], "missing": [] if version["status"] in ("no-match", "absent") else version["missing"],
                      "reason": ""}
    state = _state(version["status"], conditions.get("status"))
    missing = []
    if version["status"] not in ("no-match", "absent"):
        missing.extend(version.get("missing") or [])
    missing.extend(conditions.get("missing") or [])
    evidence = []
    for c in version.get("checks") or []:
        evidence.append({
            "kind": "version", "product": c.get("product"),
            "field": c.get("field"), "value": c.get("observed", c.get("detail")),
            "source": c.get("source"), "status": c.get("status"),
        })
    for c in conditions.get("checks") or []:
        evidence.append({
            "kind": "condition", "condition": c.get("condition"),
            "field": c.get("field"), "value": c.get("value"),
            "source": c.get("source"), "status": c.get("status"),
            "detail": c.get("detail"),
        })
    return {
        "cve": entry["id"],
        "id": entry["id"],
        "title": entry.get("title"),
        "component": entry.get("component"),
        "component_name": entry.get("component_name"),
        "severity": entry.get("severity"),
        "cvss": entry.get("cvss"),
        "kind": entry.get("kind"),
        "state": state,
        "state_label": {"zh": STATE_LABELS[state][0], "en": STATE_LABELS[state][1]},
        "version": version,
        "preconditions": conditions,
        "evidence": evidence,
        "missing": _dedupe_collect(missing),
        "why": _why(entry, state, version, conditions),
        "modules": list(entry.get("modules") or []),
        "chains": list(entry.get("chains") or []),
        "rules": list(entry.get("rules") or []),
        "sources": list(entry.get("sources") or []),
        "fixed": entry.get("fixed"),
        "fixed_note": entry.get("fixed_note"),
        "affected": entry.get("affected_text") or "",
        "condition_text": entry.get("condition_text") or "",
        "requires_hardware": entry.get("requires_hardware"),
        "mockable": entry.get("mockable"),
        "catalog_ref": {"path": entry.get("catalog_path") or "",
                        "index": entry.get("raw_index")},
    }


def assess_cves(inventory: dict | str | Path | None = None, catalog: dict | str | Path | None = None,
                *, catalog_path: str | Path | None = None, home: str | Path | None = None,
                link: bool = True) -> dict:
    """入口：环境清单 + CVE 目录 → 四态判定 + 证据 + 模块/链/规则键。"""
    from ..assess.inventory import load_inventory, normalize_inventory

    inv = normalize_inventory(inventory if not isinstance(inventory, (str, Path))
                              else load_inventory(inventory))
    if isinstance(catalog, (str, Path)):
        cat = load_catalog(catalog, home=home, link=link)
    elif isinstance(catalog, list):
        cat = _normalize_catalog_doc(catalog, str(catalog_path or "inline"))
        if link:
            _enrich_links(cat)
        cat["_linked"] = True
    elif isinstance(catalog, dict) and "entries" in catalog:
        first = next((e for e in catalog.get("entries") or [] if isinstance(e, dict)), {})
        if catalog.get("_normalized") or "versions" in first:
            cat = catalog
            if link and not cat.get("_linked"):
                _enrich_links(cat)
                cat["_linked"] = True
        else:
            cat = _normalize_catalog_doc(catalog, str(catalog_path or "inline"))
            if link:
                _enrich_links(cat)
            cat["_linked"] = True
    elif isinstance(catalog, dict):
        cat = _normalize_catalog_doc(catalog, str(catalog_path or "inline"))
        if link:
            _enrich_links(cat)
        cat["_linked"] = True
    else:
        cat = load_catalog(catalog_path, home=home, link=link)
    for entry in cat.get("entries") or []:
        entry["catalog_path"] = str(cat.get("path") or "")
    products = derive_products(inv)
    results = [_assess_entry(e, products, inv) for e in cat.get("entries") or []]
    summary = {state: 0 for state in STATES}
    by_severity: dict[str, dict[str, int]] = {}
    for r in results:
        summary[r["state"]] = summary.get(r["state"], 0) + 1
        sev = str(r.get("severity") or "unknown").lower()
        bucket = by_severity.setdefault(sev, {state: 0 for state in STATES})
        bucket[r["state"]] += 1
    module_index: dict[str, dict] = {}
    for r in results:
        for mod in r.get("modules") or []:
            rec = module_index.setdefault(mod, {"module": mod, "cves": [], "states": {}})
            rec["cves"].append(r["cve"])
            rec["states"][r["cve"]] = r["state"]
    for rec in module_index.values():
        states = list(rec["states"].values())
        if STATE_APPLICABLE in states:
            rec["state"] = STATE_APPLICABLE
        elif STATE_UNKNOWN in states:
            rec["state"] = STATE_UNKNOWN
        elif STATE_BLOCKED in states:
            rec["state"] = STATE_BLOCKED
        else:
            rec["state"] = STATE_NOT_APPLICABLE
        rec["gate"] = "open" if rec["state"] == STATE_APPLICABLE else rec["state"]
    gaps = _collection_gaps(inv, results)
    return {
        "schema": SCHEMA,
        "generated_at": _now(),
        "inventory": {
            "schema": inv.get("schema"),
            "collected_at": inv.get("collected_at") or "",
            "source": inv.get("source"),
            "cluster": inv.get("cluster") or {},
            "coverage": inv.get("coverage") or {},
            "path": inv.get("path") or "",
        },
        "catalog": {
            "schema": cat.get("schema"),
            "path": cat.get("path") or "",
            "found": bool(cat.get("found")),
            "entries": len(cat.get("entries") or []),
            "verified_at": cat.get("verified_at") or "",
            "warnings": list(cat.get("warnings") or []),
        },
        "summary": {**summary, "total": len(results)},
        "by_severity": by_severity,
        "entries": results,
        "module_index": module_index,
        "collection_gaps": gaps,
        "limits": [
            "只读判定：inventory 采集只使用 kubectl get / auth can-i 与离线 snapshot。",
            "unknown 不会被自动升级为 applicable；缺条件时输出补采命令。",
            "自由文本前置条件按保守映射求值；未映射条款记为 unknown。",
            "硬件/带外（BMC/交换机）不在 Kubernetes API 内，需额外清单。",
        ],
    }


def _collection_gaps(inventory: dict, results: list[dict]) -> list[dict]:
    gaps = []
    for err in (inventory.get("collection") or {}).get("errors") or []:
        gaps.append({"kind": "collection-error", **err} if isinstance(err, dict) else
                    {"kind": "collection-error", "detail": str(err)})
    seen: set[tuple[str, str]] = set()
    for r in results:
        if r["state"] != STATE_UNKNOWN:
            continue
        for miss in r.get("missing") or []:
            key = (str(miss.get("field") or ""), str(miss.get("why") or ""))
            if key in seen:
                continue
            seen.add(key)
            gaps.append({"kind": "missing-field", "cve": r["cve"], **miss})
    return gaps


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ====================================================================== 模块闸门 / 解释 / 矩阵


def gate_module(assessment: dict | None, module_key: str) -> dict:
    """返回模块的 CVE 闸门：open / blocked / unknown / not-applicable / not-gated。"""
    if not assessment:
        return {"module": module_key, "gated": False, "state": "not-evaluated",
                "gate": "not-evaluated", "allow": True, "cves": [],
                "basis": ["未提供环境清单：本次未执行 CVE 适用性评估（不阻断）"],
                "missing": [], "evidence": []}
    entries = [e for e in assessment.get("entries") or [] if module_key in (e.get("modules") or [])]
    if not entries:
        return {"module": module_key, "gated": False, "state": "not-gated",
                "gate": "open", "allow": True, "cves": [],
                "basis": ["该模块未在任何 CVE 条目的 modules 中登记"],
                "missing": [], "evidence": []}
    states = [e["state"] for e in entries]
    if STATE_APPLICABLE in states:
        state = STATE_APPLICABLE
    elif STATE_UNKNOWN in states:
        state = STATE_UNKNOWN
    elif STATE_BLOCKED in states:
        state = STATE_BLOCKED
    else:
        state = STATE_NOT_APPLICABLE
    allow = state == STATE_APPLICABLE
    missing = []
    for e in entries:
        missing.extend(e.get("missing") or [])
    return {
        "module": module_key,
        "gated": True,
        "state": state,
        "gate": "open" if allow else state,
        "allow": allow,
        "cves": [e["cve"] for e in entries],
        "basis": [f"{e['cve']}: {e['state_label']['zh']} — {e['why']['zh']}" for e in entries],
        "missing": _dedupe_collect(missing),
        "evidence": [ev for e in entries for ev in (e.get("evidence") or [])][:24],
    }


def gate_chain(chain: dict, assessment: dict | None) -> dict:
    steps = chain.get("steps") or []
    gates = [gate_module(assessment, str(s.get("module") or "")) for s in steps]
    blocked = [g for g in gates if g.get("gated") and not g.get("allow")]
    unknown = [g for g in gates if g.get("state") == STATE_UNKNOWN]
    return {
        "evaluated": assessment is not None,
        "summary": (assessment or {}).get("summary") or {},
        "catalog": (assessment or {}).get("catalog") or {},
        "inventory": (assessment or {}).get("inventory") or {},
        "objective": bool(chain.get("objective")),
        "cves": sorted({c for g in gates for c in (g.get("cves") or [])}),
        "blocked_steps": [g["module"] for g in blocked],
        "unknown_steps": [g["module"] for g in unknown],
        "gates": {g["module"]: g for g in gates},
        "basis": [
            f"{g['module']}: {g['state']}" + (f"（{'; '.join(g['basis'][:2])}）" if g.get("basis") else "")
            for g in gates if g.get("gated")
        ],
    }


def evaluate_condition(expression: Any, inventory: dict | None = None) -> dict:
    """公开的条件求值入口（测试/插件/CLI 调试）：返回 status/evidence/missing。"""
    from ..assess.inventory import normalize_inventory

    inv = normalize_inventory(inventory or {})
    products = derive_products(inv)
    ctx = ConditionContext(inventory=inv, products=products,
                           probes=inv.get("probes") or {})
    result = _eval_condition(expression, ctx)
    return {
        "status": result.status,
        "label": result.label,
        "evidence": result.evidence,
        "missing": _dedupe_collect(result.collect),
        "reason": result.reason,
    }


def explain(assessment: dict, cve_id: str, *, lang: str = "zh") -> str:
    """人话解释：为什么适用/不适用、缺什么条件、怎么补采。"""
    entry = next((e for e in assessment.get("entries") or []
                  if str(e.get("cve", "")).upper() == str(cve_id).upper()), None)
    if entry is None:
        known = ", ".join(str(e.get("cve")) for e in (assessment.get("entries") or [])[:8])
        raise ApplicabilityError(
            f"目录中没有 {cve_id}。已纳管示例：{known}{' …' if known else ''}；"
            f"目录路径：{(assessment.get('catalog') or {}).get('path') or '未落盘'}"
        )
    title = entry.get("title")
    title_text = title.get("zh") if isinstance(title, dict) else str(title or "")
    lines = [
        f"# {entry['cve']} — {title_text}",
        "",
        f"- 结论：**{entry['state_label']['zh']} ({entry['state']})**",
        f"- 组件：`{entry.get('component') or '-'}` · 严重度：`{entry.get('severity') or '-'}` · CVSS：`{entry.get('cvss') or '-'}`",
        f"- 受影响版本（目录）：{entry.get('affected') or '-'}",
        f"- 修复版本：{entry.get('fixed') or '未标注'}"
        + (f"（{entry.get('fixed_note')}）" if entry.get('fixed_note') else ""),
        "",
        "## 为什么",
        "",
        entry["why"]["zh"],
        "",
        "## 版本依据",
        "",
    ]
    checks = entry.get("version", {}).get("checks") or []
    if not checks:
        lines.append("- （目录无可用版本区间）")
    for c in checks:
        lines.append(
            f"- `{c.get('product')}`：观测 `{c.get('observed', '—')}` vs 区间 `{c.get('range')}` "
            f"→ **{c.get('status')}**"
            f"（字段 `{c.get('field') or '—'}`，来源 `{c.get('source') or '—'}`）"
            + (f" — {c.get('detail')}" if c.get('detail') else "")
        )
    lines += ["", "## 前置条件依据", ""]
    conds = entry.get("preconditions", {}).get("checks") or []
    if not conds:
        lines.append("- （未声明前置条件，或版本未命中而未求值）")
    for c in conds:
        if c.get("status") == "advisory":
            lines.append(f"- 目录文本：{c.get('value')}（仅说明，不替代实测）")
            continue
        lines.append(
            f"- `{c.get('condition')}` → **{c.get('status')}**"
            f"（字段 `{c.get('field') or '—'}`，观测 `{c.get('value') if c.get('value') is not None else '—'}`，"
            f"来源 `{c.get('source') or '—'}`）"
            + (f" — {c.get('detail')}" if c.get('detail') else "")
        )
    lines += ["", "## 缺什么 / 怎么补采", ""]
    if entry.get("missing"):
        for m in entry["missing"]:
            lines.append(f"- `{m.get('field')}`：{m.get('why')}"
                         + (f"\n  - 命令/方法：`{m.get('command')}`" if m.get('command') else ""))
    else:
        lines.append("- 无缺失采集项；结论已由版本与前置条件的实测证据支撑。")
    lines += ["", "## 可用模块 / 链 / 规则", ""]
    lines.append("- 模块：" + (", ".join(f"`{m}`" for m in entry.get("modules") or []) or "（无）"))
    lines.append("- 链：" + (", ".join(f"`{c}`" for c in entry.get("chains") or []) or "（无）"))
    lines.append("- 规则：" + (", ".join(f"`{r}`" for r in entry.get("rules") or []) or "（无）"))
    lines += ["", "## 证据边界", ""]
    inv = assessment.get("inventory") or {}
    lines.append(f"- 环境清单采集时间：{inv.get('collected_at') or '未提供'}")
    lines.append(f"- 环境清单来源：{json.dumps(inv.get('source'), ensure_ascii=False) if isinstance(inv.get('source'), (dict, list)) else inv.get('source') or '未提供'}")
    lines.append(f"- CVE 目录：{assessment.get('catalog', {}).get('path') or '未落盘'}")
    lines.append("- `unknown` 不会自动升级为 `applicable`；本解释不替代授权范围/备份闸门。")
    return "\n".join(lines)


def render_matrix(assessment: dict, lang: str = "bi") -> str:
    """报告用 Markdown 矩阵：版本 / 前置 / 实测条件 / 结论 / 证据。"""
    def pick(zh: str, en: str) -> str:
        return zh if lang == "zh" else en if lang == "en" else f"{zh} / {en}"

    cats = assessment.get("catalog") or {}
    inv = assessment.get("inventory") or {}
    summary = assessment.get("summary") or {}
    if lang == "bi":
        head_lines = [
            f"- 目录：`{cats.get('path') or '未落盘'}`（{cats.get('entries', 0)} 条） · "
            f"清单：`{inv.get('path') or '未提供'}` · 采集时间：{inv.get('collected_at') or '—'}",
            f"- Catalog: `{cats.get('path') or 'not found'}` ({cats.get('entries', 0)} entries) · "
            f"Inventory: `{inv.get('path') or 'not provided'}` · collected: {inv.get('collected_at') or '-'}",
            f"- 四态：适用 **{summary.get(STATE_APPLICABLE, 0)}** · 前置不满足 **{summary.get(STATE_BLOCKED, 0)}** · "
            f"不适用 **{summary.get(STATE_NOT_APPLICABLE, 0)}** · 信息不足 **{summary.get(STATE_UNKNOWN, 0)}**",
            f"- States: applicable **{summary.get(STATE_APPLICABLE, 0)}** · blocked **{summary.get(STATE_BLOCKED, 0)}** · "
            f"not applicable **{summary.get(STATE_NOT_APPLICABLE, 0)}** · unknown **{summary.get(STATE_UNKNOWN, 0)}**",
            "",
        ]
    else:
        head_lines = [
            pick(
                f"- 目录：`{cats.get('path') or '未落盘'}`（{cats.get('entries', 0)} 条） · "
                f"清单：`{inv.get('path') or '未提供'}` · 采集时间：{inv.get('collected_at') or '—'}",
                f"- Catalog: `{cats.get('path') or 'not found'}` ({cats.get('entries', 0)} entries) · "
                f"Inventory: `{inv.get('path') or 'not provided'}` · collected: {inv.get('collected_at') or '-'}",
            ),
            pick(
                f"- 四态：适用 **{summary.get(STATE_APPLICABLE, 0)}** · 前置不满足 **{summary.get(STATE_BLOCKED, 0)}** · "
                f"不适用 **{summary.get(STATE_NOT_APPLICABLE, 0)}** · 信息不足 **{summary.get(STATE_UNKNOWN, 0)}**",
                f"- States: applicable **{summary.get(STATE_APPLICABLE, 0)}** · blocked **{summary.get(STATE_BLOCKED, 0)}** · "
                f"not applicable **{summary.get(STATE_NOT_APPLICABLE, 0)}** · unknown **{summary.get(STATE_UNKNOWN, 0)}**",
            ),
            "",
        ]
    lines = head_lines
    if not cats.get("found"):
        lines.append(pick(
            "**CVE 目录未落盘**：本节不生成任何推断结论；请先提供 `trident/core/cve-catalog.json`。",
            "**CVE catalog not found**: no inference is made in this section. Provide `trident/core/cve-catalog.json` first.",
        ))
        return "\n".join(lines)
    if lang == "zh":
        header = "| CVE | 组件 | 版本区间 | 观测版本 | 前置条件 | 实测条件/证据 | 结论 | 模块/链 |"
    elif lang == "en":
        header = "| CVE | Component | Affected range | Observed | Preconditions | Live evidence | State | Modules/chains |"
    else:
        header = ("| CVE | 组件 / Component | 版本区间 / Affected | 观测 / Observed | "
                  "前置 / Preconditions | 实测证据 / Live evidence | 结论 / State | 模块·链 / Modules·chains |")
    lines += [header, "|---|---|---|---|---|---|---|---|"]
    if not assessment.get("entries"):
        lines.append(pick("| （无条目） | | | | | | | |",
                          "| (no entries) | | | | | | | |"))
    for e in assessment.get("entries") or []:
        ranges = "; ".join(f"{c.get('product')}: {c.get('range')}"
                           for c in e.get("version", {}).get("checks") or []) or "—"
        observed = "; ".join(str(c.get("observed")) for c in e.get("version", {}).get("checks") or []
                             if c.get("observed") not in (None, "")) or "—"
        conds = []
        seen_cond = set()
        for c in e.get("preconditions", {}).get("checks") or []:
            key = (c.get("condition"), c.get("status"))
            if key in seen_cond:
                continue
            seen_cond.add(key)
            conds.append(c)
        cond_text = "; ".join(f"{c.get('condition')}={c.get('status')}"
                              for c in conds if c.get("status") != "advisory") or "—"
        seen_ev = set()
        evidence_parts = []
        for ev in e.get("evidence") or []:
            if not ev.get("field") or ev.get("status") == "advisory":
                continue
            key = (ev.get("field"), str(ev.get("value")), ev.get("source"))
            if key in seen_ev:
                continue
            seen_ev.add(key)
            evidence_parts.append(f"{ev.get('field')}={_short(ev.get('value'))}"
                                  + (f" ({ev.get('source')})" if ev.get("source") else ""))
        evidence = "; ".join(evidence_parts) or "—"
        links = ", ".join((e.get("modules") or [])[:2] + (e.get("chains") or [])[:2]) or "—"
        state_text = (e["state_label"]["zh"] if lang in ("zh", "bi")
                      else e["state_label"]["en"])
        if lang == "bi":
            state_text = f"{e['state_label']['zh']} / {e['state_label']['en']}"
        lines.append(
            f"| `{e.get('cve')}` | {_cell(e.get('component') or '—')} | {_cell(ranges)} | "
            f"{_cell(observed)} | {_cell(cond_text)} | {_cell(evidence)} | "
            f"**{state_text}** | {_cell(links)} |"
        )
    lines += ["", pick(
        "**读法**：`applicable` 才开放对应模块；`blocked` 列出缺失前置；`not-applicable` 为版本不命中/组件未部署；"
        "`unknown` 表示信息不足，不升级为适用。证据列格式为 `字段=值 (来源)`。",
        "**How to read**: only `applicable` opens the linked module; `blocked` lists missing preconditions; "
        "`not-applicable` means version mismatch/component absent; `unknown` is never upgraded to applicable. "
        "Evidence is `field=value (source)`.",
    )]
    return "\n".join(lines)


def _short(value: Any, limit: int = 48) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _cell(value: Any) -> str:
    return str(value if value is not None else "—").replace("|", "\\|").replace("\n", " ")
