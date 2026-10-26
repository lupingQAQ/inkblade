"""network-policy-coverage — 网络策略覆盖缺口与默认拒绝检测（静态推演层，免 bash）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    policies = snapshot.get("networkpolicies", [])
    pods_by_ns: dict[str, list[dict]] = {}
    for pod in snapshot.get("pods", []):
        pods_by_ns.setdefault(pod.get("namespace", "default"), []).append(pod)
    # 索引：namespace → 策略列表（O(policies) 一次分组，避免每命名空间全表扫描的 O(ns×policies)）
    policies_by_ns: dict[str, list[dict]] = {}
    for policy in policies:
        policies_by_ns.setdefault(policy.get("namespace", "default"), []).append(policy)

    for ns, pods in sorted(pods_by_ns.items()):
        ns_policies = policies_by_ns.get(ns, [])
        # 空选择器（podSelector == {}）= 选择命名空间内全部 Pod；缺省 policyTypes 视为 ["Ingress"]
        selecting_all = [p for p in ns_policies if not p.get("podSelector")]
        ingress_selecting = [p for p in selecting_all if "Ingress" in p.get("policyTypes", ["Ingress"])]
        default_deny = any(not p.get("ingress") for p in ingress_selecting)
        pod_names = ", ".join(sorted(p.get("name", "?") for p in pods))
        if not ingress_selecting:
            findings.append(finding(
                "high", f"命名空间 {ns} 的 {len(pods)} 个 Pod 未被任何入站 NetworkPolicy 选择（覆盖缺口）",
                detail=f"Pod 清单：{pod_names}。无策略选择 = 入站全放行（平网前提），任意同集群 Pod 可直达。",
                evidence=f"ns={ns} pods={len(pods)} policies_in_ns={len(ns_policies)}",
                mapping="链「平网 → 管理面 → 权重投毒」前置；可达性图（静态策略推演层）",
                fix="落地默认拒绝（Ingress+Egress deny-all）后按域放行；管理端口仅网段可达",
            ))
        elif not default_deny:
            findings.append(finding(
                "medium", f"命名空间 {ns} 缺默认拒绝入站策略（有选择策略但无 deny-all）",
                detail="存在策略不等于隔离有效：未入选标的 Pod 仍全放行，需 deny-all 兜底。",
                evidence=f"ns={ns} selecting={len(ingress_selecting)} default_deny=no",
                mapping="设计基线 5.6 设计约束 1",
                fix="补 podSelector 为空的默认拒绝策略，再按服务网格最小放行",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="网络策略覆盖分析")
