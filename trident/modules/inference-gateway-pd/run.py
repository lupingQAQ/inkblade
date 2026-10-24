# -*- coding: utf-8 -*-
"""推理网关与预填充-解码分离（spec 5.2 网络架构模块 / 5.6 服务与网关层）。

Gateway API / HTTPRoute / InferencePool+EPP / llm-d / LWS / router：
failureMode=FailOpen 故障域放大、管理端口、KV-cache 路由信息面、
预填充-解码分离信任边界（DNAT 隐藏真实端点；EPP 是新的未授权入口面）。
"""

from __future__ import annotations

import json
from pathlib import Path


def _merge_file(merged: dict, stem: str, data) -> None:
    if isinstance(data, dict):
        kind = str(data.get("kind", ""))
        if kind.endswith("List"):  # PodList/NetworkPolicyList/... 项缺 kind → 补单数 kind
            for it in data.get("items", []) or []:
                if isinstance(it, dict) and not it.get("kind"):
                    it["kind"] = kind[:-4]
        merged.setdefault("_sources", {})[stem] = data
        for k, v in data.items():
            if k in merged and isinstance(merged[k], list) and isinstance(v, list):
                merged[k] = merged[k] + v
            elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k].update(v)
            else:
                merged[k] = v
    elif isinstance(data, list):
        merged["items"] = merged.get("items", []) + data


def _load_snapshot(params: dict) -> dict:
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 lab/fixtures/network/ 路径）")
    if isinstance(snap, dict):
        return snap
    paths = snap if isinstance(snap, (list, tuple)) else [snap]
    merged: dict = {}
    for raw in paths:
        p = Path(str(raw))
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            _merge_file(merged, f.stem, json.loads(f.read_text(encoding="utf-8")))
    return merged


def _artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run")
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def _finding(sev: str, title: str, detail: str, fps: dict, combo=()) -> dict:
    f = {"sev": sev, "title": title, "detail": detail,
         "fingerprints": {k: bool(v) for k, v in fps.items()},
         "combo": list(combo)}
    tail = " ||fingerprints=" + json.dumps(f["fingerprints"], sort_keys=True, ensure_ascii=False)
    if combo:
        tail += " ||combo=" + ",".join(combo)
    f["detail"] += tail
    return f


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    items = snap.get("items", [])
    findings: list[dict] = []
    fps: dict = {}

    gateways = [i for i in items if i.get("kind") == "Gateway"]
    routes = [i for i in items if i.get("kind") == "HTTPRoute"]
    pools = [i for i in items if i.get("kind") == "InferencePool"]
    lws = [i for i in items if i.get("kind") == "LeaderWorkerSet"]
    services = [i for i in items if i.get("kind") == "Service"]
    configmaps = [i for i in items if i.get("kind") == "ConfigMap"]

    # Deployment/DaemonSet → EPP 姿态
    epps: list[dict] = []
    for item in items:
        if item.get("kind") not in ("Deployment", "DaemonSet"):
            continue
        for c in (item.get("spec", {}).get("template", {}).get("spec", {}) or {}).get("containers", []) or []:
            env = {str(e.get("name", "")): str(e.get("value", "")) for e in c.get("env", []) or []}
            mode = env.get("EXT_ENDPOINT_POOL_FAILURE_MODE", "")
            if mode or "epp" in str(item.get("metadata", {}).get("name", "")).lower():
                mgmt = [p.get("name") or p.get("containerPort") for p in c.get("ports", []) or []
                        if str(p.get("name", "")).lower() in ("mgmt", "admin", "debug")
                        or int(p.get("containerPort", 0)) in (8080, 9010)]
                epps.append({
                    "name": item.get("metadata", {}).get("name", "?"),
                    "failureMode": mode or "未声明",
                    "mgmt_ports": mgmt,
                    "pool": env.get("EXT_ENDPOINTS", ""),
                })
    if gateways:
        fps["gateway-api"] = True
    if pools:
        fps["inferencepool"] = True

    # --- FailOpen ---
    failopen = [e for e in epps if e["failureMode"].lower() == "failopen"]
    if failopen:
        fps["failopen"] = True
        findings.append(_finding(
            "high", "EPP failureMode=FailOpen：网关故障域放大",
            f"FailOpen EPP：{json.dumps(failopen, ensure_ascii=False)}。EPP 故障时放行全量流量："
            "（1）绕过基于池的调度与准入；（2）网关成为新的未授权入口面与放大器"
            "（spec 5.6 服务与网关层 + 12.1 Gateway API Inference Extension）。",
            {"inferencepool": True, "failopen": True, "gateway-api": bool(gateways)},
            combo=("inferencepool-failopen-gateway",)))
    elif epps:
        findings.append(_finding(
            "info", "EPP failureMode 非 FailOpen",
            f"EPP 清单：{json.dumps(epps, ensure_ascii=False)}",
            {"inferencepool": bool(pools), "failopen": False}))

    # --- 预填充-解码分离信任边界 ---
    pd_pods = [i for i in items if i.get("kind") == "Pod"
               and (("llm-d.ai/pod-role" in (i.get("metadata", {}).get("labels", {}) or {}))
                    or any(str(e.get("name", "")) == "POD_ROLE"
                           for c in (i.get("spec", {}) or {}).get("containers", []) or []
                           for e in c.get("env", []) or []))]
    if lws or pd_pods:
        fps["pd-split"] = True
        fps["lws"] = bool(lws)
        roles = sorted({str((p.get("metadata", {}).get("labels", {}) or {}).get("llm-d.ai/pod-role", ""))
                        for p in pd_pods} - {""})
        findings.append(_finding(
            "medium", "预填充-解码分离信任边界",
            f"LWS={len(lws)}（{[x.get('metadata', {}).get('name') for x in lws]}）；角色 Pod {len(pd_pods)}"
            f"（roles={roles}）。分离架构共享同一池内信任域：到达池网络的任意主体可直达 prefill/decode "
            "Pod（无 per-tenant 隔离）；LWS 集群级 Secrets 面见权限链模块 lws-secrets-lateral。",
            {"pd-split": True, "lws": bool(lws), "gateway-api": bool(gateways)},
            combo=("sglang-lws-pd-split", "pd-split-nixl-rdma-kv-channel")))

    # --- KV-cache 路由信息面 ---
    kv_hints = []
    for cm in configmaps:
        blob = json.dumps(cm.get("data", {}), ensure_ascii=False)
        if "kv" in blob.lower():
            kv_hints.append(cm.get("metadata", {}).get("name", "?"))
    nixl_env = any(
        str(e.get("name", "")) in ("KV_TRANSFER_ENGINE", "VLLM_KV_TRANSFER_ENGINE", "NIXL_TLS")
        for i in items if i.get("kind") == "Pod"
        for c in (i.get("spec", {}) or {}).get("containers", []) or []
        for e in c.get("env", []) or []
    )
    if kv_hints or nixl_env:
        fps["kv-route-info-surface"] = True
        findings.append(_finding(
            "medium", "KV-cache 路由信息面",
            f"路由提示 ConfigMap：{kv_hints}；工作负载 KV 传输环境变量在位={nixl_env}。"
            "EPP 全量可见请求流并决定 prefill→decode KV 复用：路由元数据 + KV 通道（NIXL/Mooncake "
            "over RDMA，明文）构成推理操纵与信息泄露面（通道细节见 collective-communication-surface）。",
            {"kv-route-info-surface": True, "pd-split": fps.get("pd-split", False)},
            combo=("pd-split-nixl-rdma-kv-channel",)))

    # --- llm-d / 管理端口 ---
    llm_d = [cm.get("metadata", {}).get("name", "?") for cm in configmaps
             if "llm-d" in str(cm.get("metadata", {}).get("name", "")).lower()
             or "llm-d" in json.dumps(cm.get("data", {}))]
    if llm_d:
        fps["llm-d"] = True
    mgmt_ports = [f"svc/{s.get('metadata', {}).get('name', '?')}:{p.get('port')}"
                  for s in services for p in s.get("spec", {}).get("ports", []) or []
                  if str(p.get("name", "")).lower() in ("mgmt", "admin", "debug")]
    if mgmt_ports or any(e["mgmt_ports"] for e in epps):
        fps["epp-mgmt-port"] = True
        findings.append(_finding(
            "medium", "推理网关管理端口暴露",
            f"管理端口：{mgmt_ports or [e['mgmt_ports'] for e in epps]}。管理面（router/EPP）"
            "常缺鉴权：与横向利用模块的框架管理面 fail-open 同型（sglang-admin-failopen 等）。",
            {"epp-mgmt-port": True, "gateway-api": bool(gateways)},
            combo=("sglang-admin-failopen", "unlimited-query-distillation")))

    # --- 路由 → 池映射（DNAT 隐藏真实端点） ---
    if routes and pools:
        mapping = [
            {"route": r.get("metadata", {}).get("name", "?"),
             "pools": [b.get("name") for rule in (r.get("spec", {}) or {}).get("rules", []) or []
                       for b in rule.get("backendRefs", []) or []
                       if b.get("kind") == "InferencePool"]}
            for r in routes
        ]
        findings.append(_finding(
            "info", "HTTPRoute → InferencePool 映射",
            f"{json.dumps(mapping, ensure_ascii=False)}；池 selector 端口经 DNAT 转发，"
            "真实 Pod 端点对外不可见（服务与网关层事实）。",
            {"gateway-api": True, "inferencepool": True}))

    if not findings:
        findings.append(_finding(
            "info", "未发现推理网关对象",
            "快照内未发现 Gateway/HTTPRoute/InferencePool/EPP/LWS。", {"gateway-api": False}))

    artifacts = _artifact(ctx, "inference-gateway-pd.json", {
        "gateways": gateways, "routes": routes, "pools": pools, "epps": epps,
        "lws": lws, "pd_pods": len(pd_pods), "mgmt_ports": mgmt_ports,
        "fingerprints": fps,
    })
    return {
        "summary": f"推理网关：Gateway {len(gateways)}，InferencePool {len(pools)}，EPP {len(epps)}"
                   f"（FailOpen {len(failopen)}），LWS {len(lws)}，pd Pod {len(pd_pods)}",
        "artifacts": artifacts,
        "findings": findings,
    }
