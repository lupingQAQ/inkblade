# -*- coding: utf-8 -*-
"""DNS 与服务发现（spec 5.2 网络架构模块 / 5.6 服务与网关层）。

CoreDNS 配置/转发、headless Service、Ray GCS 发现、跨集群 MCS/Submariner、
DNS 投毒。cluster.local 是集群内最通用的名字解析信任根。
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
    services = [i for i in items if i.get("kind") == "Service"]
    imports = [i for i in items if i.get("kind") == "ServiceImport"]
    endpoints = [i for i in items if i.get("kind") == "Endpoint"]

    findings: list[dict] = []
    fps: dict = {}

    # --- CoreDNS Corefile ---
    corefile = ""
    for cm in [i for i in items if i.get("kind") == "ConfigMap"]:
        if "Corefile" in (cm.get("data", {}) or {}):
            corefile = str(cm["data"]["Corefile"])
            break
    if not corefile and isinstance(snap.get("data", {}).get("Corefile", ""), str):
        corefile = str(snap["data"]["Corefile"])

    if corefile:
        forward_open = "forward . /etc/resolv.conf" in corefile or "forward . " in corefile
        pods_insecure = "pods insecure" in corefile
        has_cache = "cache" in corefile
        has_rewrite = "rewrite" in corefile or "hosts" in corefile
        if forward_open:
            fps["coredns-forward-open"] = True
        if pods_insecure or has_rewrite:
            fps["dns-poison-surface"] = True
        if forward_open or pods_insecure:
            reasons = []
            if forward_open:
                reasons.append("上游转发跟随节点 resolv.conf（云厂商 DNS，集群外不可控）")
            if pods_insecure:
                reasons.append("kubernetes 插件 pods insecure：PTR 反查信任 Pod 自报名字，"
                               "可被用于服务身份仿冒")
            if has_rewrite:
                reasons.append("rewrite/hosts 覆写面在位")
            findings.append(_finding(
                "medium", "CoreDNS 配置面：转发与投毒面",
                "；".join(reasons) + "。缓存=" + ("有（无 DNSSEC 校验，投毒 TTL 内持续生效）" if has_cache
                else "无") + "。任何可控 DNS 应答的路径（hostNetwork Pod / 上游劫持 / hosts 覆写）"
                "可重定向框架 rendezvous、镜像源与云 API 名字（设计基线 5.6 服务与网关层）。",
                {"coredns-forward-open": forward_open, "dns-poison-surface": pods_insecure or has_rewrite,
                 "dns-caching": has_cache},
                combo=("hybrid-cloud-egress-pivot",)))
        findings.append(_finding(
            "info", "CoreDNS Corefile 基线", f"Corefile 原文已入 artifact。\n{corefile}",
            {"coredns-present": True}))

    # --- headless Service / Ray GCS / rendezvous 发现 ---
    headless = []
    for svc in services:
        spec = svc.get("spec", {}) or {}
        if spec.get("clusterIP") != "None":
            continue
        name = str(svc.get("metadata", {}).get("name", "?"))
        ports = [int(p.get("port", 0)) for p in spec.get("ports", []) or []]
        headless.append({"service": name, "ports": ports})
        if any(p in (6379, 8265, 10001) for p in ports):
            fps["ray-gcs-discoverable"] = True
        if 29500 in ports:
            fps["rendezvous-discoverable"] = True
    if headless:
        fps["headless-service"] = True
        ray = [h for h in headless if any(p in (6379, 8265, 10001) for p in h["ports"])]
        if ray:
            findings.append(_finding(
                "medium", "Ray GCS/Dashboard headless 直连发现面",
                f"headless 服务 {ray} 直接解析到 Ray 头 Pod IP：GCS(6379)/Dashboard(8265)/Client(10001)"
                "无鉴权时可从任意可达 Pod 直达（链路联动 ray-dashboard-job）。",
                {"ray-gcs-discoverable": True, "headless-service": True},
                combo=("ray-dashboard-job", "verl-skyrl-kuberay-admin-plane")))
        findings.append(_finding(
            "info", "headless Service 清单（端点直出）",
            f"{json.dumps(headless, ensure_ascii=False)}。headless 服务把 Pod IP 直接暴露给解析方，"
            "绕过 ClusterIP/策略观测面（策略仍按 Pod IP 生效，但审计按 svc 统计时全走丢）。",
            {"headless-service": True}))

    # --- 跨集群（MCS / Submariner） ---
    if imports or endpoints:
        fps["cross-cluster-dns"] = True
        findings.append(_finding(
            "medium", "跨集群服务发现在位（MCS/Submariner）",
            f"ServiceImport={len(imports)}，Submariner Endpoint={len(endpoints)}。跨集群名字解析"
            "（clusterset.local）把远端集群端点注入本地 DNS：远端被攻陷即经 DNS 直达本地负载；"
            "DNS 投毒面同步放大（设计基线 5.6 云与混合边界层）。",
            {"cross-cluster-dns": True},
            combo=("hybrid-cloud-egress-pivot",)))

    if not findings:
        findings.append(_finding(
            "info", "未发现 DNS/服务发现线索",
            "快照内无 CoreDNS ConfigMap / headless Service / ServiceImport。",
            {"dns-mapped": False}))

    artifacts = _artifact(ctx, "dns-service-discovery.json", {
        "corefile": corefile, "headless": headless,
        "service_imports": imports, "submariner_endpoints": endpoints,
        "fingerprints": fps,
    })
    return {
        "summary": f"DNS/发现：Corefile={'有' if corefile else '无'}，headless {len(headless)}，"
                   f"跨集群对象 {len(imports) + len(endpoints)}",
        "artifacts": artifacts,
        "findings": findings,
    }
