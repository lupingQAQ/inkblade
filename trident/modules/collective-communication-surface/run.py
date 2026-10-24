# -*- coding: utf-8 -*-
"""集合通信面测绘（spec 5.2 网络架构模块 / 5.6 集合通信层）。

NCCL bootstrap（TCPStore/rendezvous）、NCCL 环境变量基线、
DeepEP/NVSHMEM/Mooncake/NIXL 通道与端口、rank 入组可行性。
关键事实：bootstrap/rendezvous 无认证，rank 可被任意可达端点加入。
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


_FRAMEWORKS = ("areal", "sglang", "vllm", "verl", "skyrl", "ray")


def _pod_env(pod: dict) -> dict:
    env: dict = {}
    for c in (pod.get("spec", {}) or {}).get("containers", []) or []:
        for e in c.get("env", []) or []:
            env[str(e.get("name", ""))] = str(e.get("value", ""))
    return env


def run(ctx: dict, params: dict) -> dict:
    snap = _load_snapshot(params)
    items = snap.get("items", [])
    pods = [i for i in items if i.get("kind") == "Pod"] + list(snap.get("pods", []))
    services = [i for i in items if i.get("kind") == "Service"]

    findings: list[dict] = []
    fps: dict = {}

    nccl_baseline: dict[str, list[str]] = {}
    bootstrap: list[dict] = []
    frameworks: set[str] = set()
    kv_channels: list[dict] = []

    for pod in pods:
        meta = pod.get("metadata", {}) or {}
        name = str(meta.get("name", "?"))
        env = _pod_env(pod)
        images = [str(c.get("image", "")) for c in (pod.get("spec", {}) or {}).get("containers", []) or []]
        blob = " ".join(images).lower()
        fw = {f for f in _FRAMEWORKS if f in blob}
        frameworks |= fw

        nccl_keys = {k: v for k, v in env.items() if k.startswith("NCCL_")}
        if nccl_keys:
            nccl_baseline[name] = nccl_keys
            fps["nccl"] = True

        master = env.get("MASTER_ADDR", "")
        if master:
            bootstrap.append({
                "pod": name, "endpoint": f"{master}:{env.get('MASTER_PORT', '?')}",
                "kind": "torch-TCPStore/c10d",
                "auth": "无（bootstrap/rendezvous 无认证）",
            })
        rdzv = env.get("TORCHELASTIC_RUN_ID", "") or env.get("PET_RDZV_ENDPOINT", "")
        if rdzv:
            bootstrap.append({"pod": name, "endpoint": rdzv, "kind": "torchelastic",
                              "auth": "无"})

        # KV / 共享内存传输通道（预填充-解码分离 & 专家并行）
        engine = (env.get("KV_TRANSFER_ENGINE") or env.get("VLLM_KV_TRANSFER_ENGINE") or "").lower()
        nixl = engine == "nixl" or any(k.startswith("NIXL_") for k in env)
        mooncake = any(k.startswith("MOONCAKE_") for k in env)
        nvshmem = any(k.startswith("NVSHMEM_") for k in env)
        deepep = any(k.startswith("DEEP_EP") or k.startswith("DEEPEP") for k in env)
        if nixl or mooncake or nvshmem or deepep:
            rdma_capable = "NCCL_IB_HCA" in env or "rdma/hca" in json.dumps(
                pod.get("spec", {}).get("containers", [])) or "mlx5" in json.dumps(env)
            tls_off = env.get("NIXL_TLS", "") == "false" or "tls" in engine
            kv_channels.append({
                "pod": name, "engine": "nixl" if nixl else "mooncake" if mooncake
                else "nvshmem" if nvshmem else "deepep",
                "rdma": rdma_capable, "tls": not tls_off,
            })
            if nixl and rdma_capable:
                fps["nixl-rdma"] = True
            if mooncake:
                fps["mooncake-kv"] = True
            if nvshmem:
                fps["nvshmem"] = True
            if deepep:
                fps["deepep"] = True

    # headless rendezvous / GCS 端点（服务发现面）
    headless = []
    for svc in services:
        spec = svc.get("spec", {}) or {}
        if spec.get("clusterIP") == "None":
            ports = [p.get("port") for p in spec.get("ports", []) or []]
            headless.append({"service": svc.get("metadata", {}).get("name", "?"),
                             "ports": ports})
            if 29500 in ports:
                fps["rendezvous-discoverable"] = True

    for fw in frameworks:
        fps[fw] = True

    if nccl_baseline or bootstrap:
        fps["tcpstore-unauth"] = bool(bootstrap)
        fps["collective-join-feasible"] = True
        fps_high = {k: True for k in ("nccl", "tcpstore-unauth", "collective-join-feasible") if fps.get(k)}
        fps_high.update({fw: True for fw in frameworks})
        findings.append(_finding(
            "high", "集合通信 bootstrap 无认证（rank 可入组）",
            "NCCL/Gloo/c10d 的 TCPStore/rendezvous 无认证：任意可达端点均可加入通信组"
            "（梯度/权重注入与窃听面，spec 5.6 集合通信层）。\n"
            f"框架：{sorted(frameworks)}\n"
            f"NCCL 基线：{json.dumps(nccl_baseline, ensure_ascii=False)}\n"
            f"bootstrap 端点：{json.dumps(bootstrap, ensure_ascii=False)}\n"
            f"headless 服务：{json.dumps(headless, ensure_ascii=False)}",
            fps_high,
            combo=("areal-sglang-nccl-rdma-flatnet", "nccl-collective-join")))

    if kv_channels:
        cleartext = [c for c in kv_channels if not c["tls"]]
        fps_kv = {"nixl-rdma": fps.get("nixl-rdma", False), "kv-cleartext": bool(cleartext),
                  "mooncake-kv": fps.get("mooncake-kv", False),
                  "nvshmem": fps.get("nvshmem", False), "deepep": fps.get("deepep", False)}
        fps_kv.update({fw: True for fw in frameworks})
        findings.append(_finding(
            "medium", "KV/共享内存传输通道明文过网（NIXL/Mooncake/NVSHMEM/DeepEP）",
            f"通道清单：{json.dumps(kv_channels, ensure_ascii=False)}；其中明文（TLS 关闭）{len(cleartext)} 条。"
            "预填充-解码分离架构下 KV cache 经 RDMA 明文传输且 rendezvous 无认证 → "
            "通道注入/篡改/窃听可操纵推理输出（spec 5.6 + 6.3 预填充-解码 KV 通道链）。",
            fps_kv,
            combo=("pd-split-nixl-rdma-kv-channel",)))

    if not findings:
        findings.append(_finding(
            "info", "未发现集合通信端点",
            "快照内未发现 NCCL/TCPStore/rendezvous/KV 通道线索。", {"collective-join-feasible": False}))

    artifacts = _artifact(ctx, "collective-surface.json", {
        "nccl_baseline": nccl_baseline, "bootstrap": bootstrap,
        "headless": headless, "kv_channels": kv_channels,
        "frameworks": sorted(frameworks), "fingerprints": fps,
    })
    return {
        "summary": f"集合通信面：NCCL Pod {len(nccl_baseline)}，bootstrap 端点 {len(bootstrap)}，"
                   f"KV 通道 {len(kv_channels)}，框架 {sorted(frameworks)}",
        "artifacts": artifacts,
        "findings": findings,
    }
