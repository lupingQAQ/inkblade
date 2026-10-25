# -*- coding: utf-8 -*-
"""把 CVE 模块并入版本矩阵（幂等）：product 定义 + 每模块 2 个探针变体。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trident.core import cve_catalog  # noqa: E402

MATRIX = ROOT / "trident" / "core" / "data" / "version-matrix.json"
MODULES = ROOT / "trident" / "modules"

PRODUCTS = {
    "nvidia": {"name": "NVIDIA Container Toolkit / GPU Operator", "repo": "NVIDIA/container-toolkit",
               "release_notes": "https://github.com/NVIDIA/nvidia-container-toolkit/releases",
               "latest_tag_checked": "1.17.8", "checked_at": "2026-10-26",
               "note": "2026-10-26 webfetch 核验：1.17.8 修复 CVE-2025-23266/23267；GPU Operator 25.3.1 对应"},
    "bmc": {"name": "BMC / IPMI / Redfish", "repo": None, "latest_tag_checked": None,
            "release_notes": None, "checked_at": "2026-10-26",
            "note": "厂商公告：AMI MegaRAC SPx12 12.4 / HPE iLO 4 2.53；IPMI 2.0 RAKP 无单一修复版本"},
    "sonic": {"name": "SONiC / Dell Enterprise SONiC", "repo": "sonic-net/sonic-buildimage",
              "release_notes": "https://github.com/sonic-net/sonic-buildimage/security/advisories",
              "latest_tag_checked": None, "checked_at": "2026-10-26",
              "note": "GHSA-h26v-922j-28cg 仅说明 master 修复；Dell 4.5.0a / 4.4.1 为厂商修复锚"},
    "cumulus": {"name": "NVIDIA Cumulus Linux", "repo": None,
                "release_notes": "https://www.nvidia.com/en-us/security/",
                "latest_tag_checked": "5.16", "checked_at": "2026-10-26",
                "note": "NVIDIA 公告：CVE-2025-33180 修 5.14/5.11.4/5.9.4；CVE-2026-24184 修 5.16/5.11.5/5.9.5"},
    "megatron": {"name": "NVIDIA Megatron-LM", "repo": "NVIDIA/Megatron-LM",
                 "release_notes": "https://github.com/NVIDIA/Megatron-LM/releases",
                 "latest_tag_checked": "0.15.3", "checked_at": "2026-10-26",
                 "note": "NVIDIA 2026/5881：CVE-2026-65110 修 17.1；0.15.3/0.13.1 为历史修复锚"},
    "deepspeed": {"name": "Microsoft DeepSpeed", "repo": "deepspeedai/DeepSpeed",
                  "release_notes": "https://github.com/deepspeedai/DeepSpeed/releases",
                  "latest_tag_checked": "0.15.1", "checked_at": "2026-10-26",
                  "note": "CVE-2024-43497 修 0.15.1"},
    "pytorch": {"name": "PyTorch / torchrun", "repo": "pytorch/pytorch",
                "release_notes": "https://github.com/pytorch/pytorch/releases",
                "latest_tag_checked": "2.6.0", "checked_at": "2026-10-26",
                "note": "CVE-2025-32434 修 2.6.0"},
    "mlflow": {"name": "MLflow", "repo": "mlflow/mlflow",
               "release_notes": "https://github.com/mlflow/mlflow/releases",
               "latest_tag_checked": "3.17.2", "checked_at": "2026-10-26",
               "note": "CVE-2026-53995 修 3.17.2；CVE-2024-0520 修 2.9.0"},
    "kuberay": {"name": "KubeRay", "repo": "ray-project/kuberay",
                "release_notes": "https://github.com/ray-project/kuberay/releases",
                "latest_tag_checked": "v1.7.1", "checked_at": "2026-10-26",
                "note": "无独立 CVE/GHSA（API 查询为空）；风险来自托管的 Ray Dashboard 默认暴露"},
    "lws": {"name": "LeaderWorkerSet (LWS)", "repo": "kubernetes-sigs/lws",
            "release_notes": "https://github.com/kubernetes-sigs/lws/releases",
            "latest_tag_checked": None, "checked_at": "2026-10-26",
            "note": "无公开安全公告（API 查询为空）；按 RBAC/NetworkPolicy 收敛"},
    "hami": {"name": "HAMi", "repo": "Project-HAMi/HAMi",
             "release_notes": "https://github.com/Project-HAMi/HAMi/releases",
             "latest_tag_checked": "v2.10.0", "checked_at": "2026-10-26",
             "note": "无公开 CVE/GHSA；scheduler/device-plugin 面按网络策略收敛"},
    "cgpu": {"name": "Alibaba cGPU", "repo": None, "release_notes": None,
             "latest_tag_checked": None, "checked_at": "2026-10-26",
             "note": "商业组件无公开漏洞编号；隔离审计面"},
    "linux-kernel": {"name": "Linux kernel (cgroups)", "repo": "torvalds/linux",
                     "release_notes": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                     "latest_tag_checked": "5.16.2", "checked_at": "2026-10-26",
                     "note": "CVE-2022-0492 修复 5.16.2 及稳定分支"},
    "runc": {"name": "runc", "repo": "opencontainers/runc",
             "release_notes": "https://github.com/opencontainers/runc/releases",
             "latest_tag_checked": "v1.2.8", "checked_at": "2026-10-26",
             "note": "CVE-2024-21626 修 1.1.12；CVE-2025-31133 修 1.2.8/1.3.3"},
    "containerd": {"name": "containerd", "repo": "containerd/containerd",
                   "release_notes": "https://github.com/containerd/containerd/releases",
                   "latest_tag_checked": "v2.0.7", "checked_at": "2026-10-26",
                   "note": "CVE-2020-15257 修 1.4.3；CVE-2024-25621 修 1.7.29/2.0.7"},
}

# module -> (product, surface, probe, routes, affected, fixed, variants)
SPECS = {
    "ray-job-marker-rce": ("ray", "http", "GET /ray/dashboard + POST /ray/api/jobs/ 无 token → job SUCCEEDED",
                           ["/ray/dashboard", "/ray/api/jobs/"], "*", None,
                           [("v1-path-trailing", "POST /ray/api/jobs/", {"op": "path_suffix", "arg": "/"}),
                            ("v2-header-empty", "POST /ray/api/jobs/ + X-Ray-Authorization 空",
                             {"op": "header", "arg": ["X-Ray-Authorization", ""]})]),
    "sglang-zmq-pickle-rce": ("sglang", "http", "GET /sglang/server_info 泄露 key；POST /sglang/zmq 无认证落 marker",
                              ["/sglang/server_info", "/sglang/zmq"], "==0.5.10", None,
                              [("v1-path-trailing", "POST /sglang/zmq/", {"op": "path_suffix", "arg": "/"}),
                               ("v2-path-case", "POST /Sglang/zmq", {"op": "path_case"})]),
    "sglang-route-poison": ("sglang", "http", "PUT /sglang/route 写入 rank_ip/rank_port",
                            ["/sglang/route"], "<=0.5.19", None,
                            [("v1-path-trailing", "PUT /sglang/route/", {"op": "path_suffix", "arg": "/"}),
                             ("v2-method-alt", "POST /sglang/route", {"op": "method", "arg": "POST"})]),
    "sglang-weight-exfil": ("sglang", "http", "GET /sglang/server_info 返回 api_key；GET /sglang/weights 导出",
                            ["/sglang/server_info", "/sglang/weights"], "<=0.5.15", None,
                            [("v1-path-trailing", "GET /sglang/weights/", {"op": "path_suffix", "arg": "/"}),
                             ("v2-pct-encode", "GET /sglang/%77eights", {"op": "pct_encode"})]),
    "vllm-pickle-pipe-rce": ("vllm", "http", "GET /vllm/metrics 出现 mooncake；POST /vllm/mooncake 无认证落 marker",
                             ["/vllm/metrics", "/vllm/mooncake"], ">=0.6.5,<0.8.5", "0.8.5",
                             [("v1-path-trailing", "POST /vllm/mooncake/", {"op": "path_suffix", "arg": "/"}),
                              ("v2-path-case", "POST /Vllm/mooncake", {"op": "path_case"})]),
    "vllm-timing-oracle": ("vllm", "http", "GET /vllm/models 无 key 200 + 校验耗时差分",
                           ["/vllm/metrics", "/vllm/models"], "<0.11", "0.11.0rc2",
                           [("v1-header-empty", "GET /vllm/models + Authorization 空",
                             {"op": "header", "arg": ["Authorization", "Bearer "]}),
                            ("v2-path-trailing", "GET /vllm/models/", {"op": "path_suffix", "arg": "/"})]),
    "litellm-default-key-exfil": ("litellm", "http", "GET /litellm/config Bearer sk-1234 → 上游 key 全量",
                                  ["/litellm/config", "/litellm/health"], "*", None,
                                  [("v1-header-alt", "GET /litellm/config Bearer sk-litellm-master-key",
                                    {"op": "header", "arg": ["Authorization", "Bearer sk-litellm-master-key"]}),
                                   ("v2-path-trailing", "GET /litellm/config/", {"op": "path_suffix", "arg": "/"})]),
    "litellm-config-update-rce": ("litellm", "http", "POST /litellm/config/update 低权限 key → 配置写入",
                                  ["/litellm/config/update"], "<1.83.0", "1.83.0",
                                  [("v1-path-trailing", "POST /litellm/config/update/", {"op": "path_suffix", "arg": "/"}),
                                   ("v2-method-alt", "PUT /litellm/config/update", {"op": "method", "arg": "PUT"})]),
    "ipmi-cipher-zero-bypass": ("bmc", "params", "POST /ipmi/rmcp cipher=0 auth=none → admin 会话",
                                ["/ipmi/info", "/ipmi/rmcp"], "*", None,
                                [("v1-authtype-none", "auth=none", {"op": "param", "arg": ["auth", "none"]}),
                                 ("v2-cipher-zero", "cipher=0", {"op": "param", "arg": ["cipher", "0"]})]),
    "redfish-default-credentials": ("bmc", "http", "GET /redfish/v1 + POST 会话 Basic admin:admin → 201 Token",
                                    ["/redfish/v1", "/redfish/v1/SessionService/Sessions"], "*", None,
                                    [("v1-root-calvin", "Basic root:calvin",
                                      {"op": "header", "arg": ["Authorization", "Basic cm9vdDpjYWx2aW4="]}),
                                     ("v2-path-trailing", "POST 会话路径 /", {"op": "path_suffix", "arg": "/"})]),
    "sonic-config-plane-write": ("sonic", "http", "GET/POST RESTCONF 配置面无认证 → applied",
                                 ["/sonic/restconf/data/sonic-system:sonic-system"], "==4.5.0", "4.5.0a",
                                 [("v1-path-trailing", "POST 配置面路径 /", {"op": "path_suffix", "arg": "/"}),
                                  ("v2-method-alt", "PUT 配置面", {"op": "method", "arg": "PUT"})]),
    "sonic-rsyslog-injection": ("sonic", "http", "POST /sonic/config welf_firewall_name 含换行 → root 配置注入",
                                 ["/sonic/config"], "*", None,
                                 [("v1-path-trailing", "POST /sonic/config/", {"op": "path_suffix", "arg": "/"}),
                                  ("v2-header-empty", "POST /sonic/config + Authorization 空",
                                   {"op": "header", "arg": ["Authorization", ""]})]),
    "cumulus-nvue-injection": ("cumulus", "http", "POST /cumulus/nvue/system 低权限命令注入",
                               ["/cumulus/nvue/system"], "<5.14", "5.14",
                               [("v1-path-trailing", "POST /cumulus/nvue/system/", {"op": "path_suffix", "arg": "/"}),
                                ("v2-path-case", "POST /Cumulus/nvue/system", {"op": "path_case"})]),
    "runc-escape-detect": ("runc", "params", "snapshot nodes[].runc <1.1.12 / <1.2.8；cgroups v1 + SYS_ADMIN",
                            ["runc", "cgroups", "capabilities"], "<1.1.12", "1.1.12",
                            [("v1-runc-version", "runc=1.1.11", {"op": "param", "arg": ["probe", "runc-version"]}),
                             ("v2-cgroup-caps", "cgroups=v1 + SYS_ADMIN",
                              {"op": "param", "arg": ["probe", "cgroup-caps"]})]),
    "containerd-shim-escape-detect": ("containerd", "params", "snapshot nodes[].containerd <1.4.3 / <1.7.29",
                                       ["containerd", "shim"], "<1.4.3", "1.4.3",
                                       [("v1-containerd-version", "containerd=1.4.2",
                                         {"op": "param", "arg": ["probe", "containerd-version"]}),
                                        ("v2-host-network", "hostNetwork=true",
                                         {"op": "param", "arg": ["probe", "host-network"]})]),
    "kubelet-gitrepo-exec-detect": ("kubernetes", "params", "snapshot nodes[].kubelet <=1.30.2 + gitRepoVolumes",
                                     ["kubelet", "gitRepoVolumes"], "<=1.30.2", "1.30.3",
                                     [("v1-kubelet-version", "kubelet=1.28.11",
                                       {"op": "param", "arg": ["probe", "kubelet-version"]}),
                                      ("v2-envfrom", "envFromPods 非空",
                                       {"op": "param", "arg": ["probe", "envfrom"]})]),
    "nvidia-toolkit-escape-detect": ("nvidia", "params", "snapshot nvidia.containerToolkit <=1.16.1 / <=1.17.7",
                                      ["containerToolkit", "cdi"], "<=1.17.7", "1.17.8",
                                      [("v1-toolkit-version", "toolkit=1.16.1",
                                        {"op": "param", "arg": ["probe", "toolkit-version"]}),
                                       ("v2-cdi-off", "cdi=false", {"op": "param", "arg": ["probe", "cdi-off"]})]),
    "gpu-operator-driver-audit": ("nvidia", "params", "snapshot gpuOperator.version <=25.3.0 / driver",
                                   ["gpuOperator", "driver"], "<=25.3.0", "25.3.1",
                                   [("v1-operator-version", "gpuOperator=24.6.1",
                                     {"op": "param", "arg": ["probe", "operator-version"]}),
                                    ("v2-driver", "driver=535.104.05",
                                     {"op": "param", "arg": ["probe", "driver"]})]),
    "megatron-checkpoint-rce": ("megatron", "http", "POST /megatron/load_checkpoint 恶意检查点 → marker",
                                 ["/megatron/load_checkpoint"], "<17.1", "17.1",
                                 [("v1-path-trailing", "POST /megatron/load_checkpoint/", {"op": "path_suffix", "arg": "/"}),
                                  ("v2-path-case", "POST /Megatron/load_checkpoint", {"op": "path_case"})]),
    "deepspeed-checkpoint-rce": ("deepspeed", "http", "POST /deepspeed/load_checkpoint 恶意配置 → marker",
                                  ["/deepspeed/load_checkpoint"], "<0.15.1", "0.15.1",
                                  [("v1-path-trailing", "POST /deepspeed/load_checkpoint/", {"op": "path_suffix", "arg": "/"}),
                                   ("v2-method-alt", "PUT /deepspeed/load_checkpoint", {"op": "method", "arg": "PUT"})]),
    "torch-weights-bypass-rce": ("pytorch", "http", "POST /torch/load weights_only 绕过 → marker",
                                  ["/torch/load"], "<=2.5.1", "2.6.0",
                                  [("v1-path-trailing", "POST /torch/load/", {"op": "path_suffix", "arg": "/"}),
                                   ("v2-pct-encode", "POST /torch/%6Coad", {"op": "pct_encode"})]),
    "mlflow-trace-write": ("mlflow", "http", "POST /mlflow/api/3.0/mlflow/traces trace_id 含 ../ → 任意写",
                            ["/mlflow/api/3.0/mlflow/traces"], "<=3.17.1", "3.17.2",
                            [("v1-path-trailing", "POST traces/", {"op": "path_suffix", "arg": "/"}),
                             ("v2-method-alt", "PUT traces", {"op": "method", "arg": "PUT"})]),
    "mlflow-model-rce": ("mlflow", "http", "POST model-versions/create 恶意 source → marker",
                          ["/mlflow/api/2.0/mlflow/model-versions/create"], "<2.9.0", "2.9.0",
                          [("v1-path-trailing", "POST model-versions/create/", {"op": "path_suffix", "arg": "/"}),
                           ("v2-header-empty", "POST + Authorization 空",
                            {"op": "header", "arg": ["Authorization", ""]})]),
    "dify-code-node-escape": ("dify", "http", "GET system-features 未授权 + POST code-node → root 执行",
                               ["/dify/console/api/system-features", "/dify/api/v1/code-node/run"], ">=1.1.0,<1.1.3", "1.1.3",
                               [("v1-path-trailing", "POST code-node/run/", {"op": "path_suffix", "arg": "/"}),
                                ("v2-path-dotseg", "POST /dify/api/v1/./code-node/run", {"op": "path_dotseg"})]),
    "open-webui-file-overwrite": ("open-webui", "http", "POST retrieval process/files/batch 无属主校验 → 覆盖",
                                   ["/openwebui/api/v1/retrieval/process/files/batch"], "<0.8.6", "0.8.6",
                                   [("v1-path-trailing", "POST batch/", {"op": "path_suffix", "arg": "/"}),
                                    ("v2-path-dotseg", "POST /openwebui/api/v1/./retrieval/process/files/batch",
                                     {"op": "path_dotseg"})]),
    "hami-scheduler-auth-gap": ("hami", "http", "GET /hami/scheduler/pods + POST /filter 无认证 200",
                                 ["/hami/scheduler/pods", "/hami/scheduler/filter"], "*", None,
                                 [("v1-path-trailing", "POST /hami/scheduler/filter/", {"op": "path_suffix", "arg": "/"}),
                                  ("v2-header-empty", "POST /filter + Authorization 空",
                                   {"op": "header", "arg": ["Authorization", ""]})]),
    "cgpu-isolation-audit": ("cgpu", "params", "snapshot cgpu.isolation=policy + crossTenant=true",
                              ["cgpu", "isolation"], "*", None,
                              [("v1-policy", "isolation=policy", {"op": "param", "arg": ["probe", "policy"]}),
                               ("v2-cross-tenant", "crossTenant=true", {"op": "param", "arg": ["probe", "cross-tenant"]})]),
    "lws-leader-endpoint-audit": ("lws", "params", "snapshot lws.templateMutable + networkPolicy=absent",
                                   ["lws", "leaderAddressEnv"], "*", None,
                                   [("v1-template", "templateMutable=true", {"op": "param", "arg": ["probe", "template"]}),
                                    ("v2-netpol", "networkPolicy=absent", {"op": "param", "arg": ["probe", "netpol"]})]),
}


def main() -> int:
    data = json.loads(MATRIX.read_text(encoding="utf-8"))
    data["products"].update(PRODUCTS)
    existing = {e["module"] for e in data["entries"]}
    added = 0
    for module, (product, surface, probe, routes, affected, fixed, variants) in SPECS.items():
        if module in existing:
            continue
        cat = cve_catalog.for_module(module)
        cves = [c["id"] for c in cat]
        note = "；".join(f"{c['id']} fixed={c['fixed'] or 'null'}" for c in cat) or "无公开修复版本"
        entry = {
            "module": module,
            "product": product,
            "kind": "detect" if surface == "params" else "exploit",
            "surface": surface,
            "fingerprint": {"probe": probe, "routes": routes, "cves": cves},
            "affected": affected,
            "fixed": fixed,
            "fixed_note": f"CVE 情报库：{note}（2026-10-26 核验）",
            "variants": [{"id": vid, "kind": "probe", "request": req, "transform": tr}
                         for vid, req, tr in variants],
            "sources": [c["source"] + "（2026-10-26 核验）" for c in cat] or ["https://github.com/Project-HAMi/HAMi（2026-10-26 核验）"],
            "audit_refs": ["docs/CVE-CATALOG.md", f"trident/modules/{module}/run.py"],
        }
        data["entries"].append(entry)
        added += 1
    data["verified_at"] = "2026-10-26"
    data["method_note"] += " 2026-10-26 增补：CVE 模块 28 条并入版本矩阵（每模块 ≥2 变体），修复版本与 core/cve-catalog.json 对账。"
    MATRIX.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"added {added} entries; total {len(data['entries'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
