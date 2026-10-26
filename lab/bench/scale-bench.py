"""lab/bench/scale-bench.py — 侦察/可达性/规则生成的合成规模压测（100 / 1,000 / 5,000 / 10,000 对象）。

目的（设计基线第 11 节「规模化」）：
    用确定性合成快照（namespaces / pods / services / networkpolicies / rbac / storage）
    对 11 个侦察模块 + CNI 可达性图 + 规则转化引擎跑批，记录每阶段耗时、Python 堆峰值
    （tracemalloc）与进程 RSS，暴露 O(n²) 与超时点。

口径与边界：
- 合成快照只保留模块实际消费的字段（见 `_SNAPSHOT_CONTRACT`），不含任何真实集群数据；
  规模 = namespaces+pods+services+netpol+rbac+storage 的对象总数，逐 scale 精确等于目标值。
- 每个 scale 在**独立子进程**中执行（`--isolate`，默认开启），避免上一轮堆残留污染 RSS 曲线；
  子进程只回传 JSON，父进程汇总成 JSON+Markdown。
- 计时含模块 `run()` 胶水（findings 汇总/排序），与 CLI 单模块执行同路径；不含 webserver。
- 可达性图按「每命名空间指纹 → infer → 合并」测量：核心规则集是固定规模的（≤6 节点/指纹集），
  真实增长项是多租户命名空间数 × 命名空间内对象；文档中不把固定规模规则说成线性扫描。
- 规则生成以该 scale 的全部侦察 findings 为输入（0 漏过校验仍生效）。

命令行（仓库根目录）：
    python lab/bench/scale-bench.py run [--scales 100,1000,5000,10000] [--out-json P] [--out-md P]
    python lab/bench/scale-bench.py one --scale 10000 --json P     # 子进程模式（内部用）

输出：lab/bench/out/scale-bench.json + docs/SCALE-RESULTS.md（--write-doc）
"""
from __future__ import annotations

import argparse
import gc
import importlib.util
import json
import platform
import random
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.bench.bench import MemorySampler  # noqa: E402

MODULES_DIR = REPO_ROOT / "inkblade" / "modules"
CHAINS_DIR = REPO_ROOT / "inkblade" / "chains"
OUT_DIR = Path(__file__).resolve().parent / "out"
DEFAULT_SCALES = (100, 1000, 5000, 10000)

# 侦察 11 模块（_recon-common 消费者）——压测口径固定为这 11 个，新增模块需显式登记。
RECON_MODULES = (
    "cloud-integration-fingerprint",
    "escape-primitives",
    "exposure-mapping",
    "framework-port-matching",
    "metadata-egress",
    "network-policy-coverage",
    "observability-exposure",
    "privileged-workloads",
    "ray-control-plane",
    "rbac-mapping",
    "storage-sharing",
)

# 合成快照契约：模块实际读取的键（docstring 供审计对照，测试断言键集合）。
_SNAPSHOT_CONTRACT = (
    "namespaces", "nodes", "pods", "services", "ingresses", "httproutes",
    "networkpolicies", "clusterroles", "roles", "clusterrolebindings", "rolebindings",
    "cani", "secrets", "serviceaccounts", "storageclasses", "pvcs", "pvs",
    "rayclusters", "rayservices", "rayjobs", "interconnects",
)

# 对象预算权重（除 pods 外全部固定，pods 吸收余量 → 总数精确等于 scale）
_WEIGHTS = {
    "namespaces": 0.02,
    "services": 0.15,
    "networkpolicies": 0.13,
    "roles": 0.06,
    "clusterroles": 0.01,
    "rolebindings": 0.035,
    "clusterrolebindings": 0.005,
    "pvcs": 0.10,
    "pvs": 0.03,
    "storageclasses": 0.002,
    "secrets": 0.06,
    "serviceaccounts": 0.045,
}

GPU_IMAGES = ("vllm/vllm-openai:latest", "lmsysorg/sglang:latest", "rayproject/ray:2.40.0",
              "nvcr.io/nvidia/pytorch:24.10", "openrlhf/openrlhf:latest")
FRAMEWORK_SERVICES = (
    ("sglang-admin", 30000, "LoadBalancer"),
    ("ray-dashboard", 8265, "NodePort"),
    ("vllm-plugin", 8000, "ClusterIP"),
    ("openrlhf-rm", 5000, "LoadBalancer"),
    ("dcgm-exporter", 9400, "NodePort"),
    ("prometheus", 9090, "ClusterIP"),
    ("grafana", 3000, "LoadBalancer"),
    ("mlflow", 5000, "ClusterIP"),
)
PROVIDER_IDS = ("aws:///cn-north-1/i-0abc", "azure:///subscriptions/x/vm", "gce://proj/zone/inst",
                "cn-hangzhou.i-abc", "qcloud://ins-abc", "cce:cn-north-4/node-1")


# ---------------------------------------------------------------- 合成快照

def _counts(scale: int) -> dict[str, int]:
    """按权重切分对象预算；pods 吸收余量，保证六类对象总数 == scale。"""
    counts = {key: max(1, int(round(scale * weight))) for key, weight in _WEIGHTS.items()}
    counts["namespaces"] = max(2, min(counts["namespaces"], 400))
    counts["storageclasses"] = max(1, min(counts["storageclasses"], 8))
    counts["clusterroles"] = max(1, counts["clusterroles"])
    counts["clusterrolebindings"] = max(1, counts["clusterrolebindings"])
    fixed = sum(counts.values())
    if fixed >= scale:
        raise ValueError(f"scale={scale} 太小，固定对象预算已占 {fixed}")
    counts["pods"] = scale - fixed
    return counts


def build_snapshot(scale: int, seed: int = 20261025) -> dict:
    """生成确定性合成快照；对象总数精确等于 scale（见 counts['pods'] 余量规则）。"""
    if scale < 60:
        raise ValueError("scale 至少 60（固定对象预算下限）")
    rnd = random.Random(seed + scale)
    n = _counts(scale)
    ns_total = n["namespaces"]
    namespaces = [f"ml-tenant-{i:04d}" for i in range(ns_total)]
    snap: dict = {key: [] for key in _SNAPSHOT_CONTRACT}

    for i, ns in enumerate(namespaces):
        snap["namespaces"].append({
            "name": ns,
            "labels": {"inkblade-io-zone": ("ml-training" if i % 3 == 0 else
                                           "ml-inference" if i % 3 == 1 else "monitoring"),
                       "tenant": f"t{i % 7}"},
        })

    # ---- nodes（云厂商 providerID 轮转，触发 cloud-integration-fingerprint）
    for i in range(max(3, min(64, scale // 500))):
        snap["nodes"].append({"name": f"node-{i:03d}", "providerID": PROVIDER_IDS[i % len(PROVIDER_IDS)]})

    # ---- pods：三分之一命名空间无策略、三分之一有 deny-all、三分之一仅选择部分 Pod
    for p in range(n["pods"]):
        i = p % ns_total
        ns = namespaces[i]
        j = p // ns_total
        zone = "training" if i % 3 == 0 else ("inference" if i % 3 == 1 else "monitoring")
        name = f"{zone}-pod-{j:05d}"
        image = GPU_IMAGES[j % len(GPU_IMAGES)]
        pod = {
            "namespace": ns,
            "name": name,
            "labels": {"app": f"{zone}-{j % 8}", "tenant": f"t{i % 7}"},
            "serviceAccount": f"sa-{i % max(1, n['serviceaccounts'])}",
            "containers": [{
                "name": "main",
                "image": image,
                "env": ([{"name": "HF_TOKEN"}] if j % 97 == 0 else
                        [{"name": "AWS_ACCESS_KEY_ID"}] if j % 211 == 0 else []),
                "securityContext": (
                    {"privileged": True} if j % 53 == 0 else
                    {"capabilities": {"add": ["SYS_ADMIN"]}} if j % 71 == 0 else
                    {"seccompProfile": "Unconfined"} if j % 89 == 0 else {}),
            }],
            "volumes": [],
        }
        if j % 41 == 0:
            pod["volumes"].append({"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}})
        elif j % 67 == 0:
            pod["volumes"].append({"name": "cache", "hostPath": {"path": "/mnt/hf-cache"}})
        if j % 101 == 0:
            pod["hostNetwork"] = True
        snap["pods"].append(pod)

    # ---- services（含框架核心端口 + 观测面 + Ingress/Gateway 关联）
    svc_ns = namespaces
    for i in range(n["services"]):
        ns = svc_ns[i % len(svc_ns)]
        fw, port, typ = FRAMEWORK_SERVICES[i % len(FRAMEWORK_SERVICES)]
        name = f"{fw}-{i:05d}"
        svc = {"namespace": ns, "name": name, "type": typ,
               "ports": [{"port": port, "targetPort": port,
                          **({"nodePort": 30000 + (i % 2000)} if typ == "NodePort" else {})}]}
        if typ == "LoadBalancer" and i % 4 == 0:
            svc["externalIPs"] = [f"203.0.113.{i % 250}"]
        snap["services"].append(svc)
        if i < max(1, scale // 400):
            snap["ingresses"].append({"namespace": ns, "name": f"ing-{i}", "host": f"{fw}-{i}.example.test",
                                      "service": name, "port": port})
            snap["httproutes"].append({"namespace": ns, "name": f"route-{i}", "hostname": f"{fw}-{i}.gw.test",
                                       "service": name, "port": port,
                                       "inferencePool": {"name": f"pool-{i}",
                                                         "failureMode": "FailOpen" if i % 2 else "FailClose"}})

    # ---- networkpolicies：i%3==0 命名空间完全无策略（覆盖缺口）；i%3==1 空选择器 deny-all；
    #      i%3==2 仅标签选择器（有策略但无 deny-all → medium）
    policy_ns = [idx for idx in range(ns_total) if idx % 3 != 0] or [0]
    for i in range(n["networkpolicies"]):
        ns_idx = policy_ns[i % len(policy_ns)]
        ns = namespaces[ns_idx]
        if ns_idx % 3 == 1:
            snap["networkpolicies"].append({
                "namespace": ns, "name": f"np-deny-{i:05d}", "podSelector": {},
                "policyTypes": ["Ingress", "Egress"], "ingress": [],
            })
        else:
            snap["networkpolicies"].append({
                "namespace": ns, "name": f"np-allowlist-{i:05d}",
                "podSelector": {},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
            })

    # ---- RBAC：通配符角色 / RBAC 扩散 / cluster-admin 绑定 / can-i 矩阵
    for i in range(n["roles"]):
        ns = namespaces[i % len(namespaces)]
        rules = ([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}] if i % 37 == 0 else
                 [{"apiGroups": [""], "resources": ["pods", "secrets"], "verbs": ["get", "list"]},
                  {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles", "rolebindings"],
                   "verbs": ["create"]}] if i % 23 == 0 else
                 [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}])
        snap["roles"].append({"namespace": ns, "name": f"role-{i:05d}", "rules": rules})
    for i in range(n["clusterroles"]):
        snap["clusterroles"].append({
            "name": f"cr-{i:04d}",
            "rules": ([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}] if i % 11 == 0 else
                      [{"apiGroups": [""], "resources": ["nodes", "pods"], "verbs": ["get", "list"]}]),
        })
    for i in range(n["rolebindings"]):
        ns = namespaces[i % len(namespaces)]
        snap["rolebindings"].append({
            "namespace": ns, "name": f"rb-{i:05d}", "role": f"role-{i % max(1, n['roles']):05d}",
            "subjects": [{"kind": "ServiceAccount", "name": f"sa-{i % 32}", "namespace": ns}],
        })
    for i in range(n["clusterrolebindings"]):
        snap["clusterrolebindings"].append({
            "name": f"crb-{i:04d}", "role": "cluster-admin" if i % 9 == 0 else f"cr-{i % max(1, n['clusterroles']):04d}",
            "subjects": [{"kind": "Group", "name": "system:masters" if i % 9 == 0 else "dev-readonly"}],
        })
    for i in range(max(1, scale // 120)):
        snap["cani"].append({"subject": f"sa-{i % 32}",
                             "allowed": (["*"] if i % 17 == 0 else
                                         ["get pods", "create pods"] if i % 7 == 0 else
                                         ["get pods", "pods/exec"] if i % 5 == 0 else ["get pods"])})

    # ---- 存储面：RWX PVC / NFS PV / 共享 provisioner / Secret / SA
    for i in range(n["secrets"]):
        snap["secrets"].append({"namespace": namespaces[i % len(namespaces)], "name": f"secret-{i:05d}"})
    for i in range(n["serviceaccounts"]):
        ns = namespaces[i % len(namespaces)]
        ann = {}
        if i % 13 == 0:
            ann["eks.amazonaws.com/role-arn"] = f"arn:aws:iam::111122223333:role/irsa-{i}"
        elif i % 17 == 0:
            ann["iam.gke.io/gcp-service-account"] = f"gsa-{i}@proj.iam.gserviceaccount.com"
        snap["serviceaccounts"].append({"namespace": ns, "name": f"sa-{i:05d}",
                                        "annotations": ann, "automount": i % 4 != 0})
    for i in range(n["storageclasses"]):
        snap["storageclasses"].append({
            "name": f"sc-{i}", "provisioner": ("nfs.csi.k8s.io" if i % 3 == 0 else
                                               "ebs.csi.aws.com" if i % 3 == 1 else "juicefs.csi.k8s.io"),
        })
    for i in range(n["pvcs"]):
        ns = namespaces[i % len(namespaces)]
        snap["pvcs"].append({"namespace": ns, "name": f"pvc-{i:05d}",
                             "accessModes": ["ReadWriteMany"] if i % 6 == 0 else ["ReadWriteOnce"],
                             "storageClass": f"sc-{i % max(1, n['storageclasses'])}"})
    for i in range(n["pvs"]):
        snap["pvs"].append({"name": f"pv-{i:05d}",
                            "nfs": {"server": f"10.0.{i % 250}.10", "path": f"/export/ckpt-{i}"} if i % 3 == 0 else {},
                            "accessModes": ["ReadWriteMany"]})

    # ---- Ray 控制面
    for i in range(max(1, scale // 150)):
        ns = namespaces[i % len(namespaces)]
        snap["rayclusters"].append({
            "namespace": ns, "name": f"ray-{i:04d}", "headService": f"ray-dashboard-{i:05d}",
            "dashboardPort": 8265, "auth": "none" if i % 3 == 0 else "token",
            "autoscalerSA": f"sa-{i % 32}",
        })
        if i % 4 == 0:
            snap["rayjobs"].append({"namespace": ns, "name": f"job-{i:04d}"})
    snap["interconnects"] = [{"kind": "ExpressRoute", "name": "er-1", "peer": "10.0.0.1"}]
    return snap


def snapshot_object_count(snapshot: dict) -> dict[str, int]:
    """对象计数（六类 + 其余），供报告核对「规模 == 目标值」。"""
    keys = ("namespaces", "pods", "services", "networkpolicies", "roles", "clusterroles",
            "rolebindings", "clusterrolebindings", "pvcs", "pvs", "storageclasses",
            "secrets", "serviceaccounts")
    counts = {key: len(snapshot.get(key) or []) for key in keys}
    counts["total"] = sum(counts.values())
    return counts


# ---------------------------------------------------------------- 模块装载

_MODULE_CACHE: dict[str, object] = {}


def load_module(name: str):
    """按仓库布局装载 inkblade/modules/<name>/run.py（模块非包，用 file location 载入）。"""
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]
    path = MODULES_DIR / name / "run.py"
    spec = importlib.util.spec_from_file_location(f"inkblade_scale_mod_{name.replace('-', '_')}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法装载模块 {name}（{path}）")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MODULE_CACHE[name] = module
    return module


# ---------------------------------------------------------------- 单阶段测量

def _measure(fn, *, memory: bool = True) -> tuple[object, dict]:
    """计时一遍（干净，无 tracemalloc 干扰），可选第二遍只测 Python 堆峰值。

    tracemalloc 会按分配次数放大耗时（实测 ~10×），混在计时里会把「检测器成本」算成
    「算法成本」；因此耗时与堆峰值分两遍采集，口径在文档中写明。
    """
    gc.collect()
    started = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    metrics = {"elapsed_ms": round(elapsed_ms, 2)}
    if memory:
        gc.collect()
        tracemalloc.start()
        fn()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        metrics["py_heap_peak_kb"] = round(peak / 1024, 1)
        metrics["py_heap_end_kb"] = round(current / 1024, 1)
    return result, metrics


def _run_recon_stage(snapshot: dict) -> tuple[list[dict], dict]:
    """11 个侦察模块顺序跑批；返回 (汇总 findings, 阶段指标集合)。"""
    all_findings: list[dict] = []
    stages: dict[str, dict] = {}
    for name in RECON_MODULES:
        module = load_module(name)
        result, metrics = _measure(lambda m=module: m.run({}, {"snapshot": snapshot}))
        findings = result.get("findings") or []
        metrics["findings"] = len(findings)
        metrics["summary_chars"] = len(str(result.get("summary") or ""))
        stages[name] = metrics
        for f in findings:
            item = dict(f)
            item.setdefault("module", name)
            all_findings.append(item)
    return all_findings, stages


def _run_reachability_stage(snapshot: dict) -> tuple[dict, dict]:
    """每命名空间指纹 → core.reachability.infer → 合并图（多租户自然路径）。"""
    from inkblade.core.reachability import infer

    def build():
        pods_by_ns: dict[str, list[dict]] = {}
        for pod in snapshot.get("pods", []):
            pods_by_ns.setdefault(pod.get("namespace", "default"), []).append(pod)
        policies_by_ns: dict[str, list[dict]] = {}
        for policy in snapshot.get("networkpolicies", []):
            policies_by_ns.setdefault(policy.get("namespace", "default"), []).append(policy)
        merged_nodes = 0
        merged_edges = 0
        graphs = 0
        for ns, pods in pods_by_ns.items():
            policies = policies_by_ns.get(ns, [])
            ingress = [p for p in policies if not p.get("podSelector")
                       and "Ingress" in p.get("policyTypes", ["Ingress"])]
            fps = {
                "hostnetwork-pod": any(p.get("hostNetwork") for p in pods),
                "network-policy-coverage": bool(ingress),
                "sriov-attachment": ns.endswith(("0", "5")),
                "ib-attachment": ns.endswith(("0",)),
                "ib-fabric": ns.endswith(("0",)),
                "ib-partition": ns.endswith(("0", "5")),
                "vpc-native-cni": True,
                "security-group-gap": ns.endswith(("1",)),
            }
            g = infer(fps)
            graph_view = g.render_matrix()
            merged_nodes += len(g.nodes)
            merged_edges += sum(len(v) for v in graph_view.values())
            graphs += 1
        return {"graphs": graphs, "nodes": merged_nodes, "edges": merged_edges}

    result, metrics = _measure(build)
    return result, metrics


def _run_rules_stage(findings: list[dict]) -> tuple[dict, dict]:
    from inkblade.rules.generate import generate_all

    out_dir = tempfile.mkdtemp(prefix="inkblade-scale-rules-")
    try:
        pack, metrics = _measure(lambda: generate_all(CHAINS_DIR, findings=findings, out_dir=out_dir))
        result = {"rules": pack.total_rules, "chains": pack.covered_chain_count,
                  "files": len(pack.files)}
    finally:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)
    return result, metrics


def run_scale(scale: int, *, with_rules: bool = True) -> dict:
    """单 scale 跑批：合成快照 → 11 侦察模块 → 可达性图 → 规则生成。"""
    sampler = MemorySampler()
    sampler.start()
    started = time.perf_counter()
    snapshot, build_metrics = _measure(lambda: build_snapshot(scale))
    counts = snapshot_object_count(snapshot)
    findings, recon_stages = _run_recon_stage(snapshot)
    reach, reach_metrics = _run_reachability_stage(snapshot)
    rules_metrics: dict = {}
    rules: dict = {}
    if with_rules:
        rules, rules_metrics = _run_rules_stage(findings)
    total_ms = (time.perf_counter() - started) * 1000.0
    sampler.stop()
    recon_ms = sum(v["elapsed_ms"] for v in recon_stages.values())
    slowest = sorted(recon_stages.items(), key=lambda kv: kv[1]["elapsed_ms"], reverse=True)[:5]
    return {
        "scale": scale,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "objects": counts,
        "stages": {
            "build_snapshot": build_metrics,
            **recon_stages,
            "reachability-graph": reach_metrics,
            **({"rules-generate": rules_metrics} if with_rules else {}),
        },
        "totals": {
            "elapsed_ms": round(total_ms, 2),
            "recon_ms": round(recon_ms, 2),
            "recon_over_60s": recon_ms > 60_000,
            "recon_over_60s_per_10k": (recon_ms / max(1, counts["total"])) * 10_000 > 60_000,
            "findings": len(findings),
            "max_rss_kb": sampler.max_rss_kb,
            "peak_rss_kb": sampler.peak_rss_kb,
            "rss_backend": sampler.backend,
        },
        "reachability": reach,
        "rules": rules,
        "slowest_recon": [{"module": k, **v} for k, v in slowest],
    }


# ---------------------------------------------------------------- 汇总

def _fmt_ms(value: float) -> str:
    return f"{value / 1000:.2f}s" if value >= 1000 else f"{value:.1f}ms"


def render_markdown(results: list[dict], *, clusters: list[dict] | None = None) -> str:
    lines = [
        "# InkBlade 规模压测结果（合成快照）",
        "",
        f"> 生成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}　"
        f"平台：{results[0]['platform'] if results else 'n/a'}　Python：{results[0]['python'] if results else 'n/a'}",
        "> 数据来源：`lab/bench/scale-bench.py`（每 scale 独立子进程）；原始 JSON：`lab/bench/out/scale-bench.json`。",
        "> 边界：合成快照，非真实集群；规模=namespaces+pods+services+netpol+rbac+storage 对象数，逐 scale 精确等于目标值。",
        "",
        "## 总览曲线",
        "",
        "| 对象数 | 侦察 11 模块 | 侦察/万对象 | 可达性图 | 规则生成 | 总耗时 | 峰值 RSS | findings |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        t = r["totals"]
        per10k_s = (t["recon_ms"] / max(1, r["objects"]["total"])) * 10_000 / 1000
        lines.append(
            f"| {r['objects']['total']:,} | {_fmt_ms(t['recon_ms'])} | {per10k_s:.2f}s | "
            f"{_fmt_ms(r['stages']['reachability-graph']['elapsed_ms'])} | "
            f"{_fmt_ms(r['stages'].get('rules-generate', {}).get('elapsed_ms', 0))} | "
            f"{_fmt_ms(t['elapsed_ms'])} | {t['max_rss_kb'] / 1024:.0f}MB | {t['findings']:,} |"
        )

    lines += ["", "## 各模块耗时（ms）", ""]
    header = "| 模块 | " + " | ".join(f"{r['objects']['total']:,}" for r in results) + " |"
    lines += [header, "|---" * (len(results) + 1) + "|"]
    for name in RECON_MODULES:
        cells = []
        for r in results:
            stage = r["stages"].get(name, {})
            cells.append(f"{stage.get('elapsed_ms', 0):.1f}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    for name in ("reachability-graph", "rules-generate"):
        cells = []
        for r in results:
            stage = r["stages"].get(name, {})
            cells.append(f"{stage.get('elapsed_ms', 0):.1f}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")

    lines += ["", "## Python 堆峰值（MB / 阶段）", ""]
    lines += ["| 模块 | " + " | ".join(f"{r['objects']['total']:,}" for r in results) + " |",
              "|---" * (len(results) + 1) + "|"]
    for name in RECON_MODULES:
        cells = [f"{r['stages'].get(name, {}).get('py_heap_peak_kb', 0) / 1024:.1f}" for r in results]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")

    growth = []
    for prev, cur in zip(results, results[1:]):
        prev_n, cur_n = prev["objects"]["total"], cur["objects"]["total"]
        if not prev_n:
            continue
        factor_n = cur_n / prev_n
        factor_t = cur["totals"]["recon_ms"] / max(1e-9, prev["totals"]["recon_ms"])
        growth.append({
            "from": prev_n, "to": cur_n,
            "objects_x": round(factor_n, 2), "time_x": round(factor_t, 2),
            "superlinear": factor_t > factor_n * 1.6,
        })
    lines += ["", "## 增长倍率（侦察耗时 vs 对象数）", "",
              "| 区间 | 对象× | 耗时× | 判定 |", "|---|---:|---:|---|"]
    for g in growth:
        lines.append(f"| {g['from']:,}→{g['to']:,} | {g['objects_x']} | {g['time_x']} | "
                     f"{'超线性' if g['superlinear'] else '近似线性'} |")

    if clusters:
        lines += ["", "## 真实集群规模点（k3s / QEMU TCG）", "",
                  "| 对象数 | 采集 | 侦察 11 模块 | findings | 来源 |", "|---:|---:|---:|---:|---|"]
        for c in clusters:
            lines.append(f"| {c.get('objects', 0):,} | {_fmt_ms(c.get('collect_ms', 0))} | "
                         f"{_fmt_ms(c.get('recon_ms', 0))} | {c.get('findings', 0):,} | {c.get('source', '-')} |")

    lines += [
        "",
        "## 判定口径",
        "",
        "- 阈值：单模块 >60s 或折算 >60s/万对象 即视为瓶颈并修复（见各 scale 的 `recon_over_60s*`）。",
        "- 修复判据：改为索引/流式后，耗时增长倍率 ≤ 对象增长倍率 ×1.6，且同输入 findings 逐条一致。",
        "- 合成快照的 findings 数量本身随 Pod 数线性增长（每 Pod 一条出网/SA 发现），这是检测语义而非缺陷；",
        "  评测算力时看「耗时/对象」与增长倍率，不看 findings 绝对数。",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def _run_isolated(scale: int, with_rules: bool) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        out_path = Path(fh.name)
    cmd = [sys.executable, str(Path(__file__).resolve()), "one",
           "--scale", str(scale), "--json", str(out_path)]
    if not with_rules:
        cmd.append("--no-rules")
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0:
            raise RuntimeError(f"scale={scale} 子进程失败：{proc.stderr[-2000:]}")
        return json.loads(out_path.read_text(encoding="utf-8"))
    finally:
        out_path.unlink(missing_ok=True)


def _force_utf8_stdout() -> None:
    """Windows 控制台默认 cp1252：中文/箭头输出会 UnicodeEncodeError，这里统一改 UTF-8。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = argparse.ArgumentParser(description="InkBlade 合成规模压测（侦察/可达性/规则）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="跑多个 scale 并汇总")
    p_run.add_argument("--scales", default=",".join(str(s) for s in DEFAULT_SCALES))
    p_run.add_argument("--out-json", default=str(OUT_DIR / "scale-bench.json"))
    p_run.add_argument("--out-md", default=None, help="Markdown 输出路径（缺省不写）")
    p_run.add_argument("--no-rules", action="store_true", help="跳过规则生成阶段")
    p_run.add_argument("--in-process", action="store_true", help="不隔离子进程（调试用）")

    p_one = sub.add_parser("one", help="跑单个 scale（子进程模式）")
    p_one.add_argument("--scale", type=int, required=True)
    p_one.add_argument("--json", default=None)
    p_one.add_argument("--no-rules", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd == "one":
        result = run_scale(args.scale, with_rules=not args.no_rules)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.json:
            Path(args.json).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0

    scales = [int(s) for s in args.scales.split(",") if s.strip()]
    results = []
    for scale in scales:
        if args.in_process:
            results.append(run_scale(scale, with_rules=not args.no_rules))
        else:
            results.append(_run_isolated(scale, not args.no_rules))
        last = results[-1]["totals"]
        print(f"[scale {scale:,}] recon={last['recon_ms']:.0f}ms "
              f"total={last['elapsed_ms']:.0f}ms rss={last['max_rss_kb'] / 1024:.0f}MB "
              f"findings={last['findings']:,}", flush=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "scales": results,
    }
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_markdown(results)
    if args.out_md:
        out_md = Path(args.out_md)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(md, encoding="utf-8")
    print(f"JSON -> {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
