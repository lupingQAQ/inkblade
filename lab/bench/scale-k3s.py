"""lab/bench/scale-k3s.py — 真实 k3s 集群上的 ~200 对象规模点（QEMU TCG 实验室）。

与合成压测（lab/bench/scale-bench.py）互补：
- 合成快照回答「算法在 1k–10k 对象上的曲线」；
- 本脚本回答「真实 API 采集 + 真实对象形态下，11 个侦察模块的跑批耗时」。
对象全部落在 `scale-lab-*` 命名空间且带 `inkblade.io/scale-lab=true` 标签，采集后可一键清理。

流程：apply 对象清单（12 NS / 60 Pod / 60 Service / 36 NetPol / 12 SA / 12 Role / 12 RoleBinding）
→ kubectl get -o json 归一化成侦察快照（复用 lab/qemu-k3s/collect_snapshot.py 的 normalizer）
→ 11 模块跑批计时（不落库、不写集群）→ JSON 证据（默认 reports/samples/scale/k3s-scale.json）
→ 可选 --cleanup 删除对象。

边界：Pod 只要求「对象存在」，不要求 Ready（TCG 下镜像拉取不可控）；因此本点是**采集/分析规模点**，
不是运行时性能点。真实结论以 kubelet/CNI 实跑为准。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KUBECTL = ROOT / "lab" / "qemu-k3s" / "kubectl.exe"
KUBECONFIG = ROOT / "lab" / "qemu-k3s" / "out" / "k3s.yaml"
COLLECT = ROOT / "lab" / "qemu-k3s" / "collect_snapshot.py"
DEFAULT_OUT = ROOT / "reports" / "samples" / "scale" / "k3s-scale.json"
RECON_MODULES = (
    "cloud-integration-fingerprint", "escape-primitives", "exposure-mapping",
    "framework-port-matching", "metadata-egress", "network-policy-coverage",
    "observability-exposure", "privileged-workloads", "ray-control-plane",
    "rbac-mapping", "storage-sharing",
)
LABEL = "inkblade.io/scale-lab=true"
NS_COUNT = 12
PODS = 60
SERVICES = 60
NETPOLS = 36


def _load(path: Path, name: str):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest() -> str:
    """生成 ~200 个对象的 YAML（Pod 用 pause 镜像，仅为对象存在性，不等待 Ready）。"""
    docs: list[str] = []
    for n in range(NS_COUNT):
        docs.append(f"""apiVersion: v1
kind: Namespace
metadata:
  name: scale-lab-{n:02d}
  labels:
    inkblade.io/scale-lab: "true"
    inkblade-io-zone: {"ml-training" if n % 3 == 0 else "ml-inference"}
""")
        docs.append(f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: scale-sa
  namespace: scale-lab-{n:02d}
  labels:
    inkblade.io/scale-lab: "true"
""")
        docs.append(f"""apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: scale-reader
  namespace: scale-lab-{n:02d}
  labels:
    inkblade.io/scale-lab: "true"
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]
""")
        docs.append(f"""apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: scale-reader
  namespace: scale-lab-{n:02d}
  labels:
    inkblade.io/scale-lab: "true"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: scale-reader
subjects:
- kind: ServiceAccount
  name: scale-sa
  namespace: scale-lab-{n:02d}
""")
    # 36 NetPol：12 个 deny-all（每 3 个 ns 一个）+ 24 个标签选择（覆盖缺口/部分选择混合）
    for i in range(NETPOLS):
        ns = f"scale-lab-{i % NS_COUNT:02d}"
        if i < NS_COUNT:
            spec = "  podSelector: {}\n  policyTypes: [Ingress, Egress]\n  ingress: []\n  egress: []"
            name = "scale-deny-all"
        else:
            spec = ("  podSelector:\n    matchLabels:\n      app: scale-app\n"
                    "  policyTypes: [Ingress]\n  ingress:\n  - from:\n    - ipBlock:\n        cidr: 10.0.0.0/8")
            name = f"scale-partial-{i:02d}"
        docs.append(f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
  namespace: {ns}
  labels:
    inkblade.io/scale-lab: "true"
spec:
{spec}
""")
    for i in range(PODS):
        ns = f"scale-lab-{i % NS_COUNT:02d}"
        docs.append(f"""apiVersion: v1
kind: Pod
metadata:
  name: scale-pod-{i:03d}
  namespace: {ns}
  labels:
    inkblade.io/scale-lab: "true"
    app: scale-app
spec:
  serviceAccountName: scale-sa
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.9
    imagePullPolicy: IfNotPresent
    resources:
      requests:
        cpu: 1m
        memory: 1Mi
""")
    for i in range(SERVICES):
        ns = f"scale-lab-{i % NS_COUNT:02d}"
        port = 8265 if i % 4 == 0 else 30000 if i % 4 == 1 else 9400 if i % 4 == 2 else 9090
        typ = "NodePort" if i % 4 == 0 else "ClusterIP"
        # 固定 nodePort 会冲突：NodePort 让 API 分配
        docs.append(f"""apiVersion: v1
kind: Service
metadata:
  name: scale-svc-{i:03d}
  namespace: {ns}
  labels:
    inkblade.io/scale-lab: "true"
spec:
  type: {typ}
  selector:
    app: scale-app
  ports:
  - name: p{port}
    port: {port}
    targetPort: {port}
""")
    return "---\n".join(docs)


def _kubectl(*args: str, timeout: float = 900.0, stdin: str | None = None) -> subprocess.CompletedProcess:
    cmd = [str(KUBECTL), "--kubeconfig", str(KUBECONFIG), *args]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def _count_objects() -> dict[str, int]:
    def count(kind: str) -> int:
        proc = _kubectl("get", kind, "-n", "scale-lab-00", "--ignore-not-found", "-o", "name", timeout=120)
        return len([line for line in proc.stdout.splitlines() if line.strip()])

    out = {}
    total = 0
    ns = _kubectl("get", "namespaces", "-l", LABEL, "-o", "name", timeout=120)
    out["namespaces"] = len([line for line in ns.stdout.splitlines() if line.strip()])
    total += out["namespaces"]
    for key, args in (("pods", ("pods",)), ("services", ("services",)),
                      ("networkpolicies", ("networkpolicies",)),
                      ("serviceaccounts", ("serviceaccounts",)),
                      ("roles", ("roles",)), ("rolebindings", ("rolebindings",))):
        proc = _kubectl("get", *args, "--all-namespaces", "-l", LABEL, "-o", "name", timeout=300)
        out[key] = len([line for line in proc.stdout.splitlines() if line.strip()])
        total += out[key]
    out["total"] = total
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="real k3s ~200-object scale point")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--cleanup", action="store_true", help="采集后删除 scale-lab-* 对象")
    ap.add_argument("--skip-create", action="store_true", help="复用集群里已有的 scale-lab 对象")
    args = ap.parse_args(argv)

    collect_mod = _load(COLLECT, "collect_snapshot")
    evidence: dict = {"mode": "real-k3s-qemu-tcg", "generated_at": None,
                      "kubeconfig": "lab/qemu-k3s/out/k3s.yaml", "steps": {}}

    if not args.skip_create:
        started = time.perf_counter()
        proc = _kubectl("apply", "-f", "-", stdin=manifest(), timeout=1800)
        evidence["steps"]["apply"] = {
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-1500:],
            "stderr_tail": proc.stderr[-1500:],
        }
        if proc.returncode != 0:
            print(proc.stdout[-2000:], file=sys.stderr)
            print(proc.stderr[-2000:], file=sys.stderr)
            return 1

    evidence["objects"] = _count_objects()

    started = time.perf_counter()
    snapshot = {
        "source": "live-kubectl",
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pods": collect_mod.normalize_pods(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "pods", "--all-namespaces", "-o", "json")),
        "services": collect_mod.normalize_services(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "services", "--all-namespaces", "-o", "json")),
        "networkpolicies": collect_mod.normalize_netpols(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "networkpolicies", "--all-namespaces", "-o", "json")),
        "roles": collect_mod.normalize_roles(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "roles", "--all-namespaces", "-o", "json"), False),
        "rolebindings": collect_mod.normalize_bindings(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "rolebindings", "--all-namespaces", "-o", "json"), False),
        "clusterroles": collect_mod.normalize_roles(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "clusterroles", "-o", "json"), True),
        "clusterrolebindings": collect_mod.normalize_bindings(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "clusterrolebindings", "-o", "json"), True),
        "ingresses": collect_mod.normalize_ingresses(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "ingresses", "--all-namespaces", "-o", "json")),
        "nodes": collect_mod.normalize_nodes(collect_mod._kubectl(
            str(KUBECTL), str(KUBECONFIG), "get", "nodes", "-o", "json")),
        "serviceaccounts": [
            {"namespace": i.get("metadata", {}).get("namespace", "default"),
             "name": i.get("metadata", {}).get("name"), "annotations": i.get("metadata", {}).get("annotations", {})}
            for i in (collect_mod._kubectl(
                str(KUBECTL), str(KUBECONFIG), "get", "serviceaccounts", "--all-namespaces", "-o", "json")
                .get("items") or [])
        ],
        "cani": [],
        "provenance": {"tool": "kubectl", "note": "live cluster, no fixtures merged"},
    }
    evidence["steps"]["collect"] = {"elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                                    "counts": {k: len(v) for k, v in snapshot.items() if isinstance(v, list)}}

    per_module = {}
    total_findings = 0
    started = time.perf_counter()
    for key in RECON_MODULES:
        module = _load(ROOT / "inkblade" / "modules" / key / "run.py", f"k3s_scale_{key.replace('-', '_')}")
        t0 = time.perf_counter()
        result = module.run({}, {"snapshot": snapshot})
        elapsed = (time.perf_counter() - t0) * 1000
        per_module[key] = {"elapsed_ms": round(elapsed, 2), "findings": len(result["findings"])}
        total_findings += len(result["findings"])
    evidence["steps"]["recon"] = {"elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                                 "findings": total_findings, "modules": per_module}
    evidence["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[scale-k3s] objects={evidence['objects']['total']} "
          f"collect={evidence['steps']['collect']['elapsed_ms']}ms "
          f"recon={evidence['steps']['recon']['elapsed_ms']}ms findings={total_findings} -> {out}")

    if args.cleanup:
        proc = _kubectl("delete", "namespaces", "-l", LABEL, "--ignore-not-found", "--timeout=300s", timeout=900)
        evidence["steps"]["cleanup"] = {"returncode": proc.returncode,
                                        "stdout_tail": proc.stdout[-800:],
                                        "stderr_tail": proc.stderr[-800:]}
        out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
