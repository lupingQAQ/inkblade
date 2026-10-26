"""Real-cluster verification for InkBlade (k3s on QEMU/TCG).

Runs against the live cluster reachable with the supplied kubeconfig and writes
machine-readable evidence to reports/samples/real-cluster/:

  cluster-info.json      kubectl version, nodes, API latency samples
  snapshot.json          recon input built from `kubectl get -o json`
  recon-findings.json    InkBlade recon modules run on that snapshot
  service-probe.json     InkBlade module (real HTTP) against the NodePort Service
  netpol-proof.json      default-deny vs hostNetwork bypass, with curl/wget output

The script never silently "passes": every check records rc/stdout/stderr, and
the summary states exactly what was proven and what was not.

    python lab/qemu-k3s/verify_real_cluster.py \
        --kubectl lab/qemu-k3s/kubectl.exe \
        --kubeconfig lab/qemu-k3s/out/k3s.yaml \
        --out reports/samples/real-cluster
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

MODULES = [
    "exposure-mapping",
    "network-policy-coverage",
    "rbac-mapping",
    "framework-port-matching",
    "escape-primitives",
    "observability-exposure",
]
NAMESPACE = "inkblade-proof"
NODE_PORT = 30080


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class K:
    """Thin kubectl wrapper that records every call for the evidence file."""

    def __init__(self, kubectl: str, kubeconfig: str, log: list[dict]):
        self.kubectl = kubectl
        self.kubeconfig = kubeconfig
        self.log = log

    def run(self, *args: str, timeout: float = 180.0, check: bool = False) -> subprocess.CompletedProcess:
        cmd = [self.kubectl, "--kubeconfig", self.kubeconfig, *args]
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
        elapsed = round(time.time() - t0, 2)
        entry = {"cmd": " ".join(args), "rc": proc.returncode, "seconds": elapsed,
                 "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}
        self.log.append(entry)
        if check and proc.returncode != 0:
            raise RuntimeError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc

    def json(self, *args: str) -> dict:
        return json.loads(self.run(*args, check=True).stdout)

    def exec(self, pod: str, *cmd: str, timeout: float = 90.0) -> subprocess.CompletedProcess:
        return self.run("-n", NAMESPACE, "exec", pod, "--", *cmd, timeout=timeout)


def wait_rollout(k: K, target: str, timeout: float = 900.0) -> dict:
    proc = k.run("-n", NAMESPACE, "rollout", "status", target, f"--timeout={int(timeout)}s",
                 timeout=timeout + 30)
    return {"target": target, "rc": proc.returncode, "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip()}


def cluster_info(k: K) -> dict:
    info: dict = {"collected_at": now()}
    version = k.run("version", "-o", "json")
    info["kubectl_version"] = version.stdout.strip()[:2000]
    info["api_latency_s"] = []
    for _ in range(3):
        t0 = time.time()
        proc = k.run("get", "--raw", "/readyz?verbose", timeout=60)
        info["api_latency_s"].append(round(time.time() - t0, 3))
        info["readyz"] = proc.stdout.strip()[-1500:]
    nodes = k.json("get", "nodes", "-o", "json")
    info["nodes"] = [
        {
            "name": n["metadata"]["name"],
            "kubelet": n["status"]["nodeInfo"].get("kubeletVersion"),
            "os": n["status"]["nodeInfo"].get("osImage"),
            "kernel": n["status"]["nodeInfo"].get("kernelVersion"),
            "containerRuntime": n["status"]["nodeInfo"].get("containerRuntimeVersion"),
            "capacity": n["status"].get("capacity", {}),
            "ready": any(c["type"] == "Ready" and c["status"] == "True"
                         for c in n["status"].get("conditions", [])),
        }
        for n in nodes.get("items", [])
    ]
    info["node_count"] = len(info["nodes"])
    info["all_ready"] = bool(info["nodes"]) and all(n["ready"] for n in info["nodes"])
    kube_system = k.json("get", "pods", "-n", "kube-system", "-o", "json")
    info["kube_system_pods"] = [
        {"name": p["metadata"]["name"], "phase": p["status"].get("phase"),
         "node": p["spec"].get("nodeName"), "restarts": sum(
             c.get("restartCount", 0) for c in p["status"].get("containerStatuses", []))}
        for p in kube_system.get("items", [])
    ]
    return info


def deploy_mock_target(k: K) -> dict:
    out: dict = {}
    nsdoc = k.run("create", "namespace", NAMESPACE, "--dry-run=client", "-o", "yaml")
    nsapply = subprocess.run([k.kubectl, "--kubeconfig", k.kubeconfig, "apply", "-f", "-"],
                             input=nsdoc.stdout, capture_output=True, text=True, encoding="utf-8")
    out["namespace"] = {"rc": nsapply.returncode, "stdout": nsapply.stdout.strip(),
                        "stderr": nsapply.stderr.strip()}
    src = REPO / "lab" / "mock_targets.py"
    cm = k.run("-n", NAMESPACE, "create", "configmap", "mock-targets-src",
               f"--from-file=mock_targets.py={src}", "--dry-run=client", "-o", "yaml")
    apply_cm = subprocess.run([k.kubectl, "--kubeconfig", k.kubeconfig, "apply", "-f", "-"],
                              input=cm.stdout, capture_output=True, text=True, encoding="utf-8")
    out["configmap"] = {"rc": apply_cm.returncode, "stdout": apply_cm.stdout.strip(),
                        "stderr": apply_cm.stderr.strip()}
    manifest = REPO / "lab" / "qemu-k3s" / "manifests" / "20-mock-target.yaml"
    apply = k.run("apply", "-f", str(manifest))
    if apply.returncode != 0:
        raise RuntimeError(f"mock target apply failed: {apply.stderr.strip()}")
    out["deployment"] = apply.stdout.strip()
    out["rollout"] = wait_rollout(k, "deploy/mock-target")
    svc = k.json("-n", NAMESPACE, "get", "svc", "mock-target", "-o", "json")
    out["service"] = {
        "type": svc["spec"].get("type"),
        "clusterIP": svc["spec"].get("clusterIP"),
        "nodePort": svc["spec"]["ports"][0].get("nodePort"),
        "port": svc["spec"]["ports"][0].get("port"),
    }
    pods = k.json("-n", NAMESPACE, "get", "pods", "-l", "app=mock-target", "-o", "json")
    out["pod"] = [{"name": p["metadata"]["name"], "ip": p["status"].get("podIP"),
                   "hostIP": p["status"].get("hostIP"), "phase": p["status"].get("phase")}
                  for p in pods.get("items", [])]
    return out


def window_probe() -> dict:
    """Plain HTTP from Windows to the NodePort (QEMU hostfwd 30080)."""
    import urllib.error
    import urllib.request

    result = {"url": f"http://127.0.0.1:{NODE_PORT}/__routes__", "attempts": []}
    for _ in range(3):
        t0 = time.time()
        try:
            with urllib.request.urlopen(result["url"], timeout=10) as resp:
                body = resp.read().decode("utf-8", "replace")
                result["attempts"].append({"status": resp.status, "seconds": round(time.time() - t0, 2),
                                           "body_head": body[:300]})
        except Exception as exc:  # connection refused / timeout
            result["attempts"].append({"status": 0, "seconds": round(time.time() - t0, 2),
                                       "error": f"{type(exc).__name__}: {exc}"})
    result["ok"] = any(a.get("status") == 200 for a in result["attempts"])
    return result


def run_recon(snapshot: dict, evidence_root: Path, tag: str) -> dict:
    from inkblade.core.evidence import EvidenceStore
    from inkblade.core.roe import LEVELS, init_roe
    from inkblade.core.runner import run_module
    from inkblade.core.users import UserStore

    store = EvidenceStore(evidence_root, workspace="local-lab")
    init_roe(store, fields={
        "level": LEVELS[-1],
        "namespaces": [NAMESPACE, "kube-system", "default"],
        "cidrs": ["127.0.0.0/8", "10.0.0.0/8"],
        "window": f"inkblade qemu tcg lab {tag}",
        "client": "InkBlade maintainers (self-owned lab cluster)",
    })
    users = UserStore(evidence_root / "users.json")
    users.create_user("real-cluster", "x", "tester", ["*"])
    session = users.verify("real-cluster", "x")
    run = store.create_run(f"real-cluster-{tag}")

    modules = []
    for key in MODULES:
        try:
            run_module(store, session, key, {"snapshot": snapshot},
                       modules_dir=REPO / "inkblade" / "modules", run=run)
            modules.append({"key": key, "ok": True})
        except Exception as exc:
            modules.append({"key": key, "ok": False, "error": f"{type(exc).__name__}: {exc}"})

    # result summaries live on the step rows; findings use step_key/severity
    steps = {row[0]: {"summary": row[1], "archive": row[2]} for row in run.query(
        "SELECT step_key, result_summary, archive FROM steps WHERE run=? ORDER BY id", (run.name,))}
    for m in modules:
        m.update(steps.get(m["key"], {}))
    findings = [
        {"module": f["step_key"], "sev": f["severity"], "title": f["title"],
         "detail": f["detail"], "evidence_path": f["evidence_path"],
         "is_zeroday": bool(f["is_zeroday"])}
        for f in run.findings if f["step_key"] in MODULES
    ]
    return {"run": run.name, "run_dir": str(run.dir), "modules": modules,
            "finding_count": len(findings), "findings": findings}


def netpol_proof(k: K, cluster_ip: str, pod_ip: str) -> dict:
    proof: dict = {"collected_at": now(), "cluster_ip": cluster_ip, "pod_ip": pod_ip,
                   "probes": []}
    k.run("-n", NAMESPACE, "apply", "-f", str(REPO / "lab" / "qemu-k3s" / "manifests" / "10-default-deny.yaml"))
    k.run("-n", NAMESPACE, "apply", "-f", str(REPO / "lab" / "qemu-k3s" / "manifests" / "30-probe-pods.yaml"))
    for pod in ("proof-normal", "proof-hostnet"):
        wait = k.run("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=600s",
                     timeout=660)
        proof.setdefault("pod_ready", {})[pod] = {"rc": wait.returncode, "stderr": wait.stderr.strip()}

    targets = [("clusterIP", f"http://{cluster_ip}:8000/__routes__"),
               ("podIP", f"http://{pod_ip}:8000/__routes__")]
    for pod in ("proof-normal", "proof-hostnet"):
        for label, url in targets:
            proc = k.exec(pod, "wget", "-q", "-T", "5", "-O", "/dev/null", url, timeout=60)
            proof["probes"].append({
                "pod": pod, "target": label, "url": url, "rc": proc.returncode,
                "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()[-500:],
                "verdict": "connected" if proc.returncode == 0 else "blocked",
            })

    normal = [p for p in proof["probes"] if p["pod"] == "proof-normal"]
    hostnet = [p for p in proof["probes"] if p["pod"] == "proof-hostnet"]
    proof["normal_all_blocked"] = all(p["verdict"] == "blocked" for p in normal)
    proof["hostnet_any_connected"] = any(p["verdict"] == "connected" for p in hostnet)
    if proof["normal_all_blocked"] and proof["hostnet_any_connected"]:
        proof["verdict"] = "bypass-confirmed"
    elif not proof["normal_all_blocked"]:
        proof["verdict"] = "environment-invalid (policy not enforced)"
    else:
        proof["verdict"] = "bypass-not-observed"
    proof["policy"] = k.run("-n", NAMESPACE, "get", "networkpolicy", "default-deny-all", "-o", "yaml").stdout
    return proof


def service_probe_module(tag: str, evidence_root: Path) -> dict:
    """Run a InkBlade HTTP module from Windows against the real NodePort Service."""
    from inkblade.core.evidence import EvidenceStore
    from inkblade.core.roe import LEVELS, init_roe
    from inkblade.core.runner import run_module
    from inkblade.core.users import UserStore

    store = EvidenceStore(evidence_root, workspace="local-lab")
    init_roe(store, fields={
        "level": LEVELS[-1], "namespaces": [NAMESPACE],
        "cidrs": ["127.0.0.0/8"], "window": f"qemu tcg {tag}",
        "client": "InkBlade maintainers (self-owned lab cluster)",
    })
    users = UserStore(evidence_root / "users.json")
    try:
        users.create_user("real-cluster-http", "x", "tester", ["*"])
    except Exception:
        pass
    session = users.verify("real-cluster-http", "x")
    run = store.create_run(f"real-cluster-http-{tag}")
    target = f"http://127.0.0.1:{NODE_PORT}"
    run_module(store, session, "vllm-plugin-auth-bypass", {"target": target, "mode": "probe-only"},
               modules_dir=REPO / "inkblade" / "modules", run=run)
    trace = _trace_from_run(run)
    steps = run.query("SELECT step_key, result_summary FROM steps WHERE run=?", (run.name,))
    summary = next((r[1] for r in steps if r[0] == "vllm-plugin-auth-bypass"), "")
    findings = [{"sev": f["severity"], "title": f["title"], "detail": f["detail"]}
                for f in run.findings]
    return {"target": target, "summary": summary, "trace": trace, "findings": findings}


def _trace_from_run(run) -> dict | None:
    """The module writes traces/ into the run dir, which the evidence store then
    archives into steps/<module>.tar.gz. Read whichever exists."""
    import tarfile

    direct = Path(run.dir) / "traces" / "vllm-plugin-auth-bypass.json"
    if direct.is_file():
        return json.loads(direct.read_text(encoding="utf-8"))
    archive = Path(run.dir) / "steps" / "vllm-plugin-auth-bypass.tar.gz"
    if archive.is_file():
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.name.endswith("vllm-plugin-auth-bypass.json"):
                    return json.load(tar.extractfile(member))
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kubectl", default=str(Path(__file__).parent / "kubectl.exe"))
    ap.add_argument("--kubeconfig", default=str(Path(__file__).parent / "out" / "k3s.yaml"))
    ap.add_argument("--out", default=str(REPO / "reports" / "samples" / "real-cluster"))
    ap.add_argument("--evidence-home", default=str(Path(__file__).parent / "out" / "evidence-home"))
    ap.add_argument("--skip-deploy", action="store_true")
    args = ap.parse_args(argv)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_root = Path(args.evidence_home)
    tag = time.strftime("%Y%m%d-%H%M%S")
    calls: list[dict] = []
    k = K(args.kubectl, args.kubeconfig, calls)
    summary: dict = {"started_at": now(), "tag": tag, "steps": {}}

    info = cluster_info(k)
    (outdir / "cluster-info.json").write_text(json.dumps({**info, "kubectl_calls": calls}, indent=1, ensure_ascii=False), encoding="utf-8")
    summary["steps"]["cluster"] = {"nodes": info["node_count"], "ready": info["all_ready"],
                                   "api_latency_s": info["api_latency_s"]}

    if not args.skip_deploy:
        deploy = deploy_mock_target(k)
        (outdir / "service-deploy.json").write_text(json.dumps({**deploy, "kubectl_calls": calls[-12:]}, indent=1, ensure_ascii=False), encoding="utf-8")
        summary["steps"]["deploy"] = {"clusterIP": deploy["service"]["clusterIP"],
                                      "nodePort": deploy["service"]["nodePort"],
                                      "rollout_rc": deploy["rollout"]["rc"]}

        win = window_probe()
        probe = service_probe_module(tag, evidence_root)
        (outdir / "service-probe.json").write_text(
            json.dumps({"windows_http": win, "inkblade_module": probe}, indent=1, ensure_ascii=False),
            encoding="utf-8")
        summary["steps"]["service_probe"] = {"windows_ok": win["ok"],
                                             "module_summary": probe["summary"][:300]}

        pod_ip = deploy["pod"][0]["ip"] if deploy["pod"] else ""
        proof = netpol_proof(k, deploy["service"]["clusterIP"], pod_ip)
        (outdir / "netpol-proof.json").write_text(json.dumps(proof, indent=1, ensure_ascii=False), encoding="utf-8")
        summary["steps"]["netpol"] = {"verdict": proof["verdict"],
                                      "normal_all_blocked": proof["normal_all_blocked"],
                                      "hostnet_any_connected": proof["hostnet_any_connected"]}

    # final snapshot: after the workload + NetworkPolicy exist, so the recon
    # modules see the same objects the proofs exercised
    from collect_snapshot import main as collect_main  # same directory
    collect_main(["--kubectl", args.kubectl, "--kubeconfig", args.kubeconfig,
                  "--out", str(outdir / "snapshot.json")])
    snapshot = json.loads((outdir / "snapshot.json").read_text(encoding="utf-8"))
    summary["steps"]["snapshot"] = {k2: len(v) for k2, v in snapshot.items() if isinstance(v, list)}

    recon = run_recon(snapshot, evidence_root, tag)
    (outdir / "recon-findings.json").write_text(json.dumps(recon, indent=1, ensure_ascii=False), encoding="utf-8")
    summary["steps"]["recon"] = {"modules": len(recon["modules"]),
                                 "ok": sum(1 for m in recon["modules"] if m["ok"]),
                                 "findings": recon["finding_count"]}

    summary["finished_at"] = now()
    summary["qemu_tcg"] = {
        "note": "pure software emulation (-accel tcg), 4 vCPU / 2048 MB, no KVM/Hyper-V/WSL",
        "implication": "control-plane operations are 5-20x slower than native; see cluster-info.json api_latency_s",
    }
    (outdir / "verification-summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    return 0 if summary["steps"].get("cluster", {}).get("ready") else 2


if __name__ == "__main__":
    raise SystemExit(main())

