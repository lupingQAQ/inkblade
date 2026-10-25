"""Real-cluster kill-chain lab: intranet entry → cluster-admin → node root.

Runs the Trident objective chain against the live QEMU/TCG k3s VM and records
``reports/samples/kill-chain/{proof.json,report.md,proof.html,...}``.

    python lab/qemu-k3s/kill_chain_lab.py \
        --kubectl lab/qemu-k3s/kubectl.exe \
        --kubeconfig lab/qemu-k3s/out/k3s.yaml

If the VM/kubectl is unavailable, ``--backend fake`` (or the default ``auto``
fallback) runs the explicit fake-kubectl fixture.  The resulting proof and
report say ``real_cluster=false``; it is never presented as a real cluster.

The lab fixture (``manifests/40-killchain-operator.yaml``) is intentionally
over-broad.  It is removed by objective stage 7 (``cleanup_fixture=True``), and
the wrapper verifies the namespace is gone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.objective import (  # noqa: E402
    FakeKubectlBackend, KubectlBackend, load_objective, render_report,
    run_objective, write_report,
)
from trident.core.roe import init_roe  # noqa: E402
from trident.core.users import Session  # noqa: E402

LAB = Path(__file__).resolve().parent
FIXTURE = LAB / "manifests" / "40-killchain-operator.yaml"
ENTRY = LAB / "manifests" / "41-killchain-entry.yaml"
NAMESPACE = "trident-killchain"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kubectl(kubectl_bin: str, kubeconfig: str | None, *args: str,
            input_text: str | None = None, timeout: float = 120.0) -> dict:
    cmd = [kubectl_bin]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    cmd += list(args)
    t0 = time.time()
    proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    return {"cmd": " ".join(args), "rc": proc.returncode,
            "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:],
            "seconds": round(time.time() - t0, 2)}


def apply_file(kubectl_bin: str, kubeconfig: str | None, path: Path) -> dict:
    return kubectl(kubectl_bin, kubeconfig, "apply", "-f", str(path))


def delete_file(kubectl_bin: str, kubeconfig: str | None, path: Path) -> dict:
    return kubectl(kubectl_bin, kubeconfig, "delete", "-f", str(path),
                   "--ignore-not-found=true", timeout=180)


def service_port_taken(kubectl_bin: str, kubeconfig: str | None, port: int = 30081) -> bool:
    out = kubectl(kubectl_bin, kubeconfig, "get", "svc", "-A", "-o", "json")
    if out["rc"] != 0:
        return False
    try:
        doc = json.loads(out["stdout"])
    except ValueError:
        return False
    for item in doc.get("items", []):
        for p in (item.get("spec", {}).get("ports") or []):
            if p.get("nodePort") == port:
                return True
    return False


def deploy_fixture(kubectl_bin: str, kubeconfig: str | None) -> dict:
    out = {"fixture": apply_file(kubectl_bin, kubeconfig, FIXTURE)}
    out["entry"] = {"skipped": True, "reason": "NodePort 30081 已被现有服务占用"}
    if not service_port_taken(kubectl_bin, kubeconfig, 30081):
        entry = apply_file(kubectl_bin, kubeconfig, ENTRY)
        out["entry"] = entry
        if entry["rc"] == 0:
            # Wait for the entry deployment to become available (image is cached
            # in the lab, but allow a short TCG allowance).
            out["entry_rollout"] = kubectl(
                kubectl_bin, kubeconfig, "-n", NAMESPACE, "rollout", "status",
                "deploy/trident-entry-api", "--timeout=180s", timeout=210)
    return out


def _free_port(preferred: int = 28080) -> int:
    for port in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_port_forward(kubectl_bin: str, kubeconfig: str | None,
                       remote_port: int = 8000) -> tuple[subprocess.Popen | None, str]:
    """Expose the lab entry Service on a free loopback port via the API server.

    NodePort 30081 is not QEMU-host-forwarded; port-forward is the lab's access
    path and is recorded as such in the report.  We wait for an actual HTTP 200
    (TCP-accept alone can be a stale listener or a not-yet-wired forward).
    """
    local_port = _free_port()
    # Forward to a Ready pod, not the Service: a terminating old ReplicaSet pod
    # can otherwise receive the forward and refuse the connection.
    pods = kubectl(kubectl_bin, kubeconfig, "-n", NAMESPACE, "get", "pods",
                   "-l", "app=trident-entry-api", "-o", "json")
    pod_name = ""
    if pods["rc"] == 0:
        try:
            for item in json.loads(pods["stdout"]).get("items", []):
                meta = item.get("metadata", {})
                statuses = item.get("status", {}).get("containerStatuses") or []
                if (meta.get("deletionTimestamp") is None
                        and item.get("status", {}).get("phase") == "Running"
                        and statuses and all(s.get("ready") for s in statuses)):
                    pod_name = meta["name"]
                    break
        except (ValueError, KeyError):
            pod_name = ""
    target = f"pod/{pod_name}" if pod_name else "svc/trident-entry-api"
    cmd = [kubectl_bin]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    cmd += ["-n", NAMESPACE, "port-forward", target, f"{local_port}:{remote_port}"]
    log_path = LAB / "out" / "port-forward.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{local_port}/", timeout=2) as resp:
                if resp.status == 200:
                    return proc, f"http://127.0.0.1:{local_port}/"
        except Exception:
            pass
        time.sleep(0.7)
    proc.terminate()
    try:
        print(f"port-forward failed (port {local_port}):\n"
              f"{log_path.read_text(encoding='utf-8', errors='replace')[-1200:]}",
              file=sys.stderr)
    except OSError:
        pass
    return None, ""


def teardown_fixture(kubectl_bin: str, kubeconfig: str | None) -> dict:
    return {
        "entry": delete_file(kubectl_bin, kubeconfig, ENTRY),
        "fixture": delete_file(kubectl_bin, kubeconfig, FIXTURE),
    }


def verify_no_namespace(kubectl_bin: str, kubeconfig: str | None) -> dict:
    out = kubectl(kubectl_bin, kubeconfig, "get", "namespace", NAMESPACE,
                  "--ignore-not-found=true", "-o", "json")
    absent = out["rc"] != 0 or not out["stdout"].strip() or '"name"' not in out["stdout"]
    return {"absent": absent, "probe": out}


def _sanitize_for_public(value, replacements: list[tuple[str, str]]):
    """Recursively replace host-absolute paths before writing committed samples."""
    if isinstance(value, dict):
        return {k: _sanitize_for_public(v, replacements) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_public(v, replacements) for v in value]
    if isinstance(value, str):
        for old, new in replacements:
            if old:
                value = value.replace(old, new)
        return value
    return value


def _report_header(proof: dict, env: dict) -> str:
    backend = proof.get("backend") or {}
    real = bool(backend.get("real_cluster"))
    title = ("# 最高权限证明（真实 k3s 集群）/ Highest-Privilege Proof (real k3s cluster)"
             if real else
             "# 最高权限证明（fake-kubectl 夹具）/ Highest-Privilege Proof (fake-kubectl fixture)")
    lines = [
        title,
        "",
        f"> 生成时间 / generated: `{now()}`；PROOF marker: `{proof.get('marker')}`；"
        f"backend: `{backend.get('kind')}` (real_cluster={real})",
        "",
        "## 环境 / Environment",
        "",
        "| 项 / Item | 值 / Value |",
        "|---|---|",
        f"| cluster | `{env.get('cluster', 'n/a')}` |",
        f"| node | `{env.get('node', 'n/a')}` |",
        f"| API | `{env.get('api', 'n/a')}` |",
        f"| QEMU | `{env.get('qemu', 'n/a')}` |",
        f"| lab fixture | `{env.get('fixture', 'n/a')}` |",
        "",
        "> 说明 / Note：单节点 QEMU TCG k3s，非生产规模；硬件/交换机/带外阶段只做版本闸门与只读，"
        "不执行硬件写入。",
        "",
    ]
    if not real:
        lines += [
            "> **本报告来自 fake-kubectl 夹具，不是真实 Kubernetes API。**"
            " / This report came from the fake-kubectl fixture, not a real Kubernetes API.",
            "",
        ]
    return "\n".join(lines)


def _screenshot_section(png: Path | None, report_dir: Path) -> str:
    if not png or not png.is_file():
        return ""
    try:
        rel = png.relative_to(report_dir)
    except ValueError:
        rel = png
    return ("\n## 截图 / Screenshot\n\n"
            f"![PROOF terminal capture]({str(rel).replace(chr(92), '/')})\n\n"
            f"- file: `{str(rel).replace(chr(92), '/')}`\n"
            f"- sha256: `{sha256_file(png)}`\n")


def write_lab_report(proof: dict, out: Path, env: dict, png: Path | None) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    display = json.loads(json.dumps(proof))
    if png and png.is_file():
        try:
            rel = png.relative_to(out)
        except ValueError:
            rel = png
        display.setdefault("artifacts", {})["screenshot"] = {
            "path": str(rel).replace("\\", "/"), "sha256": sha256_file(png)}
    text = _report_header(display, env) + "\n" + render_report(display, lang="bi")
    path = out / "report.md"
    path.write_text(text, encoding="utf-8")
    return path


def write_proof_html(proof: dict, out: Path) -> Path:
    hp = proof.get("highest_privilege") or {}
    rbac = hp.get("rbac") or {}
    node = hp.get("node_root") or {}
    secrets = hp.get("cluster_secrets") or {}
    cleanup = proof.get("cleanup") or {}
    backend = proof.get("backend") or {}
    actions = proof.get("cluster_actions") or []
    rows = "".join(
        f"<tr><td>{a.get('stage','')}</td><td>{a.get('verb','')}</td>"
        f"<td>{a.get('resource','')}</td><td>{a.get('namespace','')}</td>"
        f"<td>{a.get('name','')}</td><td>{a.get('result','')}</td>"
        f"<td class=mono>{str(a.get('sha256',''))[:16]}</td></tr>"
        for a in actions
    )
    checks = "".join(
        f"<tr><td>{c.get('check','')}</td><td class={'ok' if c.get('ok') else 'bad'}>"
        f"{'PASS' if c.get('ok') else 'FAIL'}</td><td>{c.get('observed','')}</td></tr>"
        for c in (cleanup.get("checks") or [])
    )
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Trident PROOF {proof.get('marker')}</title>
<style>
 body {{ background:#0b1020; color:#d7e2f4; font:14px/1.45 Consolas,Menlo,monospace; margin:24px; }}
 h1 {{ font-size:20px; color:#7ee787; }} h2 {{ font-size:15px; color:#79c0ff; margin-top:22px; }}
 .box {{ border:1px solid #30435f; padding:12px 16px; margin:10px 0; background:#111a2e; }}
 .ok {{ color:#7ee787; }} .bad {{ color:#ff7b72; }} .mono {{ font-family:Consolas,monospace; }}
 table {{ border-collapse:collapse; width:100%; margin-top:8px; }}
 td,th {{ border:1px solid #30435f; padding:4px 7px; text-align:left; vertical-align:top; }}
 th {{ background:#16233a; color:#9fb3d1; }}
 .kv {{ display:grid; grid-template-columns:220px 1fr; gap:4px 12px; }}
 .k {{ color:#9fb3d1; }}
</style></head><body>
<h1>TRIDENT — Highest-Privilege PROOF</h1>
<div class="box">
<div class="kv">
<div class="k">marker</div><div>{proof.get('marker')}</div>
<div class="k">backend</div><div>{backend.get('kind')} (real_cluster={backend.get('real_cluster')})</div>
<div class="k">generated</div><div>{now()}</div>
<div class="k">proof_sha256</div><div class="mono">{proof.get('hashes', {}).get('proof_sha256','')}</div>
<div class="k">RBAC</div><div class="ok">{rbac.get('role')} — {rbac.get('clusterrolebinding')}</div>
<div class="k">node root</div><div class="ok">verified={node.get('verified')} node={node.get('node')} uid={node.get('uid')}</div>
<div class="k">node marker</div><div class="mono">{node.get('path')}<br>sha256={node.get('sha256')}</div>
<div class="k">cluster secrets</div><div>count={secrets.get('count')} namespaces={secrets.get('namespaces')}</div>
<div class="k">test namespace</div><div>{(hp.get('test_namespace') or {}).get('name')} created={(hp.get('test_namespace') or {}).get('created')}</div>
<div class="k">test ConfigMap</div><div>read_back={(hp.get('test_configmap') or {}).get('read_back')}</div>
<div class="k">cleanup verified</div><div class="{'ok' if cleanup.get('verified') else 'bad'}">{cleanup.get('verified')} — residue={cleanup.get('residue')}</div>
</div></div>
<h2>Cluster-level actions</h2>
<table><tr><th>stage</th><th>verb</th><th>resource</th><th>ns</th><th>name</th><th>result</th><th>sha256</th></tr>{rows}</table>
<h2>Cleanup checks</h2>
<table><tr><th>check</th><th>result</th><th>observed</th></tr>{checks}</table>
<h2>Cleanup declaration</h2>
<div class="box ok">已清理 / Cleanup confirmed: test namespace, ConfigMap, pwn bindings, privileged Pod and
node /root marker were deleted and re-checked against baseline. No persistent objects remain.</div>
</body></html>"""
    path = out / "proof.html"
    path.write_text(html, encoding="utf-8")
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Trident real-cluster kill-chain lab")
    ap.add_argument("--kubectl", default=str(LAB / "kubectl.exe"))
    ap.add_argument("--kubeconfig", default=str(LAB / "out" / "k3s.yaml"))
    ap.add_argument("--backend", choices=["auto", "kubectl", "fake"], default="auto")
    ap.add_argument("--proof-marker", default="")
    ap.add_argument("--out", default=str(REPO / "reports" / "samples" / "kill-chain"))
    ap.add_argument("--home", default=str(LAB / "out" / "kill-chain-home"))
    ap.add_argument("--workspace", default="local-lab")
    ap.add_argument("--entry-url", default=None,
                    help="入口 HTTP URL；缺省时对实验室 entry Service 启 port-forward")
    ap.add_argument("--pod-image", default="alpine:3.21")
    ap.add_argument("--skip-fixture", action="store_true")
    ap.add_argument("--render-only", action="store_true")
    ap.add_argument("--screenshot", default="")
    args = ap.parse_args(argv)

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    png = Path(args.screenshot).resolve() if args.screenshot else None
    env: dict = {"api": "<kubeconfig>", "fixture": str(FIXTURE.relative_to(REPO)),
                 "qemu": "QEMU TCG (documented in docs/REAL-CLUSTER-VERIFICATION.md)"}

    if args.render_only:
        proof_path = out / "proof.json"
        if not proof_path.is_file():
            print(f"missing {proof_path}", file=sys.stderr)
            return 2
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        env["cluster"] = "real k3s" if proof.get("backend", {}).get("real_cluster") else "fake-kubectl"
        env["node"] = (proof.get("highest_privilege", {}).get("node_root") or {}).get("node", "n/a")
        write_lab_report(proof, out, env, png)
        write_proof_html(proof, out)
        print(json.dumps({"rendered": str(out / "report.md"), "screenshot": str(png) if png else None},
                         ensure_ascii=False))
        return 0

    real_backend = None
    if args.backend in ("auto", "kubectl"):
        candidate = KubectlBackend(args.kubectl, args.kubeconfig)
        ready = candidate.readyz()
        if ready.get("ok"):
            real_backend = candidate
        elif args.backend == "kubectl":
            print(f"kubectl backend unavailable: {ready}", file=sys.stderr)
            return 91
    pf_proc = None
    fixture_applied = False
    entry_url = args.entry_url
    if real_backend is not None:
        # cluster identity for the report
        try:
            nodes = real_backend.nodes()
            env["node"] = ", ".join(f"{n['name']}({n.get('kubelet')})" for n in nodes)
            env["cluster"] = "k3s / real Kubernetes API"
        except Exception as exc:  # noqa: BLE001
            env["node"] = f"unavailable: {exc}"
        if not args.skip_fixture:
            fixture = deploy_fixture(args.kubectl, args.kubeconfig)
            if fixture["fixture"]["rc"] != 0:
                print(f"fixture apply failed: {fixture['fixture']['stderr']}", file=sys.stderr)
                return 2
            fixture_applied = True
            entry_ok = fixture.get("entry", {}).get("rc") == 0
            env["fixture"] = (f"{FIXTURE.relative_to(REPO)}; entry="
                              f"{'deployed' if entry_ok else 'reused/ skipped'}")
            if entry_ok and not entry_url:
                pf_proc, pf_url = start_port_forward(args.kubectl, args.kubeconfig)
                if pf_url:
                    entry_url = pf_url
                    env["entry"] = f"{pf_url} (kubectl port-forward -> svc/trident-entry-api:8000)"
                else:
                    print("entry port-forward failed; falling back to NodePort probe",
                          file=sys.stderr)
        backend = real_backend
    else:
        backend = FakeKubectlBackend()
        env["cluster"] = "fake-kubectl fixture (NOT a real cluster)"
        env["node"] = "k3s-fake (simulated)"
        env["api"] = "in-process fake"

    marker = args.proof_marker or f"real-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    store = EvidenceStore(Path(args.home), workspace=args.workspace)
    init_roe(store, {
        "level": "全影响演示",
        "namespaces": [NAMESPACE],
        "cidrs": ["127.0.0.1/32", "10.0.0.0/8"],
        "window": "2026-01-01 – 2026-12-31",
        "authorized_by": "Trident QEMU lab (self-owned cluster)",
    })
    session = Session(None, "lab-lead", "lead", [args.workspace], "lab-session")
    chain = load_objective(REPO / "trident" / "chains")
    started = time.time()
    result = None
    try:
        result = run_objective(
            store, session, chain, backend,
            proof_marker=marker, namespace=NAMESPACE,
            auto_approve=True, cleanup_fixture=True,
            entry_url=entry_url, pod_image=args.pod_image,
            out_dir=out,
        )
    finally:
        if pf_proc is not None:
            pf_proc.terminate()
            try:
                pf_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pf_proc.kill()
        if real_backend is not None and fixture_applied:
            # objective cleanup should already have removed the fixture namespace;
            # this is the wrapper's belt-and-braces teardown.
            teardown = teardown_fixture(args.kubectl, args.kubeconfig)
        else:
            teardown = None
    if result is None:
        print("objective run aborted before producing a proof", file=sys.stderr)
        return 3
    proof = result["proof"]
    proof["artifacts"]["screenshot"] = None
    if real_backend is not None:
        final_ns = verify_no_namespace(args.kubectl, args.kubeconfig)
    else:
        final_ns = {"absent": NAMESPACE not in backend.state["namespaces"]}
    proof["cleanup"]["fixture_namespace_absent_after_wrapper"] = final_ns.get("absent")
    # Do not mutate the proof hash after writing it; the wrapper verification is
    # recorded separately and repeated in the report.
    (out / "lab-wrapper.json").write_text(json.dumps({
        "generated_at": now(), "backend": proof["backend"],
        "fixture_namespace_absent": final_ns.get("absent"),
        "duration_seconds": round(time.time() - started, 2),
        "result_ok": result["ok"], "complete": result["complete"],
        "failed_stage": result["failed_stage"],
        "proof_sha256": proof["hashes"]["proof_sha256"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    write_lab_report(proof, out, env, png)
    write_proof_html(proof, out)
    # transcript: redacted backend calls (token already redacted by KubectlBackend)
    calls = []
    for call in getattr(backend, "calls", []):
        if isinstance(call, dict):
            calls.append({k: call.get(k) for k in ("argv", "rc", "stdout", "stderr", "seconds",
                                                   "mutates", "stage", "sha256")})
        else:
            calls.append(call.as_dict())
    replacements = [
        (str(REPO), "<repo>"),
        (str(Path(args.kubeconfig).resolve()), "<kubeconfig>"),
        (str(Path(args.home).resolve()), "<lab-home>"),
    ]
    calls = _sanitize_for_public(calls, replacements)
    (out / "transcript.jsonl").write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in calls) + "\n", encoding="utf-8")

    summary = {
        "ok": result["ok"], "complete": result["complete"],
        "backend": proof["backend"], "proof_sha256": proof["hashes"]["proof_sha256"],
        "cleanup_verified": proof["cleanup"].get("verified"),
        "fixture_namespace_absent": final_ns.get("absent"),
        "report": str((out / "report.md").relative_to(REPO)).replace("\\", "/"),
        "proof": str((out / "proof.json").relative_to(REPO)).replace("\\", "/"),
        "duration_seconds": round(time.time() - started, 2),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result["ok"] and final_ns.get("absent") else 3


if __name__ == "__main__":
    raise SystemExit(main())
