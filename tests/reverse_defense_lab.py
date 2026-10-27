# -*- coding: utf-8 -*-
"""Reproducible local defense-lab experiment for the reverse channel.

It runs a low-privilege Kubernetes Pod (non-root, read-only root filesystem,
no hostPath, no privileged, no service-account token) against a local
controller, for each encrypted transport.  Falco and Kyverno are inspected
when the QEMU k3s lab is running; WAF is reported ``not-applicable`` when no
WAF sits in the egress path.  The script never claims a universal bypass.

Usage:
  python tests/reverse_defense_lab.py --live --transport tls
  python tests/reverse_defense_lab.py --live --all
  python tests/reverse_defense_lab.py --out results.json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
KUBECTL = ROOT / "lab" / "qemu-k3s" / "kubectl.exe"
KUBECONFIG = ROOT / "lab" / "qemu-k3s" / "out" / "k3s.yaml"
POD = "reverse-lowpriv"
TOKEN = "reverse-defense-lab-token"

POD_MANIFEST = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": POD, "namespace": "default", "labels": {"app": POD}},
    "spec": {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
            "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [{
            "name": "probe",
            "image": "python:3.12-alpine",
            "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "-c", "import time; time.sleep(3600)"],
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "privileged": False,
                "capabilities": {"drop": ["ALL"]},
            },
            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                          "limits": {"cpu": "200m", "memory": "128Mi"}},
        }],
        "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory",
                                                 "sizeLimit": "64Mi"}}],
    },
}


CONTROLLER = "reverse-controller"
CONTROLLER_MANIFEST = json.loads(json.dumps(POD_MANIFEST))
CONTROLLER_MANIFEST["metadata"]["name"] = CONTROLLER
CONTROLLER_MANIFEST["metadata"]["labels"] = {"app": CONTROLLER}


def kubectl(*args: str, input_bytes: bytes | None = None, timeout: int = 120):
    command = [str(KUBECTL), "--kubeconfig", str(KUBECONFIG), *args]
    return subprocess.run(
        command, input=input_bytes, capture_output=True, timeout=timeout
    )


def ensure_pod() -> dict[str, Any]:
    manifest = json.dumps(POD_MANIFEST).encode("utf-8")
    applied = kubectl("apply", "-f", "-", input_bytes=manifest)
    if applied.returncode != 0:
        raise RuntimeError(f"apply failed: {applied.stderr.decode('utf-8', 'replace')}")
    ready = kubectl("wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=120s")
    if ready.returncode != 0:
        raise RuntimeError(f"pod not ready: {ready.stderr.decode('utf-8', 'replace')}")
    document = kubectl("get", "pod", POD, "-o", "json")
    pod = json.loads(document.stdout.decode("utf-8"))
    security = pod["spec"]["containers"][0].get("securityContext", {})
    return {
        "runAsUser": pod["spec"].get("securityContext", {}).get("runAsUser"),
        "runAsNonRoot": pod["spec"].get("securityContext", {}).get("runAsNonRoot"),
        "readOnlyRootFilesystem": security.get("readOnlyRootFilesystem"),
        "privileged": security.get("privileged"),
        "allowPrivilegeEscalation": security.get("allowPrivilegeEscalation"),
        "automountServiceAccountToken": pod["spec"].get("automountServiceAccountToken"),
        "hostPath": any("hostPath" in volume for volume in pod["spec"].get("volumes", [])),
    }


def push_file(path: Path, remote: str) -> None:
    data = path.read_bytes()
    result = kubectl(
        "-n", "default", "exec", "-i", POD, "--", "sh", "-c", f"cat > {remote}",
        input_bytes=data,
    )
    if result.returncode != 0:
        raise RuntimeError(f"push {remote}: {result.stderr.decode('utf-8', 'replace')}")


def falco_pod() -> str | None:
    result = kubectl("-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/name=falco",
                     "-o", "jsonpath={.items[0].metadata.name}")
    name = result.stdout.decode("utf-8", "replace").strip()
    return name or None


def falco_lines(pod: str, since: str = "2m") -> list[str]:
    if not pod:
        return []
    result = kubectl("-n", "kube-system", "logs", pod, f"--since={since}")
    return [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line]


def waf_pods() -> list[str]:
    result = kubectl("get", "pods", "-A", "-o", "json")
    if result.returncode != 0:
        return []
    document = json.loads(result.stdout.decode("utf-8"))
    names = []
    for pod in document.get("items", []):
        name = pod.get("metadata", {}).get("name", "")
        if any(token in name.lower() for token in ("waf", "modsecurity", "crs", "coraza")):
            names.append(name)
    return names


def classify_transport_falco(lines: list[str], controller_ip: str) -> dict[str, Any]:
    hits = [
        line for line in lines
        if "INKBLADE-BENIGN" not in line and (
            "reverse-lowpriv" in line or controller_ip in line
        )
    ]
    return {"verdict": "detected" if hits else "not-observed",
            "hits": hits[-8:]}


def run_primitive(argv: list[str], marker: str) -> dict[str, Any]:
    result = kubectl("-n", "default", "exec", POD, "--", *argv, timeout=60)
    return {
        "marker": marker,
        "exit_code": result.returncode,
        "stdout": result.stdout.decode("utf-8", "replace")[:500],
        "stderr": result.stderr.decode("utf-8", "replace")[:500],
    }


def classify_falco(lines: list[str], marker: str, *, match_pod: bool = True) -> dict[str, Any]:
    hits = [
        line for line in lines
        if marker in line or (match_pod and POD in line)
    ]
    return {"verdict": "detected" if hits else "not-observed",
            "hits": hits[-8:]}


def ensure_controller() -> str:
    manifest = json.dumps(CONTROLLER_MANIFEST).encode("utf-8")
    applied = kubectl("apply", "-f", "-", input_bytes=manifest)
    if applied.returncode != 0:
        raise RuntimeError(f"controller apply failed: {applied.stderr.decode('utf-8', 'replace')}")
    ready = kubectl("wait", "--for=condition=Ready", f"pod/{CONTROLLER}",
                    "--timeout=120s")
    if ready.returncode != 0:
        raise RuntimeError(f"controller not ready: {ready.stderr.decode('utf-8', 'replace')}")
    result = kubectl("get", "pod", CONTROLLER, "-o", "jsonpath={.status.podIP}")
    address = result.stdout.decode("utf-8", "replace").strip()
    if not address:
        raise RuntimeError("controller Pod has no IP")
    return address


def controller_bundle(material: dict[str, Any], token_file: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for relative, arcname in (
            ("inkblade/__init__.py", "pkg/inkblade/__init__.py"),
            ("inkblade/channel.py", "pkg/inkblade/channel.py"),
            ("inkblade/reverse.py", "pkg/inkblade/reverse.py"),
            ("tests/reverse_controller_incluster.py", "run.py"),
        ):
            archive.add(ROOT / relative, arcname=arcname)
        archive.add(Path(material["ca_file"]), arcname="tls/ca.pem")
        archive.add(Path(material["cert_file"]), arcname="tls/server.pem")
        archive.add(Path(material["key_file"]), arcname="tls/server-key.pem")
        pin_file = Path(material["cert_file"]).parent / "server.sha256"
        archive.add(pin_file, arcname="tls/server.sha256")
        archive.add(token_file, arcname="token")
    return buffer.getvalue()


def push_bundle(data: bytes) -> None:
    result = kubectl("-n", "default", "exec", "-i", CONTROLLER, "--",
                     "tar", "-xf", "-", "-C", "/tmp", input_bytes=data)
    if result.returncode != 0:
        raise RuntimeError(f"controller bundle: {result.stderr.decode('utf-8', 'replace')}")


def run_transport(transport: str, primitives: bool) -> dict[str, Any]:
    from inkblade.reverse import ensure_tls_material

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        material = ensure_tls_material(
            home / "tls", hosts=["reverse-controller", "127.0.0.1", "localhost"]
        )
        token_file = home / "token"
        token_file.write_text(TOKEN, encoding="utf-8")
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass
        controller_ip = ensure_controller()
        push_bundle(controller_bundle(material, token_file))
        push_file(ROOT / "tests" / "fake_reverse_probe.py", "/tmp/fake.py")
        push_file(Path(material["ca_file"]), "/tmp/ca.pem")
        push_file(token_file, "/tmp/token")
        kubectl("-n", "default", "exec", POD, "--", "chmod", "644",
                "/tmp/fake.py", "/tmp/ca.pem", "/tmp/token")
        falco = falco_pod()
        start = time.time()
        entry: dict[str, Any] = {
            "transport": transport, "connected": False, "collect": False,
            "exec": False, "child_parent_id": None, "falco": None,
            "kyverno": None, "waf": None, "controller_ip": controller_ip,
        }
        kubectl("-n", "default", "exec", CONTROLLER, "--", "sh", "-c",
                "pkill -f /tmp/run.py || true")
        controller = subprocess.Popen(
            [str(KUBECTL), "--kubeconfig", str(KUBECONFIG), "-n", "default",
             "exec", CONTROLLER, "--", "python3", "/tmp/run.py",
             transport, controller_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        probe = None
        try:
            time.sleep(1.5)
            probe = subprocess.Popen(
                [str(KUBECTL), "--kubeconfig", str(KUBECONFIG), "-n", "default",
                 "exec", POD, "--", "python3", "/tmp/fake.py",
                 "--host", controller_ip, "--port", "9443",
                 "--transport", transport,
                 "--ca-file", "/tmp/ca.pem", "--pin", material["pin"],
                 "--sni", "reverse-controller", "--token-file", "/tmp/token",
                 "--probe-id", "pod-parent", "--allow-write",
                 "--spawn-child", "--path=/ws"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            stdout, stderr = controller.communicate(timeout=170)
            entry["controller_stdout"] = stdout[-3000:]
            entry["controller_stderr"] = stderr[-1000:]
            result_line = None
            for line in stdout.splitlines():
                if line.startswith("RESULT:"):
                    result_line = line
            if result_line:
                document = json.loads(result_line[len("RESULT:"):])
                entry.update({
                    "connected": document.get("connected", False),
                    "collect": document.get("collect", False),
                    "exec": document.get("exec", False),
                    "child_parent_id": document.get("child_parent_id"),
                    "child_upload": document.get("child_upload"),
                    "remote": document.get("remote"),
                    "read_only": document.get("read_only"),
                    "caps": document.get("caps"),
                    "error": document.get("error"),
                })
            else:
                entry["error"] = "controller did not produce RESULT"
            time.sleep(1.0)
            lines = falco_lines(falco, since="5m")
            entry["falco"] = classify_transport_falco(lines, controller_ip)
            entry["falco"]["transport_hits"] = entry["falco"]["hits"]
            entry["kyverno"] = {
                "verdict": "not-applicable",
                "reason": "admission controller sees the Pod object, not runtime "
                          "reverse traffic or exec inside an admitted Pod",
                "pod_admitted": True,
            }
            entry["waf"] = {
                "verdict": "not-applicable" if not waf_pods() else "not-observed",
                "reason": "controller listener is reached by Pod-to-Pod egress; "
                          "no WAF is in that path",
                "waf_pods": waf_pods(),
            }
            if primitives:
                kubectl("-n", "default", "exec", POD, "--", "sh", "-c",
                        "cat /bin/busybox > /tmp/inkblade-benign && chmod 700 /tmp/inkblade-benign")
                existing = run_primitive(
                    ["python3", "-c",
                     "import os; os.execv('/bin/'+'echo',['echo','INKBLADE-BENIGN:existing'])"],
                    "INKBLADE-BENIGN:existing",
                )
                tmpcopy = run_primitive(
                    ["python3", "-c",
                     "import os; os.execv('/tmp/inkblade-benign',['echo','INKBLADE-BENIGN:tmp'])"],
                    "INKBLADE-BENIGN:tmp",
                )
                memfd = run_primitive(
                    ["python3", "-c",
                     "import os; fd=os.memfd_create('b'); os.write(fd,open('/bin/echo','rb').read()); "
                     "os.set_inheritable(fd,True); os.execve('/proc/self/fd/%d'%fd,['echo','INKBLADE-BENIGN:memfd'],{})"],
                    "INKBLADE-BENIGN:memfd",
                )
                after = falco_lines(falco, since="5m")
                entry["primitives"] = [
                    {**existing, "falco": classify_falco(after, "INKBLADE-BENIGN:existing", match_pod=False)},
                    {**tmpcopy, "falco": classify_falco(after, "INKBLADE-BENIGN:tmp", match_pod=False)},
                    {**memfd, "falco": classify_falco(after, "INKBLADE-BENIGN:memfd", match_pod=False)},
                ]
        finally:
            if probe is not None:
                probe.terminate()
                try:
                    _out, err = probe.communicate(timeout=10)
                    entry["probe_stderr"] = (err or "")[-2000:]
                except subprocess.TimeoutExpired:
                    probe.kill()
            if controller.poll() is None:
                controller.kill()
                try:
                    controller.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            kubectl("-n", "default", "exec", CONTROLLER, "--", "sh", "-c",
                    "pkill -f /tmp/run.py || true")
            entry["duration_s"] = round(time.time() - start, 2)
        return entry


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["tls", "wss", "https"], default="tls")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--live", action="store_true",
                        help="use the QEMU k3s lab (otherwise print limitations)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    result: dict[str, Any] = {
        "schema": "inkblade-reverse-defense-lab-v1",
        "generated_at": time.time(),
        "pod": POD,
        "pod_security": None,
        "transports": [],
        "limitations": [],
    }
    if not args.live:
        result["limitations"].append(
            "local mode: no live Falco/Kyverno/WAF observer; use --live with the QEMU lab"
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if not KUBECTL.is_file() or not KUBECONFIG.is_file():
        result["limitations"].append("QEMU k3s lab or kubeconfig not present")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2
    result["pod_security"] = ensure_pod()
    transports = ["tls", "wss", "https"] if args.all else [args.transport]
    for index, transport in enumerate(transports):
        result["transports"].append(run_transport(transport, primitives=index == 0))
    result["limitations"] += [
        "the Pod-side probe is the stdlib fake probe; Rust binary deployment is "
        "covered by tests/test_probe_reverse_rust.py and is not claimed in this run",
        "the Falco deployment is the lab's 0.45.1 ruleset; absence of an alert is "
        "recorded as not-observed, not as a universal bypass",
        "WAF/ModSecurity was not running in front of the controller egress path",
        "Kyverno is admission-time only and does not inspect runtime reverse traffic",
    ]
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
