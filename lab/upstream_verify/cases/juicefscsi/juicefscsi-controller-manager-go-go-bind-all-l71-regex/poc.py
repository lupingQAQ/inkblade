# -*- coding: utf-8 -*-
"""Dynamic proof for juicefs-csi v0.33.1 controller metrics exposure.

Binary provenance: official image
``juicedata/juicefs-csi-driver:v0.33.1``
(``sha256:103ac60b6b9c6de2d2a2ced95afc2b8c092b3a2004670bbfaed1e8e2c8047ceb``),
extracted ``/usr/local/bin/juicefs-csi-driver``; ``--version`` reports
``gitCommit ab62a2106b6993f260b9f4c82f5dba51463e6748`` (pinned tag).

The controller requires in-cluster credentials when it is not in webhook mode,
so the PoC writes a projected service-account token/CA under
``/var/run/secrets/kubernetes.io/serviceaccount``, creates a minimal
``juicefs-csi-node`` DaemonSet (the controller reads its pod template), then
starts the real controller.  The controller-runtime metrics listener binds
``0.0.0.0:8084`` with ``secure=false`` and serves ``/metrics`` to any client;
pprof stays on ``127.0.0.1:6060``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import golab  # noqa: E402
import poclib  # noqa: E402

CASE_ID = "juicefscsi-controller-manager-go-go-bind-all-l71-regex"
PORT = 8084

DAEMONSET = """apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: juicefs-csi-node
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: juicefs-csi-node
  template:
    metadata:
      labels:
        app: juicefs-csi-node
    spec:
      containers:
      - name: juicefs-plugin
        image: juicedata/juicefs-csi-driver:v0.33.1
        command: ["/bin/sh", "-c", "sleep 3600"]
"""


def kill_controller() -> None:
    golab.run("ps | awk '/[j]uicefs-csi-driver/ {print $1}' | xargs -r kill -9 2>/dev/null || true",
              check=False)


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    evidence = poclib.EVIDENCE_DIR
    (evidence / "http").mkdir(parents=True, exist_ok=True)

    def save(name: str, text: str) -> None:
        (evidence / "http" / name).write_text(text, encoding="utf-8")

    payload = {"case": CASE_ID, "method": "dynamic-http", "component": "juicefscsi",
               "version": manifest.get("version"),
               "binary_provenance": "juicedata/juicefs-csi-driver@sha256:103ac60b6b9c6de2d2a2ced95afc2b8c092b3a2004670bbfaed1e8e2c8047ceb"}
    try:
        kill_controller()
        golab.run("kubectl -n kube-system create sa juicefs-lab --dry-run=client -o yaml | "
                  "kubectl apply -f - >/dev/null")
        golab.run("kubectl create clusterrolebinding juicefs-lab --clusterrole=cluster-admin "
                  "--serviceaccount=kube-system:juicefs-lab --dry-run=client -o yaml | "
                  "kubectl apply -f - >/dev/null")
        token = golab.run("kubectl -n kube-system create token juicefs-lab --duration=2h").strip()
        golab.run("mkdir -p /var/run/secrets/kubernetes.io/serviceaccount")
        golab.run("cat > /var/run/secrets/kubernetes.io/serviceaccount/token",
                  stdin=token + "\n")
        golab.run("cp /var/lib/rancher/k3s/server/tls/server-ca.crt "
                  "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        golab.run("printf kube-system > /var/run/secrets/kubernetes.io/serviceaccount/namespace")

        golab.run("kubectl apply -f - >/dev/null", stdin=DAEMONSET)
        golab.run(
            "POD_NAME=juicefs-csi-controller KUBERNETES_SERVICE_HOST=127.0.0.1 "
            "KUBERNETES_SERVICE_PORT=6443 nohup /root/bin/juicefs-csi-driver "
            "--nodeid=k3s --endpoint=unix:///tmp/csi.sock >/root/jfs.log 2>&1 &",
            check=False,
        )
        code = "000"
        for _ in range(40):
            code = golab.run(f"curl -s -o /dev/null -w '%{{http_code}}' "
                             f"http://127.0.0.1:{PORT}/metrics", check=False).strip()
            if code == "200":
                break
            golab.ssh("sleep 1", check=False)
        metrics = golab.run(f"curl -s http://127.0.0.1:{PORT}/metrics", check=False)
        save("metrics.txt", f"status={code}\n" + metrics[:4000])
        poclib.require(code == "200", "unauthenticated /metrics did not return 200", status=code)
        poclib.require("controller_runtime" in metrics or "go_gc_duration_seconds" in metrics,
                       "metrics body does not look like the controller registry")

        listeners = golab.run(f"netstat -lntp 2>/dev/null | grep -E ':{PORT}|:6060' || true")
        save("listeners.txt", listeners)
        poclib.require(f":{PORT}" in listeners, "metrics listener missing", listeners=listeners)
        poclib.require(not any(f"127.0.0.1:{PORT}" in ln for ln in listeners.splitlines()),
                       "metrics listener is loopback-only", listeners=listeners)

        eth0 = golab.run("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1").strip()
        nonloop = golab.run(f"curl -s -o /dev/null -w '%{{http_code}}' http://{eth0}:{PORT}/metrics",
                            check=False).strip()
        save("nonloopback.txt", f"eth0={eth0} status={nonloop}\n")
        poclib.require(nonloop == "200", "non-loopback metrics request failed", status=nonloop)

        pprof = golab.run("curl -s -o /dev/null -w '%{http_code}' "
                          "http://127.0.0.1:6060/debug/pprof/", check=False).strip()
        save("pprof-localhost.txt", f"status={pprof}\n")
        poclib.require(pprof == "200", "pprof did not answer on 6060", status=pprof)
        poclib.require(any("127.0.0.1:6060" in ln for ln in listeners.splitlines()),
                       "pprof is not loopback-bound")

        log = golab.run("tail -n 40 /root/jfs.log", check=False)
        save("jfs.log", log)
        version = golab.run("/root/bin/juicefs-csi-driver --version", check=False)
        save("version.json", version)
        binary_sha = golab.run("sha256sum /root/bin/juicefs-csi-driver | awk '{print $1}'").strip()

        payload.update({
            "http": [
                {"url": f"http://127.0.0.1:{PORT}/metrics", "status": int(code),
                 "authorization": None},
                {"url": f"http://{eth0}:{PORT}/metrics", "status": int(nonloop), "non_loopback": True},
                {"url": "http://127.0.0.1:6060/debug/pprof/", "status": int(pprof), "loopback_only": True},
            ],
            "listeners": listeners.splitlines(),
            "version_output": version,
            "binary_sha256": binary_sha,
            "impact": "The controller-runtime metrics listener is created with BindAddress "
                      "0.0.0.0:8084 and secure=false, so any workload in the cluster network can "
                      "scrape volume/queue metrics without authentication; pprof is loopback-only.",
        })
    finally:
        kill_controller()
        golab.run("kubectl delete daemonset juicefs-csi-node -n kube-system "
                  "--ignore-not-found --wait=false >/dev/null", check=False)
        golab.run("kubectl delete clusterrolebinding juicefs-lab --ignore-not-found >/dev/null",
                  check=False)
        golab.run("kubectl -n kube-system delete sa juicefs-lab --ignore-not-found >/dev/null",
                  check=False)
        golab.run("rm -rf /var/run/secrets/kubernetes.io/serviceaccount", check=False)

    poclib.prove_marker()
    poclib.finish_verified(payload)


if __name__ == "__main__":
    main()
