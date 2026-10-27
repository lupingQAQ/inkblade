# -*- coding: utf-8 -*-
"""In-cluster controller used by tests/reverse_defense_lab.py.

Runs inside the QEMU k3s lab as an unprivileged Pod.  The low-privilege probe
Pod dials this Pod's port over cluster networking, so the experiment exercises
real Pod egress, container DNS/SNI, TLS, and the same framed protocol.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, "/tmp/pkg")

from inkblade.reverse import (  # noqa: E402
    ReverseListener,
    deploy_reverse_child,
)


def main() -> int:
    transport = sys.argv[1] if len(sys.argv) > 1 else "tls"
    controller_host = sys.argv[2] if len(sys.argv) > 2 else "10.42.0.1"
    token = Path("/tmp/token").read_text(encoding="utf-8").strip()
    material = {
        "ca_file": "/tmp/tls/ca.pem",
        "cert_file": "/tmp/tls/server.pem",
        "key_file": "/tmp/tls/server-key.pem",
        "pin": Path("/tmp/tls/server.sha256").read_text(encoding="utf-8").strip(),
        "hosts": ["reverse-controller", "127.0.0.1", "localhost"],
    }
    listener = ReverseListener(
        token, bind="0.0.0.0", port=9443, timeout=60,
        home=None, workspace="defense", transport=transport,
        tls_material=material, ping_interval=10, idle_timeout=60,
        control=False,
    ).start()
    print(f"READY {transport} {listener.port}", flush=True)
    entry = {"transport": transport, "connected": False, "collect": False,
             "exec": False, "child_parent_id": None, "error": None}
    try:
        record = listener.wait_for_probe(timeout=120, probe_id="pod-parent")
        entry["connected"] = True
        entry["remote"] = record.get("remote")
        entry["read_only"] = record.get("read_only")
        entry["caps"] = record.get("caps")
        snapshot = listener.collect("pod-parent")
        entry["collect"] = snapshot.get("probe_id") == "pod-parent"
        executed = listener.perform_exec(
            "pod-parent",
            ["python3", "-c", "print('INKBLADE-BENIGN:reverse-exec')"],
            timeout=20,
        )
        entry["exec"] = "INKBLADE-BENIGN:reverse-exec" in executed.get("stdout", "")
        child = deploy_reverse_child(
            listener.connection("pod-parent"), b"fake-child-binary",
            child_id="pod-child", host=controller_host,
            port=9443, transport=transport, sni="reverse-controller",
            ca_file="/tmp/ca.pem", pin=material["pin"],
            remote_dirs=["/tmp", "/dev/shm"], timeout=30,
        )
        entry["child_upload"] = child.get("uploaded_path")
        child_record = listener.wait_for_probe(timeout=60, probe_id="pod-child")
        entry["child_parent_id"] = child_record.get("parent_id")
    except Exception as exc:  # noqa: BLE001 - report the experiment failure
        entry["error"] = str(exc)
    finally:
        listener.stop()
    print("RESULT:" + json.dumps(entry, ensure_ascii=False), flush=True)
    return 0 if entry.get("connected") and entry.get("collect") else 1


if __name__ == "__main__":
    raise SystemExit(main())
