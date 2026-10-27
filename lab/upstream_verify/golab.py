# -*- coding: utf-8 -*-
"""Helpers for Go-service cases verified inside the QEMU k3s lab VM.

The VM is the same one documented in ``docs/REAL-CLUSTER-VERIFICATION.md``:
QEMU TCG, Alpine 3.24, k3s, SSH forwarded to 127.0.0.1:2222.  Builds happen
inside the guest (the Windows host blocks unsigned toolchain binaries) with the
pinned Go release and module proxy.  The SSH key is a gitignored lab artifact;
a fresh clone must provision it with ``start-vm.ps1`` before running the case.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY = ROOT / "lab" / "qemu-k3s" / "http" / "id_ed25519"
KNOWN_HOSTS = ROOT / "lab" / "qemu-k3s" / "out" / "known_hosts"
PORT = "2222"
HOST = "root@127.0.0.1"


class LabError(RuntimeError):
    pass


def available() -> bool:
    return KEY.is_file()


def _base() -> list[str]:
    if not KEY.is_file():
        raise LabError(
            f"lab SSH key missing: {KEY}. Provision the QEMU k3s VM first "
            "(lab/qemu-k3s/start-vm.ps1); the key is intentionally gitignored."
        )
    args = ["ssh", "-i", str(KEY), "-p", PORT,
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15"]
    if KNOWN_HOSTS.is_file():
        args += ["-o", f"UserKnownHostsFile={KNOWN_HOSTS}"]
    return args


def ssh(command: str, *, stdin: str | None = None, timeout: int = 300,
        check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [*_base(), HOST, command],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise LabError(f"ssh failed ({proc.returncode}): {command}\n{proc.stderr[-1500:]}")
    return proc


def run(command: str, *, stdin: str | None = None, timeout: int = 300,
        check: bool = True) -> str:
    return ssh(command, stdin=stdin, timeout=timeout, check=check).stdout


def wait_http(url: str, *, expect: str = "200", attempts: int = 40) -> str:
    last = ""
    for _ in range(attempts):
        proc = ssh(f"curl -s -o /dev/null -w '%{{http_code}}' {url}", check=False, timeout=30)
        last = proc.stdout.strip()
        if last == expect:
            return last
        ssh("sleep 1", check=False, timeout=30)
    raise LabError(f"{url} did not return {expect}; last={last!r}")


def binary_hash(path: str = "/root/bin/kueueviz") -> str:
    proc = ssh(f"sha256sum {path} 2>/dev/null | awk '{{print $1}}'", check=False)
    return proc.stdout.strip()
