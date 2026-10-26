"""Helpers for service-level verification cases.

The cases in this module start a *real* upstream daemon (no mocks of the
service), drive it over HTTP with a non-privileged client, and tear it down
again.  Only host plumbing lives here: free-port selection, the LAN address,
a tiny HTTP client and a Ray head-node context manager.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def lan_ip() -> str | None:
    """Return a non-loopback IPv4 address of this host, if one exists."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # UDP connect sends no packet
        addr = sock.getsockname()[0]
        return None if addr.startswith("127.") else addr
    except OSError:
        return None
    finally:
        sock.close()


def http(url: str, *, data=None, method: str | None = None,
         headers: dict | None = None, timeout: float = 20.0) -> dict:
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
    sent = {"Content-Type": "application/json"}
    if headers:
        sent.update(headers)
    request = urllib.request.Request(
        url, data=body, method=method or ("POST" if body is not None else "GET"),
        headers=sent,
    )
    record = {
        "method": request.get_method(),
        "url": url,
        "request_headers": {k: v for k, v in sent.items()},
        "request_body": body.decode("utf-8", "replace") if body else None,
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            record.update(
                status=response.status,
                response=response.read()[:4000].decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        record.update(
            status=exc.code,
            response=exc.read()[:4000].decode("utf-8", "replace"),
        )
    except Exception as exc:  # noqa: BLE001 - evidence keeps the failure
        record.update(status=-1, response=repr(exc))
    return record


def wait_http(url: str, *, timeout: float = 120.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if http(url, timeout=5).get("status") == 200:
            return True
        time.sleep(interval)
    return False


class RayHead:
    """Start/stop a real ``ray start --head`` cluster on the lab host.

    Ray 2.8.0 needs the lab host-compat shim (``sitecustomize.py`` in the
    ``ray280`` interpreter) because this host has no ``nvidia-smi``/``wmic``
    and Ray's job supervisor builds a POSIX-only ``preexec_fn`` on win32.
    """

    def __init__(self, *, dashboard_port: int | None = None,
                 dashboard_host: str = "0.0.0.0", num_cpus: int = 2) -> None:
        self.dashboard_port = dashboard_port or 8265
        self.dashboard_host = dashboard_host
        self.num_cpus = num_cpus
        self.tmp = tempfile.mkdtemp(prefix="inkblade-ray-")
        self.ray_exe = Path(sys.executable).parent / "Scripts" / "ray.exe"
        self.start_log = ""
        self.base_url = ""

    def _env(self) -> dict:
        env = dict(os.environ)
        env.update(
            {
                "RAY_ENABLE_WINDOWS_OR_OSX_CLUSTER": "1",
                "RAY_DISABLE_USAGE_STATS": "1",
                "RAY_USAGE_STATS_ENABLED": "0",
                "RAY_DEDUP_LOGS": "0",
            }
        )
        env.pop("RAY_AUTH_MODE", None)
        env.pop("RAY_AUTH_TOKEN", None)
        return env

    def _cmd(self, *args: str) -> list[str]:
        if self.ray_exe.is_file():
            return [str(self.ray_exe), *args]
        return [sys.executable, "-c",
                "import sys; from ray.scripts.scripts import main; main()", *args]

    def __enter__(self) -> "RayHead":
        cmd = self._cmd(
            "start", "--head", f"--num-cpus={self.num_cpus}",
            "--disable-usage-stats",
            f"--dashboard-host={self.dashboard_host}",
            f"--dashboard-port={self.dashboard_port}",
        )
        proc = subprocess.run(cmd, cwd=self.tmp, env=self._env(), capture_output=True,
                              text=True, timeout=300)
        self.start_log = (proc.stdout or "") + (proc.stderr or "")
        self.base_url = f"http://127.0.0.1:{self.dashboard_port}"
        if not wait_http(self.base_url + "/api/version", timeout=120):
            raise RuntimeError("ray dashboard did not become ready\n" + self.start_log[-2000:])
        return self

    def __exit__(self, *exc_info) -> None:
        try:
            subprocess.run(self._cmd("stop", "--force"), cwd=self.tmp, env=self._env(),
                           capture_output=True, text=True, timeout=120)
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def address(self) -> str:
        """Address a remote client would use (non-loopback when available)."""
        host = lan_ip() or "127.0.0.1"
        return f"http://{host}:{self.dashboard_port}"
