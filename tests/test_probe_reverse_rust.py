# -*- coding: utf-8 -*-
"""Dynamic reverse-channel tests against the compiled Rust probe.

The binary is optional; CI builds the static musl probe.  Windows local builds
(``probe/target/release/inkblade-probe.exe``) are also exercised when present.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from inkblade.reverse import (
    ReverseListener,
    deploy_reverse_child,
    ensure_tls_material,
    reverse_paths,
)

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "rust-reverse-token"


def _binary() -> Path | None:
    candidates = []
    if os.environ.get("INKBLADE_PROBE_BIN"):
        candidates.append(Path(os.environ["INKBLADE_PROBE_BIN"]))
    candidates += [
        ROOT / "probe" / "target" / "release" / "inkblade-probe.exe",
        ROOT / "probe" / "target" / "release" / "inkblade-probe",
        ROOT / "dist" / "inkblade-probe-linux-amd64",
        ROOT / "dist" / "inkblade-probe-linux-arm64",
        ROOT / "probe" / "dist" / "inkblade-probe-linux-amd64",
        ROOT / "probe" / "dist" / "inkblade-probe-linux-arm64",
        ROOT / "probe" / "target" / "debug" / "inkblade-probe.exe",
        ROOT / "probe" / "target" / "debug" / "inkblade-probe",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        if os.name == "nt" and path.read_bytes()[:4] == b"\x7fELF":
            continue
        if os.name != "nt" and path.suffix == ".exe":
            continue
        return path
    return None


BINARY = _binary()


def _shell_argv() -> list[str]:
    if os.name == "nt":
        return ["cmd", "/c", "echo", "rust-reverse-ok"]
    return ["sh", "-c", "echo rust-reverse-ok"]


def _shell_cmd() -> list[str]:
    return ["--allow-cmd", "cmd"] if os.name == "nt" else ["--allow-cmd", "sh"]


@unittest.skipUnless(BINARY is not None, "no runnable Rust probe binary")
class RustReverseDynamic(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.material = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )
        self.procs: list[subprocess.Popen] = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        self.temp.cleanup()

    def _listener(self, transport: str, **kwargs) -> ReverseListener:
        return ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=15,
            home=self.home, workspace="ws", transport=transport,
            tls_material=self.material, ping_interval=0, idle_timeout=0,
            **kwargs,
        ).start()

    def _start_probe(self, listener, probe_id: str, transport: str,
                     extra: list[str] | None = None) -> subprocess.Popen:
        command = [
            str(BINARY), "reverse",
            "--transport", transport,
            "--host", "127.0.0.1", "--port", str(listener.port),
            "--ca-file", self.material["ca_file"],
            "--pin", self.material["pin"],
            "--sni", "127.0.0.1",
            "--token", TOKEN,
            "--probe-id", probe_id,
            "--no-reconnect",
            "--allow-write",
            *_shell_cmd(),
            *(extra or []),
        ]
        proc = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.procs.append(proc)
        return proc

    def _transport_round_trip(self, transport: str) -> None:
        listener = self._listener(transport)
        try:
            self._start_probe(listener, f"rust-{transport}", transport)
            record = listener.wait_for_probe(timeout=20, probe_id=f"rust-{transport}")
            self.assertEqual(record["transport"], transport)
            snapshot = listener.collect(f"rust-{transport}")
            self.assertEqual(snapshot.get("probe_id"), f"rust-{transport}")
            result = listener.perform_exec(
                f"rust-{transport}", _shell_argv(), timeout=20
            )
            self.assertEqual(result.get("exit_code"), 0, result)
            self.assertIn("rust-reverse-ok", result.get("stdout", ""))
        finally:
            listener.stop()

    def test_tls_round_trip(self):
        self._transport_round_trip("tls")

    def test_wss_round_trip(self):
        self._transport_round_trip("wss")

    def test_https_round_trip(self):
        self._transport_round_trip("https")

    def test_tls_child_deploy_and_parent_id(self):
        listener = self._listener("tls")
        try:
            self._start_probe(listener, "rust-parent", "tls")
            parent_record = listener.wait_for_probe(timeout=20, probe_id="rust-parent")
            parent = listener.connection("rust-parent")
            remote = Path(self.temp.name) / "podtmp"
            remote.mkdir()
            binary = BINARY.read_bytes()
            result = deploy_reverse_child(
                parent, binary, child_id="rust-child",
                host="127.0.0.1", port=listener.port, transport="tls",
                ca_file=self.material["ca_file"], pin=self.material["pin"],
                remote_dirs=[str(remote)], timeout=60,
            )
            self.assertEqual(result["probe_id"], "rust-child")
            child = listener.wait_for_probe(timeout=30, probe_id="rust-child")
            self.assertEqual(child["parent_id"], "rust-parent")
            self.assertEqual(child["transport"], "tls")
            self.assertEqual(parent_record["probe_id"], "rust-parent")
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
