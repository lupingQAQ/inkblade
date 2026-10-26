# -*- coding: utf-8 -*-
"""Dynamic tests against the compiled Rust probe (skipped without a binary).

CI builds the static musl binary in ``.github/workflows/probe-release.yml``.
Set ``INKBLADE_PROBE_BIN`` or place an artifact under ``dist/`` to run these
tests locally.  They exercise real HTTP, real process execution and the real
SOCKS relay, not the Python engine.
"""

from __future__ import annotations

import http.server
import os
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

from inkblade.channel import ChannelServer, ProbeConnection

ROOT = Path(__file__).resolve().parents[1]


def _binary() -> Path | None:
    candidates = []
    if os.environ.get("INKBLADE_PROBE_BIN"):
        candidates.append(Path(os.environ["INKBLADE_PROBE_BIN"]))
    candidates += [
        ROOT / "dist" / "inkblade-probe-linux-amd64",
        ROOT / "dist" / "inkblade-probe-linux-arm64",
        ROOT / "probe" / "target" / "release" / "inkblade-probe",
        ROOT / "probe" / "target" / "release" / "inkblade-probe.exe",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


BINARY = _binary()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"version":"2.10.0","object":"list","items":[{"id":"m"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Echo:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self.stop:
            try:
                client, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._echo, args=(client,), daemon=True).start()

    @staticmethod
    def _echo(client):
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            client.close()

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@unittest.skipUnless(BINARY is not None, "Rust probe binary not built (CI builds linux-musl)")
class RustProbeDynamic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = "dynamic-test-token"
        cls.http = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.http_thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.http_thread.start()
        cls.url = f"http://127.0.0.1:{cls.http.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()

    def setUp(self):
        self.probe = ProbeConnection(
            [str(BINARY), "run", "--stdio", "--token", self.token, "--read-only"],
            self.token,
            timeout=20,
        ).start()

    def tearDown(self):
        try:
            self.probe.close()
        except Exception:
            pass

    def test_real_collect_and_http_template(self):
        snapshot = self.probe.collect()
        self.assertTrue(snapshot.get("probe_id"))
        template = {
            "name": "dynamic-http",
            "budget": {"max_steps": 4, "max_ms": 5000, "max_bytes": 65536},
            "steps": [
                {"id": "version", "op": "http", "method": "GET",
                 "url": self.url + "/version", "expect": {"status": [200]}},
            ],
        }
        result = self.probe.run_task(template, {}, task_id="dynamic-http")
        self.assertTrue(result["ok"])
        step = result["vars"]["steps.version"]
        self.assertEqual(step["status"], 200)
        self.assertIn("2.10.0", step["text"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "exec allow-list test runs on Linux")
    def test_real_exec(self):
        result = self.probe.exec(["id"])
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("uid=", result["stdout"])

    def test_real_socks_relay(self):
        echo = _Echo()
        channel = ChannelServer(self.probe, socks_port=0).start()
        try:
            client = socket.create_connection(("127.0.0.1", channel.socks_port), timeout=5)
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(client.recv(2), b"\x05\x00")
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                           + struct.pack(">H", echo.port))
            self.assertEqual(client.recv(10)[:2], b"\x05\x00")
            client.sendall(b"rust-relay")
            self.assertEqual(client.recv(10), b"rust-relay")
            client.close()
        finally:
            channel.stop()
            echo.close()


if __name__ == "__main__":
    unittest.main()
