# -*- coding: utf-8 -*-
"""Probe transport + SOCKS5/port-forward channel integration tests.

These use a stdlib fake probe over the real framed protocol, so they exercise
authentication, framing, multiplexing, relay and cleanup without a cluster.
"""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from inkblade.channel import (
    AuthError,
    ChannelError,
    ChannelServer,
    Forward,
    ProbeConnection,
    ProbeError,
    ProbeTimeout,
    kubectl_probe_command,
    read_frame,
    encode_frame,
)

ROOT = Path(__file__).resolve().parents[1]
FAKE = Path(__file__).with_name("fake_probe.py")


def _connection(token: str = "test-token", *extra: str) -> ProbeConnection:
    return ProbeConnection(
        [sys.executable, str(FAKE), "--token", token, *extra], token, timeout=10
    )


class EchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.closed = False
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.closed:
            try:
                client, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._echo, args=(client,), daemon=True).start()

    @staticmethod
    def _echo(client: socket.socket) -> None:
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def close(self) -> None:
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


class TestProbeTransport(unittest.TestCase):
    def test_auth_failure(self):
        with self.assertRaises(AuthError):
            ProbeConnection(
                [sys.executable, str(FAKE), "--token", "test-token"], "wrong", timeout=5
            ).start()

    def test_collect_exec_beacon(self):
        probe = _connection().start()
        try:
            collected = probe.collect()
            self.assertEqual(collected["probe_id"], "fake-probe")
            result = probe.exec([sys.executable, "-c", "print('hello-probe')"])
            self.assertEqual(result["exit_code"], 0)
            self.assertIn("hello-probe", result["stdout"])
            self.assertTrue(probe.beacon()["probe_id"])
            self.assertEqual(probe.ping()["pong"], True)
        finally:
            probe.close()

    def test_exec_timeout_is_reported(self):
        probe = _connection().start()
        try:
            result = probe.exec(
                [sys.executable, "-c", "import time; time.sleep(2)"], timeout_ms=100
            )
            self.assertTrue(result["timed_out"])
        finally:
            probe.close()

    def test_upload_download_roundtrip(self):
        probe = _connection().start()
        with tempfile.TemporaryDirectory() as tmp:
            remote = str(Path(tmp) / "payload.bin")
            data = bytes(range(256)) * 700
            try:
                receipt = probe.upload(remote, data, chunk_size=4096)
                self.assertTrue(receipt)
                self.assertEqual(Path(remote).read_bytes(), data)
                self.assertEqual(probe.download(remote, max_bytes=len(data)), data)
            finally:
                probe.close()

    def test_kubectl_command_only_loopback_and_token_file(self):
        command = kubectl_probe_command(
            "kubectl", namespace="ml", pod="probe-1", probe_path="/tmp/p",
            token_file="/tmp/t", container="c", read_only=True,
        )
        self.assertEqual(command[:7], ["kubectl", "-n", "ml", "exec", "-i", "probe-1", "-c"])
        self.assertIn("/tmp/p", command)
        self.assertIn("--read-only", command)
        self.assertIn("--token-file", command)

    def test_fake_kubectl_launches_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = "kubectl-token"
            script = Path(tmp) / "kubectl.py"
            script.write_text(
                "import os, subprocess, sys\n"
                f"probe = {str(FAKE)!r}\n"
                "args = sys.argv[1:]\n"
                "if '--' in args:\n"
                "    tail = args[args.index('--') + 2:]\n"
                "else:\n"
                "    tail = []\n"
                "out = []\n"
                "i = 0\n"
                "tok = None\n"
                "while i < len(tail):\n"
                "    if tail[i] == '--token-file':\n"
                "        i += 2\n"
                "        continue\n"
                "    out.append(tail[i]); i += 1\n"
                "env = dict(os.environ); env['INKBLADE_PROBE_TOKEN'] = "
                f"{token!r}\n"
                "raise SystemExit(subprocess.call([sys.executable, probe] + out, env=env))\n",
                encoding="utf-8",
            )
            command = [
                sys.executable, str(script), "-n", "default", "exec", "-i", "pod", "--",
                "/tmp/probe", "run", "--stdio", "--token-file", "/tmp/token",
                "--read-only",
            ]
            probe = ProbeConnection(command, token).start()
            try:
                self.assertEqual(probe.collect()["probe_id"], "fake-probe")
            finally:
                probe.close()


class TestChannel(unittest.TestCase):
    def setUp(self):
        self.echo = EchoServer()
        self.probe = _connection().start()

    def tearDown(self):
        try:
            self.probe.close()
        except Exception:
            pass
        self.echo.close()

    def _socks_connect(self, channel: ChannelServer, host: str, port: int) -> socket.socket:
        client = socket.create_connection(("127.0.0.1", channel.socks_port), timeout=5)
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(client.recv(2), b"\x05\x00")
        request = b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port)
        client.sendall(request)
        reply = client.recv(10)
        self.assertEqual(reply[:2], b"\x05\x00")
        return client

    def test_socks5_connect_and_relay(self):
        channel = ChannelServer(self.probe, socks_port=0).start()
        try:
            client = self._socks_connect(channel, "127.0.0.1", self.echo.port)
            client.sendall(b"hello-socks")
            self.assertEqual(client.recv(11), b"hello-socks")
            client.close()
            deadline = time.time() + 3
            while channel.connections < 1 and time.time() < deadline:
                time.sleep(0.02)
            self.assertGreaterEqual(channel.connections, 1)
        finally:
            channel.stop()

    def test_socks5_domain_name(self):
        channel = ChannelServer(self.probe, socks_port=0).start()
        try:
            client = socket.create_connection(("127.0.0.1", channel.socks_port), timeout=5)
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(client.recv(2), b"\x05\x00")
            host = b"localhost"
            client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host
                           + struct.pack(">H", self.echo.port))
            self.assertEqual(client.recv(10)[:2], b"\x05\x00")
            client.sendall(b"domain")
            self.assertEqual(client.recv(6), b"domain")
            client.close()
        finally:
            channel.stop()

    def test_port_forward(self):
        channel = ChannelServer(
            self.probe, socks_port=-1,
            forwards=[Forward(0, "127.0.0.1", self.echo.port)],
        ).start()
        try:
            local = channel.forward_ports[0]["local"]
            client = socket.create_connection(("127.0.0.1", local), timeout=5)
            client.sendall(b"forward")
            self.assertEqual(client.recv(7), b"forward")
            client.close()
        finally:
            channel.stop()

    def test_status_and_cleanup(self):
        channel = ChannelServer(self.probe, socks_port=0).start()
        status = channel.status()
        self.assertTrue(status["running"])
        self.assertIsNotNone(status["socks"])
        channel.stop()
        self.assertFalse(channel.status()["running"])
        self.assertEqual(self.probe._streams, {})

    def test_socks_rejects_non_connect(self):
        channel = ChannelServer(self.probe, socks_port=0).start()
        try:
            client = socket.create_connection(("127.0.0.1", channel.socks_port), timeout=5)
            client.sendall(b"\x05\x01\x00")
            client.recv(2)
            client.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")
            reply = client.recv(10)
            self.assertEqual(reply[1], 0x07)
            client.close()
        finally:
            channel.stop()

    def test_channel_refuses_public_bind(self):
        with self.assertRaises(ChannelError):
            ChannelServer(self.probe, socks_port=0, bind_host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
