# -*- coding: utf-8 -*-
"""Reverse channel tests: probe dials controller, same framed protocol.

The fake TCP probe performs a real challenge-HMAC handshake, so these tests
exercise the listener, socket ProbeConnection, child deployment and CLI
without a cluster or a Rust binary.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from inkblade.channel import ProbeConnection
from inkblade.reverse import (
    DEFAULT_REMOTE_DIRS,
    ReverseChannelError,
    ReverseListener,
    control_request,
    deploy_reverse_child,
    ensure_tls_material,
    reverse_paths,
)
from tests.fake_reverse_probe import FakeReverseProbe

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "reverse-test-token"


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            sock.close()
            return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"port {port} did not open")


class EchoServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop:
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
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class _ListenerCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.material = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )
        self.listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10,
            home=self.home, workspace="ws", transport="tls",
            tls_material=self.material, ping_interval=0, idle_timeout=0,
        ).start()
        self.probes: list[FakeReverseProbe] = []

    def tearDown(self):
        for probe in self.probes:
            probe.stop()
        self.listener.stop()
        self.temp.cleanup()

    def connect_probe(self, probe_id="parent", **kwargs) -> FakeReverseProbe:
        kwargs.setdefault("transport", "tls")
        kwargs.setdefault("ca_file", self.material["ca_file"])
        kwargs.setdefault("pin", self.material["pin"])
        kwargs.setdefault("sni", "127.0.0.1")
        probe = FakeReverseProbe(
            "127.0.0.1", self.listener.port, TOKEN, probe_id, **kwargs
        )
        self.probes.append(probe)
        probe.start()
        probe.ready.wait(timeout=10)
        self.assertIsNone(probe.error, f"probe {probe_id} failed: {probe.error}")
        return probe


class TestReverseHandshake(_ListenerCase):
    def test_controller_authenticates_probe_and_collects(self):
        self.connect_probe("parent")
        record = self.listener.wait_for_probe(timeout=5, probe_id="parent")
        self.assertEqual(record["probe_id"], "parent")
        self.assertEqual(record["transport"], "tls")
        self.assertTrue(record["remote"].startswith("127.0.0.1:"))
        self.assertTrue(record["read_only"])
        self.assertIn("collect", record["caps"])

        snapshot = self.listener.collect("parent")
        self.assertEqual(snapshot["probe_id"], "parent")
        self.assertEqual(snapshot["transport"], "reverse")

        paths = reverse_paths(self.home, "ws")
        self.assertTrue(paths["probes"].is_file())
        document = json.loads(paths["probes"].read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "inkblade-reverse-probes-v1")
        self.assertEqual(document["probes"][0]["probe_id"], "parent")

    def test_bad_hmac_is_rejected_and_listener_keeps_accepting(self):
        bad = FakeReverseProbe(
            "127.0.0.1", self.listener.port, "wrong-token", "bad",
            transport="tls", ca_file=self.material["ca_file"],
            pin=self.material["pin"], sni="127.0.0.1",
        )
        self.probes.append(bad)
        bad.start()
        bad.ready.wait(timeout=10)
        self.assertIsNotNone(bad.error)
        self.assertEqual(self.listener.online_count(), 0)
        self.connect_probe("good")
        self.listener.wait_for_probe(timeout=5, probe_id="good")

    def test_control_port_lists_and_runs_ops(self):
        self.connect_probe("parent")
        self.listener.wait_for_probe(timeout=5, probe_id="parent")
        data = control_request(self.home, "ws", {"op": "list"})
        self.assertEqual([row["probe_id"] for row in data["probes"]], ["parent"])
        pong = control_request(self.home, "ws", {
            "op": "request", "probe_id": "parent", "op_name": "ping", "args": {},
        })
        self.assertTrue(pong["pong"])
        result = control_request(self.home, "ws", {
            "op": "exec", "probe_id": "parent",
            "argv": [sys.executable, "-c", "print('reverse-exec-ok')"],
        })
        self.assertIn("reverse-exec-ok", result["stdout"])

    def test_state_marks_probe_offline_after_stop(self):
        self.connect_probe("parent")
        self.listener.wait_for_probe(timeout=5)
        self.listener.stop()
        document = json.loads(
            reverse_paths(self.home, "ws")["probes"].read_text(encoding="utf-8")
        )
        self.assertEqual(document["probes"][0]["status"], "offline")


class TestSocketProbeConnection(_ListenerCase):
    def test_socket_request_upload_spawn_and_dial(self):
        self.connect_probe("parent")
        self.listener.wait_for_probe(timeout=5, probe_id="parent")
        probe: ProbeConnection = self.listener.connection("parent")
        self.assertEqual(probe.transport, "reverse")
        self.assertTrue(probe.ping()["pong"])

        target = Path(self.temp.name) / "upload.bin"
        payload = b"\x00socket-upload\xff" * 1024
        probe.upload(str(target), payload, mode=0o600)
        self.assertEqual(target.read_bytes(), payload)

        spawn = probe.spawn(b"child-binary-bytes", probe_id="child-a")
        self.assertEqual(spawn["probe_id"], "child-a")
        self.assertEqual(spawn["parent_id"], "parent")
        fake = self.probes[0]
        self.assertEqual(fake.spawns[-1]["probe_id"], "child-a")

        echo = EchoServer()
        try:
            stream = probe.dial("127.0.0.1", echo.port, timeout_ms=5000)
            stream.send(b"reverse-dial-ok")
            self.assertEqual(stream.recv(timeout=5), b"reverse-dial-ok")
            stream.close()
        finally:
            echo.close()

    def test_deploy_reverse_child_registers_parent_id(self):
        children: list[FakeReverseProbe] = []

        def spawn_child(args, parent):
            child = FakeReverseProbe(
                "127.0.0.1", self.listener.port, TOKEN,
                str(args["probe_id"]), parent_id=parent.probe_id,
                transport="tls", ca_file=self.material["ca_file"],
                pin=self.material["pin"], sni="127.0.0.1",
            )
            children.append(child)
            self.probes.append(child)
            child.start()
            return {
                "probe_id": str(args["probe_id"]),
                "parent_id": parent.probe_id,
                "registered": True,
            }

        self.connect_probe("parent", spawn_handler=spawn_child)
        self.listener.wait_for_probe(timeout=5, probe_id="parent")
        parent = self.listener.connection("parent")
        upload_dir = Path(self.temp.name) / "pod-tmp"
        upload_dir.mkdir()
        result = deploy_reverse_child(
            parent, b"\x7fELFfake-child-binary", child_id="child-1",
            host="127.0.0.1", port=self.listener.port,
            transport="tls", ca_file=self.material["ca_file"],
            pin=self.material["pin"], remote_dirs=[str(upload_dir)], timeout=10,
        )
        self.assertTrue(result["uploaded_path"].startswith(str(upload_dir)))
        self.assertEqual(result["transport"], "tls")
        self.assertEqual(result["reverse"]["port"], self.listener.port)
        uploaded = Path(result["uploaded_path"])
        self.assertEqual(uploaded.read_bytes(), b"\x7fELFfake-child-binary")
        self.assertEqual(parent.parent_id, None)

        child = self.listener.wait_for_probe(timeout=5, probe_id="child-1")
        self.assertEqual(child["parent_id"], "parent")
        self.assertEqual(child["transport"], "tls")
        self.assertEqual(parent.probe_id, "parent")
        # The controller can command both the parent and the child directly.
        self.assertEqual(self.listener.collect("child-1")["probe_id"], "child-1")

    def test_upload_falls_back_to_shm(self):
        self.connect_probe("parent")
        self.listener.wait_for_probe(timeout=5, probe_id="parent")
        parent = self.listener.connection("parent")
        missing = Path(self.temp.name) / "missing"
        shm = Path(self.temp.name) / "shm"
        shm.mkdir()
        result = deploy_reverse_child(
            parent, b"fallback-child", child_id="child-shm",
            host="127.0.0.1", port=self.listener.port, transport="tls",
            ca_file=self.material["ca_file"], pin=self.material["pin"],
            remote_dirs=[str(missing), str(shm)], timeout=10,
        )
        self.assertTrue(result["uploaded_path"].startswith(str(shm)))
        self.assertEqual(
            Path(result["uploaded_path"]).read_bytes(), b"fallback-child"
        )

    def test_read_only_rootfs_reports_explicit_error(self):
        self.connect_probe("parent", read_only_rootfs=True)
        self.listener.wait_for_probe(timeout=5, probe_id="parent")
        parent = self.listener.connection("parent")
        with self.assertRaises(ReverseChannelError) as caught:
            deploy_reverse_child(
                parent, b"child", child_id="child-ro", host="127.0.0.1",
                port=self.listener.port, transport="tls",
                ca_file=self.material["ca_file"], pin=self.material["pin"],
                remote_dirs=["/tmp", "/dev/shm"],
            )
        self.assertEqual(caught.exception.code, "read_only_rootfs")
        attempts = caught.exception.data["attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertIn("Read-only file system", attempts[0]["error"])


class TestEncryptedTransports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.material = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )

    def tearDown(self):
        self.temp.cleanup()

    def _listener(self, transport, **kwargs):
        return ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10,
            home=self.home, workspace="ws", transport=transport,
            tls_material=self.material, ping_interval=0, idle_timeout=0,
            **kwargs,
        ).start()

    def _probe(self, listener, probe_id="enc", **kwargs):
        probe = FakeReverseProbe(
            "127.0.0.1", listener.port, kwargs.pop("token", TOKEN), probe_id,
            transport=kwargs.pop("transport", listener.transport),
            ca_file=kwargs.pop("ca_file", self.material["ca_file"]),
            pin=kwargs.pop("pin", self.material["pin"]),
            sni=kwargs.pop("sni", "127.0.0.1"), **kwargs,
        )
        probe.start()
        probe.ready.wait(timeout=10)
        return probe

    def test_tls_handshake_collect_and_exec(self):
        listener = self._listener("tls")
        probe = self._probe(listener)
        try:
            self.assertIsNone(probe.error)
            record = listener.wait_for_probe(timeout=5, probe_id="enc")
            self.assertEqual(record["transport"], "tls")
            self.assertIn("collect", record["caps"])
            self.assertEqual(listener.collect("enc")["probe_id"], "enc")
            result = listener.perform_exec(
                "enc", [sys.executable, "-c", "print('tls-exec-ok')"]
            )
            self.assertIn("tls-exec-ok", result["stdout"])
        finally:
            probe.stop()
            listener.stop()

    def test_tls_wrong_pin_is_rejected(self):
        listener = self._listener("tls")
        probe = self._probe(listener, pin="00" * 32)
        try:
            probe.ready.wait(timeout=10)
            self.assertIsNotNone(probe.error)
            self.assertIn("pin", str(probe.error).lower())
            self.assertEqual(listener.online_count(), 0)
        finally:
            probe.stop()
            listener.stop()

    def test_tls_wrong_token_is_rejected(self):
        listener = self._listener("tls")
        probe = self._probe(listener, token="wrong-token")
        try:
            probe.ready.wait(timeout=10)
            self.assertIsNotNone(probe.error)
            deadline = time.time() + 3
            while time.time() < deadline and listener.auth_failures < 1:
                time.sleep(0.05)
            self.assertEqual(listener.online_count(), 0)
            self.assertGreaterEqual(listener.auth_failures, 1)
        finally:
            probe.stop()
            listener.stop()

    def test_expired_server_certificate_is_rejected(self):
        expired = ensure_tls_material(
            self.home / "expired", hosts=["127.0.0.1"], expired=True
        )
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10, home=self.home,
            workspace="ws-expired", transport="tls", tls_material=expired,
            ping_interval=0, idle_timeout=0,
        ).start()
        probe = FakeReverseProbe(
            "127.0.0.1", listener.port, TOKEN, "expired",
            transport="tls", ca_file=expired["ca_file"], pin=expired["pin"],
            sni="127.0.0.1",
        )
        probe.start()
        try:
            probe.ready.wait(timeout=10)
            self.assertIsNotNone(probe.error)
            self.assertEqual(listener.online_count(), 0)
        finally:
            probe.stop()
            listener.stop()

    def test_wss_handshake_and_collect(self):
        listener = self._listener("wss")
        probe = self._probe(listener, transport="wss", path="/ws")
        try:
            self.assertIsNone(probe.error)
            record = listener.wait_for_probe(timeout=5, probe_id="enc")
            self.assertEqual(record["transport"], "wss")
            self.assertEqual(listener.collect("enc")["probe_id"], "enc")
        finally:
            probe.stop()
            listener.stop()

    def test_wss_wrong_path_is_rejected(self):
        listener = self._listener("wss")
        probe = self._probe(listener, transport="wss", path="/wrong")
        try:
            probe.ready.wait(timeout=10)
            self.assertIsNotNone(probe.error)
            self.assertEqual(listener.online_count(), 0)
        finally:
            probe.stop()
            listener.stop()

    def test_https_long_poll_collect_and_exec(self):
        listener = self._listener("https")
        probe = self._probe(listener, transport="https")
        try:
            self.assertIsNone(probe.error)
            record = listener.wait_for_probe(timeout=10, probe_id="enc")
            self.assertEqual(record["transport"], "https")
            self.assertEqual(listener.collect("enc")["probe_id"], "enc")
            result = listener.perform_exec(
                "enc", [sys.executable, "-c", "print('https-exec-ok')"]
            )
            self.assertIn("https-exec-ok", result["stdout"])
            state = json.loads(
                reverse_paths(self.home, "ws")["probes"].read_text(encoding="utf-8")
            )
            self.assertEqual(state["transport"], "https")
            self.assertEqual(state["probes"][0]["last_seen"] > 0, True)
        finally:
            probe.stop()
            listener.stop()

    def test_plaintext_requires_lab_flag(self):
        with self.assertRaises(ReverseChannelError):
            ReverseListener(TOKEN, bind="127.0.0.1", port=0, transport="tcp")


class TestMultiProbeAndHeartbeat(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _listener(self, **kwargs):
        return ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10, home=self.home,
            workspace="ws", transport="tcp", lab_plaintext=True, **kwargs,
        ).start()

    def test_twenty_concurrent_probes(self):
        listener = self._listener(ping_interval=0, idle_timeout=0, max_probes=25)
        probes = []
        try:
            for index in range(20):
                probe = FakeReverseProbe(
                    "127.0.0.1", listener.port, TOKEN, f"p{index}",
                    parent_id=None if index == 0 else "p0",
                )
                probes.append(probe)
                probe.start()
            for index in range(20):
                listener.wait_for_probe(timeout=10, probe_id=f"p{index}")
            rows = listener.records()
            self.assertEqual(len(rows), 20)
            self.assertEqual(sum(1 for row in rows if row["status"] == "online"), 20)
            self.assertEqual(listener.collect("p7")["probe_id"], "p7")
        finally:
            for probe in probes:
                probe.stop()
            listener.stop()

    def test_max_probes_limit(self):
        listener = self._listener(ping_interval=0, idle_timeout=0, max_probes=1)
        first = FakeReverseProbe("127.0.0.1", listener.port, TOKEN, "one")
        second = FakeReverseProbe("127.0.0.1", listener.port, TOKEN, "two")
        try:
            first.start()
            first.ready.wait(timeout=10)
            listener.wait_for_probe(timeout=5, probe_id="one")
            second.start()
            second.ready.wait(timeout=10)
            time.sleep(0.5)
            self.assertEqual(listener.online_count(), 1)
            self.assertEqual([row["probe_id"] for row in listener.records()], ["one"])
        finally:
            first.stop()
            second.stop()
            listener.stop()

    def test_heartbeat_updates_last_seen_and_drops_dead_probe(self):
        listener = self._listener(ping_interval=0.2, idle_timeout=5)
        probe = FakeReverseProbe("127.0.0.1", listener.port, TOKEN, "hb")
        try:
            probe.start()
            probe.ready.wait(timeout=10)
            record = listener.wait_for_probe(timeout=5, probe_id="hb")
            before = record["last_seen"]
            time.sleep(0.8)
            after = [row for row in listener.records() if row["probe_id"] == "hb"][0]
            self.assertGreater(after["last_seen"], before)
            probe.stop()
            deadline = time.time() + 5
            while time.time() < deadline:
                rows = [row for row in listener.records() if row["probe_id"] == "hb"]
                if rows and rows[0]["status"] == "offline":
                    break
                time.sleep(0.1)
            rows = [row for row in listener.records() if row["probe_id"] == "hb"]
            self.assertEqual(rows[0]["status"], "offline")
        finally:
            probe.stop()
            listener.stop()

    def test_reconnect_replaces_same_probe_id(self):
        listener = self._listener(ping_interval=0, idle_timeout=0)
        first = FakeReverseProbe("127.0.0.1", listener.port, TOKEN, "re")
        second = None
        try:
            first.start()
            first.ready.wait(timeout=10)
            first_record = listener.wait_for_probe(timeout=5, probe_id="re")
            first.stop()
            time.sleep(0.2)
            second = FakeReverseProbe("127.0.0.1", listener.port, TOKEN, "re")
            second.start()
            second.ready.wait(timeout=10)
            deadline = time.time() + 8
            rows = listener.records()
            while time.time() < deadline:
                rows = listener.records()
                if rows and rows[0]["status"] == "online" \
                        and rows[0]["connected_at"] > first_record["connected_at"]:
                    break
                time.sleep(0.1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["probe_id"], "re")
            self.assertTrue(rows[0]["replaced"])
            self.assertEqual(rows[0]["status"], "online")
        finally:
            first.stop()
            if second is not None:
                second.stop()
            listener.stop()



class TestReverseCli(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.token_file = self.home / "probe.token"
        self.token_file.write_text(TOKEN, encoding="utf-8")
        try:
            os.chmod(self.token_file, 0o600)
        except OSError:
            pass
        self.tls = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )

    def tearDown(self):
        self.temp.cleanup()

    def _env(self) -> dict[str, str]:
        return {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1"}

    def _cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "inkblade", "--home", str(self.home), *args],
            cwd=str(ROOT), env=self._env(), capture_output=True, text=True, timeout=60,
        )

    def test_listen_once_exec_collect_json_and_probe_list(self):
        port = free_port()
        process = subprocess.Popen(
            [
                sys.executable, "-m", "inkblade", "--home", str(self.home),
                "channel", "listen", "--bind", "127.0.0.1", "--port", str(port),
                "--token-file", str(self.token_file), "--workspace", "ws",
                "--transport", "tls", "--tls-dir", str(self.home / "tls"),
                "--once", "--exec", "collect", "--timeout", "15", "--json",
            ],
            cwd=str(ROOT), env=self._env(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        probe = None
        try:
            wait_port(port, timeout=15)
            probe = FakeReverseProbe(
                "127.0.0.1", port, TOKEN, "cli-probe",
                transport="tls", ca_file=self.tls["ca_file"],
                pin=self.tls["pin"], sni="127.0.0.1",
            )
            probe.start()
            probe.ready.wait(timeout=10)
            self.assertIsNone(probe.error)
            stdout, stderr = process.communicate(timeout=30)
        finally:
            if probe is not None:
                probe.stop()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        document = json.loads(stdout)
        self.assertEqual(document["probe"]["probe_id"], "cli-probe")
        self.assertEqual(document["probe"]["transport"], "tls")
        self.assertEqual(document["result"]["probe_id"], "cli-probe")
        self.assertIn("caps", document["probe"])

        listing = self._cli("probe", "list", "--workspace", "ws", "--json")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        rows = json.loads(listing.stdout)
        self.assertEqual([row["probe_id"] for row in rows], ["cli-probe"])

    def test_long_running_control_port_serves_another_process(self):
        port = free_port()
        process = subprocess.Popen(
            [
                sys.executable, "-m", "inkblade", "--home", str(self.home),
                "channel", "listen", "--bind", "127.0.0.1", "--port", str(port),
                "--token-file", str(self.token_file), "--workspace", "ws",
                "--transport", "tls", "--tls-dir", str(self.home / "tls"),
                "--duration", "8", "--json",
            ],
            cwd=str(ROOT), env=self._env(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        probe = None
        try:
            wait_port(port, timeout=15)
            probe = FakeReverseProbe(
                "127.0.0.1", port, TOKEN, "long-probe",
                transport="tls", ca_file=self.tls["ca_file"],
                pin=self.tls["pin"], sni="127.0.0.1",
            )
            probe.start()
            probe.ready.wait(timeout=10)
            self.assertIsNone(probe.error)
            control = reverse_paths(self.home, "ws")["control"]
            deadline = time.time() + 10
            while time.time() < deadline and not control.is_file():
                time.sleep(0.05)
            self.assertTrue(control.is_file())
            result = self._cli(
                "channel", "exec", "--workspace", "ws",
                "--probe-id", "long-probe", "--op", "ping", "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            body = json.loads(result.stdout)
            self.assertTrue(body["pong"])
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
            startup = json.loads(stdout)
            self.assertEqual(startup["status"], "listening")
            self.assertTrue(startup["control"]["port"])
            state = json.loads(
                reverse_paths(self.home, "ws")["probes"].read_text(encoding="utf-8")
            )
            self.assertEqual(state["probes"][0]["probe_id"], "long-probe")
        finally:
            if probe is not None:
                probe.stop()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_listen_once_wss_and_https(self):
        for transport in ("wss", "https"):
            port = free_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "inkblade", "--home", str(self.home),
                    "channel", "listen", "--bind", "127.0.0.1", "--port", str(port),
                    "--token-file", str(self.token_file), "--workspace", "ws",
                    "--transport", transport, "--tls-dir", str(self.home / "tls"),
                    "--once", "--exec", "collect", "--timeout", "15", "--json",
                ],
                cwd=str(ROOT), env=self._env(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            probe = None
            try:
                wait_port(port, timeout=15)
                probe = FakeReverseProbe(
                    "127.0.0.1", port, TOKEN, f"cli-{transport}",
                    transport=transport, ca_file=self.tls["ca_file"],
                    pin=self.tls["pin"], sni="127.0.0.1",
                )
                probe.start()
                probe.ready.wait(timeout=10)
                self.assertIsNone(probe.error)
                stdout, stderr = process.communicate(timeout=30)
            finally:
                if probe is not None:
                    probe.stop()
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            document = json.loads(stdout)
            self.assertEqual(document["probe"]["probe_id"], f"cli-{transport}")
            self.assertEqual(document["result"]["probe_id"], f"cli-{transport}")
            self.assertEqual(document["probe"]["transport"], transport)

    def test_probe_deploy_reverse_dry_run(self):
        binary = self.home / "probe.bin"
        binary.write_bytes(b"not-an-elf-in-dry-run")
        result = self._cli(
            "probe", "deploy", "--reverse", "parent-1", "--binary", str(binary),
            "--reverse-host", "198.51.100.10", "--reverse-port", "9443",
            "--probe-command", "true", "--dry-run",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertTrue(document["dry_run"])
        self.assertEqual(document["parent_id"], "parent-1")
        self.assertEqual(document["reverse"]["host"], "198.51.100.10")
        self.assertEqual(document["reverse"]["port"], 9443)


if __name__ == "__main__":
    unittest.main()
