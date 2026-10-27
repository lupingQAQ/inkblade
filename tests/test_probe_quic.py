# -*- coding: utf-8 -*-
"""QUIC, WebTransport and MASQUE CONNECT-UDP transport tests.

The aioquic tests need the optional ``aioquic`` package; they are skipped when
it is absent.  The Rust probe tests are skipped when no runnable probe binary
exists, matching ``test_probe_reverse_rust.py``.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from inkblade.reverse import (
    ReverseListener,
    ensure_tls_material,
    reverse_paths,
)

try:
    from tests.fake_quic_probe import (
        HAS_AIOQUIC,
        FakeQuicReverseProbe,
        MasqueClient,
    )
except Exception:  # pragma: no cover - optional dependency
    HAS_AIOQUIC = False
    FakeQuicReverseProbe = None
    MasqueClient = None

from tests.fake_reverse_probe import FakeReverseProbe

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "quic-reverse-token"


def _binary() -> Path | None:
    candidates = []
    if os.environ.get("INKBLADE_PROBE_BIN"):
        candidates.append(Path(os.environ["INKBLADE_PROBE_BIN"]))
    candidates += [
        ROOT / "probe" / "target" / "release" / "inkblade-probe.exe",
        ROOT / "probe" / "target" / "release" / "inkblade-probe",
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


class _UdpEcho:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, address = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.sock.sendto(b"echo:" + data, address)
            except OSError:
                break

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


@unittest.skipUnless(HAS_AIOQUIC, "aioquic is not installed")
class _QuicCase(unittest.TestCase):
    transport = "quic"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.material = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )
        self.listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10,
            home=self.home, workspace="ws", transport=self.transport,
            tls_material=self.material, ping_interval=0, idle_timeout=0,
        ).start()
        self.probes = []

    def tearDown(self):
        for probe in self.probes:
            probe.stop()
        self.listener.stop()
        self.temp.cleanup()

    def connect(self, probe_id="parent", **kwargs):
        probe = FakeQuicReverseProbe(
            "127.0.0.1", self.listener.port, kwargs.pop("token", TOKEN), probe_id,
            transport=kwargs.pop("transport", self.transport),
            ca_file=kwargs.pop("ca_file", self.material["ca_file"]),
            pin=kwargs.pop("pin", self.material["pin"]),
            sni=kwargs.pop("sni", "127.0.0.1"),
            **kwargs,
        )
        self.probes.append(probe)
        probe.start()
        probe.ready.wait(timeout=20)
        return probe


class TestQuicTransport(_QuicCase):
    def test_quic_collect_and_exec(self):
        probe = self.connect("quic-parent")
        self.assertIsNone(probe.error, probe.error)
        record = self.listener.wait_for_probe(timeout=10, probe_id="quic-parent")
        self.assertEqual(record["transport"], "quic")
        self.assertIn("collect", record["caps"])
        self.assertIn("udp", record["caps"])
        self.assertEqual(self.listener.collect("quic-parent")["probe_id"], "quic-parent")
        result = self.listener.perform_exec(
            "quic-parent", [sys.executable, "-c", "print('quic-exec-ok')"]
        )
        self.assertIn("quic-exec-ok", result["stdout"])

    def test_quic_wrong_pin_is_rejected(self):
        probe = self.connect("quic-pin", pin="00" * 32)
        self.assertIsNotNone(probe.error)
        self.assertIn("pin", str(probe.error).lower())
        self.assertEqual(self.listener.online_count(), 0)

    def test_quic_wrong_token_is_rejected(self):
        probe = self.connect("quic-token", token="wrong-token")
        self.assertIsNotNone(probe.error)
        deadline = time.time() + 3
        while time.time() < deadline and self.listener.auth_failures < 1:
            time.sleep(0.05)
        self.assertEqual(self.listener.online_count(), 0)
        self.assertGreaterEqual(self.listener.auth_failures, 1)

    def test_quic_heartbeat_updates_last_seen(self):
        self.listener.stop()
        self.listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10,
            home=self.home, workspace="ws", transport="quic",
            tls_material=self.material, ping_interval=0.2, idle_timeout=5,
        ).start()
        probe = self.connect("hb-quic")
        self.assertIsNone(probe.error)
        record = self.listener.wait_for_probe(timeout=10, probe_id="hb-quic")
        before = record["last_seen"]
        time.sleep(0.8)
        rows = [row for row in self.listener.records() if row["probe_id"] == "hb-quic"]
        self.assertGreater(rows[0]["last_seen"], before)
        probe.stop()
        deadline = time.time() + 5
        while time.time() < deadline:
            rows = [row for row in self.listener.records() if row["probe_id"] == "hb-quic"]
            if rows and rows[0]["status"] == "offline":
                break
            time.sleep(0.1)
        self.assertEqual(rows[0]["status"], "offline")

    def test_quic_reconnect_replaces_same_probe_id(self):
        first = self.connect("re-quic")
        self.listener.wait_for_probe(timeout=10, probe_id="re-quic")
        first.stop()
        time.sleep(0.2)
        second = self.connect("re-quic")
        deadline = time.time() + 10
        rows = []
        while time.time() < deadline:
            rows = [row for row in self.listener.records()
                    if row["probe_id"] == "re-quic"]
            if rows and rows[0].get("replaced"):
                break
            time.sleep(0.1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["replaced"])
        self.assertEqual(rows[0]["status"], "online")
        self.assertIsNone(second.error)

    def test_quic_state_file_records_transport(self):
        self.connect("state-quic")
        self.listener.wait_for_probe(timeout=10, probe_id="state-quic")
        document = __import__("json").loads(
            reverse_paths(self.home, "ws")["probes"].read_text(encoding="utf-8")
        )
        self.assertEqual(document["transport"], "quic")
        self.assertEqual(document["probes"][0]["transport"], "quic")
        self.assertIn("fallback_transport", document)


class TestQuicConcurrency(_QuicCase):
    def test_twenty_concurrent_quic_probes(self):
        probes = []
        try:
            for index in range(20):
                probe = FakeQuicReverseProbe(
                    "127.0.0.1", self.listener.port, TOKEN, f"q{index}",
                    parent_id=None if index == 0 else "q0",
                    transport="quic", ca_file=self.material["ca_file"],
                    pin=self.material["pin"], sni="127.0.0.1",
                    connect_timeout=20,
                )
                probes.append(probe)
                probe.start()
            for index in range(20):
                self.listener.wait_for_probe(timeout=40, probe_id=f"q{index}")
            rows = self.listener.records()
            self.assertEqual(len(rows), 20)
            self.assertEqual(sum(1 for row in rows if row["status"] == "online"), 20)
            self.assertEqual(self.listener.collect("q7")["probe_id"], "q7")
        finally:
            for probe in probes:
                probe.stop()


class TestWebTransport(_QuicCase):
    transport = "webtransport"

    def test_webtransport_handshake_collect_exec(self):
        probe = self.connect("wt-parent")
        self.assertIsNone(probe.error, probe.error)
        record = self.listener.wait_for_probe(timeout=15, probe_id="wt-parent")
        self.assertEqual(record["transport"], "webtransport")
        self.assertEqual(self.listener.collect("wt-parent")["probe_id"], "wt-parent")
        result = self.listener.perform_exec(
            "wt-parent", [sys.executable, "-c", "print('wt-exec-ok')"]
        )
        self.assertIn("wt-exec-ok", result["stdout"])
        self.assertEqual(self.listener.status()["quic"]["webtransport_sessions"], 1)

    def test_webtransport_wrong_path_is_rejected(self):
        probe = self.connect("wt-path", path="/wrong")
        self.assertIsNotNone(probe.error)
        self.assertEqual(self.listener.online_count(), 0)

    def test_webtransport_wrong_token_is_rejected(self):
        probe = self.connect("wt-token", token="wrong-token")
        self.assertIsNotNone(probe.error)
        deadline = time.time() + 3
        while time.time() < deadline and self.listener.auth_failures < 1:
            time.sleep(0.05)
        self.assertEqual(self.listener.online_count(), 0)
        self.assertGreaterEqual(self.listener.auth_failures, 1)


class TestMasque(_QuicCase):
    transport = "masque"

    def test_connect_udp_echo_through_probe(self):
        echo = _UdpEcho()
        probe = FakeReverseProbe(
            "127.0.0.1", self.listener.port, TOKEN, "masque-probe",
            transport="tls", ca_file=self.material["ca_file"],
            pin=self.material["pin"], sni="127.0.0.1",
        )
        self.probes.append(probe)
        probe.start()
        probe.ready.wait(timeout=10)
        try:
            self.listener.wait_for_probe(timeout=10, probe_id="masque-probe")
            client = MasqueClient(
                "127.0.0.1", self.listener.port,
                target_host="127.0.0.1", target_port=echo.port,
                token=TOKEN, ca_file=self.material["ca_file"],
                pin=self.material["pin"], probe_id="masque-probe",
            )
            try:
                self.assertEqual(client.status, 200)
                for index in range(3):
                    client.send_udp(b"masque-%d" % index)
                    self.assertEqual(client.recv_udp(5), b"echo:masque-%d" % index)
            finally:
                client.close()
            self.assertGreater(
                self.listener.status()["quic"]["masque_relays"], 0
            )
        finally:
            echo.close()

    def test_connect_udp_bad_token_is_rejected(self):
        echo = _UdpEcho()
        probe = FakeReverseProbe(
            "127.0.0.1", self.listener.port, TOKEN, "masque-probe",
            transport="tls", ca_file=self.material["ca_file"],
            pin=self.material["pin"], sni="127.0.0.1",
        )
        self.probes.append(probe)
        probe.start()
        probe.ready.wait(timeout=10)
        try:
            self.listener.wait_for_probe(timeout=10, probe_id="masque-probe")
            with self.assertRaises(Exception):
                MasqueClient(
                    "127.0.0.1", self.listener.port,
                    target_host="127.0.0.1", target_port=echo.port,
                    token="wrong-token", ca_file=self.material["ca_file"],
                    pin=self.material["pin"], probe_id="masque-probe",
                )
        finally:
            echo.close()


class TestFallbackMarker(unittest.TestCase):
    def test_tls_fallback_is_marked_in_record(self):
        temp = tempfile.TemporaryDirectory()
        home = Path(temp.name)
        material = ensure_tls_material(home / "tls", hosts=["127.0.0.1"])
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10, home=home,
            workspace="ws", transport="quic", tls_material=material,
            ping_interval=0, idle_timeout=0,
        ).start()
        probe = FakeReverseProbe(
            "127.0.0.1", listener.port, TOKEN, "fallback-probe",
            transport="tls", ca_file=material["ca_file"],
            pin=material["pin"], sni="127.0.0.1", fallback_from="quic",
        )
        try:
            probe.start()
            probe.ready.wait(timeout=10)
            record = listener.wait_for_probe(timeout=10, probe_id="fallback-probe")
            self.assertEqual(record["transport"], "tls")
            self.assertTrue(record["fallback"])
            self.assertEqual(record["fallback_from"], "quic")
        finally:
            probe.stop()
            listener.stop()
            temp.cleanup()

    def test_wss_fallback_is_marked_in_record(self):
        temp = tempfile.TemporaryDirectory()
        home = Path(temp.name)
        material = ensure_tls_material(home / "tls", hosts=["127.0.0.1"])
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=10, home=home,
            workspace="ws", transport="quic", tls_material=material,
            fallback_transport="wss", ping_interval=0, idle_timeout=0,
        ).start()
        probe = FakeReverseProbe(
            "127.0.0.1", listener.fallback_port, TOKEN, "fallback-wss",
            transport="wss", ca_file=material["ca_file"],
            pin=material["pin"], sni="127.0.0.1", fallback_from="quic",
        )
        try:
            probe.start()
            probe.ready.wait(timeout=10)
            record = listener.wait_for_probe(timeout=10, probe_id="fallback-wss")
            self.assertEqual(record["transport"], "wss")
            self.assertTrue(record["fallback"])
        finally:
            probe.stop()
            listener.stop()
            temp.cleanup()

    def test_controller_udp_bind_failure_keeps_tls_fallback(self):
        temp = tempfile.TemporaryDirectory()
        home = Path(temp.name)
        material = ensure_tls_material(home / "tls", hosts=["127.0.0.1"])
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        port = blocker.getsockname()[1]
        listener = None
        probe = None
        try:
            listener = ReverseListener(
                TOKEN, bind="127.0.0.1", port=port, timeout=10, home=home,
                workspace="ws", transport="quic", tls_material=material,
                ping_interval=0, idle_timeout=0,
            ).start()
            self.assertTrue(listener.status()["quic_error"])
            self.assertEqual(listener.fallback_port, port)
            probe = FakeReverseProbe(
                "127.0.0.1", listener.fallback_port, TOKEN, "udp-blocked-ctl",
                transport="tls", ca_file=material["ca_file"],
                pin=material["pin"], sni="127.0.0.1", fallback_from="quic",
            )
            probe.start()
            probe.ready.wait(timeout=10)
            record = listener.wait_for_probe(timeout=10, probe_id="udp-blocked-ctl")
            self.assertEqual(record["transport"], "tls")
            self.assertTrue(record["fallback"])
        finally:
            if probe is not None:
                probe.stop()
            if listener is not None:
                listener.stop()
            blocker.close()
            temp.cleanup()


class TestCliEntry(unittest.TestCase):
    @unittest.skipUnless(HAS_AIOQUIC, "aioquic is not installed")
    def test_cli_listen_accepts_quic_transport(self):
        import argparse
        from inkblade import reverse as reverse_module

        temp = tempfile.TemporaryDirectory()
        home = Path(temp.name)
        tls_dir = home / "cli-tls"
        material = ensure_tls_material(tls_dir, hosts=["127.0.0.1"])
        token_file = home / "probe.token"
        token_file.write_text(TOKEN, encoding="utf-8")
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        args = argparse.Namespace(
            token_file=str(token_file), transport="quic", lab_plaintext=False,
            tls_host=[], tls_cert=None, tls_key=None, tls_ca=None,
            sni=None, tls_dir=str(tls_dir), tls_days=3650,
            bind="127.0.0.1", port=port, timeout=15.0, workspace="ws",
            no_control=True, max_probes=0, max_pending=64,
            ping_interval=0, idle_timeout=0, wss_path="/ws",
            poll_path="/v1/probe/poll", result_path="/v1/probe/result",
            webtransport_path="/inkblade/wt",
            masque_path="/.well-known/masque/udp",
            fallback="tls", user_agent="", json=True, once=True,
            exec_action="collect", op=None, args_json="{}", argv=[],
            duration=0.0,
        )
        codes: list[int] = []
        thread = threading.Thread(
            target=lambda: codes.append(reverse_module.cli_listen(args, home)),
            daemon=True,
        )
        thread.start()
        probe = None
        try:
            time.sleep(1.5)
            probe = FakeQuicReverseProbe(
                "127.0.0.1", port, TOKEN, "cli-quic",
                transport="quic", ca_file=material["ca_file"],
                pin=material["pin"], sni="127.0.0.1",
            )
            probe.start()
            probe.ready.wait(timeout=15)
            self.assertIsNone(probe.error)
            thread.join(timeout=20)
            self.assertFalse(thread.is_alive())
            self.assertEqual(codes, [0])
        finally:
            if probe is not None:
                probe.stop()
            temp.cleanup()


def _shell_argv() -> list[str]:
    if os.name == "nt":
        return ["cmd", "/c", "echo", "rust-quic-ok"]
    return ["sh", "-c", "echo rust-quic-ok"]


def _shell_cmd() -> list[str]:
    return ["--allow-cmd", "cmd"] if os.name == "nt" else ["--allow-cmd", "sh"]


@unittest.skipUnless(BINARY is not None, "no runnable Rust probe binary")
class TestRustQuic(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.material = ensure_tls_material(
            self.home / "tls", hosts=["127.0.0.1", "localhost"]
        )
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        self.temp.cleanup()

    def _start(
        self,
        port: int,
        probe_id: str,
        *extra: str,
        transport: str = "quic",
        fallback: str = "",
        connect_timeout_ms: int = 0,
    ) -> subprocess.Popen:
        command = [
            str(BINARY), "reverse", "--transport", transport,
            "--host", "127.0.0.1", "--port", str(port),
            "--ca-file", self.material["ca_file"],
            "--pin", self.material["pin"],
            "--sni", "127.0.0.1", "--token", TOKEN,
            "--probe-id", probe_id, "--no-reconnect", "--allow-write",
            *_shell_cmd(), *extra,
        ]
        if fallback:
            command += ["--fallback", fallback]
        if connect_timeout_ms:
            command += ["--connect-timeout-ms", str(connect_timeout_ms)]
        proc = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
        self.procs.append(proc)
        return proc

    def test_rust_udp_blocked_without_fallback_reports(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        port = blocker.getsockname()[1]
        try:
            proc = subprocess.Popen(
                [
                    str(BINARY), "reverse", "--transport", "quic",
                    "--fallback", "none", "--host", "127.0.0.1",
                    "--port", str(port), "--ca-file", self.material["ca_file"],
                    "--pin", self.material["pin"], "--sni", "127.0.0.1",
                    "--token", TOKEN, "--probe-id", "rust-no-fallback",
                    "--no-reconnect", "--read-only",
                    "--connect-timeout-ms", "1000",
                ],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            )
            self.procs.append(proc)
            _stdout, stderr = proc.communicate(timeout=15)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("udp-blocked", stderr.lower())
        finally:
            blocker.close()

    def test_rust_quic_collect_exec(self):
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=20, home=self.home,
            workspace="ws", transport="quic", tls_material=self.material,
            ping_interval=0, idle_timeout=0,
        ).start()
        try:
            self._start(listener.port, "rust-quic")
            record = listener.wait_for_probe(timeout=25, probe_id="rust-quic")
            self.assertEqual(record["transport"], "quic")
            self.assertEqual(listener.collect("rust-quic")["probe_id"], "rust-quic")
            result = listener.perform_exec("rust-quic", _shell_argv(), timeout=20)
            self.assertEqual(result.get("exit_code"), 0, result)
            self.assertIn("rust-quic-ok", result.get("stdout", ""))
        finally:
            listener.stop()

    def test_rust_udp_op(self):
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=20, home=self.home,
            workspace="ws", transport="quic", tls_material=self.material,
            ping_interval=0, idle_timeout=0,
        ).start()
        echo = _UdpEcho()
        try:
            self._start(listener.port, "rust-udp")
            listener.wait_for_probe(timeout=25, probe_id="rust-udp")
            probe = listener.connection("rust-udp")
            bound = probe.udp_bind()
            self.assertTrue(bound["socket"])
            probe.udp_send(bound["socket"], "127.0.0.1", echo.port, b"rust-udp")
            reply = probe.udp_recv(bound["socket"], timeout_ms=3000)
            self.assertEqual(__import__("base64").b64decode(reply["data_b64"]),
                             b"echo:rust-udp")
            probe.udp_close(bound["socket"])
        finally:
            echo.close()
            listener.stop()

    def test_rust_udp_blocked_falls_back_to_tls(self):
        listener = ReverseListener(
            TOKEN, bind="127.0.0.1", port=0, timeout=30, home=self.home,
            workspace="ws", transport="tls", tls_material=self.material,
            ping_interval=0, idle_timeout=0,
        ).start()
        try:
            self._start(
                listener.port, "rust-fallback",
                transport="quic", fallback="tls", connect_timeout_ms=2000,
            )
            record = listener.wait_for_probe(timeout=30, probe_id="rust-fallback")
            self.assertEqual(record["transport"], "tls")
            self.assertTrue(record["fallback"])
            self.assertEqual(record["fallback_from"], "quic")
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
