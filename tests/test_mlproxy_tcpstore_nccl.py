# -*- coding: utf-8 -*-
"""P4 TCPStore/Gloo TLS relay and P6 NCCL/UCX TCP profile tests."""

from __future__ import annotations

import hashlib
import hmac
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from inkblade.channel import ProbeConnection
from inkblade.mlproxy import NcclTlsProxy, TcpStoreTlsProxy
from inkblade.reverse import ensure_tls_material

FAKE = Path(__file__).with_name("fake_probe.py")
TOKEN = "tcp-relay-token"


class EchoServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
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
            try:
                client.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class TcpRelayCase(unittest.TestCase):
    def setUp(self):
        self.probe = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "probe-token"],
            "probe-token", timeout=10,
        ).start()
        self.material = ensure_tls_material(
            Path(tempfile.gettempdir()) / f"inkblade-tcp-relay-{id(self)}",
            hosts=["127.0.0.1", "localhost"],
        )

    def tearDown(self):
        self.probe.close()

    def _client(self, port: int):
        context = ssl.create_default_context(cafile=self.material["ca_file"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        self.assertEqual(
            hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest(),
            self.material["pin"],
        )
        return tls

    @staticmethod
    def _line(sock: socket.socket) -> str:
        data = bytearray()
        while len(data) < 512:
            chunk = sock.recv(1)
            if not chunk:
                break
            if chunk == b"\n":
                return data.decode("ascii", "replace").rstrip("\r")
            data.extend(chunk)
        return data.decode("ascii", "replace")

    def _auth(self, tls, token: str = TOKEN) -> bool:
        line = self._line(tls)
        if not line.startswith("INKBLADE-AUTH "):
            return False
        nonce = line.split(" ", 1)[1]
        mac = hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        tls.sendall((mac + "\n").encode("ascii"))
        return self._line(tls) == "INKBLADE-OK"


class TestTcpStoreTlsProxy(TcpRelayCase):
    def test_hmac_preamble_and_echo(self):
        target = EchoServer()
        proxy = TcpStoreTlsProxy(
            self.probe, target_host="127.0.0.1", target_port=target.port,
            token=TOKEN, tls_material=self.material, keepalive_s=0.2,
        ).start()
        try:
            tls = self._client(proxy.port_map[0]["local"])
            try:
                self.assertTrue(self._auth(tls))
                tls.sendall(b"tcpstore-echo")
                self.assertEqual(tls.recv(13), b"tcpstore-echo")
                time.sleep(0.6)
                status = proxy.status()
                self.assertEqual(status["protocol"], "tcpstore-tls")
                self.assertGreaterEqual(status["keepalive"]["pings"], 1)
                self.assertEqual(status["keepalive"]["failures"], 0)
                self.assertNotIn(TOKEN, str(status))
            finally:
                tls.close()
        finally:
            proxy.stop()
            target.close()

    def test_wrong_hmac_is_rejected(self):
        target = EchoServer()
        proxy = TcpStoreTlsProxy(
            self.probe, target_host="127.0.0.1", target_port=target.port,
            token=TOKEN, tls_material=self.material,
        ).start()
        try:
            tls = self._client(proxy.port_map[0]["local"])
            try:
                self.assertFalse(self._auth(tls, token="wrong"))
                self.assertGreaterEqual(proxy.auth_failures, 1)
            finally:
                tls.close()
        finally:
            proxy.stop()
            target.close()

    def test_plaintext_is_not_relayed(self):
        target = EchoServer()
        proxy = TcpStoreTlsProxy(
            self.probe, target_host="127.0.0.1", target_port=target.port,
            token=TOKEN, tls_material=self.material,
        ).start()
        try:
            raw = socket.create_connection(
                ("127.0.0.1", proxy.port_map[0]["local"]), timeout=3
            )
            raw.sendall(b"plaintext-before-tls")
            try:
                self.assertIn(raw.recv(16), (b"",))
            except OSError:
                pass
            raw.close()
            deadline = time.time() + 3
            while proxy.errors < 1 and time.time() < deadline:
                time.sleep(0.05)
            self.assertGreaterEqual(proxy.errors, 1)
        finally:
            proxy.stop()
            target.close()


class TestNcclTlsProxy(TcpRelayCase):
    def test_port_mapping_and_echo(self):
        first = EchoServer()
        second = EchoServer()
        proxy = NcclTlsProxy(
            self.probe, target_host="127.0.0.1",
            port_spec=f"{first.port},{second.port}", protocol="nccl",
            token=TOKEN, tls_material=self.material, keepalive_s=0.2,
        ).start()
        try:
            self.assertEqual(len(proxy.port_map), 2)
            for row in proxy.port_map:
                tls = self._client(row["local"])
                try:
                    self.assertTrue(self._auth(tls))
                    payload = f"nccl-{row['target_port']}".encode()
                    tls.sendall(payload)
                    self.assertEqual(tls.recv(len(payload)), payload)
                finally:
                    tls.close()
            status = proxy.status()
            self.assertEqual(status["protocol"], "nccl-tcp-tls")
            self.assertFalse(status["rdma_verbs"])
            self.assertEqual(len(status["ports"]), 2)
        finally:
            proxy.stop()
            first.close()
            second.close()

    def test_invalid_port_spec(self):
        with self.assertRaises(Exception):
            NcclTlsProxy(
                self.probe, target_host="127.0.0.1", port_spec="not-a-port",
                token=TOKEN, tls_material=self.material,
            )


if __name__ == "__main__":
    unittest.main()
