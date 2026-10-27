# -*- coding: utf-8 -*-
"""P2: Redis RESP over TLS proxy (Ray GCS 6379 shape)."""

from __future__ import annotations

import hashlib
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from inkblade.channel import ProbeConnection
from inkblade.mlproxy import RedisTlsProxy
from inkblade.reverse import ensure_tls_material

FAKE = Path(__file__).with_name("fake_probe.py")
TOKEN = "redis-proxy-token"


class FakeRedisTarget:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop:
            try:
                client, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        try:
            buffer = b""
            while not self._stop:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\r\n" in buffer:
                    line, _, buffer = buffer.partition(b"\r\n")
                    command = line.decode("utf-8", "replace").upper()
                    if command == "PING":
                        client.sendall(b"+PONG\r\n")
                    elif command == "SET":
                        client.sendall(b"+OK\r\n")
                    elif command == "GET":
                        client.sendall(b"$0\r\n\r\n")
                    elif command:
                        client.sendall(b"+OK\r\n")
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


def _resp(*args: str) -> bytes:
    out = f"*{len(args)}\r\n".encode()
    for arg in args:
        raw = arg.encode("utf-8")
        out += f"${len(raw)}\r\n".encode() + raw + b"\r\n"
    return out


class TestRedisTlsProxy(unittest.TestCase):
    def setUp(self):
        self.probe = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "probe-token"],
            "probe-token", timeout=10,
        ).start()
        self.target = FakeRedisTarget()
        self.material = ensure_tls_material(
            Path(tempfile.gettempdir()) / f"inkblade-redis-test-{id(self)}",
            hosts=["127.0.0.1", "localhost"],
        )
        self.proxy = RedisTlsProxy(
            self.probe, target_host="127.0.0.1", target_port=self.target.port,
            token=TOKEN, tls_material=self.material,
        ).start()

    def tearDown(self):
        self.proxy.stop()
        self.target.close()
        self.probe.close()

    def _client(self):
        context = ssl.create_default_context(cafile=self.material["ca_file"])
        raw = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5)
        tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        self.assertEqual(
            hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest(),
            self.material["pin"],
        )
        return tls

    @staticmethod
    def _line(sock: socket.socket) -> bytes:
        data = b""
        while not data.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def test_auth_then_ping(self):
        client = self._client()
        try:
            client.sendall(_resp("AUTH", TOKEN))
            self.assertEqual(self._line(client), b"+OK\r\n")
            client.sendall(b"PING\r\n")
            self.assertEqual(self._line(client), b"+PONG\r\n")
            status = self.proxy.status()
            self.assertEqual(status["protocol"], "redis-resp-tls")
            self.assertEqual(status["tls"]["pin"], self.material["pin"])
            self.assertNotIn(TOKEN, str(status))
        finally:
            client.close()

    def test_wrong_token_is_rejected(self):
        client = self._client()
        try:
            client.sendall(_resp("AUTH", "wrong-token"))
            self.assertTrue(self._line(client).startswith(b"-ERR"))
            self.assertGreaterEqual(self.proxy.auth_failures, 1)
        finally:
            client.close()

    def test_auth_required(self):
        client = self._client()
        try:
            client.sendall(b"PING\r\n")
            self.assertTrue(self._line(client).startswith(b"-ERR AUTH"))
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
