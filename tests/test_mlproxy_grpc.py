# -*- coding: utf-8 -*-
"""P1: gRPC over TLS proxy (Triton 8001 / Ray 8265 shape).

The fake target speaks HTTP/2 + gRPC length-prefixed messages and echoes
bidirectional DATA frames.  The proxy must terminate local TLS, authenticate a
bearer token in gRPC metadata, inject that metadata toward the target, and
multiplex the stream through the probe's encrypted transport.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded
    H2_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    H2_AVAILABLE = False

from inkblade.channel import ProbeConnection
from inkblade.mlproxy import GrpcTlsProxy
from inkblade.reverse import ensure_tls_material

ROOT = Path(__file__).resolve().parents[1]
FAKE = Path(__file__).with_name("fake_probe.py")
TOKEN = "grpc-proxy-token"


class FakeGrpcTarget:
    """Plaintext HTTP/2 target that echoes gRPC DATA frames."""

    def __init__(self, token: str = TOKEN):
        self.token = token
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.seen_metadata: list[dict[str, str]] = []
        self.received: list[bytes] = []
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
        if not H2_AVAILABLE:
            client.close()
            return
        h2 = H2Connection(config=H2Configuration(
            client_side=False, header_encoding="utf-8"
        ))
        h2.initiate_connection()
        client.sendall(h2.data_to_send())
        authorized: set[int] = set()
        try:
            while not self._stop:
                data = client.recv(65536)
                if not data:
                    break
                events = h2.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        metadata = {name.lower(): value for name, value in event.headers}
                        self.seen_metadata.append(metadata)
                        token = metadata.get("authorization", "")
                        if token.lower().startswith("bearer "):
                            token = token[7:]
                        if token != self.token:
                            h2.send_headers(event.stream_id, [
                                (":status", "200"),
                                ("content-type", "application/grpc"),
                                ("grpc-status", "16"),
                                ("grpc-message", "unauthenticated"),
                            ], end_stream=True)
                            continue
                        authorized.add(event.stream_id)
                        h2.send_headers(event.stream_id, [
                            (":status", "200"),
                            ("content-type", "application/grpc"),
                        ])
                    elif isinstance(event, DataReceived):
                        h2.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                        if event.stream_id in authorized:
                            self.received.append(event.data)
                            h2.send_data(event.stream_id, event.data)
                    elif isinstance(event, StreamEnded):
                        if event.stream_id in authorized:
                            h2.send_headers(
                                event.stream_id, [("grpc-status", "0")],
                                end_stream=True,
                            )
                pending = h2.data_to_send()
                if pending:
                    client.sendall(pending)
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


def _grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


@unittest.skipUnless(H2_AVAILABLE, "h2 is required for the gRPC TLS proxy test")
class TestGrpcTlsProxy(unittest.TestCase):
    def setUp(self):
        self.probe = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "probe-token"],
            "probe-token", timeout=10,
        ).start()
        self.target = FakeGrpcTarget()
        self.material = ensure_tls_material(
            Path(tempfile.gettempdir()) / f"inkblade-grpc-test-{id(self)}",
            hosts=["127.0.0.1", "localhost"],
        )
        self.proxy = GrpcTlsProxy(
            self.probe, target_host="127.0.0.1", target_port=self.target.port,
            token=TOKEN, tls_material=self.material,
        ).start()

    def tearDown(self):
        self.proxy.stop()
        self.target.close()
        self.probe.close()

    def _client(self, token: str = TOKEN):
        context = ssl.create_default_context(cafile=self.material["ca_file"])
        raw = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5)
        tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        der = tls.getpeercert(binary_form=True)
        self.assertEqual(hashlib.sha256(der).hexdigest(), self.material["pin"])
        h2 = H2Connection(config=H2Configuration(
            client_side=True, header_encoding="utf-8"
        ))
        h2.initiate_connection()
        tls.sendall(h2.data_to_send())
        headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "triton.local:8001"),
            (":path", "/inkblade.Echo/Stream"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("authorization", f"Bearer {token}"),
        ]
        h2.send_headers(1, headers)
        tls.sendall(h2.data_to_send())
        return tls, h2

    def _read_client(self, tls, h2, timeout: float = 5.0):
        deadline = time.time() + timeout
        events = []
        while time.time() < deadline:
            tls.settimeout(max(0.1, deadline - time.time()))
            try:
                data = tls.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            events.extend(h2.receive_data(data))
            if any(isinstance(item, (StreamEnded,)) for item in events):
                break
            if any(isinstance(item, DataReceived) for item in events):
                # Keep reading briefly for the second echo/trailer.
                continue
        return events

    def test_bidi_stream_echo_and_metadata(self):
        tls, h2 = self._client()
        try:
            first = _grpc_frame(b"first-message")
            second = _grpc_frame(b"second-message")
            h2.send_data(1, first)
            h2.send_data(1, second)
            tls.sendall(h2.data_to_send())
            seen = b""
            deadline = time.time() + 5
            while time.time() < deadline and seen.count(b"first-message") == 0:
                tls.settimeout(max(0.1, deadline - time.time()))
                data = tls.recv(65536)
                events = h2.receive_data(data)
                for event in events:
                    if isinstance(event, DataReceived):
                        seen += event.data
            self.assertIn(first, seen)
            self.assertEqual(self.target.received, [first, second])
            metadata = self.target.seen_metadata[0]
            self.assertEqual(metadata.get("authorization"), f"Bearer {TOKEN}")
            self.assertEqual(metadata.get("x-inkblade-token"), TOKEN)
            self.assertEqual(self.proxy.status()["protocol"], "grpc-tls")
            self.assertEqual(self.proxy.status()["tls"]["pin"], self.material["pin"])
        finally:
            tls.close()

    def test_wrong_token_is_rejected_before_upstream(self):
        tls, h2 = self._client(token="wrong-token")
        try:
            events = self._read_client(tls, h2)
            headers = {}
            for event in events:
                if isinstance(event, ResponseReceived):
                    headers.update(dict(event.headers))
            self.assertEqual(headers.get("grpc-status"), "16")
            self.assertGreaterEqual(self.proxy.auth_failures, 1)
            self.assertEqual(self.target.seen_metadata, [])
        finally:
            tls.close()

    def test_missing_token_is_rejected(self):
        context = ssl.create_default_context(cafile=self.material["ca_file"])
        raw = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5)
        tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        h2 = H2Connection(config=H2Configuration(
            client_side=True, header_encoding="utf-8"
        ))
        h2.initiate_connection()
        tls.sendall(h2.data_to_send())
        h2.send_headers(1, [
            (":method", "POST"), (":scheme", "https"), (":authority", "ray:8265"),
            (":path", "/ray.rpc/RayletState"), ("content-type", "application/grpc"),
        ])
        tls.sendall(h2.data_to_send())
        try:
            headers = {}
            deadline = time.time() + 5
            while time.time() < deadline:
                tls.settimeout(max(0.1, deadline - time.time()))
                data = tls.recv(65536)
                for event in h2.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        headers.update(dict(event.headers))
                if headers:
                    break
            self.assertEqual(headers.get("grpc-status"), "16")
            self.assertEqual(self.target.seen_metadata, [])
        finally:
            tls.close()


if __name__ == "__main__":
    unittest.main()
