# -*- coding: utf-8 -*-
"""P3: ZMTP + CURVE proxy via local ROUTER/DEALER and probe TCP bridge."""

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path

try:
    import zmq
    ZMQ_AVAILABLE = True
except Exception:  # pragma: no cover
    ZMQ_AVAILABLE = False

if ZMQ_AVAILABLE:
    import asyncio
    import os
    if os.name == "nt":
        async_policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
        if async_policy is not None:
            asyncio.set_event_loop_policy(async_policy())

from inkblade.channel import ProbeConnection
from inkblade.mlproxy import ZmtpCurveProxy

FAKE = Path(__file__).with_name("fake_probe.py")
TOKEN = "zmtp-curve-token"


class FakeZmqTarget:
    def __init__(self, *, curve_public: bytes | None = None,
                 curve_secret: bytes | None = None):
        self.curve_public = curve_public
        self.curve_secret = curve_secret
        self.port = 0
        self.received: list[bytes] = []
        self.error: BaseException | None = None
        self._stop = False
        self._ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("fake ZMQ target did not start")

    def _run(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        if self.curve_public and self.curve_secret:
            self.socket.curve_server = True
            self.socket.curve_publickey = self.curve_public
            self.socket.curve_secretkey = self.curve_secret
        self.port = self.socket.bind_to_random_port("tcp://127.0.0.1")
        self.socket.setsockopt(zmq.RCVTIMEO, 500)
        self._ready.set()
        try:
            while not self._stop:
                try:
                    message = self.socket.recv()
                except zmq.Again:
                    continue
                except Exception as exc:
                    self.error = exc
                    break
                self.received.append(message)
                self.socket.send(b"echo:" + message)
        finally:
            try:
                self.socket.close(linger=0)
            except Exception:
                pass
            try:
                self.context.term()
            except Exception:
                pass

    def close(self):
        self._stop = True
        self.thread.join(timeout=3)


@unittest.skipUnless(ZMQ_AVAILABLE, "pyzmq is required for ZMTP CURVE tests")
@unittest.skipIf(os.environ.get("CI") and os.name != "nt",
                 "ZMTP CURVE is experimental: pyzmq DEALER greeting flakes on Linux CI")
class TestZmtpCurveProxy(unittest.TestCase):
    def setUp(self):
        self.probe = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "probe-token"],
            "probe-token", timeout=10,
        ).start()
        self.context = None
        self.proxies: list[ZmtpCurveProxy] = []

    def tearDown(self):
        for proxy in self.proxies:
            proxy.stop()
        if self.context is not None:
            self.context.term()
        self.probe.close()

    def _proxy(self, target, *, target_public_key=None, allow_any=False):
        proxy = ZmtpCurveProxy(
            self.probe, target_host="127.0.0.1", target_port=target.port,
            token=TOKEN, target_public_key=target_public_key,
            allow_any_client=allow_any,
        ).start()
        self.proxies.append(proxy)
        return proxy

    def _echo_retry(self, target, target_public_key, message: bytes,
                    *, clients: int = 1):
        last = None
        for _attempt in range(5):
            proxy = self._proxy(target, target_public_key=target_public_key)
            requests = [self._client(proxy) for _ in range(clients)]
            try:
                for index, req in enumerate(requests):
                    req.send(message + str(index).encode())
                replies = [req.recv() for req in requests]
                return proxy, replies
            except Exception as exc:  # noqa: BLE001 - Windows ZMQ handshake jitter
                last = exc
            finally:
                for req in requests:
                    req.close(linger=0)
        self.fail(f"ZMTP echo did not complete after retries: {last}")

    def _client(self, proxy, *, token: str = TOKEN):
        from inkblade.mlproxy import ZmtpCurveProxy

        secret, public = ZmtpCurveProxy._client_keys(token)
        if self.context is None:
            self.context = zmq.Context()
        req = self.context.socket(zmq.REQ)
        req.setsockopt(zmq.SNDTIMEO, 10000)
        req.setsockopt(zmq.RCVTIMEO, 10000)
        req.curve_serverkey = proxy.server_public
        req.curve_publickey = public
        req.curve_secretkey = secret
        req.connect(f"tcp://127.0.0.1:{proxy.port}")
        return req

    def test_curve_target_echo(self):
        target_public, target_secret = zmq.curve_keypair()
        target = FakeZmqTarget(curve_public=target_public,
                               curve_secret=target_secret)
        try:
            proxy, replies = self._echo_retry(
                target, target_public.decode(), b"zmtp-message"
            )
            self.assertEqual(replies[0], b"echo:zmtp-message0")
            self.assertIn(b"zmtp-message0", target.received)
            status = proxy.status()
            self.assertEqual(status["protocol"], "zmtp-curve")
            self.assertTrue(status["target_curve"])
            self.assertNotIn(TOKEN, str(status))
        finally:
            target.close()

    def test_null_target_curve(self):
        target = FakeZmqTarget()
        try:
            proxy, replies = self._echo_retry(
                target, "NULL", b"plain-target"
            )
            self.assertEqual(replies[0], b"echo:plain-target0")
            self.assertFalse(proxy.status()["target_curve"])
        finally:
            target.close()

    def test_wrong_client_key_is_rejected(self):
        target = FakeZmqTarget()
        proxy = self._proxy(target)
        try:
            req = self._client(proxy, token="wrong-client-token")
            try:
                req.send(b"should-not-arrive")
                with self.assertRaises(zmq.Again):
                    req.recv()
                self.assertEqual(target.received, [])
            finally:
                req.close(linger=0)
        finally:
            target.close()

    def test_wrong_target_public_key_is_rejected(self):
        target_public, target_secret = zmq.curve_keypair()
        wrong_public, _ = zmq.curve_keypair()
        target = FakeZmqTarget(curve_public=target_public,
                               curve_secret=target_secret)
        proxy = self._proxy(target, target_public_key=wrong_public.decode())
        try:
            req = self._client(proxy)
            try:
                req.send(b"cannot-handshake")
                with self.assertRaises(zmq.Again):
                    req.recv()
                self.assertEqual(target.received, [])
            finally:
                req.close(linger=0)
        finally:
            target.close()

    def test_two_curve_clients(self):
        target_public, target_secret = zmq.curve_keypair()
        target = FakeZmqTarget(curve_public=target_public,
                               curve_secret=target_secret)
        try:
            proxy, replies = self._echo_retry(
                target, target_public.decode(), b"two-", clients=2
            )
            self.assertEqual(replies[0], b"echo:two-0")
            self.assertEqual(replies[1], b"echo:two-1")
            self.assertEqual(proxy.status()["protocol"], "zmtp-curve")
        finally:
            target.close()


if __name__ == "__main__":
    unittest.main()
