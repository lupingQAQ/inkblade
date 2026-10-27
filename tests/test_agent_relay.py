# -*- coding: utf-8 -*-
"""Cross-cluster relay tests: fake kubectl/API, SOCKS5/dial, loops, budgets."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.agent.coverage import CoverageGraph, render_markdown
from inkblade.agent.graph import PlanGraph
from inkblade.agent.relay import (KubectlDeployer, ProbeDialer, RelayBudgetExceeded,
                                  RelayError, RelayLoopError, RelayManager,
                                  RelayRefused, RelayUnreachable, SocketStream,
                                  Socks5Dialer)
from inkblade.cli import main
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe

ROE = {"level": "全影响演示", "namespaces": ["train", "ml"],
       "cidrs": ["127.0.0.0/8"], "window": "2026-01-01 – 2030-12-31"}


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _ApiHandler(BaseHTTPRequestHandler):
    server_version = "FakeK8s/1.30"

    def do_GET(self):
        if self.path.startswith("/version") or self.path.startswith("/healthz"):
            body = json.dumps({
                "major": "1", "minor": "30",
                "gitVersion": "v1.30.0-fake",
                "cluster": getattr(self.server, "cluster_id", ""),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class FakeApi:
    def __init__(self, cluster_id: str):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ApiHandler)
        self.server.cluster_id = cluster_id
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name="fake-api", daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class FakeSocks5:
    """No-auth SOCKS5 CONNECT proxy for the two-cluster tests."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.url = f"socks5://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._accept, name="fake-socks",
                                       daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client: socket.socket):
        upstream = None
        try:
            head = _recv_exact(client, 2)
            methods = _recv_exact(client, head[1])
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")
            req = _recv_exact(client, 4)
            if req[0] != 5 or req[1] != 1:
                return
            atyp = req[3]
            if atyp == 1:
                host = socket.inet_ntoa(_recv_exact(client, 4))
            elif atyp == 3:
                host = _recv_exact(client, _recv_exact(client, 1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
            else:
                return
            port = int.from_bytes(_recv_exact(client, 2), "big")
            upstream = socket.create_connection((host, port), timeout=5)
            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            thread = threading.Thread(target=self._pump,
                                      args=(client, upstream), daemon=True)
            thread.start()
            self._pump(upstream, client)
            thread.join(timeout=5)
        except OSError:
            pass
        finally:
            for item in (client, upstream):
                if item is not None:
                    try:
                        item.close()
                    except OSError:
                        pass

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass


class FakeDeployer:
    def __init__(self, failures=None):
        self.calls: list[dict] = []
        self.failures = set(failures or ())

    def deploy(self, target, probe_id, *, via, binary=None, token=None):
        self.calls.append({
            "cluster_id": target.cluster_id, "probe_id": probe_id, "via": via,
            "kubeconfig": target.kubeconfig, "context": target.context,
            "namespace": target.namespace,
        })
        if (target.cluster_id, via) in self.failures:
            raise RelayUnreachable(
                f"fake kubectl failed for {target.cluster_id}/{via}")
        return {"ok": True, "transport": via, "endpoint": target.api_server,
                "pod": f"probe-{probe_id}",
                "evidence": sha(f"{target.cluster_id}|{probe_id}|{via}")}


class RecordingRunner:
    def __init__(self):
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        return {"ok": True, "returncode": 0, "stdout": "applied\n",
                "stderr": ""}


class ProbeStub:
    """Minimal object exposing the real ProbeConnection.dial contract."""

    def dial(self, host, port, timeout_ms=None):
        return SocketStream(socket.create_connection(
            (host, int(port)), timeout=max(1.0, (timeout_ms or 5000) / 1000)))


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = EvidenceStore(self.home, workspace="lab")
        init_roe(self.store, ROE)
        self.apis: list[FakeApi] = []
        self.proxies: list[FakeSocks5] = []

    def tearDown(self):
        for proxy in self.proxies:
            proxy.stop()
        for api in self.apis:
            api.stop()
        self.tmp.cleanup()

    def _api(self, cluster_id: str) -> FakeApi:
        api = FakeApi(cluster_id)
        self.apis.append(api)
        return api

    def _proxy(self) -> FakeSocks5:
        proxy = FakeSocks5()
        self.proxies.append(proxy)
        return proxy

    def _manager(self, *, coverage=None, deployer=None, store=None):
        return RelayManager(store=self.store if store is None else store,
                            deployer=deployer or FakeDeployer(),
                            coverage=coverage)

    def _two_clusters(self):
        api_a = self._api("A")
        api_b = self._api("B")
        proxy_a = self._proxy()
        proxy_b = self._proxy()
        coverage = CoverageGraph()
        deployer = FakeDeployer()
        manager = self._manager(coverage=coverage, deployer=deployer)
        manager.add_cluster(
            "A", kubeconfig="a.kubeconfig", context="ctx-a",
            api_server=api_a.url, namespace="ml", transport="kubectl",
            proxies=[proxy_a.url], roe_level="全影响演示",
            budget={"steps": 10, "actions": 20})
        manager.add_cluster(
            "B", parent_id="A", kubeconfig="b.kubeconfig", context="ctx-b",
            api_server=api_b.url, namespace="train", transport="kubectl",
            proxies=[proxy_b.url], roe_level="全影响演示",
            budget={"steps": 10, "actions": 20})
        return manager, coverage, deployer, api_a, api_b

    # ---------------------------------------------------------- deploy
    def test_two_cluster_cross_deploy_and_closure(self):
        manager, coverage, deployer, _, _ = self._two_clusters()
        first = manager.deploy("A", "probe-a1", via="kubectl")
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["status"], "ready")
        self.assertEqual(first["cluster_id"], "A")
        second = manager.deploy("B", "probe-b1", via="kubectl",
                                parent_id="probe-a1")
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["parent_id"], "probe-a1")
        self.assertEqual(second["parent_cluster_id"], "A")
        self.assertEqual(second["status"], "ready")
        self.assertEqual(len(deployer.calls), 2)
        self.assertEqual(deployer.calls[0]["context"], "ctx-a")
        self.assertEqual(deployer.calls[1]["context"], "ctx-b")
        self.assertEqual(deployer.calls[1]["namespace"], "train")

        # probes and parent edge are visible in relay and coverage
        status = manager.status()
        self.assertEqual(len(status["probes"]), 2)
        self.assertTrue(all(p["registered"] for p in status["probes"]))
        self.assertTrue(all(p["baseline_ok"] for p in status["probes"]))
        proof_edges = manager.proof()["edges"]
        self.assertTrue(any(e["src"] == "probe:A/probe-a1" and
                            e["dst"] == "probe:B/probe-b1"
                            for e in proof_edges))

        # SOCKS5 reachability (the probe/channel dial path) is used per cluster
        reached_a = manager.reach("A")
        self.assertTrue(reached_a["ok"], reached_a)
        self.assertEqual(reached_a["via"], "socks5")
        reached_b = manager.reach("B")
        self.assertEqual(reached_b["via"], "socks5")
        # direct ProbeDialer uses the existing probe dial contract unchanged
        probe_reached = manager.reach("A", dialer=ProbeDialer(ProbeStub()))
        self.assertTrue(probe_reached["ok"], probe_reached)
        self.assertEqual(probe_reached["via"], "dialer")

        # complete the declared asset/permission surface
        coverage.add_asset("asset:A/api", cluster_id="A", kind="workload",
                           name="api", namespace="ml")
        coverage.add_asset("asset:B/api", cluster_id="B", kind="workload",
                           name="api", namespace="train")
        coverage.add_identity("sa:A/agent", cluster_id="A", name="agent",
                              namespace="ml")
        coverage.add_permission("sa:A/agent", "asset:A/api", verb="get",
                                resource="secrets", scope="ml")
        edge = [e for e in coverage.edges() if e["relation"] == "can"][0]
        for cluster, probe, asset in (
                ("A", "probe-a1", "asset:A/api"),
                ("B", "probe-b1", "asset:B/api")):
            coverage.mark_check(
                asset, probe_id=CoverageGraph.probe_ref(cluster, probe),
                module="recon", mode="probe", ok=True,
                evidence=sha(f"check-{cluster}"), template="recon")
        coverage.mark_permission_attempt(edge["id"], outcome="blocked",
                                         reason="namespace RBAC denies secrets")
        manager.bind_graph(PlanGraph())
        closure = coverage.evaluate(graph=PlanGraph())
        self.assertTrue(closure["closed"], closure)
        self.assertEqual(manager.status()["gaps"], [])
        self.assertTrue(manager.status()["coverage_closed"])

    def test_duplicate_cluster_and_probe_are_prevented(self):
        manager, _, deployer, _, _ = self._two_clusters()
        duplicate = manager.add_cluster("A")
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(len(manager.list_clusters()), 2)
        first = manager.deploy("A", "p1", baseline=False)
        calls = len(deployer.calls)
        again = manager.deploy("A", "p1", baseline=False)
        self.assertTrue(again["duplicate"])
        self.assertEqual(len(deployer.calls), calls)
        self.assertTrue(any(p["kind"] == "duplicate-cluster"
                            for p in manager.prevented()))
        self.assertTrue(any(p["kind"] == "duplicate-probe"
                            for p in manager.prevented()))

    def test_cluster_parent_cycle_is_rejected(self):
        manager = self._manager()
        manager.add_cluster("A")
        manager.add_cluster("B", parent_id="A")
        manager.add_cluster("C", parent_id="B")
        with self.assertRaises(RelayLoopError):
            manager.add_cluster("A", parent_id="C", force=True)
        with self.assertRaises(RelayLoopError):
            manager.add_cluster("D", parent_id="D")
        self.assertTrue(any(p["kind"] == "cluster-cycle"
                            for p in manager.prevented()))

    def test_per_cluster_roe_and_budget_are_independent(self):
        api = self._api("A")
        low_store = EvidenceStore(self.home / "low-roe", workspace="lab")
        init_roe(low_store, {**ROE, "level": "主动探测"})
        manager = RelayManager(store=low_store, deployer=FakeDeployer())
        manager.add_cluster("A", api_server=api.url, roe_level="主动探测",
                            transport="kubectl",
                            budget={"steps": 1, "actions": 5})
        manager.add_cluster("B", api_server=api.url, roe_level="只读侦察",
                            transport="kubectl",
                            budget={"steps": 5, "actions": 5})
        first = manager.deploy("A", "p1", baseline=False)
        self.assertTrue(first["ok"], first)
        with self.assertRaises(RelayBudgetExceeded):
            manager.deploy("A", "p2", baseline=False)
        other = manager.deploy("B", "p1", baseline=False)
        self.assertTrue(other["ok"], other)
        status = manager.status()
        self.assertTrue(any(g["reason"] == "budget-exhausted"
                            for g in status["gaps"]), status["gaps"])
        with self.assertRaises(RelayRefused):
            manager.add_cluster("C", roe_level="全影响演示")

    def test_transport_fallback_records_attempts(self):
        api = self._api("A")
        deployer = FakeDeployer(failures={("A", "kubectl")})
        manager = self._manager(deployer=deployer)
        manager.add_cluster("A", api_server=api.url, transport="kubectl",
                            fallback=["kubectl", "sa-token"],
                            budget={"steps": 5, "actions": 5})
        result = manager.deploy("A", "p1", baseline=False)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["transport"], "sa-token")
        self.assertEqual(result["fallback_from"], "kubectl")
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual([c["via"] for c in deployer.calls],
                         ["kubectl", "sa-token"])

    def test_deploy_failure_produces_coverage_and_status_gaps(self):
        api = self._api("A")
        coverage = CoverageGraph()
        manager = self._manager(coverage=coverage,
                                deployer=FakeDeployer(failures={
                                    ("A", "kubectl"), ("A", "sa-token"),
                                    ("A", "exec")}))
        manager.add_cluster("A", api_server=api.url, transport="kubectl",
                            fallback=["kubectl", "sa-token", "exec"],
                            budget={"steps": 5, "actions": 5})
        result = manager.deploy("A", "p1", baseline=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        gaps = manager.status()["gaps"]
        self.assertTrue(any(g["kind"] == "probe" for g in gaps), gaps)
        proof = coverage.proof(graph=PlanGraph())
        self.assertFalse(proof["closed"])
        reasons = {g["reason"] for g in proof["gaps"]}
        self.assertIn("probe-not-registered", reasons)
        md = render_markdown(proof)
        self.assertIn("缺口清单", md)
        self.assertIn("probe-not-registered", md)

    # ---------------------------------------------------------- kubectl/exec
    def test_kubectl_and_exec_deploy_build_real_argv(self):
        runner = RecordingRunner()
        manager = RelayManager(
            store=None, deployer=KubectlDeployer(runner=runner, pod="target-pod"))
        manager.add_cluster("A", kubeconfig="a.yaml", context="ctx-a",
                            api_server="http://127.0.0.1:1", namespace="ml",
                            transport="kubectl",
                            budget={"steps": 5, "actions": 5})
        pod = manager.deploy("A", "p1", baseline=False)
        self.assertTrue(pod["ok"], pod)
        argv, stdin = runner.calls[0]
        self.assertIn("--kubeconfig", argv)
        self.assertIn("a.yaml", argv)
        self.assertIn("--context", argv)
        self.assertIn("ctx-a", argv)
        self.assertIn("apply", argv)
        self.assertIn("-f", argv)
        self.assertIn("inkblade-probe", stdin or "")
        exec_result = manager.deploy("A", "p2", via="exec",
                                     binary=b"\x7fELF", baseline=False)
        self.assertTrue(exec_result["ok"], exec_result)
        argv, stdin = runner.calls[-1]
        self.assertIn("exec", argv)
        self.assertIn("target-pod", argv)
        self.assertIn("base64 -d", " ".join(argv))
        self.assertTrue(stdin)

    # ---------------------------------------------------------- dialers
    def test_socks5_and_direct_dial_http(self):
        api = self._api("A")
        proxy = self._proxy()
        manager = RelayManager(store=None)
        manager.add_cluster("A", api_server=api.url, proxies=[proxy.url],
                            transport="kubectl",
                            budget={"steps": 5, "actions": 5})
        result = manager.reach("A")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["via"], "socks5")
        self.assertEqual(result["body"][:1], "{")
        # direct fallback remains available when the proxy is removed
        manager.add_cluster("A", api_server=api.url, proxies=[], force=True,
                            budget={"steps": 5, "actions": 5})
        direct = manager.reach("A")
        self.assertEqual(direct["via"], "direct")

    # ---------------------------------------------------------- CLI
    def test_cli_relay_add_list_status(self):
        api = self._api("A")

        def call(argv):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                code = main(argv)
            return code, buf.getvalue()

        code, out = call(["--home", str(self.home), "agent", "relay", "list",
                          "--workspace", "lab"])
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["count"], 0)
        code, out = call([
            "--home", str(self.home), "agent", "relay", "add",
            "--cluster-id", "A", "--workspace", "lab",
            "--kubeconfig", "a.kubeconfig", "--context", "ctx-a",
            "--api-server", api.url, "--namespace", "ml",
        ])
        self.assertEqual(code, 0, out)
        added = json.loads(out)
        self.assertFalse(added["duplicate"])
        self.assertEqual(added["cluster_id"], "A")
        code, out = call(["--home", str(self.home), "agent", "relay", "list",
                          "--workspace", "lab"])
        self.assertEqual(json.loads(out)["count"], 1)
        code, out = call(["--home", str(self.home), "agent", "relay", "status",
                          "--workspace", "lab", "--cluster-id", "A"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["clusters"][0]["cluster_id"], "A")
        self.assertIn("gaps", data)
        self.assertEqual(data["coverage"]["assets"], 1)

    def test_invalid_transport_and_missing_parent(self):
        manager = self._manager()
        with self.assertRaises(RelayError):
            manager.add_cluster("A", transport="rsh")
        with self.assertRaises(RelayError):
            manager.add_cluster("B", parent_id="missing")
        manager.add_cluster("A")
        with self.assertRaises(RelayError):
            manager.deploy("A", "p1", parent_id="missing-parent",
                           baseline=False)


if __name__ == "__main__":
    unittest.main()
