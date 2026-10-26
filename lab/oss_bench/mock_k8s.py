"""Deterministic mock Kubernetes endpoints for the kube-hunter bench.

Seeded exposures (the bench ground truth):
  S1 unauthenticated read-only API server on :6443 (plain HTTP, so kube-hunter
     should also flag unencrypted transport);
  S2 read-only kubelet on :10255 exposing /pods, /metrics and /healthz,
     including one privileged container (KHV052/KHV044/KHV043).

This is not a Kubernetes API implementation; it only serves the small set of
responses the passive kube-hunter hunters inspect.  No request mutates state.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PODS: dict[str, Any] = {
    "kind": "PodList",
    "apiVersion": "v1",
    "items": [
        {
            "metadata": {"name": "trainer-0", "namespace": "ml"},
            "spec": {
                "nodeName": "gpu-node-0",
                "containers": [
                    {
                        "name": "trainer",
                        "image": "pytorch/pytorch:2.5.0-cuda12.4",
                        "securityContext": {"privileged": True},
                    }
                ],
            },
        }
    ],
}

VERSION = {
    "major": "1",
    "minor": "28",
    "gitVersion": "v1.28.0",
    "gitCommit": "0000000000000000000000000000000000000000",
    "gitTreeState": "clean",
    "buildDate": "2026-01-01T00:00:00Z",
    "goVersion": "go1.22",
    "compiler": "gc",
    "platform": "linux/amd64",
}


class K8sHandler(BaseHTTPRequestHandler):
    server_version = "inkblade-oss-bench-mock/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # silence
        return

    def _send(self, code: int, payload: Any, content_type: str = "application/json") -> None:
        body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if self.server.server_port == 6443:  # API server
            if path == "/":
                # kube-hunter's ApiServiceDiscovery looks for '"code"' on non-200.
                self._send(403, {"kind": "Status", "code": 403, "reason": "Forbidden"})
            elif path == "/version":
                self._send(200, VERSION)
            elif path == "/api":
                self._send(200, {"kind": "APIVersions", "versions": ["v1"]})
            elif path == "/apis":
                self._send(200, {"kind": "APIGroupList", "groups": []})
            elif path == "/api/v1":
                self._send(
                    200,
                    {
                        "kind": "APIResourceList",
                        "groupVersion": "v1",
                        "resources": [
                            {"name": "pods", "namespaced": True, "kind": "Pod", "verbs": ["get", "list"]},
                            {"name": "secrets", "namespaced": True, "kind": "Secret", "verbs": ["get", "list"]},
                        ],
                    },
                )
            elif path == "/api/v1/pods" or path == "/api/v1/namespaces/default/pods":
                self._send(200, PODS)
            elif path == "/api/v1/secrets":
                self._send(200, {"kind": "SecretList", "items": []})
            elif path == "/api/v1/namespaces":
                self._send(200, {"kind": "NamespaceList", "items": [{"metadata": {"name": "ml"}}]})
            elif path == "/healthz":
                self._send(200, "ok", "text/plain")
            elif path == "/metrics":
                self._send(200, "kubernetes_build_info{gitVersion=\"v1.28.0\"} 1\n", "text/plain")
            elif path == "/openapi/v2":
                self._send(200, {"swagger": "2.0", "paths": {}})
            else:
                self._send(404, {"kind": "Status", "code": 404})
        elif self.server.server_port == 10255:  # read-only kubelet
            if path == "/pods":
                self._send(200, PODS)
            elif path == "/metrics":
                self._send(
                    200,
                    "# HELP kubernetes_build_info build info\n"
                    'kubernetes_build_info{gitVersion="v1.28.0"} 1\n',
                    "text/plain",
                )
            elif path == "/healthz":
                self._send(200, "ok", "text/plain")
            else:
                self._send(404, "not found", "text/plain")
        else:
            self._send(404, "not found", "text/plain")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockCluster:
    def __init__(self, host: str = "127.0.0.1", api_port: int = 6443, kubelet_port: int = 10255):
        self.host = host
        self.api_port = api_port
        self.kubelet_port = kubelet_port
        self.servers: list[_Server] = []
        self.threads: list[threading.Thread] = []

    def __enter__(self) -> "MockCluster":
        for port in (self.api_port, self.kubelet_port):
            srv = _Server((self.host, port), K8sHandler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self.servers.append(srv)
            self.threads.append(t)
        return self

    def __exit__(self, *exc: object) -> None:
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()
        for t in self.threads:
            t.join(timeout=2)


if __name__ == "__main__":
    with MockCluster():
        print("mock cluster on 127.0.0.1:6443 (API) and :10255 (read-only kubelet); Ctrl-C to stop")
        threading.Event().wait()
