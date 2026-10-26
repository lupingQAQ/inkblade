"""lab/infra2026_sim.py — 2026 安全会议 infra/AI-infra 议题只读仿真靶场。

覆盖 17 个面：CoCo/SEV-SNP 证明、sandbox runtime、SPIRE、cert-manager webhook TLS、
Gateway API/ambient mesh、WASM 权限、GitOps 密钥与漂移、多集群联邦、DPU/IPU offload、
PCIe IOMMU/DMA、TPM measured boot、后量子 TLS、模型水印/后门、RAG 向量注入、
联邦学习、数据来源证明。

两种姿态：
- vulnerable：证明测量值不匹配、debug TEE、SPIRE 通配 ID、证书过期、ambient 策略放行、
  WASM 全能力、GitOps 明文密钥、Karmada 通配传播、DPU 未 offload、IOMMU 关闭、
  Secure Boot 关闭、TLS1.2 RSA、无水印、RAG 注入、联邦更新未签名、证明签名无效；
- fixed：上述全部加固，模块应无 high finding。

只读：所有 POST/PUT/PATCH/DELETE 返回 405；仅 127.0.0.1，内存态。
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"


def _coco_attestation(mode: str) -> dict:
    if mode == "fixed":
        return {
            "tee": "sev-snp",
            "measurement": "sha256:9f2c" + "0" * 60,
            "expected_measurement": "sha256:9f2c" + "0" * 60,
            "snp_policy": {"abi_major": 1, "abi_minor": 55, "debug": False, "smt": True},
            "report_data_binding": True,
            "signed": True,
            "policy": "strict",
            "guest_svn": 8,
        }
    return {
        "tee": "sev-snp",
        "measurement": "sha256:1111" + "0" * 60,
        "expected_measurement": "sha256:2222" + "0" * 60,
        "snp_policy": {"abi_major": 1, "abi_minor": 55, "debug": True, "smt": True},
        "report_data_binding": False,
        "signed": False,
        "policy": "insecure",
        "guest_svn": 3,
    }


def _coco_policy(mode: str) -> dict:
    if mode == "fixed":
        return {
            "runtime_class": "kata-qemu",
            "require_attestation": True,
            "allowed_images": ["registry.example/llm@sha256:" + "a" * 64],
            "initdata_verified": True,
            "allow_debug": False,
        }
    return {
        "runtime_class": "kata-qemu",
        "require_attestation": False,
        "allowed_images": ["*"],
        "initdata_verified": False,
        "allow_debug": True,
    }


def _sandbox_runtime(mode: str) -> dict:
    if mode == "fixed":
        return {
            "runtime_classes": [
                {"name": "gvisor", "handler": "runsc", "sandboxed": True},
                {"name": "kata", "handler": "kata-qemu", "sandboxed": True},
            ],
            "pods": [{
                "name": "agent", "namespace": "infer", "runtime": "gvisor",
                "sandboxed": True, "host_pid": False, "host_network": False,
                "privileged": False, "seccomp": "RuntimeDefault",
                "capabilities": [],
            }],
            "gvisor": True,
            "firecracker": True,
        }
    return {
        "runtime_classes": [
            {"name": "runc", "handler": "runc", "sandboxed": False},
            {"name": "gvisor", "handler": "runsc", "sandboxed": True},
        ],
        "pods": [{
            "name": "agent", "namespace": "infer", "runtime": "runc",
            "sandboxed": False, "host_pid": True, "host_network": True,
            "privileged": False, "seccomp": "Unconfined",
            "capabilities": ["SYS_ADMIN", "NET_ADMIN"],
        }],
        "gvisor": True,
        "firecracker": False,
    }


def _spire_entries(mode: str) -> dict:
    if mode == "fixed":
        return {
            "trust_domain": "example.org",
            "server": {
                "bind": "127.0.0.1:8081",
                "admin_socket": "/run/spire/sockets/admin.sock",
                "admin_acl": True,
            },
            "entries": [
                {"spiffe_id": "spiffe://example.org/ns/infer/sa/model",
                 "selectors": ["k8s:ns:infer", "k8s:sa:model"], "ttl": 3600},
                {"spiffe_id": "spiffe://example.org/ns/train/sa/trainer",
                 "selectors": ["k8s:ns:train", "k8s:sa:trainer"], "ttl": 3600},
            ],
        }
    return {
        "trust_domain": "example.org",
        "server": {
            "bind": "0.0.0.0:8081",
            "admin_socket": "/run/spire/sockets/admin.sock",
            "admin_acl": False,
        },
        "entries": [
            {"spiffe_id": "spiffe://example.org/*",
             "selectors": ["unix:uid:0"], "ttl": 0},
            {"spiffe_id": "spiffe://example.org/ns/default/sa/*",
             "selectors": [], "ttl": 86400},
            {"spiffe_id": "spiffe://example.org/ns/infer/sa/model",
             "selectors": ["k8s:ns:infer"], "ttl": 3600},
        ],
    }


def _webhook_tls(mode: str) -> dict:
    if mode == "fixed":
        return {
            "secret": "webhook-tls",
            "not_after": "2027-04-01T00:00:00Z",
            "now": "2026-10-26T00:00:00Z",
            "san": ["webhook.secure.svc", "webhook.secure.svc.cluster.local"],
            "expected_san": ["webhook.secure.svc", "webhook.secure.svc.cluster.local"],
            "ca_bundle_matches": True,
            "insecure_skip_verify": False,
            "cert_rotator": True,
        }
    return {
        "secret": "webhook-tls",
        "not_after": "2026-09-01T00:00:00Z",
        "now": "2026-10-26T00:00:00Z",
        "san": ["webhook.default.svc"],
        "expected_san": ["webhook.secure.svc"],
        "ca_bundle_matches": False,
        "insecure_skip_verify": True,
        "cert_rotator": False,
    }


def _mesh_policies(mode: str) -> dict:
    if mode == "fixed":
        return {
            "mode": "ambient",
            "waypoint": {"enabled": True, "namespace": "default", "authz_enforced": True},
            "peer_auth": {"mtls": "strict"},
            "l7_policy": [{"name": "deny-all", "action": "deny", "namespace": "default"}],
            "ztunnel_bypass": [],
            "ambient_redirection_excluded": ["kube-system"],
            "gateways": [{
                "name": "gw", "namespace": "default",
                "listeners": [{"port": 443, "protocol": "HTTPS", "hostname": "app.example",
                               "tls": "cert-manager"}],
            }],
            "httproutes": [{
                "name": "app", "namespace": "default", "hostnames": ["app.example"],
                "backend": "app-api", "allowed_routes_from_all": False,
            }],
        }
    return {
        "mode": "ambient",
        "waypoint": {"enabled": True, "namespace": "default", "authz_enforced": False},
        "peer_auth": {"mtls": "permissive"},
        "l7_policy": [],
        "ztunnel_bypass": ["hostNetwork", "vm"],
        "ambient_redirection_excluded": ["kube-system", "default"],
        "gateways": [{
            "name": "gw", "namespace": "default",
            "listeners": [{"port": 80, "protocol": "HTTP", "hostname": "*", "tls": None}],
        }],
        "httproutes": [{
            "name": "admin", "namespace": "kube-system", "hostnames": ["*"],
            "backend": "admin-api", "allowed_routes_from_all": True,
        }],
    }


def _wasm_modules(mode: str) -> dict:
    if mode == "fixed":
        return {
            "runtime": "spinkube",
            "modules": [{
                "name": "agent-tool", "signed": True,
                "capabilities": {"filesystem": [], "network": [], "env": [],
                                 "allow_wasi_unstable": False},
            }],
        }
    return {
        "runtime": "spinkube",
        "modules": [{
            "name": "agent-tool", "signed": False,
            "capabilities": {"filesystem": ["/"], "network": ["*"],
                             "env": ["AWS_*"], "allow_wasi_unstable": True},
        }],
    }


def _gitops_secrets(mode: str) -> dict:
    if mode == "fixed":
        return {
            "tool": "argocd",
            "repo": "https://git.example/infra",
            "plaintext_secrets": 0,
            "secret_names": [],
            "encrypted": True,
            "external_secrets": True,
            "drift_entries": 0,
            "auto_sync": True,
            "signed_commits": True,
            "prune": True,
        }
    return {
        "tool": "argocd",
        "repo": "https://git.example/infra",
        "plaintext_secrets": 3,
        "secret_names": ["db-password", "registry-token", "cloud-key"],
        "encrypted": False,
        "external_secrets": False,
        "drift_entries": 2,
        "auto_sync": True,
        "signed_commits": False,
        "prune": False,
    }


def _multicluster(mode: str) -> dict:
    if mode == "fixed":
        return {
            "hub": "karmada",
            "clusters": ["prod-a", "prod-b"],
            "propagation": {"wildcard": False, "cluster_selector": "prod-a,prod-b",
                            "failover": "automatic"},
            "policy": {"requires_approval": True, "namespace_isolation": True},
            "kubeconfigs_shared": False,
        }
    return {
        "hub": "karmada",
        "clusters": ["prod-a", "prod-b", "dev"],
        "propagation": {"wildcard": True, "cluster_selector": "*", "failover": "none"},
        "policy": {"requires_approval": False, "namespace_isolation": False},
        "kubeconfigs_shared": True,
    }


def _dpu_offload(mode: str) -> dict:
    if mode == "fixed":
        return {
            "dpu": {
                "model": "BlueField-3", "mode": "dpu", "host_offload": True,
                "services_on_host": [], "iommu_enabled": True, "switchdev": True,
                "isolated": True, "firmware_verified": True,
            }
        }
    return {
        "dpu": {
            "model": "BlueField-3", "mode": "dpu", "host_offload": False,
            "services_on_host": ["ovn", "kube-proxy", "storage"],
            "iommu_enabled": False, "switchdev": False, "isolated": False,
            "firmware_verified": False,
        }
    }


def _iommu_groups(mode: str) -> dict:
    if mode == "fixed":
        return {
            "iommu_enabled": True,
            "acs_enabled": True,
            "groups": [
                {"id": 1, "devices": ["0000:01:00.0"], "functions": 1, "passthrough": False},
                {"id": 2, "devices": ["0000:02:00.0"], "functions": 1, "passthrough": False},
            ],
            "kernel_dma_protection": True,
            "ats_enabled": True,
            "ats_protected": True,
        }
    return {
        "iommu_enabled": False,
        "acs_enabled": False,
        "groups": [{
            "id": 1, "devices": ["0000:01:00.0", "0000:02:00.0"],
            "functions": 8, "passthrough": True,
        }],
        "kernel_dma_protection": False,
        "ats_enabled": True,
        "ats_protected": False,
    }


def _tpm_eventlog(mode: str) -> dict:
    if mode == "fixed":
        return {
            "tpm_version": "2.0",
            "secure_boot": True,
            "measured_boot": True,
            "pcr_bank": "sha256",
            "eventlog_verified": True,
            "pcr_mismatches": [],
            "attestation_key_protected": True,
        }
    return {
        "tpm_version": "2.0",
        "secure_boot": False,
        "measured_boot": False,
        "pcr_bank": "sha1",
        "eventlog_verified": False,
        "pcr_mismatches": ["PCR4", "PCR7"],
        "attestation_key_protected": False,
    }


def _tls_posture(mode: str) -> dict:
    if mode == "fixed":
        return {
            "min_version": "TLS1.3",
            "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
            "key_exchange": "ecdhe",
            "hybrid_group": "X25519MLKEM768",
            "cert": {"alg": "RSA", "bits": 3072},
            "signature_alg": "ML-DSA-65",
            "hndl_exposed": False,
            "hndl_safe": True,
        }
    return {
        "min_version": "TLS1.2",
        "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
        "key_exchange": "rsa",
        "hybrid_group": None,
        "cert": {"alg": "RSA", "bits": 2048},
        "signature_alg": "sha256WithRSAEncryption",
        "hndl_exposed": True,
        "hndl_safe": False,
    }


def _model_watermark(mode: str) -> dict:
    if mode == "fixed":
        return {
            "model": "llm-x",
            "weights_hash": "sha256:" + "c" * 64,
            "watermark": {"present": True, "algorithm": "kgw", "verify_endpoint": True},
            "backdoor_scan": {"performed": True, "trigger_scan": True},
            "provenance": "sigstore",
        }
    return {
        "model": "llm-x",
        "weights_hash": "sha256:" + "d" * 64,
        "watermark": {"present": False, "algorithm": "none", "verify_endpoint": False},
        "backdoor_scan": {"performed": False, "trigger_scan": False},
        "provenance": "unknown",
    }


def _rag_documents(mode: str) -> dict:
    if mode == "fixed":
        return {
            "tenant": "a",
            "collection": "tenant-a-kb",
            "embedding_namespace": "tenant-a",
            "documents": [{
                "id": "d1", "source": "internal", "trusted": True,
                "injected_instruction": False, "signed": True,
            }],
            "retrieval": {"tenant_filter": True, "max_docs": 8, "sanitize": True},
        }
    return {
        "tenant": "a",
        "collection": "shared-kb",
        "embedding_namespace": "shared",
        "documents": [{
            "id": "d1", "source": "external", "trusted": False,
            "injected_instruction": True, "signed": False,
        }],
        "retrieval": {"tenant_filter": False, "max_docs": 100, "sanitize": False},
    }


def _fl_round(mode: str) -> dict:
    if mode == "fixed":
        return {
            "round": 12,
            "aggregator": "central",
            "clients": 8,
            "updates": [
                {"client": "c1", "verified": True, "signed": True, "norm": 1.2},
                {"client": "c2", "verified": True, "signed": True, "norm": 0.9},
            ],
            "dp": {"enabled": True, "epsilon": 4.0},
            "secure_aggregation": True,
            "byzantine_filter": True,
        }
    return {
        "round": 12,
        "aggregator": "central",
        "clients": 8,
        "updates": [
            {"client": "c1", "verified": False, "signed": False, "norm": 1000.0},
            {"client": "c2", "verified": False, "signed": False, "norm": 0.0},
        ],
        "dp": {"enabled": False, "epsilon": None},
        "secure_aggregation": False,
        "byzantine_filter": False,
    }


def _provenance(mode: str) -> dict:
    if mode == "fixed":
        return {
            "artifact": "model.bin",
            "attestation": {
                "present": True, "signature_valid": True,
                "builder": "buildkit@sha256:" + "e" * 64,
                "materials": [{"uri": "git+https://git.example/llm", "digest": "sha256:" + "f" * 64}],
                "slsa_level": 3, "in_toto": True, "rekor": True,
            },
            "sbom": {"present": True},
            "drift": False,
        }
    return {
        "artifact": "model.bin",
        "attestation": {
            "present": True, "signature_valid": False, "builder": "unknown",
            "materials": [], "slsa_level": 0, "in_toto": False, "rekor": False,
        },
        "sbom": {"present": False},
        "drift": True,
    }


ROUTE_TABLE = (
    {"path": "/coco/attestation", "service": "coco", "behavior": _coco_attestation},
    {"path": "/coco/policy", "service": "coco", "behavior": _coco_policy},
    {"path": "/sandbox/runtime", "service": "sandbox", "behavior": _sandbox_runtime},
    {"path": "/spire/entries", "service": "spire", "behavior": _spire_entries},
    {"path": "/webhook/tls", "service": "cert-manager", "behavior": _webhook_tls},
    {"path": "/mesh/policies", "service": "ambient-mesh", "behavior": _mesh_policies},
    {"path": "/wasm/modules", "service": "wasm", "behavior": _wasm_modules},
    {"path": "/gitops/secrets", "service": "gitops", "behavior": _gitops_secrets},
    {"path": "/multicluster/federation", "service": "karmada", "behavior": _multicluster},
    {"path": "/dpu/offload", "service": "dpu", "behavior": _dpu_offload},
    {"path": "/iommu/groups", "service": "iommu", "behavior": _iommu_groups},
    {"path": "/tpm/eventlog", "service": "tpm", "behavior": _tpm_eventlog},
    {"path": "/tls/posture", "service": "pq-tls", "behavior": _tls_posture},
    {"path": "/model/watermark", "service": "model", "behavior": _model_watermark},
    {"path": "/rag/documents", "service": "rag", "behavior": _rag_documents},
    {"path": "/fl/round", "service": "federated", "behavior": _fl_round},
    {"path": "/provenance/attestation", "service": "provenance", "behavior": _provenance},
)
_ROUTES = {row["path"]: row for row in ROUTE_TABLE}


def _routes_payload() -> dict:
    return {
        "routes": [{k: v for k, v in row.items() if k != "behavior"} for row in ROUTE_TABLE],
        "read_only": True,
        "host": HOST,
    }


class _InfraHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, mode: str):
        super().__init__(addr, _InfraHandler)
        self.lab_mode = mode
        self.lab_started = time.time()
        self.lab_requests = 0


class _InfraHandler(BaseHTTPRequestHandler):
    server_version = "TridentInfra2026/1.0"

    def log_message(self, fmt, *args):  # noqa: A003 - 静默，避免测试噪声
        return

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._method_not_allowed()

    def do_PUT(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def _method_not_allowed(self):
        self._send(405, {"error": "method not allowed", "methods": ["GET"],
                         "note": "infra2026 lab is read-only"})

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        path = split.path.rstrip("/") or "/"
        server = self.server  # type: _InfraHTTPServer
        server.lab_requests += 1
        if path == "/__routes__":
            self._send(200, _routes_payload())
            return
        entry = _ROUTES.get(path)
        if entry is None:
            self._send(404, {"error": "not found", "path": path})
            return
        if method != "GET":
            self._method_not_allowed()
            return
        try:
            payload = entry["behavior"](server.lab_mode)
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": "mock internal error",
                             "service": entry["service"], "detail": str(exc)})
            return
        self._send(200, payload)


class Server:
    """仿真服务句柄：.port/.mode/.url()/.routes()/.shutdown()。"""

    def __init__(self, httpd: _InfraHTTPServer, thread: threading.Thread, mode: str):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return _routes_payload()["routes"]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE) -> Server:
    """启动只读仿真服务（单服务器，仅 127.0.0.1，内存态）。"""
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _InfraHTTPServer((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 2026 infra 只读仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE)
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode)
    print(f"infra2026-sim listening on {server.url('/')} mode={server.mode}")
    print(f"routes manifest: {server.url('/__routes__')}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
