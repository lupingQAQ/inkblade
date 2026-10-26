"""lab/chipsec_sim.py — 芯片/加速器姿态双态仿真靶场（仅 127.0.0.1，仅标准库）。

模拟的是「客户导出的设备证明/固件清单/内核 cmdline/IMEX 配置」这一现实审计入口，
不模拟硅片实验室、不开盖、不注入电压/激光、不做 Rowhammer/微架构侧信道实操。

两个姿态：
- vulnerable：GPU CC 证明被篡改、SPDM 证书过期/摘要不一致、IOMMU 直通、
  PCR 基线偏移 + UKI 签名无效、固件签名无效、IMEX 跨租户、CXL 无 IDE/TSP、
  显存释放后残留可读；
- fixed：证明链有效、SPDM 链/摘要/DOE 正常、IOMMU 严格翻译、PCR 与 golden 一致、
  固件全链有效、IMEX 租户隔离、CXL IDE+TSP、释放即清零（404）。

写面仅两条：`POST /chip/gpu/allocate` 与 `POST /chip/gpu/release`，只写 benign marker；
其余全部 GET。命令行：python lab/chipsec_sim.py [--port N] [--mode vulnerable|fixed]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.tee.fixtures import nvidia_fixture  # noqa: E402
from trident.tee.keys import (ALG_ECDSA_SHA256, CURVES, PrivateKey,  # noqa: E402
                              b64url_decode, b64url_encode, pem_wrap)
from trident.tee.x509 import build_certificate  # noqa: E402

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha384(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def _ec_key(curve: str, seed: str) -> PrivateKey:
    curve_def = CURVES[curve]
    d = int.from_bytes(hashlib.sha256(seed.encode()).digest()
                       * (curve_def.size // 32 + 1), "big")
    return PrivateKey(kind="ec", curve=curve, d=d % (curve_def.n - 1) + 1)


def _pem(cert) -> str:
    return cert.to_pem()


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def _build_pki():
    root_key = _ec_key("P-384", "trident-chip-spdm-root")
    leaf_key = _ec_key("P-384", "trident-chip-spdm-leaf")
    now = datetime.now(timezone.utc)
    root = build_certificate(
        subject="Trident Chip Fixture SPDM Root CA",
        issuer="Trident Chip Fixture SPDM Root CA",
        public_key=root_key.public_key(), signer=root_key.sign, serial=0x5101,
        not_before=now - timedelta(days=30), not_after=now + timedelta(days=3650),
        is_ca=True)
    valid_leaf = build_certificate(
        subject="Trident Chip Fixture SPDM Device",
        issuer="Trident Chip Fixture SPDM Root CA",
        public_key=leaf_key.public_key(), signer=root_key.sign, serial=0x5102,
        not_before=now - timedelta(days=10), not_after=now + timedelta(days=365))
    expired_leaf = build_certificate(
        subject="Trident Chip Fixture SPDM Device (expired)",
        issuer="Trident Chip Fixture SPDM Root CA",
        public_key=leaf_key.public_key(), signer=root_key.sign, serial=0x5103,
        not_before=now - timedelta(days=60), not_after=now - timedelta(days=1))
    return root, leaf_key, valid_leaf, expired_leaf


def _fw_pki():
    root_key = _ec_key("P-256", "trident-chip-fw-root")
    signer_key = _ec_key("P-256", "trident-chip-fw-signer")
    now = datetime.now(timezone.utc)
    root = build_certificate(
        subject="Trident Chip Fixture Firmware Root CA",
        issuer="Trident Chip Fixture Firmware Root CA",
        public_key=root_key.public_key(), signer=root_key.sign, serial=0x6101,
        not_before=now - timedelta(days=30), not_after=now + timedelta(days=3650),
        is_ca=True)
    signer = build_certificate(
        subject="Trident Chip Fixture Firmware Signer",
        issuer="Trident Chip Fixture Firmware Root CA",
        public_key=signer_key.public_key(), signer=root_key.sign, serial=0x6102,
        not_before=now - timedelta(days=10), not_after=now + timedelta(days=730))
    return root, signer_key, signer


class _ChipState:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.lock = threading.Lock()
        self.requests = 0
        self.by_path: dict[str, int] = {}
        self.started_at = _utcnow_iso()
        self.allocations: dict[str, dict] = {}
        self._seq = 0
        self.spdm_root, self.spdm_key, self.spdm_valid, self.spdm_expired = _build_pki()
        self.fw_root, self.fw_key, self.fw_signer = _fw_pki()
        self.nonce = "a1b2c3d4e5f60718293a4b5c6d7e8f90" * 2
        fx = nvidia_fixture(nonce=self.nonce)
        self.jwks = fx.jwks
        self.valid_token = fx.token
        self.tampered_token = self._tamper(fx.token)
        self.measurement_record = b"SPDM-MEASUREMENT-RECORD:gpu-fw:1.2.3"
        self.uki_content = b"TRIDENT-UKI-FIXTURE-v1"
        self.uki_key = _ec_key("P-256", "trident-chip-uki")
        self.uki_sig = self.uki_key.sign(ALG_ECDSA_SHA256, self.uki_content, raw=True)
        self.pcrs = {
            "0": _sha256(b"uefi-fw-1.2.3"),
            "4": _sha256(b"grub-uki-loader"),
            "7": _sha256(b"secureboot-db-2026-10"),
            "11": _sha256(b"uki-v1"),
        }
        if mode == "vulnerable":
            self.pcrs["0"] = _sha256(b"tampered-fw")
            self.pcrs["4"] = _sha256(b"tampered-loader")
            self.uki_sig = self.uki_key.sign(
                ALG_ECDSA_SHA256, self.uki_content + b"-tampered", raw=True)

    @staticmethod
    def _tamper(token: str) -> str:
        head, payload, sig = token.split(".")
        claims = json.loads(b64url_decode(payload).decode("utf-8"))
        claims["dbgstat"] = "enabled"
        claims["x-nvidia-gpu-name"] = "H100-TAMPERED"
        body = b64url_encode(json.dumps(claims, separators=(",", ":"),
                                        sort_keys=True).encode("utf-8"))
        return f"{head}.{body}.{sig}"

    def record(self, path: str) -> None:
        with self.lock:
            self.requests += 1
            self.by_path[path] = self.by_path.get(path, 0) + 1

    def allocate(self, tenant: str, device: str, marker: str) -> dict:
        with self.lock:
            self._seq += 1
            allocation_id = f"alloc-{self.mode}-{self._seq}"
            self.allocations[allocation_id] = {
                "tenant": tenant, "device": device, "marker": marker,
                "released": False, "zeroized": False, "process": "trident-chip-lab",
            }
            return {"allocation_id": allocation_id, "tenant": tenant, "device": device}

    def release(self, allocation_id: str) -> dict | None:
        with self.lock:
            item = self.allocations.get(allocation_id)
            if item is None:
                return None
            item["released"] = True
            if self.mode == "fixed":
                item["zeroized"] = True
                item["marker"] = ""
            return {
                "allocation_id": allocation_id,
                "released": True,
                "zeroized": item["zeroized"],
                "residue_sha256": _sha256(item["marker"].encode("utf-8")),
            }

    def residue(self, allocation_id: str) -> dict | None:
        with self.lock:
            item = self.allocations.get(allocation_id)
            if item is None or not item.get("released") or item.get("zeroized"):
                return None
            marker = item["marker"]
            return {
                "residue": [{
                    "allocation_id": allocation_id,
                    "tenant": item["tenant"],
                    "device": item["device"],
                    "process": item["process"],
                    "marker": marker,
                    "marker_sha256": _sha256(marker.encode("utf-8")),
                    "file_sha256": _sha256(("residue:" + marker).encode("utf-8")),
                    "readable_after_release": True,
                    "zeroized": False,
                    "residue_file": f"/var/lib/trident/residue/{allocation_id}.bin",
                }]
            }


def _gpu_cc(ctx):
    state = ctx.state
    token = state.tampered_token if ctx.mode == "vulnerable" else state.valid_token
    return 200, {
        "mode": ctx.mode,
        "nonce": state.nonce,
        "jwks": state.jwks,
        "token": token,
        "valid_reference": state.valid_token,
        "tampered": ctx.mode == "vulnerable",
        "claims": {
            "dbgstat": "enabled" if ctx.mode == "vulnerable" else "disabled",
            "secboot": True,
            "x-nvidia-overall-att-result": True,
        },
    }


def _spdm(ctx):
    state = ctx.state
    if ctx.mode == "vulnerable":
        return 200, {
            "device": "0000:01:00.0",
            "spdm": {
                "version": "1.0.0", "mutual_auth": False, "session": False,
                "measurement_hash_algo": "sha384",
                "measurement_record_hex": state.measurement_record.hex(),
                "measurement_summary": _sha384(state.measurement_record + b"-stale"),
                "expected_measurement_summary": _sha384(state.measurement_record),
                "chain_pem": _pem(state.spdm_expired),
                "trust_anchor_pem": _pem(state.spdm_root),
            },
            "pcie": {"doe": False, "ide": False, "tdisp": False},
        }
    return 200, {
        "device": "0000:01:00.0",
        "spdm": {
            "version": "1.3.0", "mutual_auth": True, "session": True,
            "measurement_hash_algo": "sha384",
            "measurement_record_hex": state.measurement_record.hex(),
            "measurement_summary": _sha384(state.measurement_record),
            "expected_measurement_summary": _sha384(state.measurement_record),
            "chain_pem": _pem(state.spdm_valid),
            "trust_anchor_pem": _pem(state.spdm_root),
        },
        "pcie": {"doe": True, "ide": True, "tdisp": True},
    }


def _iommu(ctx):
    if ctx.mode == "vulnerable":
        return 200, {
            "arch": "x86_64",
            "kernel_cmdline": "intel_iommu=on iommu=pt iommu.passthrough=1",
            "iommu": {"enabled": True, "passthrough": True, "strict": False,
                      "smmu": False},
            "dma_protection": False,
            "groups": [
                {"id": 1, "devices": ["0000:01:00.0", "0000:01:00.1"],
                 "acs": False, "ats": True, "ats_protected": False,
                 "identity": True, "untrusted": True, "functions": 2},
                {"id": 2, "devices": ["0000:02:00.0"], "acs": True,
                 "ats": False, "ats_protected": True, "identity": False},
            ],
        }
    return 200, {
        "arch": "x86_64",
        "kernel_cmdline": "intel_iommu=on iommu.passthrough=0 iommu.strict=1",
        "iommu": {"enabled": True, "passthrough": False, "strict": True,
                  "smmu": False},
        "dma_protection": True,
        "groups": [
            {"id": 1, "devices": ["0000:01:00.0"], "acs": True, "ats": False,
             "ats_protected": True, "identity": False},
            {"id": 2, "devices": ["0000:02:00.0"], "acs": True, "ats": False,
             "ats_protected": True, "identity": False},
        ],
    }


def _boot(ctx):
    state = ctx.state
    with state.lock:
        pcrs = dict(state.pcrs)
        baseline = {
            "0": _sha256(b"uefi-fw-1.2.3"),
            "4": _sha256(b"grub-uki-loader"),
            "7": _sha256(b"secureboot-db-2026-10"),
            "11": _sha256(b"uki-v1"),
        }
        uki = {
            "content_b64": _b64(state.uki_content),
            "signature_b64": _b64(state.uki_sig),
            "public_key_pem": pem_wrap(state.uki_key.public_key().to_spki_der(),
                                       "PUBLIC KEY"),
            "algorithm": "ecdsa-sha256",
            "signed": True,
            "signature_expected_valid": ctx.mode == "fixed",
        }
        return 200, {
            "secure_boot": True, "setup_mode": False, "eventlog_verified": True,
            "tpm": {"version": "2.0", "pcr_bank": "sha256"},
            "pcrs": pcrs, "baseline": baseline,
            "dbx": {"present": True, "entries": 1234,
                    "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
            "uki": uki,
        }


def _firmware(ctx):
    state = ctx.state
    components = []
    for name, content in (
        ("gpu-vbios", b"GV100-vbios-96.00.89.00.01"),
        ("bmc-fw", b"BMC-fw-2.10.0"),
        ("nvswitch-fw", b"NVSwitch-fw-1.8.2"),
    ):
        signed = content
        if ctx.mode == "vulnerable" and name == "bmc-fw":
            signed = content + b"-tampered"
        components.append({
            "name": name,
            "kind": "microcode" if name == "gpu-vbios" else "firmware",
            "vendor": "MockVendor",
            "version": "0x2e" if name == "gpu-vbios" else "1.0.0",
            "min_version": "0x2e" if name == "gpu-vbios" else None,
            "content_b64": _b64(content),
            "sha256": _sha256(content),
            "signature_b64": _b64(state.fw_key.sign(ALG_ECDSA_SHA256, signed, raw=True)),
            "chain_pem": _pem(state.fw_signer),
            "algorithm": "ecdsa-sha256",
            "serial": state.fw_signer.serial,
            "signature_expected_valid": not (ctx.mode == "vulnerable" and name == "bmc-fw"),
        })
    return 200, {
        "vendor": "MockVendor",
        "trust_root_pem": _pem(state.fw_root),
        "revoked_serials": [],
        "components": components,
    }


def _residue_export(ctx):
    if ctx.mode == "vulnerable":
        return 200, {
            "requester_tenant": "tenant-a",
            "policy": {"mig_enabled": True, "mps_enabled": True,
                       "zeroize_on_release": False, "mps_shared_context": True,
                       "tenant_isolation": False, "multi_tenant": True},
            "allocations": [
                {"allocation_id": "res-victim-b", "tenant": "tenant-b",
                 "device": "gpu-b-0", "mig_instance": "1g.5gb",
                 "mps_client": "mps-b", "released": True, "zeroized": False,
                 "readable_after_release": True,
                 "marker_sha256": _sha256(b"TRIDENT-BENIGN-RESIDUE-VICTIM"),
                 "residue_sha256": _sha256(b"TRIDENT-BENIGN-RESIDUE-VICTIM"),
                 "process": "vllm-tenant-b", "mps_shared_context": True},
                {"allocation_id": "res-own-a", "tenant": "tenant-a",
                 "device": "gpu-a-1", "mig_instance": "1g.5gb",
                 "mps_client": "mps-a", "released": True, "zeroized": False,
                 "readable_after_release": True,
                 "marker_sha256": _sha256(b"TRIDENT-BENIGN-OWN"),
                 "residue_sha256": _sha256(b"TRIDENT-BENIGN-OWN"),
                 "process": "vllm-tenant-a", "mps_shared_context": False},
            ],
        }
    return 200, {
        "requester_tenant": "tenant-a",
        "policy": {"mig_enabled": True, "mps_enabled": False,
                   "zeroize_on_release": True, "mps_shared_context": False,
                   "tenant_isolation": True, "multi_tenant": True},
        "allocations": [
            {"allocation_id": "res-victim-b", "tenant": "tenant-b",
             "device": "gpu-b-0", "mig_instance": "1g.5gb", "mps_client": "",
             "released": True, "zeroized": True, "readable_after_release": False,
             "marker_sha256": "", "residue_sha256": "", "process": "",
             "mps_shared_context": False},
        ],
    }


def _imex(ctx):
    if ctx.mode == "vulnerable":
        return 200, {
            "imex": {"enabled": True, "tls": False, "auth": False,
                     "bind": "0.0.0.0"},
            "fabric_manager": {"running": True, "partitioning": False,
                               "bind": "0.0.0.0"},
            "domains": [{
                "id": "imex-0", "tenant": "tenant-a",
                "members": [{"gpu": "gpu-a0", "tenant": "tenant-a"},
                            {"gpu": "gpu-b0", "tenant": "tenant-b"}],
                "permissions": {"export": ["*"], "import": ["*"]},
                "channels": [{"path": "/dev/nvidia-imex-0", "mode": "0666",
                              "tenants": ["tenant-a", "tenant-b"]}],
            }],
            "partitions": [{"id": 0, "default": True, "tenant": "tenant-a",
                            "tenants": ["tenant-a", "tenant-b"],
                            "gpus": ["gpu-a0", "gpu-b0"]}],
        }
    return 200, {
        "imex": {"enabled": True, "tls": True, "auth": True, "bind": "127.0.0.1"},
        "fabric_manager": {"running": True, "partitioning": True,
                           "bind": "127.0.0.1"},
        "domains": [
            {"id": "imex-a", "tenant": "tenant-a",
             "members": [{"gpu": "gpu-a0", "tenant": "tenant-a"}],
             "permissions": {"export": ["gpu-a0"], "import": ["gpu-a1"]},
             "channels": [{"path": "/dev/nvidia-imex-a", "mode": "0600",
                           "tenants": ["tenant-a"]}]},
            {"id": "imex-b", "tenant": "tenant-b",
             "members": [{"gpu": "gpu-b0", "tenant": "tenant-b"}],
             "permissions": {"export": ["gpu-b0"], "import": ["gpu-b1"]},
             "channels": [{"path": "/dev/nvidia-imex-b", "mode": "0600",
                           "tenants": ["tenant-b"]}]},
        ],
        "partitions": [
            {"id": 1, "default": False, "tenant": "tenant-a",
             "tenants": ["tenant-a"], "gpus": ["gpu-a0", "gpu-a1"]},
            {"id": 2, "default": False, "tenant": "tenant-b",
             "tenants": ["tenant-b"], "gpus": ["gpu-b0", "gpu-b1"]},
        ],
    }


def _cxl(ctx):
    if ctx.mode == "vulnerable":
        return 200, {
            "host": {"cxl_version": "3.2", "ide": False, "tsp": False},
            "devices": [{
                "id": "cxl0", "cxl_version": "3.2",
                "ide": {"enabled": False, "keys_programmed": False},
                "tsp": {"supported": True, "enabled": False,
                        "te_state": "CONFIG_UNLOCKED"},
                "mailbox": {"auth": False},
                "firmware": {"signed": False},
                "attestation": {},
                "decoder": {"tenants": ["tenant-a", "tenant-b"],
                            "interleave": ["cxl0", "cxl1"]},
            }],
        }
    return 200, {
        "host": {"cxl_version": "3.2", "ide": True, "tsp": True},
        "devices": [{
            "id": "cxl0", "cxl_version": "3.2",
            "ide": {"enabled": True, "keys_programmed": True},
            "tsp": {"supported": True, "enabled": True,
                    "te_state": "CONFIG_LOCKED"},
            "mailbox": {"auth": True},
            "firmware": {"signed": True},
            "attestation": {"trust_anchor": "vendor-root"},
            "decoder": {"tenants": ["tenant-a"], "interleave": ["cxl0"]},
        }],
    }


def _health(ctx):
    return 200, {"ok": True, "service": "chipsec-sim", "mode": ctx.mode,
                 "started_at": ctx.state.started_at,
                 "scope": "deployment-reachable chip posture; no silicon lab"}


def _stats(ctx):
    with ctx.state.lock:
        return 200, {"mode": ctx.mode, "requests": ctx.state.requests,
                     "by_path": dict(sorted(ctx.state.by_path.items()))}


def _routes(ctx):
    return 200, {
        "service": "trident-chipsec-lab",
        "mode": ctx.mode,
        "host": HOST,
        "route_count": len(ROUTE_TABLE),
        "routes": [{k: v for k, v in entry.items() if k != "behavior"}
                   for entry in ROUTE_TABLE],
    }


class _RequestContext:
    def __init__(self, mode: str, state: _ChipState, path: str, query: dict,
                 body: dict):
        self.mode = mode
        self.state = state
        self.path = path
        self.query = query
        self.body = body


ROUTE_TABLE = [
    {"service": "gpu-cc", "path": "/chip/gpu-cc", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _gpu_cc},
    {"service": "spdm", "path": "/chip/spdm", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _spdm},
    {"service": "iommu", "path": "/chip/iommu", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _iommu},
    {"service": "boot", "path": "/chip/boot", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _boot},
    {"service": "firmware", "path": "/chip/firmware", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _firmware},
    {"service": "residue", "path": "/chip/residue/export", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _residue_export},
    {"service": "imex", "path": "/chip/imex", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _imex},
    {"service": "cxl", "path": "/chip/cxl", "plane": "chip",
     "method": "GET", "writes": False, "behavior": _cxl},
    {"service": "residue", "path": "/chip/gpu/allocate", "plane": "residue",
     "method": "POST", "writes": True, "behavior": None},
    {"service": "residue", "path": "/chip/gpu/release", "plane": "residue",
     "method": "POST", "writes": True, "behavior": None},
    {"service": "residue", "path": "/chip/gpu/residue", "plane": "residue",
     "method": "GET", "writes": False, "behavior": None},
    {"service": "lab", "path": "/health", "plane": "config",
     "method": "GET", "writes": False, "behavior": _health},
    {"service": "lab", "path": "/__routes__", "plane": "config",
     "method": "GET", "writes": False, "behavior": _routes},
    {"service": "lab", "path": "/__stats__", "plane": "config",
     "method": "GET", "writes": False, "behavior": _stats},
]
_ROUTES = {entry["path"]: entry for entry in ROUTE_TABLE}


class _ChipHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str):
        super().__init__(address, _ChipHandler)
        self.lab_mode = mode
        self.lab_state = _ChipState(mode)


class _ChipHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentChipsecSim/0.1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._send(405, {"error": "method not allowed", "methods": ["GET", "POST"]})

    def do_DELETE(self):
        self._send(405, {"error": "method not allowed", "methods": ["GET", "POST"]})

    def do_PATCH(self):
        self._send(405, {"error": "method not allowed", "methods": ["GET", "POST"]})

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        path = split.path.rstrip("/") or "/"
        entry = _ROUTES.get(path)
        if entry is None:
            self._send(404, {"error": "not found", "path": path})
            return
        if method != entry["method"]:
            self._send(405, {"error": "method not allowed",
                             "allowed": [entry["method"]]})
            return
        raw = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            self._send(400, {"error": "invalid json"})
            return
        server = self.server  # type: _ChipHTTPServer
        server.lab_state.record(path)
        query = {k: v[0] if v else "" for k, v in parse_qs(split.query).items()}
        ctx = _RequestContext(server.lab_mode, server.lab_state, path, query, body)
        if path == "/chip/gpu/allocate":
            if not body.get("tenant") or not body.get("marker"):
                self._send(400, {"error": "tenant/marker required"})
                return
            self._send(200, server.lab_state.allocate(
                str(body["tenant"]), str(body.get("device") or "gpu-a-1"),
                str(body["marker"])))
            return
        if path == "/chip/gpu/release":
            result = server.lab_state.release(str(body.get("allocation_id") or ""))
            if result is None:
                self._send(404, {"error": "unknown allocation"})
            else:
                self._send(200, result)
            return
        if path == "/chip/gpu/residue":
            result = server.lab_state.residue(str(query.get("allocation") or ""))
            if result is None:
                self._send(404, {"error": "not found or zeroized"})
            else:
                self._send(200, result)
            return
        try:
            status, payload = entry["behavior"](ctx)
        except Exception as exc:  # noqa: BLE001 -- 仿真不泄漏堆栈
            self._send(500, {"error": "mock internal error",
                             "service": entry["service"], "detail": str(exc)})
            return
        self._send(status, payload)


class Server:
    def __init__(self, httpd: _ChipHTTPServer, thread: threading.Thread, mode: str):
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
        return [{k: v for k, v in entry.items() if k != "behavior"}
                for entry in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE) -> Server:
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _ChipHTTPServer((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 芯片/加速器姿态双态仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE)
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode)
    print(f"chipsec-sim listening on {server.url('/')} mode={server.mode}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
