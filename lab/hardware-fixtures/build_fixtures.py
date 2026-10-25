"""lab/hardware-fixtures/build_fixtures.py — 生成硬件/交换机只读审计 fixture。

全部为合成数据：无真实 GPU/BMC/交换机序列号、无真实凭据、无厂商私有配置。
固件签名 fixture 使用 HMAC（仅用于验证「签名校验路径」），生产必须换厂商非对称签名/PKI。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURE_KEY = "trident-hardware-fixture-key-2026"
GENERATED_AT = "2026-10-26T00:00:00Z"


def write_json(rel: str, payload: dict) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_manifest(manifest: dict) -> str:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sign_manifest(manifest: dict, key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_manifest(manifest).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def gpu_fixtures() -> None:
    write_text(
        "gpu/nvidia-smi.csv",
        "index, name, driver_version, vbios_version, memory.total, ecc.mode.current, pstate, temperature.gpu, persistence_mode\n"
        "0, NVIDIA H100 80GB HBM3, 580.65.06, 96.00.74.00.01, 81559 MiB, Disabled, P0, 62, Disabled\n"
        "1, NVIDIA H100 80GB HBM3, 580.65.06, 96.00.74.00.01, 81559 MiB, Enabled, P0, 58, Enabled\n"
        "2, NVIDIA H100 80GB HBM3, 565.57.01, 96.00.74.00.01, 81559 MiB, Enabled, P0, 61, Enabled\n"
        "3, NVIDIA H100 80GB HBM3, 580.65.06, 96.00.74.00.02, 81559 MiB, Enabled, P0, 60, Enabled\n",
    )
    write_json("gpu/nvml.json", {
        "driver_version": "580.65.06",
        "cuda_version": "13.0",
        "nvml_remote_management": False,
        "xid_events": [
            {"gpu": 2, "xid": 79, "count": 1, "time": "2026-10-26T02:14:09Z",
             "note": "fallback to Xid 79 (GPU has fallen off the bus) mock event"},
        ],
    })
    write_text(
        "gpu/nvidia-smi-clean.csv",
        "index, name, driver_version, vbios_version, memory.total, ecc.mode.current, pstate, temperature.gpu, persistence_mode\n"
        "0, NVIDIA H100 80GB HBM3, 580.65.06, 96.00.74.00.01, 81559 MiB, Enabled, P0, 52, Enabled\n"
        "1, NVIDIA H100 80GB HBM3, 580.65.06, 96.00.74.00.01, 81559 MiB, Enabled, P0, 53, Enabled\n",
    )
    write_json("gpu/nvml-clean.json", {
        "driver_version": "580.65.06",
        "cuda_version": "13.0",
        "nvml_remote_management": False,
        "xid_events": [],
    })


def sonic_fixtures() -> None:
    write_json("sonic/config_db.json", {
        "DEVICE_METADATA": {"localhost": {"hostname": "leaf-01", "platform": "x86_64-mock",
                                          "type": "LeafRouter"}},
        "PFC_WATCHDOG": {"GLOBAL": {"mode": "disable"}},
        "BUFFER_POOL": {"ingress_lossless_pool": {"mode": "dynamic", "size": "12766208"}},
        "WRED_PROFILE": {"AZURE_LOSSLESS": {"wred_enabled": "false", "ecn": "ecn_all",
                                             "green_min_threshold": "150000"}},
        "ACL_RULE": {"MGMT_ACL|ALLOW_ANY": {
            "PRIORITY": "1", "PACKET_ACTION": "ACCEPT", "SRC_IP": "0.0.0.0/0",
            "IP_PROTOCOL": "6", "L4_DST_PORT": "22",
        }},
        "MGMT_INTERFACE": {"eth0|10.0.0.2/24": {"gwaddr": "10.0.0.1"}},
        "SNMP": {"COMMUNITY": {"public": {"TYPE": "RO"}}},
        "NTP_SERVER": {},
        "FEATURE": {"management-framework": {"state": "enabled"}},
    })
    write_json("sonic/config_db_hardened.json", {
        "DEVICE_METADATA": {"localhost": {"hostname": "leaf-01", "platform": "x86_64-mock",
                                          "type": "LeafRouter"}},
        "PFC_WATCHDOG": {"GLOBAL": {"mode": "detect"}},
        "BUFFER_POOL": {"ingress_lossless_pool": {"mode": "dynamic", "size": "12766208"}},
        "WRED_PROFILE": {"AZURE_LOSSLESS": {"wred_enabled": "true", "ecn": "ecn_all",
                                             "green_min_threshold": "150000"}},
        "ACL_RULE": {"MGMT_ACL|DENY_ALL": {
            "PRIORITY": "1", "PACKET_ACTION": "DROP", "SRC_IP": "0.0.0.0/0",
        }},
        "MGMT_INTERFACE": {"eth0|10.0.0.2/24": {"gwaddr": "10.0.0.1"}},
        "SNMP": {"SNMP_V3": {"USER": {"auth": "sha", "priv": "aes"}}},
        "NTP_SERVER": {"10.0.0.10": {}},
        "AAA": {"TACACS+": {"10.0.0.20": {"key": "****"}}},
        "FEATURE": {"management-framework": {"state": "enabled"}},
    })
    write_json("cumulus/config.json", {
        "system": {"hostname": "spine-01", "platform": "cumulus-linux-mock"},
        "interfaces": {
            "swp1": {"pfc": {"enabled": True, "watchdog": False},
                      "ecn": {"enabled": False}},
            "swp2": {"pfc": {"enabled": True, "watchdog": False},
                      "ecn": {"enabled": False}},
        },
        "acl": {"mgmt": {"rules": [{"action": "permit", "src": "0.0.0.0/0",
                                      "dst_port": 22, "proto": "tcp"}]}},
        "snmp": {"version": "2c", "community": "public"},
        "ntp": {"servers": []},
        "aaa": {"tacacs": []},
    })


def nvswitch_fixtures() -> None:
    write_json("nvswitch/topology.json", {
        "domain": "nvl72-mock",
        "generated_at": GENERATED_AT,
        "switches": [
            {"id": "nvswitch-0", "firmware": "1.8.2.0", "partitions": [1, 3]},
            {"id": "nvswitch-1", "firmware": "1.8.1.0", "partitions": [1, 2]},
            {"id": "nvswitch-2", "firmware": "1.8.2.0", "partitions": [2, 3]},
            {"id": "nvswitch-3", "firmware": "1.8.2.0", "partitions": [2]},
        ],
        "links": [
            {"from": "gpu-0", "to": "nvswitch-0", "port": 0, "state": "up", "width": 18},
            {"from": "gpu-1", "to": "nvswitch-1", "port": 0, "state": "up", "width": 18},
            {"from": "gpu-2", "to": "nvswitch-2", "port": 0, "state": "up", "width": 18},
            {"from": "gpu-3", "to": "nvswitch-2", "port": 3, "state": "down", "width": 0},
            {"from": "gpu-4", "to": "nvswitch-0", "port": 4, "state": "up", "width": 18},
            {"from": "gpu-5", "to": "nvswitch-1", "port": 5, "state": "up", "width": 18},
            {"from": "gpu-6", "to": "nvswitch-3", "port": 0, "state": "up", "width": 18},
            {"from": "gpu-7", "to": "nvswitch-3", "port": 1, "state": "degraded", "width": 9},
        ],
        "partitions": [
            {"id": 1, "tenant": "tenant-a", "switches": ["nvswitch-0", "nvswitch-1"],
             "gpus": ["gpu-0", "gpu-1"]},
            {"id": 2, "tenant": "tenant-a",
             "switches": ["nvswitch-1", "nvswitch-2", "nvswitch-3"],
             "gpus": ["gpu-2", "gpu-3", "gpu-7"]},
            {"id": 3, "tenant": "tenant-b", "switches": ["nvswitch-0", "nvswitch-2"],
             "gpus": ["gpu-4", "gpu-0"]},
        ],
        "imex": {"channels": [
            {"id": "imex-1", "tenant": "tenant-a",
             "members": ["tenant-a/host-1", "tenant-b/host-2"]},
        ]},
    })
    write_json("nvswitch/topology-clean.json", {
        "domain": "nvl72-mock",
        "generated_at": GENERATED_AT,
        "switches": [
            {"id": "nvswitch-0", "firmware": "1.8.2.0", "partitions": [1]},
            {"id": "nvswitch-1", "firmware": "1.8.2.0", "partitions": [2]},
            {"id": "nvswitch-2", "firmware": "1.8.2.0", "partitions": [3]},
            {"id": "nvswitch-3", "firmware": "1.8.2.0", "partitions": [4]},
        ],
        "links": [
            {"from": f"gpu-{i}", "to": f"nvswitch-{i // 2}", "port": i % 2,
             "state": "up", "width": 18}
            for i in range(8)
        ],
        "partitions": [
            {"id": 1, "tenant": "tenant-a", "switches": ["nvswitch-0"],
             "gpus": ["gpu-0", "gpu-1"]},
            {"id": 2, "tenant": "tenant-a", "switches": ["nvswitch-1"],
             "gpus": ["gpu-2", "gpu-3"]},
            {"id": 3, "tenant": "tenant-b", "switches": ["nvswitch-2"],
             "gpus": ["gpu-4", "gpu-5"]},
            {"id": 4, "tenant": "tenant-b", "switches": ["nvswitch-3"],
             "gpus": ["gpu-6", "gpu-7"]},
        ],
        "imex": {"channels": [
            {"id": "imex-a", "tenant": "tenant-a", "members": ["tenant-a/host-1"]},
            {"id": "imex-b", "tenant": "tenant-b", "members": ["tenant-b/host-1"]},
        ]},
    })


def ib_fixtures() -> None:
    write_json("ib/partition-dump.json", {
        "subnet_prefix": "fe80::/64",
        "sm": {"primary": "guid-sm-1", "secondary": None, "host": "gpu-node-07",
               "routing_engine": "minhop", "opensm_version": "3.3.24", "priority": 0},
        "partitions": [
            {"pkey": "0x7fff", "name": "default", "default": True,
             "members": ["*"], "tenant": None, "ipoib": True},
            {"pkey": "0x8001", "name": "train-a", "default": False,
             "members": ["guid-h1", "guid-h2", "guid-h5"], "tenant": "tenant-a",
             "ipoib": True},
            {"pkey": "0x8002", "name": "train-b", "default": False,
             "members": ["guid-h3", "guid-h4"], "tenant": "tenant-b", "ipoib": False},
        ],
        "nodes": [
            {"guid": "guid-h1", "type": "HCA", "tenant": "tenant-a", "host": "gpu-node-01",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h2", "type": "HCA", "tenant": "tenant-a", "host": "gpu-node-02",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h3", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-03",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h4", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-04",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h5", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-05",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h7", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-07",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-sm-1", "type": "SWITCH", "tenant": None, "host": "gpu-node-07",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
        ],
        "tenants": ["tenant-a", "tenant-b"],
    })
    write_json("ib/partition-dump-clean.json", {
        "subnet_prefix": "fe80::/64",
        "sm": {"primary": "guid-sm-1", "secondary": "guid-sm-2", "host": "sm-node-01",
               "routing_engine": "minhop", "opensm_version": "3.3.24", "priority": 0},
        "partitions": [
            {"pkey": "0x7fff", "name": "default", "default": True,
             "members": ["guid-sm-1"], "tenant": None, "ipoib": False},
            {"pkey": "0x8001", "name": "train-a", "default": False,
             "members": ["guid-h1", "guid-h2"], "tenant": "tenant-a", "ipoib": False},
            {"pkey": "0x8002", "name": "train-b", "default": False,
             "members": ["guid-h3", "guid-h4"], "tenant": "tenant-b", "ipoib": False},
        ],
        "nodes": [
            {"guid": "guid-h1", "type": "HCA", "tenant": "tenant-a", "host": "gpu-node-01",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h2", "type": "HCA", "tenant": "tenant-a", "host": "gpu-node-02",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h3", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-03",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-h4", "type": "HCA", "tenant": "tenant-b", "host": "gpu-node-04",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-sm-1", "type": "SWITCH", "tenant": None, "host": "sm-node-01",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
            {"guid": "guid-sm-2", "type": "SWITCH", "tenant": None, "host": "sm-node-02",
             "ports": [{"state": "ACTIVE", "rate_gbps": 400}]},
        ],
        "tenants": ["tenant-a", "tenant-b"],
    })


def sharp_fixtures() -> None:
    write_json("sharp/config-dump.json", {
        "sharp": {"enabled": True, "version": "3.2.1", "daemon": "sharpd",
                  "am_enabled": True, "tenant_sharing": True},
        "sessions": [
            {"id": "train-alpha", "tenant": "tenant-a", "auth": "none",
             "members": ["tenant-a/rank-0", "tenant-a/rank-1"],
             "aggregation_nodes": ["leaf-1", "leaf-2"], "buffer_isolation": True},
            {"id": "train-beta", "tenant": "tenant-b", "auth": "none",
             "members": ["tenant-b/rank-0", "tenant-a/rank-1"],
             "aggregation_nodes": ["leaf-1", "leaf-2"], "buffer_isolation": False},
        ],
        "collectives": [
            {"name": "all-reduce", "session": "train-alpha", "reduction": "fp32",
             "tree": "agg-1", "buffer_isolation": True},
            {"name": "all-reduce", "session": "train-beta", "reduction": "fp32",
             "tree": "agg-1", "buffer_isolation": False},
        ],
    })
    write_json("sharp/config-dump-clean.json", {
        "sharp": {"enabled": True, "version": "3.2.1", "daemon": "sharpd",
                  "am_enabled": True, "tenant_sharing": False},
        "sessions": [
            {"id": "train-alpha", "tenant": "tenant-a", "auth": "mtls",
             "members": ["tenant-a/rank-0", "tenant-a/rank-1"],
             "aggregation_nodes": ["leaf-1"], "buffer_isolation": True},
            {"id": "train-beta", "tenant": "tenant-b", "auth": "mtls",
             "members": ["tenant-b/rank-0", "tenant-b/rank-1"],
             "aggregation_nodes": ["leaf-2"], "buffer_isolation": True},
        ],
        "collectives": [
            {"name": "all-reduce", "session": "train-alpha", "reduction": "fp32",
             "tree": "agg-1", "buffer_isolation": True},
            {"name": "all-reduce", "session": "train-beta", "reduction": "fp32",
             "tree": "agg-2", "buffer_isolation": True},
        ],
    })


def firmware_fixtures() -> None:
    blobs = {
        "gpu-driver-580.65.06.bin": "MOCK-FIRMWARE gpu-driver 580.65.06\nfixture-only\n",
        "bmc-fw-2.10.0.bin": "MOCK-FIRMWARE bmc 2.10.0\nfixture-only\n",
        "nvswitch-fw-1.8.2.bin": "MOCK-FIRMWARE nvswitch 1.8.2.0\nfixture-only\n",
        "dpu-fw-32.42.1000.bin": "MOCK-FIRMWARE dpu 32.42.1000\nfixture-only\n",
    }
    for name, text in blobs.items():
        write_text(f"firmware/blobs/{name}", text)
    components = [
        {"name": "gpu-driver", "version": "580.65.06",
         "file": "blobs/gpu-driver-580.65.06.bin",
         "sha256": sha256_file(ROOT / "firmware/blobs/gpu-driver-580.65.06.bin"),
         "vendor": "MockVendor", "signed_by": "MockVendor"},
        {"name": "bmc-fw", "version": "2.10.0",
         "file": "blobs/bmc-fw-2.10.0.bin",
         "sha256": sha256_file(ROOT / "firmware/blobs/bmc-fw-2.10.0.bin"),
         "vendor": "MockVendor", "signed_by": "MockVendor"},
        {"name": "nvswitch-fw", "version": "1.8.2.0",
         "file": "blobs/nvswitch-fw-1.8.2.bin",
         "sha256": sha256_file(ROOT / "firmware/blobs/nvswitch-fw-1.8.2.bin"),
         "vendor": "MockVendor", "signed_by": "MockVendor"},
        {"name": "dpu-fw", "version": "32.42.1000",
         "file": "blobs/dpu-fw-32.42.1000.bin",
         "sha256": sha256_file(ROOT / "firmware/blobs/dpu-fw-32.42.1000.bin"),
         "vendor": "MockVendor", "signed_by": "MockVendor"},
    ]
    manifest = {
        "schema": "trident-firmware-manifest/v1",
        "generated_at": GENERATED_AT,
        "vendor": "MockVendor",
        "signing": {"alg": "hmac-sha256-fixture", "key_id": "trident-hardware-fixture-2026"},
        "components": components,
    }
    manifest["signature"] = sign_manifest(manifest, FIXTURE_KEY)
    write_json("firmware/manifest.json", manifest)
    write_json("firmware/manifest.sig.json", {
        "alg": "hmac-sha256-fixture",
        "key_id": "trident-hardware-fixture-2026",
        "signature": manifest["signature"],
    })
    write_text("firmware/fixture-signing-key.txt", FIXTURE_KEY + "\n")
    write_text(
        "README.md",
        "# Hardware / switch fixtures (synthetic)\n\n"
        "All data is synthetic and safe to publish: no real GPU/BMC/switch serial numbers,\n"
        "no real credentials, no vendor-private configuration. The firmware signature uses\n"
        "an HMAC fixture key to exercise the verification path only; production must use a\n"
        "vendor asymmetric signature / PKI trust chain.\n\n"
        "Regenerate with: `python lab/hardware-fixtures/build_fixtures.py`.\n",
    )


def main() -> int:
    gpu_fixtures()
    sonic_fixtures()
    nvswitch_fixtures()
    ib_fixtures()
    sharp_fixtures()
    firmware_fixtures()
    print(f"fixtures written under {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
