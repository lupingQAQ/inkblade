"""lab/hardware_sim.py — 硬件/交换机只读审计仿真靶场（仅 127.0.0.1，仅标准库）。

模拟的是「拿到客户导出的配置 / 遥测 / Redfish 只读接口」这一现实审计入口，不模拟真实
固件刷新、PFC 配置下发、NVSwitch 分区写入或 BMC 写操作。整个仿真只有 GET 路由
（``writes=false``），POST 一律 405，避免把实验室脚本误用成破坏工具。

两个平面：
- 配置面：Redfish/BMC、SONiC config_db、NVSwitch/NVLink 拓扑、DPU 服务清单、固件清单；
- 遥测面：telemetry/gNMI 配置、SNMP 视图、带 tenant/serial 标签的指标。

两种姿态：
- vulnerable：匿名管理详情、厂商默认凭据可登录、IPMI over LAN、PFC watchdog 关闭、
  跨租户 NVLink/IMEX 分区、DPU 服务未鉴权/凭据明文、gNMI 无 TLS/无鉴权、SNMP v2c public；
- fixed：管理面 401、默认凭据拒绝、IPMI 关闭、PFC watchdog detect、租户隔离分区、
  DPU 全鉴权/凭据 404、gNMI TLS+鉴权、SNMPv3。

写盘边界：本仿真完全内存态（fixture 只读），shutdown 仅关服务。
命令行：python lab/hardware_sim.py [--port N] [--mode vulnerable|fixed]
"""

from __future__ import annotations

import argparse
import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
FIXTURES = Path(__file__).resolve().parent / "hardware-fixtures"

DEFAULT_BMC_USER = "root"
DEFAULT_BMC_PASSWORD = "calvin"
DEFAULT_BMC_ACCOUNTS = (
    (DEFAULT_BMC_USER, DEFAULT_BMC_PASSWORD),
    ("admin", "admin"),
)
ADMIN_USER = "trident-admin"
ADMIN_PASSWORD = "fixed-admin-token"
DPU_DEFAULT_USER = "mock-dpu-admin"
DPU_DEFAULT_PASSWORD = "mock-dpu-default-pass"


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_json(rel: str) -> dict:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def _basic_user(headers) -> str:
    raw = (headers.get("Authorization") or "").strip()
    if not raw.lower().startswith("basic "):
        return ""
    try:
        decoded = base64.b64decode(raw[6:].strip()).decode("utf-8")
    except Exception:  # noqa: BLE001 -- 畸形认证头按匿名处理
        return ""
    return decoded.split(":", 1)[0] if ":" in decoded else ""


def _basic_pair(headers) -> tuple[str, str]:
    raw = (headers.get("Authorization") or "").strip()
    if not raw.lower().startswith("basic "):
        return "", ""
    try:
        decoded = base64.b64decode(raw[6:].strip()).decode("utf-8")
    except Exception:  # noqa: BLE001
        return "", ""
    if ":" not in decoded:
        return "", ""
    user, password = decoded.split(":", 1)
    return user, password


class _HardwareState:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.lock = threading.Lock()
        self.requests = 0
        self.by_path: dict[str, int] = {}
        self.started_at = _utcnow_iso()
        self.sonic = _load_json(
            "sonic/config_db_hardened.json" if mode == "fixed" else "sonic/config_db.json"
        )
        self.nvswitch = _load_json(
            "nvswitch/topology-clean.json" if mode == "fixed" else "nvswitch/topology.json"
        )
        self.firmware = _load_json("firmware/manifest.json")
        self.firmware_sig = _load_json("firmware/manifest.sig.json")

    def record(self, path: str) -> None:
        with self.lock:
            self.requests += 1
            self.by_path[path] = self.by_path.get(path, 0) + 1


class _RequestContext:
    def __init__(self, mode: str, state: _HardwareState, headers, path: str):
        self.mode = mode
        self.state = state
        self.headers = headers
        self.path = path

    @property
    def user(self) -> str:
        return _basic_user(self.headers)

    @property
    def admin(self) -> bool:
        return _basic_pair(self.headers) == (ADMIN_USER, ADMIN_PASSWORD)

    @property
    def default_login(self) -> bool:
        pair = _basic_pair(self.headers)
        return self.mode == "vulnerable" and pair in DEFAULT_BMC_ACCOUNTS


# ---------------------------------------------------------------------------
# 配置面
# ---------------------------------------------------------------------------


def _redfish_root(ctx: _RequestContext):
    return 200, {
        "@odata.id": "/redfish/v1/",
        "RedfishVersion": "1.18.0",
        "Vendor": "MockVendor",
        "Product": "MockBMC-X1",
        "Managers": {"@odata.id": "/redfish/v1/Managers"},
        "Systems": {"@odata.id": "/redfish/v1/Systems"},
    }


def _redfish_manager(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "redfish-manager"}
    return 200, {
        "@odata.id": "/redfish/v1/Managers/BMC",
        "Id": "BMC",
        "Name": "Mock BMC",
        "FirmwareVersion": "2.10.0",
        "UUID": "MOCK-BMC-UUID-0001",
        "AccountService": {"@odata.id": "/redfish/v1/AccountService"},
        "NetworkProtocol": {"@odata.id": "/redfish/v1/Managers/BMC/NetworkProtocol"},
    }


def _redfish_network_protocol(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "redfish-network-protocol"}
    if ctx.mode == "fixed":
        return 200, {
            "IPMI": {"ProtocolEnabled": False, "Port": 623},
            "SSH": {"ProtocolEnabled": True, "Port": 22, "PasswordAuthentication": False},
            "HTTPS": {"ProtocolEnabled": True, "Port": 443},
            "SNMP": {"ProtocolEnabled": False},
        }
    return 200, {
        "IPMI": {"ProtocolEnabled": True, "Port": 623},
        "SSH": {"ProtocolEnabled": True, "Port": 22, "PasswordAuthentication": True},
        "HTTPS": {"ProtocolEnabled": True, "Port": 443},
        "SNMP": {"ProtocolEnabled": True, "Port": 161},
    }


def _redfish_accounts(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "redfish-accounts"}
    members = [
        {"UserName": "root", "RoleId": "Administrator", "Enabled": True,
         "DefaultCredential": True, "Locked": False},
        {"UserName": "service", "RoleId": "Operator", "Enabled": True,
         "DefaultCredential": False, "Locked": False},
    ]
    if ctx.mode == "fixed":
        members = [
            {"UserName": ADMIN_USER, "RoleId": "Administrator", "Enabled": True,
             "DefaultCredential": False, "Locked": False},
        ]
    return 200, {"Members": members, "Members@odata.count": len(members)}


def _redfish_system(ctx: _RequestContext):
    if not (ctx.admin or ctx.default_login):
        return 401, {"error": "unauthorized", "service": "redfish-system"}
    return 200, {
        "@odata.id": "/redfish/v1/Systems/1",
        "Id": "1",
        "Name": "Mock GPU Server",
        "PowerState": "On",
        "ProcessorSummary": {"Count": 2},
        "MemorySummary": {"TotalSystemMemoryGiB": 2048},
        "Links": {"Chassis": [{"@odata.id": "/redfish/v1/Chassis/1"}]},
    }


def _sonic_config(ctx: _RequestContext):
    return 200, ctx.state.sonic


def _nvswitch_topology(ctx: _RequestContext):
    return 200, ctx.state.nvswitch


def _firmware_manifest(ctx: _RequestContext):
    return 200, ctx.state.firmware


def _firmware_signature(ctx: _RequestContext):
    return 200, ctx.state.firmware_sig


# ---------------------------------------------------------------------------
# DPU 面
# ---------------------------------------------------------------------------


def _dpu_health(ctx: _RequestContext):
    return 200, {
        "hostname": "dpu-01", "state": "ready", "mode": ctx.mode,
        "doca_version": "3.2.0", "fw_version": "32.42.1000",
    }


def _dpu_services(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 200, {
            "hostname": "dpu-01",
            "services": [
                {"name": "redfish", "port": 443, "protocol": "https",
                 "management": True, "auth_required": True},
                {"name": "grpc-doca", "port": 50051, "protocol": "grpc",
                 "management": True, "auth_required": True},
                {"name": "ssh", "port": 22, "protocol": "ssh",
                 "management": True, "auth_required": True, "password_auth": False},
                {"name": "telemetry", "port": 8080, "protocol": "http",
                 "management": False, "auth_required": True},
            ],
            "rshim": {"enabled": False, "device": "/dev/rshim0"},
        }
    return 200, {
        "hostname": "dpu-01",
        "services": [
            {"name": "redfish", "port": 443, "protocol": "https",
             "management": True, "auth_required": False},
            {"name": "grpc-doca", "port": 50051, "protocol": "grpc",
             "management": True, "auth_required": False},
            {"name": "ssh", "port": 22, "protocol": "ssh",
             "management": True, "auth_required": True, "password_auth": True},
            {"name": "telemetry", "port": 8080, "protocol": "http",
             "management": False, "auth_required": False},
        ],
        "rshim": {"enabled": True, "device": "/dev/rshim0"},
    }


def _dpu_credentials(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 404, {"error": "not found", "service": "dpu-credentials"}
    return 200, {
        "source": "factory-default",
        "username": DPU_DEFAULT_USER,
        "password": DPU_DEFAULT_PASSWORD,
        "rotation_required": True,
    }


# ---------------------------------------------------------------------------
# 遥测面
# ---------------------------------------------------------------------------


def _telemetry_config(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 200, {
            "plane": "telemetry",
            "gnmi": {"enabled": True, "port": 6030, "tls": True, "auth": True},
            "snmp": {"version": "3", "community": None, "acl": ["10.0.0.0/8"]},
            "tsdb": {"retention_days": 90},
            "collectors": ["pfc", "ecn", "buffer"],
        }
    return 200, {
        "plane": "telemetry",
        "gnmi": {"enabled": True, "port": 6030, "tls": False, "auth": False},
        "snmp": {"version": "2c", "community": "public", "acl": []},
        "tsdb": {"retention_days": 400},
        "collectors": ["pfc", "ecn", "buffer"],
    }


def _telemetry_metrics(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "telemetry"}
    return 200, {
        "generated_at": _utcnow_iso(),
        "tenants": ["tenant-a", "tenant-b"] if ctx.mode == "vulnerable" else ["tenant-a"],
        "metrics": [
            {"name": "fabric_pfc_pause_frames_total",
             "labels": {"switch": "leaf-01", "tenant": "tenant-a", "serial": "SN-MOCK-0001"},
             "value": 128},
            {"name": "fabric_ecn_marks_total",
             "labels": {"switch": "leaf-01", "tenant": "tenant-b", "serial": "SN-MOCK-0002"},
             "value": 7},
        ],
    }


def _health(ctx: _RequestContext):
    return 200, {"ok": True, "service": "hardware-sim", "mode": ctx.mode,
                 "started_at": ctx.state.started_at, "fixtures": str(FIXTURES.name)}


def _stats(ctx: _RequestContext):
    with ctx.state.lock:
        return 200, {"mode": ctx.mode, "requests": ctx.state.requests,
                     "by_path": dict(sorted(ctx.state.by_path.items()))}


def _routes(ctx: _RequestContext):
    return 200, {
        "service": "trident-hardware-lab",
        "mode": ctx.mode,
        "host": HOST,
        "route_count": len(ROUTE_TABLE),
        "routes": [{k: v for k, v in entry.items() if k != "behavior"}
                   for entry in ROUTE_TABLE],
        "planes": sorted({entry["plane"] for entry in ROUTE_TABLE}),
    }


# ---------------------------------------------------------------------------
# 路由表（全部 GET / writes=false）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "redfish", "path": "/redfish/v1/", "plane": "redfish", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "Redfish 服务根与版本", "behavior": _redfish_root},
    {"service": "redfish", "path": "/redfish/v1/Managers/BMC", "plane": "redfish",
     "method": "GET", "vulnerable": 200, "fixed": 401, "writes": False,
     "title": "BMC 管理详情（固件/UUID）", "behavior": _redfish_manager},
    {"service": "redfish", "path": "/redfish/v1/Managers/BMC/NetworkProtocol", "plane": "redfish",
     "method": "GET", "vulnerable": 200, "fixed": 401, "writes": False,
     "title": "BMC 网络协议（IPMI/SSH/SNMP）", "behavior": _redfish_network_protocol},
    {"service": "redfish", "path": "/redfish/v1/Managers/BMC/Accounts", "plane": "redfish",
     "method": "GET", "vulnerable": 200, "fixed": 401, "writes": False,
     "title": "BMC 账号与默认凭据标记", "behavior": _redfish_accounts},
    {"service": "redfish", "path": "/redfish/v1/Systems/1", "plane": "redfish",
     "method": "GET", "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "BMC 主机系统详情（需 Basic 认证）", "behavior": _redfish_system},
    {"service": "sonic", "path": "/sonic/config", "plane": "config", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "SONiC config_db 导出（PFC/ECN/ACL/管理面）", "behavior": _sonic_config},
    {"service": "nvswitch", "path": "/nvswitch/topology", "plane": "config",
     "method": "GET", "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "NVSwitch/NVLink 拓扑与分区导出", "behavior": _nvswitch_topology},
    {"service": "dpu", "path": "/dpu/health", "plane": "dpu", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "DPU 健康与固件版本", "behavior": _dpu_health},
    {"service": "dpu", "path": "/dpu/services", "plane": "dpu", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "DPU 服务清单与鉴权标记", "behavior": _dpu_services},
    {"service": "dpu", "path": "/dpu/credentials", "plane": "dpu", "method": "GET",
     "vulnerable": 200, "fixed": 404, "writes": False,
     "title": "DPU 凭据面（仅 vulnerable 暴露 mock 值）", "behavior": _dpu_credentials},
    {"service": "telemetry", "path": "/telemetry/v1/config", "plane": "telemetry",
     "method": "GET", "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "gNMI/SNMP/TSDB 遥测配置", "behavior": _telemetry_config},
    {"service": "telemetry", "path": "/telemetry/v1/metrics", "plane": "telemetry",
     "method": "GET", "vulnerable": 200, "fixed": 401, "writes": False,
     "title": "fabric 遥测指标（tenant/serial 标签）", "behavior": _telemetry_metrics},
    {"service": "firmware", "path": "/firmware/manifest", "plane": "firmware",
     "method": "GET", "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "固件清单（哈希 + 签名 fixture）", "behavior": _firmware_manifest},
    {"service": "firmware", "path": "/firmware/manifest.sig", "plane": "firmware",
     "method": "GET", "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "固件清单 detached 签名", "behavior": _firmware_signature},
    {"service": "lab", "path": "/health", "plane": "config", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "仿真健康检查", "behavior": _health},
    {"service": "lab", "path": "/__routes__", "plane": "config", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "路由清单", "behavior": _routes},
    {"service": "lab", "path": "/__stats__", "plane": "config", "method": "GET",
     "vulnerable": 200, "fixed": 200, "writes": False,
     "title": "请求计数（仅 GET）", "behavior": _stats},
]

_ROUTES = {entry["path"]: entry for entry in ROUTE_TABLE}


class _HardwareHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str):
        super().__init__(address, _HardwareHandler)
        self.lab_mode = mode
        self.lab_state = _HardwareState(mode)


class _HardwareHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentHardwareSim/0.1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        return

    def _send(self, status: int, payload, extra_headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._method_not_allowed()

    def do_PUT(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    def _method_not_allowed(self):
        self._send(405, {"error": "method not allowed", "methods": ["GET"],
                         "note": "hardware lab is read-only"})

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        path = split.path
        norm = path.rstrip("/") or "/"
        if norm == "":
            norm = "/"
        entry = _ROUTES.get(norm)
        if entry is None:
            # 统一去掉结尾斜杠后查找，/redfish/v1 与 /redfish/v1/ 等价
            entry = _ROUTES.get(path if path.endswith("/") else path + "/")
        if entry is None:
            self._send(404, {"error": "not found", "path": path})
            return
        if method != "GET":
            self._method_not_allowed()
            return
        server = self.server  # type: _HardwareHTTPServer
        ctx = _RequestContext(server.lab_mode, server.lab_state, self.headers, path)
        server.lab_state.record(path)
        try:
            status, payload = entry["behavior"](ctx)
        except Exception as exc:  # noqa: BLE001 -- 仿真不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        extra = {"WWW-Authenticate": 'Basic realm="BMC"'} if status == 401 else None
        self._send(status, payload, extra)


class Server:
    """仿真服务句柄：.port/.mode/.root + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _HardwareHTTPServer, thread: threading.Thread, mode: str):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self.root = FIXTURES
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{k: v for k, v in entry.items() if k != "behavior"} for entry in ROUTE_TABLE]

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
    """启动硬件/交换机只读仿真服务（单服务器，仅 127.0.0.1，内存态）。"""
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _HardwareHTTPServer((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 硬件/交换机只读仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode)
    print(f"hardware-sim listening on {server.url('/')} mode={server.mode}")
    print(f"routes manifest: {server.url('/__routes__')}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
