"""lab/cve_sim.py — CVE 武器化实验室靶场（127.0.0.1，仅标准库）。

覆盖 20+ 公开 CVE/公告的**可 mock 面**：Ray Job、SGLang ZMQ/路由、vLLM Mooncake、
LiteLLM 默认 key/配置更新、IPMI cipher-zero、Redfish 默认凭据、SONiC/Cumulus 配置面、
Dify 代码节点、Open WebUI 文件覆盖、MLflow trace/model、Megatron/DeepSpeed/torch 检查点、
HAMi scheduler。vulnerable=与公开漏洞同构的 fail-open；fixed=加固姿态（401/403/400）。

写盘边界：所有 marker 仅落 Server.root；``POST /__cleanup__ {"marker": ...}`` 删除
含该 marker 的文件并清空内存状态。真实 IPMI 为 UDP/623，本靶场以 HTTP 表达
RMCP+ cipher-zero 语义，仅用于授权实验室证明，不连接真实 BMC。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
ROTATED_ADMIN_KEY = "MOCK-rotated-admin-key-e5f6"
DEFAULT_KEYS = ("sk-1234", "sk-litellm-master-key", "MOCK-master-key-4c7a")
REDFISH_DEFAULT_CREDS = (("admin", "admin"), ("root", "calvin"), ("ADMIN", "ADMIN"))
REDFISH_STRONG = ("admin", "MOCK-strong-redfish-key")
UPSTREAM_KEYS = (
    {"provider": "openai", "api_key": "MOCK-openai-upstream-key-9f3c"},
    {"provider": "anthropic", "api_key": "MOCK-anthropic-upstream-key-71ab"},
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(value, fallback="unnamed") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return cleaned or fallback


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _Ctx:
    def __init__(self, mode, root, state, headers, body, path, query, entry):
        self.mode = mode
        self.root = root
        self.state = state
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.entry = entry

    def authorized(self) -> bool:
        return (self.headers.get("Authorization") or "") == f"Bearer {ROTATED_ADMIN_KEY}"

    def bearer(self) -> str:
        value = self.headers.get("Authorization") or ""
        return value[7:].strip() if value.lower().startswith("bearer ") else ""

    def marker_file(self, *parts: str, marker: str, extra: dict | None = None) -> dict:
        path = self.root.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"service": "trident-cve-sim", "mode": self.mode, "marker": marker,
                   "created_at": _now(), **(extra or {})}
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        path.write_text(text, encoding="utf-8")
        return {"marker_path": str(path), "marker_sha256": _sha(text)}


# ---------------------------------------------------------------------------
# 行为函数
# ---------------------------------------------------------------------------

def _ray_submit(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    entrypoint = str(ctx.body.get("entrypoint") or "python -c print('trident')")
    job_id = "raysubmit-" + uuid.uuid4().hex
    info = ctx.marker_file("ray", "jobs", f"{job_id}.marker", marker=marker,
                           extra={"job_id": job_id, "entrypoint": entrypoint})
    ctx.state["ray_jobs"][job_id] = {"job_id": job_id, "entrypoint": entrypoint, "status": "SUCCEEDED"}
    return 200, {"ok": True, "service": "ray", "job_id": job_id, "status": "SUCCEEDED", **info}


def _ray_list(ctx: _Ctx):
    jobs = sorted(ctx.state["ray_jobs"].values(), key=lambda x: x["job_id"])
    return 200, {"service": "ray", "count": len(jobs), "jobs": jobs}


def _ray_dashboard(ctx: _Ctx):
    return 200, {"service": "ray", "version": "2.8.0", "dashboard": 8265, "auth": "none"}


def _sglang_zmq(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    payload = str(ctx.body.get("payload_b64") or "")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("sglang", "zmq", f"{rid}.marker", marker=marker,
                           extra={"payload_len": len(payload), "deserialized": True})
    return 200, {"ok": True, "service": "sglang", "broker": "zmq", "rce": True, **info}


def _sglang_route(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    rank_ip = str(ctx.body.get("rank_ip") or "127.0.0.1")
    rank_port = int(ctx.body.get("rank_port") or 29400)
    info = ctx.marker_file("sglang", "route-poison.marker", marker=marker,
                           extra={"rank_ip": rank_ip, "rank_port": rank_port})
    route = ctx.root / "sglang" / "routes.json"
    route.parent.mkdir(parents=True, exist_ok=True)
    route.write_text(json.dumps({"0": {"rank_ip": rank_ip, "rank_port": rank_port},
                                 "marker": marker}, ensure_ascii=False), encoding="utf-8")
    return 200, {"ok": True, "poisoned": True, "rank_ip": rank_ip, "rank_port": rank_port, **info}


def _sglang_info(ctx: _Ctx):
    if ctx.mode == "fixed":
        return 200, {"service": "sglang", "api_key": None, "ssl_keyfile": None,
                     "auth_required": True}
    return 200, {"service": "sglang", "api_key": "MOCK-sglang-api-key-7c1d",
                 "ssl_keyfile": "/etc/sglang/ssl/private.key", "auth_required": False}


def _sglang_weights(ctx: _Ctx):
    marker = str(ctx.query.get("marker", ["TRIDENT-BENIGN"])[0])
    return 200, {"ok": True, "tensors": 3, "dtype": "bfloat16",
                 "blob_b64": base64.b64encode((marker + "\n").encode()).decode(),
                 "marker": marker, "exfiltrated": True}


def _vllm_mooncake(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("vllm", "mooncake", f"{rid}.marker", marker=marker,
                           extra={"socket": "0.0.0.0:29500", "pickle": True})
    return 200, {"ok": True, "service": "vllm", "backend": "mooncake", "rce": True, **info}


def _vllm_metrics(ctx: _Ctx):
    return 200, ('# HELP vllm:kv_transfer_backend KV transfer backend\n'
                 'vllm:kv_transfer_backend{backend="mooncake"} 1\n'
                 'vllm:num_requests_running 0\n')


def _vllm_models(ctx: _Ctx):
    return 200, {"object": "list", "data": [{"id": "mock-vllm", "object": "model"}]}


def _litellm_config(ctx: _Ctx):
    key = ctx.bearer()
    if ctx.mode == "fixed":
        if key != ROTATED_ADMIN_KEY:
            return 401, {"error": "default_master_key_rejected", "service": "litellm"}
        return 200, {"service": "litellm", "master_key": "MOCK****e5f6",
                     "upstreams": [{**u, "api_key": "MOCK****" + u["api_key"][-4:]} for u in UPSTREAM_KEYS]}
    if key not in DEFAULT_KEYS:
        return 401, {"error": "unauthorized", "service": "litellm"}
    return 200, {"service": "litellm", "master_key": key,
                 "key_class": "default" if key != ROTATED_ADMIN_KEY else "rotated",
                 "upstreams": list(UPSTREAM_KEYS)}


def _litellm_health(ctx: _Ctx):
    if ctx.mode == "fixed":
        return 200, {"service": "litellm", "status": "ok", "master_key": "MOCK****e5f6"}
    return 200, {"service": "litellm", "status": "ok", "master_key": DEFAULT_KEYS[0]}


def _litellm_config_update(ctx: _Ctx):
    key = ctx.bearer()
    if ctx.mode == "fixed":
        return 403, {"error": "proxy_admin_required", "service": "litellm", "role": "internal_user"}
    if not key:
        return 401, {"error": "unauthorized", "service": "litellm"}
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("litellm", "config", f"{rid}.marker", marker=marker,
                           extra={"handler": "attacker-passthrough", "role": "internal_user"})
    return 200, {"ok": True, "config_updated": True, "rce": True, **info}


def _ipmi_info(ctx: _Ctx):
    return 200, {"service": "ipmi", "vendor": "AMI", "product": "MegaRAC SPx12",
                 "firmware": "12.3", "ipmi_port": 623, "cipher_zero": ctx.mode != "fixed"}


def _ipmi_rmcp(ctx: _Ctx):
    cipher = int(ctx.body.get("cipher", -1))
    auth = str(ctx.body.get("auth") or "none")
    user = str(ctx.body.get("username") or "admin")
    if ctx.mode == "fixed" or cipher != 0 or auth != "none":
        return 401, {"error": "cipher_zero_rejected", "service": "ipmi",
                     "hint": "fixed 模式仅允许带认证的 cipher suite"}
    sid = "ipmi-" + uuid.uuid4().hex[:10]
    ctx.state["ipmi_sessions"][sid] = {"user": user, "privilege": "admin", "cipher": 0}
    return 200, {"ok": True, "session": sid, "cipher": 0, "username": user,
                 "privilege": "admin", "auth": "none"}


def _redfish_root(ctx: _Ctx):
    return 200, {"@odata.id": "/redfish/v1", "RedfishVersion": "1.15.0",
                 "Systems": {"@odata.id": "/redfish/v1/Systems"},
                 "Managers": {"@odata.id": "/redfish/v1/Managers"}}


def _redfish_login(ctx: _Ctx):
    raw = ctx.headers.get("Authorization") or ""
    user = password = ""
    if raw.lower().startswith("basic "):
        try:
            user, _, password = base64.b64decode(raw[6:]).decode("utf-8").partition(":")
        except Exception:
            pass
    ok = ((user, password) in REDFISH_STRONG) if ctx.mode == "fixed" else (
        (user, password) in REDFISH_DEFAULT_CREDS)
    if not ok:
        return 401, {"error": "invalid_credentials", "service": "redfish"}
    token = "redfish-" + uuid.uuid4().hex
    ctx.state["redfish_sessions"][token] = {"user": user, "privilege": "Administrator"}
    return 201, {"Id": token, "Token": token, "UserName": user, "Privilege": "Administrator",
                 "default_credentials": (user, password) in REDFISH_DEFAULT_CREDS}


def _redfish_auth(ctx: _Ctx) -> bool:
    return (ctx.headers.get("X-Auth-Token") or "") in ctx.state["redfish_sessions"]


def _redfish_systems(ctx: _Ctx):
    if not _redfish_auth(ctx):
        return 401, {"error": "unauthorized", "service": "redfish"}
    return 200, {"Id": "1", "Name": "mock-node", "PowerState": "On",
                 "Processors": {"Count": 2}, "Memory": {"TotalSystemMemoryGiB": 512}}


def _redfish_managers(ctx: _Ctx):
    if not _redfish_auth(ctx):
        return 401, {"error": "unauthorized", "service": "redfish"}
    return 200, {"Id": "1", "Name": "BMC", "FirmwareVersion": "12.3",
                 "Actions": ["Reset", "VirtualMedia.Insert"]}


def _sonic_get(ctx: _Ctx):
    return 200, {"service": "sonic", "version": "SONiC.4.5.0", "hostname": "mock-leaf-1",
                 "interfaces": ["Ethernet0", "Ethernet4"], "config_writable": True}


def _sonic_write(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    cfg = ctx.body.get("config") or {"hostname": "attacker-leaf"}
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("sonic", "config", f"{rid}.marker", marker=marker, extra={"config": cfg})
    path = ctx.root / "sonic" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"config": cfg, "marker": marker}, ensure_ascii=False), encoding="utf-8")
    return 200, {"ok": True, "applied": True, **info}


def _sonic_rsyslog(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    value = str(ctx.body.get("welf_firewall_name") or "")
    if ctx.mode == "fixed":
        return 400, {"error": "unsafe_rsyslog_value_rejected", "service": "sonic"}
    conf = f"# generated by sonic\n$template WELF,\"{value}\"\n"
    path = ctx.root / "sonic" / "rsyslog.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(conf + f"# {marker}\n", encoding="utf-8")
    return 200, {"ok": True, "rsyslog_conf": str(path), "marker_path": str(path),
                 "marker": marker, "marker_sha256": _sha(path.read_text(encoding="utf-8")),
                 "injected": True}


def _cumulus_get(ctx: _Ctx):
    return 200, {"service": "cumulus", "version": "5.13.0", "nvue": "enabled"}


def _cumulus_write(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    command = str(ctx.body.get("command") or "nv config show")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("cumulus", "nvue", f"{rid}.marker", marker=marker,
                           extra={"command": command, "injected": True})
    return 200, {"ok": True, "command": command, "privilege": "root", **info}


def _dify_features(ctx: _Ctx):
    return 200, {"service": "dify", "system_features": {"sso": False, "marketplace": True},
                 "version": "1.9.1"}


def _dify_code(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    code = str(ctx.body.get("code") or "return 1")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("dify", "code-node", f"{rid}.marker", marker=marker,
                           extra={"code": code, "sandbox": "escaped", "uid": 0})
    return 200, {"ok": True, "executed": True, "root": True, "stdout": marker, **info}


def _openwebui_batch(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    file_id = _safe(ctx.body.get("file_id") or "file-1")
    content = str(ctx.body.get("content") or marker)
    path = ctx.root / "openwebui" / "files" / f"{file_id}.marker"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content + f"\n# {marker}\n"
    path.write_text(text, encoding="utf-8")
    return 200, {"ok": True, "file_id": file_id, "overwritten": True,
                 "marker_path": str(path), "marker_sha256": _sha(text)}


def _mlflow_trace(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    trace_id = str(ctx.body.get("trace_id") or "tr-1")
    if ctx.mode == "fixed" and (".." in trace_id or trace_id.startswith("/")):
        return 400, {"error": "path_traversal_rejected", "service": "mlflow"}
    target = ctx.root / "mlflow" / "escaped" / f"{_safe(trace_id)}.marker"
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps({"trace_id": trace_id, "marker": marker}, ensure_ascii=False)
    target.write_text(text, encoding="utf-8")
    return 200, {"ok": True, "trace_id": trace_id, "escaped": ".." in trace_id,
                 "marker_path": str(target), "marker_sha256": _sha(text)}


def _mlflow_model(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    source = str(ctx.body.get("source") or "http://attacker.invalid/model")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("mlflow", "models", f"{rid}.marker", marker=marker,
                           extra={"source": source, "rce": True})
    return 200, {"ok": True, "model_version": rid, "source": source, "rce": True, **info}


def _megatron_load(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    path = str(ctx.body.get("path") or "checkpoints/iter_1000")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("megatron", "checkpoints", f"{rid}.marker", marker=marker,
                           extra={"path": path, "rce": True})
    return 200, {"ok": True, "loaded": True, "rce": True, **info}


def _deepspeed_load(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    path = str(ctx.body.get("path") or "ds_config.json")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("deepspeed", "checkpoints", f"{rid}.marker", marker=marker,
                           extra={"path": path, "command_injection": True})
    return 200, {"ok": True, "loaded": True, "rce": True, **info}


def _torch_load(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "TRIDENT-BENIGN")
    path = str(ctx.body.get("path") or "model.pt")
    rid = uuid.uuid4().hex[:12]
    info = ctx.marker_file("torch", "loads", f"{rid}.marker", marker=marker,
                           extra={"path": path, "weights_only_bypass": True})
    return 200, {"ok": True, "loaded": True, "rce": True, **info}


def _hami_pods(ctx: _Ctx):
    return 200, {"service": "hami", "pods": [{"namespace": "tenant-a", "name": "gpu-share-1",
                                              "device": "nvidia.com/gpu", "memory": "8Gi"}]}


def _hami_filter(ctx: _Ctx):
    return 200, {"ok": True, "service": "hami", "node": str(ctx.body.get("node") or "node-a"),
                 "bind": True, "auth": "none"}


def _cleanup(ctx: _Ctx):
    marker = str(ctx.body.get("marker") or "")
    deleted = 0
    if marker:
        for path in ctx.root.rglob("*"):
            if path.is_file():
                try:
                    if marker in path.read_text(encoding="utf-8", errors="ignore"):
                        path.unlink()
                        deleted += 1
                except OSError:
                    pass
    ctx.state["ray_jobs"].clear()
    ctx.state["ipmi_sessions"].clear()
    ctx.state["redfish_sessions"].clear()
    return 200, {"ok": True, "deleted": deleted, "marker": marker}


ROUTE_TABLE = [
    {"service": "ray", "name": "Ray 作业提交", "method": "POST", "path": "/ray/api/jobs/",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _ray_submit},
    {"service": "ray", "name": "Ray 作业列表", "method": "GET", "path": "/ray/api/jobs/",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _ray_list},
    {"service": "ray", "name": "Ray Dashboard 指纹", "method": "GET", "path": "/ray/dashboard",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _ray_dashboard},
    {"service": "sglang", "name": "SGLang ZMQ broker", "method": "POST", "path": "/sglang/zmq",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _sglang_zmq},
    {"service": "sglang", "name": "SGLang PD route", "method": "PUT", "path": "/sglang/route",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _sglang_route},
    {"service": "sglang", "name": "SGLang server_info", "method": "GET", "path": "/sglang/server_info",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _sglang_info},
    {"service": "sglang", "name": "SGLang 权重导出", "method": "GET", "path": "/sglang/weights",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _sglang_weights},
    {"service": "vllm", "name": "vLLM Mooncake 管道", "method": "POST", "path": "/vllm/mooncake",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _vllm_mooncake},
    {"service": "vllm", "name": "vLLM 指标", "method": "GET", "path": "/vllm/metrics",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _vllm_metrics},
    {"service": "vllm", "name": "vLLM 模型列表", "method": "GET", "path": "/vllm/models",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _vllm_models},
    {"service": "litellm", "name": "LiteLLM 配置/上游 key", "method": "GET", "path": "/litellm/config",
     "vulnerable": 200, "fixed": 401, "gate": "custom", "behavior": _litellm_config},
    {"service": "litellm", "name": "LiteLLM 健康", "method": "GET", "path": "/litellm/health",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _litellm_health},
    {"service": "litellm", "name": "LiteLLM 配置更新", "method": "POST", "path": "/litellm/config/update",
     "vulnerable": 200, "fixed": 403, "gate": "custom", "behavior": _litellm_config_update},
    {"service": "ipmi", "name": "IPMI 指纹", "method": "GET", "path": "/ipmi/info",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _ipmi_info},
    {"service": "ipmi", "name": "IPMI RMCP+ 会话", "method": "POST", "path": "/ipmi/rmcp",
     "vulnerable": 200, "fixed": 401, "gate": "custom", "behavior": _ipmi_rmcp},
    {"service": "redfish", "name": "Redfish 服务根", "method": "GET", "path": "/redfish/v1",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _redfish_root},
    {"service": "redfish", "name": "Redfish 会话", "method": "POST", "path": "/redfish/v1/SessionService/Sessions",
     "vulnerable": 201, "fixed": 201, "gate": "custom", "behavior": _redfish_login},
    {"service": "redfish", "name": "Redfish 系统", "method": "GET", "path": "/redfish/v1/Systems/1",
     "vulnerable": 200, "fixed": 200, "gate": "custom", "behavior": _redfish_systems},
    {"service": "redfish", "name": "Redfish 管理器", "method": "GET", "path": "/redfish/v1/Managers/1",
     "vulnerable": 200, "fixed": 200, "gate": "custom", "behavior": _redfish_managers},
    {"service": "sonic", "name": "SONiC 配置读", "method": "GET", "path": "/sonic/restconf/data/sonic-system:sonic-system",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _sonic_get},
    {"service": "sonic", "name": "SONiC 配置写", "method": "POST", "path": "/sonic/restconf/data/sonic-system:sonic-system",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _sonic_write},
    {"service": "sonic", "name": "SONiC rsyslog 模板", "method": "POST", "path": "/sonic/config",
     "vulnerable": 200, "fixed": 400, "gate": "custom", "behavior": _sonic_rsyslog},
    {"service": "cumulus", "name": "Cumulus NVUE 指纹", "method": "GET", "path": "/cumulus/nvue/system",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _cumulus_get},
    {"service": "cumulus", "name": "Cumulus NVUE 命令", "method": "POST", "path": "/cumulus/nvue/system",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _cumulus_write},
    {"service": "dify", "name": "Dify system-features", "method": "GET", "path": "/dify/console/api/system-features",
     "vulnerable": 200, "fixed": 401, "gate": "open", "behavior": _dify_features},
    {"service": "dify", "name": "Dify 代码节点", "method": "POST", "path": "/dify/api/v1/code-node/run",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _dify_code},
    {"service": "open-webui", "name": "Open WebUI 批量文件覆盖", "method": "POST",
     "path": "/openwebui/api/v1/retrieval/process/files/batch",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _openwebui_batch},
    {"service": "mlflow", "name": "MLflow trace", "method": "POST", "path": "/mlflow/api/3.0/mlflow/traces",
     "vulnerable": 200, "fixed": 400, "gate": "custom", "behavior": _mlflow_trace},
    {"service": "mlflow", "name": "MLflow 模型版本", "method": "POST",
     "path": "/mlflow/api/2.0/mlflow/model-versions/create",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _mlflow_model},
    {"service": "megatron", "name": "Megatron 检查点", "method": "POST", "path": "/megatron/load_checkpoint",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _megatron_load},
    {"service": "deepspeed", "name": "DeepSpeed 检查点", "method": "POST", "path": "/deepspeed/load_checkpoint",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _deepspeed_load},
    {"service": "torch", "name": "torch.load", "method": "POST", "path": "/torch/load",
     "vulnerable": 200, "fixed": 403, "gate": "bearer", "behavior": _torch_load},
    {"service": "hami", "name": "HAMi scheduler Pods", "method": "GET", "path": "/hami/scheduler/pods",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _hami_pods},
    {"service": "hami", "name": "HAMi scheduler filter", "method": "POST", "path": "/hami/scheduler/filter",
     "vulnerable": 200, "fixed": 401, "gate": "bearer", "behavior": _hami_filter},
    {"service": "meta", "name": "清理 marker", "method": "POST", "path": "/__cleanup__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "behavior": _cleanup},
]

_EXACT: dict[tuple[str, str], dict] = {}
for _e in ROUTE_TABLE:
    _EXACT[(_e["method"], _e["path"].rstrip("/") or "/")] = _e


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, root: Path):
        super().__init__(address, _Handler)
        self.mode = mode
        self.root = root
        self.state = {"ray_jobs": {}, "ipmi_sessions": {}, "redfish_sessions": {}}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentCveSim/1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, payload):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            ctype = "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"_raw": raw.decode("utf-8", "replace")}
        return value if isinstance(value, dict) else {"_value": value}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._send(200, {"ok": True, "note": "use POST /__cleanup__"})

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = split.path.rstrip("/") or "/"
        if norm == "/__routes__":
            self._send(200, {"service": "trident-cve-sim", "mode": self.server.mode,
                             "routes": [{k: v for k, v in e.items() if k != "behavior"}
                                        for e in ROUTE_TABLE]})
            return
        entry = _EXACT.get((method, norm))
        if entry is None:
            self._send(404, {"error": "not found", "path": split.path})
            return
        ctx = _Ctx(self.server.mode, self.server.root, self.server.state, self.headers,
                   self._body() if method in ("POST", "PUT") else {},
                   split.path, parse_qs(split.query), entry)
        if entry.get("gate") == "bearer" and ctx.mode == "fixed" and not ctx.authorized():
            self._send(401, {"error": "unauthorized", "service": entry["service"],
                             "hint": f"fixed 模式需要 Authorization: Bearer {ROTATED_ADMIN_KEY}"})
            return
        try:
            status, payload = entry["behavior"](ctx)
        except Exception as exc:
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        self._send(status, payload)


class Server:
    def __init__(self, httpd, thread, mode, root, owns_root):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self.root = root
        self._owns_root = owns_root
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k != "behavior"} for e in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join(timeout=5)
        finally:
            if self._owns_root:
                shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE, root: Path | str | None = None) -> Server:
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    if root is None:
        root_path = Path(tempfile.mkdtemp(prefix="trident-cve-sim-"))
        owns = True
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        owns = False
    httpd = _Server((HOST, int(port)), mode, root_path)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode, root_path, owns)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="Trident CVE 武器化 mock 靶场（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE)
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, root=args.root)
    print(f"cve sim: {server.url('/')} mode={server.mode} root={server.root}")
    print(f"routes: {server.url('/__routes__')} ({len(ROUTE_TABLE)})")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
