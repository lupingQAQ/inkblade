"""lab/mock_targets.py — Trident 实验室 mock 靶场（单文件多路由 HTTP 仿真服务）。

仅监听 127.0.0.1，仅标准库（http.server + threading）。两种姿态：
- vulnerable：与已复现漏洞面同构的 fail-open 姿态（无凭据即放行）；
- fixed：加固姿态（无凭据 401/403/400/404，按各真实修复语义）。

路由清单（GET /__routes__ 返回同表 JSON，供测试与利用模块发现）：
- sglang 管理面：POST /update_weights_from_disk、/pause、/freeze、/resume
  （vulnerable：无 key 200 且生效；fixed：无 Authorization 401，Bearer 管理密钥 200）
- slime 权重拉取：POST /pull_weights {source_dir, local_checkpoint_dir}
  （vulnerable：200 并写 server 侧 sandbox marker；fixed：401）
- areal 环境注入链：POST /set_env、/create_engine、/call
  （vulnerable：200，/call 仅白名单方法 echo 并回显结果；fixed：401）
- ray dashboard：POST /api/jobs/（vulnerable：接收 entrypoint 落 marker；fixed：401）；
  GET /api/jobs/ 两模式均 200 列表
- vllm 插件面：GET /plugins/list、POST /plugins/invoke（vulnerable：无 key 200；fixed：401）；
  GET /v1/models 对照面两模式均 401（带管理密钥 200）
- djev 开放代理：GET /v1/models、POST /v1/chat/completions（vulnerable：无 key 200 中继风格；fixed：401）
- dify-agent：POST /api/v1/bindings（vulnerable：无 token 200 建目录 marker；fixed：401）；
  POST /v1/jobs/run {script}（vulnerable：200 模拟执行=仅把 script 写入 sandbox 文件；fixed：401）
- open-webui：POST /api/v1/utils/code/execute {code}
  （vulnerable：200，模拟执行=写共享 sandbox 文件并返回 stdout='B-was-here'；fixed：403）
- 五云 IMDS（前缀 /mock-imds/）：
  aws /latest/api/token（PUT 签发令牌）与 /latest/meta-data/iam/security-credentials/{role}
  （fixed 强制 IMDSv2：无 x-aws-ec2-metadata-token 头 401）；
  azure /metadata/instance?api-version=...（fixed 无 Metadata:true 头 400，有头 200 含 access_token）；
  aliyun /latest/meta-data/ram/ 与 tencent /latest/meta-data/cam/（vulnerable 200；fixed 404）；
  gcp /computeMetadata/v1/（无 Metadata-Flavor:Google 头 403，两模式一致）

Ruling（同路径消歧）：单端口下 /v1/models 同时承载 vllm 对照面与 djev 中继面（真实部署两者不同端口），
以请求头 X-Mock-Service 消歧：缺省按 djev 语义；X-Mock-Service: vllm 时按 vllm 对照面语义。

写盘边界：一切落盘仅限 Server.root（默认临时目录并在 shutdown 清理；start_all(root=...) 可注入）。
返回的凭据样值一律 MOCK 前缀（无真实凭据语义）。

命令行：python lab/mock_targets.py [--port N] [--mode vulnerable|fixed] [--root DIR]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
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
ADMIN_TOKEN = "test-admin-key"
SERVICE_SELECTOR_HEADER = "x-mock-service"
AREAL_CALL_WHITELIST = ("echo",)
OPEN_WEBUI_MOCK_STDOUT = "B-was-here"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_name(value: str, fallback: str = "unnamed") -> str:
    """把请求可控字符串压成安全文件/目录名（防路径穿越，写盘仅限 root 内）。"""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned or fallback


class _RequestContext:
    """单次请求的上下文：模式、根目录、进程内状态、请求要素。"""

    def __init__(self, mode, root, state, headers, body, path, query, params, entry):
        self.mode = mode
        self.root = root
        self.state = state
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.params = params
        self.entry = entry

    @property
    def authorized(self) -> bool:
        """fixed 模式管理密钥（Bearer ADMIN_TOKEN）。"""
        return (self.headers.get("Authorization") or "") == f"Bearer {ADMIN_TOKEN}"

    def sandbox(self, *parts: str) -> Path:
        """在 Server.root 下取子路径并创建父目录。"""
        target = self.root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target


# ---------------------------------------------------------------------------
# 各路由行为（返回 (status, payload[, headers])；payload 为 dict 转 JSON、str 转文本）
# ---------------------------------------------------------------------------


def _sglang_admin(ctx: _RequestContext):
    return 200, {"ok": True, "service": "sglang", "route": ctx.entry["path"], "applied": True, "mode": ctx.mode}


def _slime_pull_weights(ctx: _RequestContext):
    source_dir = str(ctx.body.get("source_dir", ""))
    local_checkpoint_dir = str(ctx.body.get("local_checkpoint_dir", ""))
    marker = ctx.sandbox("slime", _safe_name(local_checkpoint_dir, "checkpoint"), "PULLED-WEIGHTS.marker")
    marker.write_text(
        json.dumps(
            {
                "service": "slime",
                "route": "/pull_weights",
                "source_dir": source_dir,
                "local_checkpoint_dir": local_checkpoint_dir,
                "mode": ctx.mode,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 200, {"ok": True, "service": "slime", "pulled": True, "marker": str(marker), "mode": ctx.mode}


def _areal_set_env(ctx: _RequestContext):
    key = str(ctx.body.get("key", ""))
    ctx.state["areal_env"][key] = ctx.body.get("value")
    return 200, {"ok": True, "service": "areal", "route": "set_env", "key": key, "env_size": len(ctx.state["areal_env"])}


def _areal_create_engine(ctx: _RequestContext):
    engine_id = "engine-" + uuid.uuid4().hex
    ctx.state["areal_engines"][engine_id] = {"module": str(ctx.body.get("module", "")), "cls": str(ctx.body.get("cls", ""))}
    return 200, {"ok": True, "service": "areal", "engine_id": engine_id, "engines": len(ctx.state["areal_engines"])}


def _areal_call(ctx: _RequestContext):
    method = str(ctx.body.get("method", ""))
    if method not in AREAL_CALL_WHITELIST:
        return 400, {
            "ok": False,
            "service": "areal",
            "error": "method not whitelisted",
            "whitelist": list(AREAL_CALL_WHITELIST),
        }
    args = ctx.body.get("args", {})
    return 200, {"ok": True, "service": "areal", "engine_id": str(ctx.body.get("engine_id", "")), "method": method, "result": args}


def _ray_submit_job(ctx: _RequestContext):
    entrypoint = str(ctx.body.get("entrypoint", ""))
    job_id = "raysubmit-" + uuid.uuid4().hex
    marker = ctx.sandbox("ray", "jobs", f"{job_id}.marker")
    marker.write_text(
        json.dumps({"service": "ray", "job_id": job_id, "entrypoint": entrypoint, "mode": ctx.mode}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    ctx.state["ray_jobs"][job_id] = {"job_id": job_id, "entrypoint": entrypoint, "status": "SUCCEEDED"}
    return 200, {"ok": True, "service": "ray", "job_id": job_id, "status": "SUCCEEDED", "marker": str(marker)}


def _ray_list_jobs(ctx: _RequestContext):
    jobs = sorted(ctx.state["ray_jobs"].values(), key=lambda item: item["job_id"])
    return 200, {"service": "ray", "count": len(jobs), "jobs": jobs}


def _vllm_plugins_list(ctx: _RequestContext):
    return 200, {
        "service": "vllm",
        "plugins": [
            {"name": "jev", "description": "mock vllm-jev 插件"},
            {"name": "mock-plugin", "description": "mock 插件"},
        ],
    }


def _vllm_plugins_invoke(ctx: _RequestContext):
    return 200, {
        "ok": True,
        "service": "vllm",
        "plugin": str(ctx.body.get("plugin", "unknown")),
        "invoked": True,
        "result": {"echo": ctx.body.get("args", {})},
    }


def _vllm_models(ctx: _RequestContext):
    if not ctx.authorized:
        return 401, {"error": "unauthorized", "service": "vllm", "note": "对照面：/v1/* 两模式均要求 api-key"}
    return 200, {"object": "list", "data": [{"id": "mock-model", "object": "model", "owned_by": "vllm"}]}


def _djev_models(ctx: _RequestContext):
    return 200, {"object": "list", "service": "djev", "data": [{"id": "mock-model", "object": "model", "owned_by": "djev-relay"}]}


def _djev_chat_completions(ctx: _RequestContext):
    return 200, {
        "id": "chatcmpl-" + uuid.uuid4().hex,
        "object": "chat.completion",
        "service": "djev",
        "model": str(ctx.body.get("model", "mock-model")),
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "mock relay response"},
            }
        ],
    }


def _dify_create_binding(ctx: _RequestContext):
    name = _safe_name(str(ctx.body.get("name", "binding")))
    marker = ctx.sandbox("dify-agent", "bindings", name, "BINDING.marker")
    marker.write_text(
        json.dumps(
            {
                "service": "dify-agent",
                "binding": name,
                "token_present": bool(ctx.headers.get("Authorization")),
                "mode": ctx.mode,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 200, {"ok": True, "service": "dify-agent", "binding": name, "created": True, "marker": str(marker)}


def _dify_run_job(ctx: _RequestContext):
    script = str(ctx.body.get("script", ""))
    run_id = "difyjob-" + uuid.uuid4().hex
    script_path = ctx.sandbox("dify-agent", "shellctl", f"{run_id}.sh")
    script_path.write_text(script, encoding="utf-8")
    marker = ctx.sandbox("dify-agent", "shellctl", f"{run_id}.marker")
    marker.write_text(
        json.dumps({"service": "dify-agent", "run_id": run_id, "simulated": True, "mode": ctx.mode}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 200, {"ok": True, "service": "dify-agent", "run_id": run_id, "status": "SUCCEEDED", "simulated": True, "script_path": str(script_path)}


def _open_webui_execute(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 403, {"error": "forbidden", "service": "open-webui", "hint": "fixed 模式禁用共享沙箱代码执行"}
    code = str(ctx.body.get("code", ""))
    cell = ctx.sandbox("open-webui", "shared", f"cell-{uuid.uuid4().hex}.py")
    cell.write_text(code, encoding="utf-8")
    return 200, {"ok": True, "service": "open-webui", "stdout": OPEN_WEBUI_MOCK_STDOUT, "code_path": str(cell)}


def _imds_aws_token(ctx: _RequestContext):
    token = "mock-imds-token-" + uuid.uuid4().hex
    ctx.state["aws_tokens"].add(token)
    return 200, token, {"x-aws-ec2-metadata-token-ttl-seconds": "21600"}


def _imds_aws_credentials(ctx: _RequestContext):
    if ctx.mode == "fixed":
        token = (ctx.headers.get("x-aws-ec2-metadata-token") or "").strip()
        if not token or token not in ctx.state["aws_tokens"]:
            return 401, {
                "error": "unauthorized",
                "service": "imds-aws",
                "hint": "fixed 模式强制 IMDSv2：先 PUT /mock-imds/aws/latest/api/token，再带 x-aws-ec2-metadata-token 头",
            }
    role = (ctx.params.get("role") or ["role"])[0]
    return 200, {
        "Code": "Success",
        "LastUpdated": _utcnow_iso(),
        "Type": "AWS-HMAC",
        "AccessKeyId": "MOCKAKIATRIDENTLAB",
        "SecretAccessKey": "MOCKSECRETTRIDENTLAB",
        "Token": "MOCKSESSIONTRIDENTLAB",
        "Expiration": "2030-01-01T00:00:00Z",
        "role": role,
        "mock": True,
    }


def _imds_azure_instance(ctx: _RequestContext):
    api_version = (ctx.query.get("api-version") or [""])[0]
    metadata_header = (ctx.headers.get("Metadata") or "").strip().lower()
    if not api_version:
        return 400, {"error": "bad request", "service": "imds-azure", "hint": "缺少 api-version 查询参数"}
    if ctx.mode == "fixed" and metadata_header != "true":
        return 400, {"error": "bad request", "service": "imds-azure", "hint": "fixed 模式要求 Metadata: true 请求头"}
    return 200, {
        "service": "imds-azure",
        "compute": {"azEnvironment": "AzurePublicCloud", "name": "mock-node", "vmSize": "Standard_MOCK_GPU"},
        "identity": {"access_token": "MOCK-AZURE-IDENTITY-TOKEN", "clientId": "mock-managed-identity", "objectType": "ManagedIdentity"},
        "mock": True,
    }


def _imds_aliyun_ram(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 404, {"error": "not found", "service": "imds-aliyun", "hint": "fixed 模式关闭 RAM 元数据面"}
    return 200, {
        "service": "imds-aliyun",
        "ram_role_name": "mock-ram-role",
        "access_key_id": "MOCKLTAITRIDENTLAB",
        "access_key_secret": "MOCKSECRETTRIDENTLAB",
        "security_token": "MOCKSTSTRIDENTLAB",
        "path": ctx.path,
        "mock": True,
    }


def _imds_tencent_cam(ctx: _RequestContext):
    if ctx.mode == "fixed":
        return 404, {"error": "not found", "service": "imds-tencent", "hint": "fixed 模式关闭 CAM 元数据面"}
    return 200, {
        "service": "imds-tencent",
        "cam_role_name": "mock-cam-role",
        "tmp_secret_id": "MOCKAKIDTRIDENTLAB",
        "tmp_secret_key": "MOCKSECRETTRIDENTLAB",
        "token": "MOCKSTSTRIDENTLAB",
        "path": ctx.path,
        "mock": True,
    }


def _imds_gcp(ctx: _RequestContext):
    if (ctx.headers.get("Metadata-Flavor") or "").strip() != "Google":
        return 403, {"error": "forbidden", "service": "imds-gcp", "hint": "要求 Metadata-Flavor: Google 请求头（两模式一致）"}
    return 200, {
        "service": "imds-gcp",
        "project": {"projectId": "mock-project"},
        "instance": {"name": "mock-instance", "zone": "mock-zone"},
        "mock": True,
    }


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "trident-mock-lab",
        "mode": ctx.mode,
        "host": HOST,
        "admin_token_hint": f"fixed 模式管理密钥 = Authorization: Bearer {ADMIN_TOKEN}",
        "service_selector_header": SERVICE_SELECTOR_HEADER,
        "route_count": len(ROUTE_TABLE),
        "routes": [{key: value for key, value in entry.items() if key != "behavior"} for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 路由表（/__routes__ 即此表去行为函数后的 JSON；vulnerable/fixed = 无凭据请求的状态码）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "sglang", "title": "SGLang 管理面磁盘权重更新", "method": "POST", "path": "/update_weights_from_disk", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "vulnerable：无 key 200 且生效；fixed：无 Authorization 401，Bearer 管理密钥 200", "behavior": _sglang_admin},
    {"service": "sglang", "title": "SGLang 管理面暂停", "method": "POST", "path": "/pause", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "同 sglang 管理面 fail-open 语义", "behavior": _sglang_admin},
    {"service": "sglang", "title": "SGLang 管理面冻结", "method": "POST", "path": "/freeze", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "同 sglang 管理面 fail-open 语义", "behavior": _sglang_admin},
    {"service": "sglang", "title": "SGLang 管理面恢复", "method": "POST", "path": "/resume", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "同 sglang 管理面 fail-open 语义", "behavior": _sglang_admin},
    {"service": "slime", "title": "slime 权重拉取", "method": "POST", "path": "/pull_weights", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": True, "description": "vulnerable：200 并写 server 侧 sandbox marker（跨租户权重写同构）；fixed：401", "behavior": _slime_pull_weights},
    {"service": "areal", "title": "AReaL 环境注入", "method": "POST", "path": "/set_env", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "vulnerable：200 注入环境；fixed：401", "behavior": _areal_set_env},
    {"service": "areal", "title": "AReaL 引擎创建", "method": "POST", "path": "/create_engine", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "vulnerable：200 任意 module/cls 建引擎；fixed：401", "behavior": _areal_create_engine},
    {"service": "areal", "title": "AReaL 白名单方法调用", "method": "POST", "path": "/call", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "vulnerable：200 执行白名单方法 echo 并回显；fixed：401", "behavior": _areal_call},
    {"service": "ray", "title": "Ray dashboard 作业提交", "method": "POST", "path": "/api/jobs/", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": True, "description": "vulnerable：接收 entrypoint 并落 marker；fixed：401", "behavior": _ray_submit_job},
    {"service": "ray", "title": "Ray dashboard 作业列表", "method": "GET", "path": "/api/jobs/", "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False, "description": "两模式均 200 列表", "behavior": _ray_list_jobs},
    {"service": "vllm", "title": "vLLM 插件清单", "method": "GET", "path": "/plugins/list", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "插件端点绕过 api-key；fixed：401", "behavior": _vllm_plugins_list},
    {"service": "vllm", "title": "vLLM 插件调用", "method": "POST", "path": "/plugins/invoke", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "插件端点绕过 api-key；fixed：401", "behavior": _vllm_plugins_invoke},
    {"service": "vllm", "title": "vLLM 模型列表对照面", "method": "GET", "path": "/v1/models", "vulnerable": 401, "fixed": 401, "gate": "open", "writes": False, "selector": {"header": SERVICE_SELECTOR_HEADER, "value": "vllm"}, "description": "对照面：/v1/* 两模式均要求 api-key（无凭据 401，Bearer 管理密钥 200）；需 X-Mock-Service: vllm 消歧", "behavior": _vllm_models},
    {"service": "djev", "title": "djev 模型列表中继", "method": "GET", "path": "/v1/models", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "缺省 /v1/models 语义：vulnerable 无 key 200；fixed：401", "behavior": _djev_models},
    {"service": "djev", "title": "djev 对话补全中继", "method": "POST", "path": "/v1/chat/completions", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": False, "description": "vulnerable：无 key 200 中继风格返回；fixed：401", "behavior": _djev_chat_completions},
    {"service": "dify-agent", "title": "dify-agent 绑定创建", "method": "POST", "path": "/api/v1/bindings", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": True, "description": "vulnerable：无 token 200 建目录 marker；fixed：401", "behavior": _dify_create_binding},
    {"service": "dify-agent", "title": "dify-agent 沙箱作业模拟执行", "method": "POST", "path": "/v1/jobs/run", "vulnerable": 200, "fixed": 401, "gate": "bearer", "writes": True, "description": "vulnerable：200 仅把 script 写入 sandbox 文件（不真执行）；fixed：401", "behavior": _dify_run_job},
    {"service": "open-webui", "title": "open-webui 共享沙箱代码执行", "method": "POST", "path": "/api/v1/utils/code/execute", "vulnerable": 200, "fixed": 403, "gate": "open", "writes": True, "description": "vulnerable：200 模拟执行（写共享 sandbox 文件，stdout=B-was-here）；fixed：403", "behavior": _open_webui_execute},
    {"service": "imds-aws", "title": "AWS IMDSv2 令牌签发", "method": "PUT", "path": "/mock-imds/aws/latest/api/token", "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False, "description": "PUT 签发 IMDSv2 令牌（两模式均可用）", "behavior": _imds_aws_token},
    {"service": "imds-aws", "title": "AWS 角色凭据直取", "method": "GET", "path": "/mock-imds/aws/latest/meta-data/iam/security-credentials/{role}", "wildcard": True, "vulnerable": 200, "fixed": 401, "gate": "open", "writes": False, "description": "vulnerable：无 token 200（v1 放行）；fixed：无 x-aws-ec2-metadata-token 头 401，持有效令牌 200", "behavior": _imds_aws_credentials},
    {"service": "imds-azure", "title": "Azure 实例元数据", "method": "GET", "path": "/mock-imds/azure/metadata/instance", "vulnerable": 200, "fixed": 400, "gate": "open", "writes": False, "description": "vulnerable：无头 200（fail-open）；fixed：无 Metadata:true 头 400，有头 200 含 access_token", "behavior": _imds_azure_instance},
    {"service": "imds-aliyun", "title": "阿里云 RAM 角色凭据", "method": "GET", "path": "/mock-imds/aliyun/latest/meta-data/ram/", "wildcard": True, "vulnerable": 200, "fixed": 404, "gate": "open", "writes": False, "description": "vulnerable：200 返回 MOCK 凭据；fixed：404", "behavior": _imds_aliyun_ram},
    {"service": "imds-tencent", "title": "腾讯云 CAM 角色凭据", "method": "GET", "path": "/mock-imds/tencent/latest/meta-data/cam/", "wildcard": True, "vulnerable": 200, "fixed": 404, "gate": "open", "writes": False, "description": "vulnerable：200 返回 MOCK 凭据；fixed：404", "behavior": _imds_tencent_cam},
    {"service": "imds-gcp", "title": "GCP 计算元数据", "method": "GET", "path": "/mock-imds/gcp/computeMetadata/v1/", "wildcard": True, "vulnerable": 403, "fixed": 403, "gate": "open", "writes": False, "description": "两模式一致：无 Metadata-Flavor:Google 头 403，有头 200", "behavior": _imds_gcp},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__", "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False, "description": "返回本清单 JSON（供测试与利用模块发现）", "behavior": _routes_manifest},
]


def _normalize(path: str) -> str:
    """去掉末尾斜杠做路由匹配（保留根 '/'）。"""
    stripped = path.rstrip("/")
    return stripped or "/"


def _prefix_of(entry: dict) -> str:
    return entry["path"].replace("{role}", "").rstrip("/")


_EXACT_ROUTES: dict[tuple[str, str], list[dict]] = {}
_PREFIX_ROUTES: list[tuple[str, str, dict]] = []
for _entry in ROUTE_TABLE:
    if _entry.get("wildcard"):
        _PREFIX_ROUTES.append((_entry["method"], _prefix_of(_entry), _entry))
    else:
        _EXACT_ROUTES.setdefault((_entry["method"], _normalize(_entry["path"])), []).append(_entry)


def _entries_for(method: str, norm: str) -> list[dict]:
    found = list(_EXACT_ROUTES.get((method, norm), []))
    for prefix_method, prefix, entry in _PREFIX_ROUTES:
        if prefix_method == method and (norm == prefix or norm.startswith(prefix + "/")):
            found.append(entry)
    return found


def _resolve(method: str, norm: str, headers) -> dict | None:
    entries = _entries_for(method, norm)
    if not entries:
        return None
    if len(entries) == 1:
        return entries[0]
    # 同路径多语义（/v1/models）：按 X-Mock-Service 选择器消歧，缺省走无选择器的默认条目。
    selector = (headers.get(SERVICE_SELECTOR_HEADER) or "").strip().lower()
    if selector:
        for entry in entries:
            rule = entry.get("selector") or {}
            if rule.get("value") == selector:
                return entry
    for entry in entries:
        if not entry.get("selector"):
            return entry
    return entries[0]


def _path_params(entry: dict, norm: str) -> dict[str, list[str]]:
    prefix = _prefix_of(entry)
    rest = norm[len(prefix):].strip("/")
    if not rest:
        return {}
    return {"role": [rest]}


class _LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, root: Path):
        super().__init__(address, _LabHandler)
        self.lab_mode = mode
        self.lab_root = root
        self.lab_state = {
            "areal_env": {},
            "areal_engines": {},
            "ray_jobs": {},
            "aws_tokens": set(),
        }


class _LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentMockLab/0.1.0"

    def log_message(self, fmt, *args):  # 静默默认访问日志（测试输出干净）
        return

    # -- 基础设施 -----------------------------------------------------------

    def _send(self, status: int, payload, extra_headers: dict | None = None):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"_raw": raw.decode("utf-8", "replace")}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}

    # -- 分发 ---------------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _resolve(method, norm, self.headers)
        if entry is None:
            if any(_entries_for(other, norm) for other in ("GET", "POST", "PUT") if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _LabHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            root=server.lab_root,
            state=server.lab_state,
            headers=self.headers,
            body=self._read_body() if method in ("POST", "PUT") else {},
            path=split.path,
            query=parse_qs(split.query),
            params=_path_params(entry, norm),
            entry=entry,
        )
        if entry.get("gate") == "bearer" and ctx.mode == "fixed" and not ctx.authorized:
            self._send(
                401,
                {
                    "error": "unauthorized",
                    "service": entry["service"],
                    "hint": f"fixed 模式需要 Authorization: Bearer {ADMIN_TOKEN}",
                },
            )
            return
        try:
            outcome = entry["behavior"](ctx)
        except Exception as exc:  # 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"], "detail": str(exc)})
            return
        status, payload = outcome[0], outcome[1]
        extra = outcome[2] if len(outcome) > 2 else None
        self._send(status, payload, extra)


# ---------------------------------------------------------------------------
# Server 句柄与启动入口
# ---------------------------------------------------------------------------


class Server:
    """mock 靶场句柄：.port/.mode/.root + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _LabHTTPServer, thread: threading.Thread, mode: str, root: Path, owns_root: bool):
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
        """本地返回路由清单（等价于 GET /__routes__ 的 routes 字段）。"""
        return [{key: value for key, value in entry.items() if key != "behavior"} for entry in ROUTE_TABLE]

    def shutdown(self) -> None:
        """停止监听并清理自建临时 root（幂等）。"""
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

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE, root: Path | str | None = None) -> Server:
    """启动全部 mock 路由（单服务器，仅 127.0.0.1）。

    port=0 自动分配；mode ∈ {vulnerable, fixed}；root 缺省临时目录（shutdown 清理），可注入。
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    if root is None:
        root_path = Path(tempfile.mkdtemp(prefix="trident-mock-lab-"))
        owns_root = True
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        owns_root = False
    httpd = _LabHTTPServer((HOST, int(port)), mode, root_path)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode, root_path, owns_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 实验室 mock 靶场（仅监听 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE, help="vulnerable=fail-open 姿态，fixed=加固姿态")
    parser.add_argument("--root", default=None, help="sandbox 根目录（缺省临时目录，退出时清理）")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, root=args.root)
    print(f"mock lab: {server.url('/')} mode={server.mode} root={server.root}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭 mock 靶场…")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
