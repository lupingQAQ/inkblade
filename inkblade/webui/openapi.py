"""OpenAPI 3.1 文档：InkBlade 本地 HTTP API（服务模式）的机器可读契约。

只读端点清单与 server.py / api_ext.py 的实际路由保持一致；写端点标注所需能力位。
文档本身公开可取（不含凭据），业务端点一律 Bearer 认证 + 工作区隔离。
"""

from __future__ import annotations

from typing import Any

_BEARER = [{"bearerAuth": []}]

_TAGS = [
    {"name": "auth", "description": "登录与会话"},
    {"name": "runs", "description": "run 列表与证据穿透（只读）"},
    {"name": "readonly", "description": "终审补全的只读视图：steps/evidence/graph/report"},
    {"name": "consent", "description": "授权（consent）签署与查询"},
    {"name": "rules", "description": "规则包状态（只读）"},
    {"name": "workspaces", "description": "工作区可见性"},
    {"name": "execute", "description": "执行与紧急停止（写）"},
    {"name": "meta", "description": "健康检查与本文档"},
]


def _op(summary: str, tag: str, *, params: list[str] = (), body: str | None = None,
        security: bool = True, responses: dict | None = None) -> dict[str, Any]:
    parameters = []
    for name in params:
        parameters.append({
            "name": name, "in": "query", "required": name in ("run",),
            "schema": {"type": "string"},
        })
    op: dict[str, Any] = {
        "summary": summary,
        "tags": [tag],
        "responses": responses or {
            "200": {"description": "OK"},
            "400": {"description": "参数缺失或非法"},
            "401": {"description": "未登录"},
            "403": {"description": "工作区越权或能力位不足"},
            "404": {"description": "对象不存在"},
            "423": {"description": "授权未完成（consent 锁）"},
        },
    }
    if security:
        op["security"] = _BEARER
    if parameters:
        op["parameters"] = parameters
    if body:
        op["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{body}"}}},
        }
    return op


_SCHEMAS = {
    "Login": {
        "type": "object", "required": ["name", "password"],
        "properties": {"name": {"type": "string"}, "password": {"type": "string"}},
    },
    "Execute": {
        "type": "object", "required": ["module"],
        "properties": {
            "workspace": {"type": "string", "default": "local-lab"},
            "module": {"type": "string"},
            "params": {"type": "object"},
        },
    },
    "ConsentFields": {
        "type": "object",
        "properties": {
            "level": {"type": "string", "enum": ["只读侦察", "主动探测", "利用验证", "全影响演示"]},
            "namespaces": {"type": "array", "items": {"type": "string"}},
            "cidrs": {"type": "array", "items": {"type": "string"}},
            "window": {"type": "object"},
            "client": {"type": "string"},
        },
    },
    "ConsentSign": {
        "type": "object", "required": ["fields"],
        "properties": {"workspace": {"type": "string"}, "fields": {"$ref": "#/components/schemas/ConsentFields"}},
    },
}


def build_openapi() -> dict[str, Any]:
    """返回 OpenAPI 3.1 文档（纯函数，便于测试锁定路径与操作摘要）。"""
    paths: dict[str, dict[str, Any]] = {
        "/api/login": {"post": _op("登录换取 Bearer token", "auth", body="Login", security=False,
                                   responses={"200": {"description": "token+role"},
                                              "401": {"description": "凭据无效"}})},
        "/api/runs": {"get": _op("列出工作区 run", "runs", params=["workspace"])},
        "/api/execute": {"post": _op("执行单个模块（授权+范围+备份闸门）", "execute", body="Execute")},
        "/api/abort": {"post": _op("工作区紧急停止（进程级标志）", "execute")},
        "/api/v1/workspaces": {"get": _op("当前会话可见工作区", "workspaces")},
        "/api/v1/steps": {"get": _op("run 的步骤（prompts/env/evidence 嵌套）", "readonly",
                                     params=["workspace", "run"])},
        "/api/v1/evidence": {"get": _op("归档证据清单 + manifest 校验状态", "readonly",
                                        params=["workspace", "run", "step"])},
        "/api/v1/graph": {"get": _op("图节点/边（层级与判定方式原样透出）", "readonly",
                                     params=["workspace", "run"])},
        "/api/v1/timeline": {"get": _op("统一时间线（steps/actions/file_ops/利用标记）", "readonly",
                                        params=["workspace", "run"])},
        "/api/v1/file-ops": {"get": _op("操作与文件访问台账（file_ops 表）", "readonly",
                                        params=["workspace", "run", "step"])},
        "/api/v1/drift": {"get": _op("周期重测差异（drift.json；缺 run 取最新）", "readonly",
                                     params=["workspace", "run"])},
        "/api/v1/report": {"get": _op("渲染双语报告（pentest|remediation）", "readonly",
                                      params=["workspace", "run", "kind", "lang", "redact"])},
        "/api/v1/rules": {"get": _op("规则包状态（mapping 规则/链计数）", "rules", params=["workspace"])},
        "/api/v1/consent": {"get": _op("授权状态与字段", "consent", params=["workspace"])},
        "/api/v1/consent/sign": {"post": _op("签署工作区授权（lead/admin）", "consent",
                                             body="ConsentSign")},
        "/api/v1/assets": {"get": _op("资产清单与图", "readonly", params=["workspace", "kind", "product"])},
        "/api/v1/explorer": {"get": _op("审批制探索器队列", "readonly", params=["workspace"])},
        "/api/v1/scheduler": {"get": _op("周期重测计划", "readonly", params=["workspace"])},
        "/api/v1/traffic": {"get": _op("流量录制条目", "readonly", params=["workspace", "run", "module"])},
        "/api/v1/zeroday": {"get": _op("零日扩展启用状态", "readonly", params=["workspace"])},
        "/api/v1/poc/reverify": {"post": _op("重验发现（授权锁 423）", "execute")},
        "/api/v1/health": {"get": _op("健康检查", "meta", security=False,
                                      responses={"200": {"description": "ok"}})},
        "/api/v1/openapi.json": {"get": _op("本文档", "meta", security=False,
                                            responses={"200": {"description": "OpenAPI 3.1"}})},
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "InkBlade ML-cluster pentest platform API",
            "version": "1.0.0",
            "description": "本地 Web API（标准库 http.server）。业务端点须 Bearer 登录并受工作区隔离；"
                           "执行类端点在工作区授权（consent）未完成时返回 423；"
                           "零日/范围/时间窗/备份闸门失败均拒绝执行。",
            "license": {"name": "Apache-2.0"},
        },
        "servers": [{"url": "http://127.0.0.1:8765", "description": "本地控制台"}],
        "tags": _TAGS,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "session-token"},
            },
            "schemas": _SCHEMAS,
        },
        "paths": paths,
    }
