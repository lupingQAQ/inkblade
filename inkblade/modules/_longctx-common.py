"""_longctx_common — 长上下文/大规模训练模块族共享库（仅标准库）。

职责：
- HTTP trace（请求+响应+错误）统一落 ``<run>/traces/<module>.json`` 作 artifact；
- 目标/租户/模式解析；finding 构造；sha256 与计数器工具。

边界：本库只做 HTTP 客户端与证据整理，不读取仿真器内部状态；
一切判定来自响应状态码、usage 计数器、/metrics 计数器与 KV/分片读回内容。
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 5
TENANT_HEADER = "X-Tenant"
DEFAULT_TENANT = "tenant-a"


class Trace:
    """HTTP 全量 trace（请求+响应+错误），dump 后作为模块 artifact。"""

    def __init__(self, ctx: dict, key: str):
        self.key = key
        self.path = Path(ctx["run"].dir) / "traces" / f"{key}.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def call(self, method: str, url: str, body=None, headers: dict | None = None):
        entry = {"ts": round(time.time(), 3), "method": method, "url": url,
                 "body": body, "headers": dict(headers or {})}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except Exception as exc:  # noqa: BLE001 —— 网络不可达同样入 trace
            entry.update(status=0, error=f"{type(exc).__name__}: {exc}")
            self.entries.append(entry)
            return entry
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text
        entry.update(status=status, response=payload, response_text=text)
        self.entries.append(entry)
        return entry

    def dump(self) -> Path:
        self.path.write_text(
            json.dumps({"module": self.key, "entries": self.entries},
                       ensure_ascii=False, indent=1),
            encoding="utf-8")
        return self.path


def target_of(params: dict) -> str:
    return str(params.get("target") or "").rstrip("/")


def tenant_of(params: dict) -> str:
    return str(params.get("tenant") or DEFAULT_TENANT)


def headers_for(params: dict) -> dict:
    return {TENANT_HEADER: tenant_of(params)}


def resolve_mode(params: dict, writes: bool) -> tuple[str, str]:
    """backup-write 仅当模块 writes=True 且提供 backup_targets；否则降级 probe-only。"""
    if params.get("mode") != "backup-write":
        return "probe-only", ""
    if writes and params.get("backup_targets"):
        return "backup-write", ""
    return "probe-only", "降级probe-only（backup-write 需 backup_targets）"


def is_ok(entry: dict | None) -> bool:
    return bool(entry) and entry.get("status") == 200


def resp(entry: dict | None) -> dict:
    payload = (entry or {}).get("response")
    return payload if isinstance(payload, dict) else {}


def marker_of(ctx: dict, params: dict) -> str:
    return str(params.get("marker") or ctx.get("marker") or "TRIDENT")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def as_text(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def int_of(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def finding(sev: str, title: str, detail: dict) -> dict:
    return {"sev": sev, "title": title, "detail": json.dumps(detail, ensure_ascii=False)}


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run")
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def no_target() -> dict:
    return {"summary": "no-target", "artifacts": [], "findings": []}
