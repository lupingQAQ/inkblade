# -*- coding: utf-8 -*-
"""_trainstack-common — 预训练/SFT/RL 训练栈模块族共享库（仅标准库）。

职责：
- HTTP trace：逐请求记录 method/url/body/headers/status/response，落
  ``<run>/traces/<module>.json`` 作 artifact；
- 双态模式协商：``backup-write`` 需 writes=True 且 ``backup_targets`` 非空，
  否则降级 ``probe-only``（不触碰写面）；
- 证据工具：``sha256_text`` / ``mask_value`` / ``int_of`` / ``ratio``；
- finding 构造与 artifact 落盘（与 runner.add_finding 同字段）。

边界：模块只按公开 HTTP 契约取证，不 import 仿真器内部状态；凭据一律 MOCK 前缀，
finding 中仅以 ``MOCK****尾4位`` 呈现，全文只进 trace 归档层。
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 5
TENANT_HEADER = "X-Tenant"
DEFAULT_TENANT = "tenant-a"
_SECRET_NAME_RE = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)


class Trace:
    """HTTP 全量 trace（请求 + 响应 + 错误），dump 后作为模块 artifact。"""

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
        except Exception as exc:  # noqa: BLE001 —— 连接类错误也保留 trace
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


def victim_tenant_of(params: dict) -> str:
    return str(params.get("victim_tenant") or "tenant-b")


def headers_for(params: dict) -> dict:
    return {TENANT_HEADER: tenant_of(params)}


def resolve_mode(params: dict, writes: bool) -> tuple[str, str]:
    """backup-write 仅在 writes=True 且带 backup_targets 时成立，否则降级 probe-only。"""
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


def float_of(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def mask_value(value) -> str:
    """凭据脱敏：MOCK****尾4位（与 aigateway/cloud 模块族同一约定）。"""
    text = str(value)
    return f"MOCK****{text[-4:]}" if len(text) > 8 else "MOCK****"


def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME_RE.search(str(name or "")))


def series_of(payload: dict, key: str) -> list:
    values = payload.get(key)
    return values if isinstance(values, list) else []


def first_last(values: list) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    return float_of(values[0]), float_of(values[-1])


def ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 3) if denominator else 0.0


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
