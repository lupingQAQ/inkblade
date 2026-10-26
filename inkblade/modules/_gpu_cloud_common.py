"""GPU 池化 / 云跨租户模块共用的 HTTP trace、模式闸门与脱敏工具。

模块 run.py 通过 ``from inkblade.modules._gpu_cloud_common import ...`` 复用；
本文件不是模块（无 module.json），注册表扫描时被忽略。
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 3


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask(value) -> str:
    """凭据脱敏：MOCK 前缀 + 尾 4 位；全文仅存证据 trace（归档层）。"""
    s = str(value)
    return f"MOCK****{s[-4:]}" if len(s) > 8 else "MOCK****"


def base_url(params: dict) -> str:
    return str(params.get("target") or "").rstrip("/")


def resolve_mode(params: dict, writes: bool) -> tuple[str, str]:
    """backup-write 仅当模块 writes=True 且提供 backup_targets；否则降级 probe-only。"""
    if params.get("mode") != "backup-write":
        return "probe-only", ""
    if writes and params.get("backup_targets"):
        return "backup-write", ""
    return "probe-only", "降级probe-only（backup-write 需 backup_targets）"


def read_headers(params: dict) -> dict:
    """租户读身份：X-Tenant + 可选 tenant token。"""
    headers: dict[str, str] = {}
    if params.get("tenant"):
        headers["X-Tenant"] = str(params["tenant"])
    if params.get("token"):
        headers["Authorization"] = f"Bearer {params['token']}"
    return headers


def write_headers(params: dict) -> dict:
    """写身份：admin token 优先，X-Tenant 仍为攻击者租户（fixed 用于跨租户拒绝）。"""
    headers = read_headers(params)
    if params.get("admin_token"):
        headers["Authorization"] = f"Bearer {params['admin_token']}"
    return headers


def benign_marker(ctx: dict, prefix: str = "GPU") -> str:
    return f"INKBLADE-BENIGN-{prefix}-{ctx.get('marker') or 'PROBE'}"


class Trace:
    """HTTP 全量 trace（请求+响应+错误），写 ctx['run'].dir/traces/<key>.json 后作 artifact。"""

    def __init__(self, ctx: dict, key: str):
        self.key = key
        d = Path(ctx["run"].dir) / "traces"
        d.mkdir(parents=True, exist_ok=True)
        self.path = d / f"{key}.json"
        self.entries: list[dict] = []

    def call(self, method: str, url: str, body=None, headers: dict | None = None):
        entry = {"ts": round(time.time(), 3), "method": method, "url": url,
                 "body": body, "headers": dict(headers or {})}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except Exception as exc:  # noqa: BLE001 —— 目标不可达记 status=0
            entry.update(status=0, error=f"{type(exc).__name__}: {exc}")
            self.entries.append(entry)
            return entry
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text
        entry.update(status=status, response=payload)
        self.entries.append(entry)
        return entry

    def dump(self) -> Path:
        self.path.write_text(
            json.dumps({"module": self.key, "entries": self.entries}, ensure_ascii=False, indent=1),
            encoding="utf-8")
        return self.path


def ok(entry: dict | None) -> bool:
    return entry is not None and entry.get("status") == 200


def resp(entry: dict | None) -> dict:
    r = (entry or {}).get("response")
    return r if isinstance(r, dict) else {}


def detail(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)
