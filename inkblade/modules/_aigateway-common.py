"""_aigateway_common — AI 网关与配套基建模块族共享工具（HTTP trace / 掩码 / 参数约定）。

约定：
- 所有模块只依赖标准库；Trace 把请求+响应写入 ctx['run'].dir/traces/<module>.json
  作为归档层证据（全文可含实验室 MOCK 凭据），findings/report 只出现掩码尾 4 位。
- target 形如 http://127.0.0.1:PORT（无尾斜杠）。
- 写类模块统一 resolve_mode：仅 mode=backup-write 且提供 backup_targets 时触碰写面，
  否则降级 probe-only（runner 备份闸门仍以 module.json 的 writes 为准）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_MASTER_KEY = "MOCK-master-key-4c7a"
DEFAULT_ROTATED_ADMIN_KEY = "MOCK-rotated-admin-key-e5f6"
DEFAULT_TENANT_KEY = "MOCK-tenant-a-key-a1b2"
DEFAULT_VICTIM_TENANT_KEY = "MOCK-tenant-b-key-c3d4"
DEFAULT_SPOOF_USER = "admin"
DEFAULT_VICTIM_PROMPT = "Quarterly revenue guidance for fiscal 2026: 42.7M USD"
DEFAULT_HIJACK_ALIAS = "gpt-4o-mini"
DEFAULT_HIJACK_BACKEND = "http://attacker.invalid/v1"
TIMEOUT = 3


def mask(value) -> str:
    """凭据脱敏：MOCK**** + 尾 4 位（全文仅存证据 trace 归档层）。"""
    s = str(value)
    return f"MOCK****{s[-4:]}" if len(s) > 8 else "MOCK****"


def target(params: dict) -> str:
    return str(params.get("target") or "").rstrip("/")


def resolve_mode(params: dict, writes: bool) -> tuple[str, str]:
    """backup-write 仅当模块 writes=True 且提供 backup_targets；否则降级 probe-only。"""
    if params.get("mode") != "backup-write":
        return "probe-only", ""
    if writes and params.get("backup_targets"):
        return "backup-write", ""
    return "probe-only", "降级probe-only（backup-write 需 backup_targets）"


def master_key(params: dict) -> str:
    return str(params.get("master_key") or DEFAULT_MASTER_KEY)


def tenant_key(params: dict) -> str:
    return str(params.get("tenant_key") or DEFAULT_TENANT_KEY)


def victim_tenant_key(params: dict) -> str:
    return str(params.get("victim_tenant_key") or DEFAULT_VICTIM_TENANT_KEY)


def spoof_user(params: dict) -> str:
    return str(params.get("spoof_user") or DEFAULT_SPOOF_USER)


def bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"} if key else {}


def finding(sev: str, title: str, detail: dict | list | None = None) -> dict:
    """runner 契约 finding：sev/title/detail（detail 统一 JSON 字符串）。"""
    payload = ""
    if detail is not None:
        payload = json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str) else detail
    return {"sev": sev, "title": title, "detail": payload}


class Trace:
    """HTTP 全量 trace（请求+响应+错误），dump 后作为模块 artifact。"""

    def __init__(self, ctx: dict, module_key: str):
        directory = Path(ctx["run"].dir) / "traces"
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f"{module_key}.json"
        self.module_key = module_key
        self.entries: list[dict] = []

    def call(self, method: str, url: str, body=None, headers: dict | None = None) -> dict:
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
        except Exception as exc:  # noqa: BLE001 —— 连接失败也要留证
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
            json.dumps({"module": self.module_key, "entries": self.entries},
                       ensure_ascii=False, indent=1),
            encoding="utf-8")
        return self.path


def ok(entry: dict | None) -> bool:
    return entry is not None and entry.get("status") == 200


def resp(entry: dict | None) -> dict:
    payload = (entry or {}).get("response")
    return payload if isinstance(payload, dict) else {}


def status(entry: dict | None) -> int:
    return int((entry or {}).get("status") or 0)
