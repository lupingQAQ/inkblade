"""NCCL 集合通信入组 — 无认证入组 → 梯度/权重注入（网络层前置见网络模块）。

Ruling: 实验室以 areal /call（白名单 echo 回显 args）同构承载 rendezvous「无认证入组+注入张量回显」；params.collective_snapshot（网络模块联动 fixture：reachable/auth/bootstrap_url/world_size）可覆盖 bootstrap 端点或直接判定前置不成立。真实写影响由 writes=true+backup-write 约束。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "nccl-collective-join"
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
    snap = params.get("collective_snapshot") or {}
    t = Trace(ctx)
    if snap and (snap.get("reachable") is False or snap.get("auth") not in (None, "none")):
        t.entries.append({"snapshot": snap, "verdict": "前置不成立：快照判定不可达或已认证，未入组"})
        artifact = t.dump()
        return {"summary": "前置不成立（collective_snapshot 判定不可达或已认证，未入组）",
                "artifacts": [str(artifact)], "findings": []}
    if not target and not snap.get("bootstrap_url"):
        return {"summary": "no-target", "artifacts": [], "findings": []}
    marker = str(ctx.get("marker") or "TRIDENT")
    bootstrap = str(snap.get("bootstrap_url") or f"{target}/call")
    world = snap.get("world_size")
    tensor = marker if mode == "backup-write" else "probe-tensor"
    join = t.call("POST", bootstrap, {
        "engine_id": "nccl-join-probe", "method": "echo",
        "args": {"rank": 0, "tensor": tensor, "world_size": world},
    })
    findings = []
    if _ok(join) and isinstance(_resp(join).get("result"), dict):
        detail = {"bootstrap": bootstrap, "auth": "none", "world_size": world,
                  "joined_rank": 0, "injected_tensor": tensor,
                  "echoed": _resp(join).get("result"),
                  "note": "集合通信 rendezvous 无认证入组 + 张量注入回显（梯度/权重污染面；网络层前置见网络模块）"}
        findings.append({"sev": "high", "title": "NCCL rendezvous 无认证入组 + 张量注入回显",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = f"bootstrap={bootstrap} 入组={join.get('status')} world_size={world} mode={mode}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
