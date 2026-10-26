"""SSRF 到云元数据 — 媒体 URL/重定向绕过 → IMDS → 云凭据（脱敏存证）。

Ruling: 实验室打 /mock-imds/aws/*（无 token GET = IMDSv1 攻击姿态；PUT 签发 v2 令牌后带 token GET = 合法 v2 流，不构成 finding）。凭据输出一律 MOCK 前缀脱敏（尾 4 位），全文仅证据 trace。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "ssrf-imds-credential"
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
    base = str(params.get("imds_base") or params.get("target") or "").rstrip("/")
    mode, note = _resolve_mode(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    role = str(params.get("role") or "role")
    t = Trace(ctx)
    creds_url = f"{base}/mock-imds/aws/latest/meta-data/iam/security-credentials/{role}"
    v1 = t.call("GET", creds_url)
    tok = t.call("PUT", f"{base}/mock-imds/aws/latest/api/token")
    v2 = None
    if _ok(tok) and isinstance(tok.get("response"), str):
        v2 = t.call("GET", creds_url, headers={"x-aws-ec2-metadata-token": tok["response"]})
    findings = []
    creds = _resp(v1)
    if _ok(v1) and str(creds.get("AccessKeyId", "")).startswith("MOCK"):
        detail = {"flow": "SSRF→IMDS(v1)→credentials", "role": role,
                  "AccessKeyId": _mask(creds.get("AccessKeyId")),
                  "SecretAccessKey": _mask(creds.get("SecretAccessKey")),
                  "Token": _mask(creds.get("Token")),
                  "imds_version": "v1-allowed",
                  "v2_with_token_status": v2.get("status") if v2 else None,
                  "note": "无 token 直取成功：IMDSv1 放行（SSRF 链终点凭据面）"}
        findings.append({"sev": "high", "title": "SSRF→云元数据凭据直取：IMDSv1 放行（凭据已脱敏存证）",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    summary = (f"imds_v1(无token)={v1.get('status')} v2(带token)={v2.get('status') if v2 else 'skipped'} "
               f"凭据={'取得(已脱敏)' if findings else '未取得'} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
