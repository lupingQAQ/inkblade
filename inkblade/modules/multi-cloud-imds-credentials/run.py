"""多云元数据凭据面 — AWS IMDSv1/v2、Azure IMDS + Managed Identity、阿里 ECS 元数据（RAM）、腾讯 CVM 元数据（CAM）、GCP 元数据。

Ruling: 实验室打五云 /mock-imds/* 攻击姿态（无 token/无 Metadata 头）差分：vulnerable 200=凭据面暴露，fixed 401/400/404=已加固；GCP 两模式一致（仅缺 Metadata-Flavor 头，内网方可伪造）→ 仅记 trace 可达性、不构成 finding。凭据输出一律 MOCK 前缀脱敏（尾 4 位）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "multi-cloud-imds-credentials"
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
    t = Trace(ctx)
    findings = []
    status_line = []

    aws = t.call("GET", f"{base}/mock-imds/aws/latest/meta-data/iam/security-credentials/role")
    status_line.append(f"aws={aws.get('status')}")
    if _ok(aws) and str(_resp(aws).get("AccessKeyId", "")).startswith("MOCK"):
        findings.append({"sev": "high", "title": "AWS IMDSv1 放行：角色凭据未鉴权可得（脱敏存证）",
                         "detail": json.dumps({"provider": "aws", "imds": "v1-allowed",
                                               "AccessKeyId": _mask(_resp(aws).get("AccessKeyId")),
                                               "SecretAccessKey": _mask(_resp(aws).get("SecretAccessKey")),
                                               "Token": _mask(_resp(aws).get("Token")),
                                               "role": _resp(aws).get("role", "")}, ensure_ascii=False)})

    azure = t.call("GET", f"{base}/mock-imds/azure/metadata/instance?api-version=2021-02-01")
    status_line.append(f"azure={azure.get('status')}")
    if _ok(azure):
        identity = _resp(azure).get("identity") or {}
        findings.append({"sev": "high", "title": "Azure IMDS fail-open：Managed Identity 令牌未鉴权可得（脱敏存证）",
                         "detail": json.dumps({"provider": "azure", "flow": "no-metadata-header",
                                               "access_token": _mask(identity.get("access_token")),
                                               "clientId": identity.get("clientId", ""),
                                               "objectType": identity.get("objectType", "")}, ensure_ascii=False)})

    aliyun = t.call("GET", f"{base}/mock-imds/aliyun/latest/meta-data/ram/security-credentials/")
    status_line.append(f"aliyun={aliyun.get('status')}")
    if _ok(aliyun):
        findings.append({"sev": "high", "title": "阿里云 ECS 元数据：RAM 角色凭据未鉴权可得（脱敏存证）",
                         "detail": json.dumps({"provider": "aliyun", "flow": "ram-role",
                                               "ram_role_name": _resp(aliyun).get("ram_role_name", ""),
                                               "access_key_id": _mask(_resp(aliyun).get("access_key_id")),
                                               "access_key_secret": _mask(_resp(aliyun).get("access_key_secret")),
                                               "security_token": _mask(_resp(aliyun).get("security_token"))}, ensure_ascii=False)})

    tencent = t.call("GET", f"{base}/mock-imds/tencent/latest/meta-data/cam/security-credentials/")
    status_line.append(f"tencent={tencent.get('status')}")
    if _ok(tencent):
        findings.append({"sev": "high", "title": "腾讯云 CVM 元数据：CAM 角色凭据未鉴权可得（脱敏存证）",
                         "detail": json.dumps({"provider": "tencent", "flow": "cam-role",
                                               "cam_role_name": _resp(tencent).get("cam_role_name", ""),
                                               "tmp_secret_id": _mask(_resp(tencent).get("tmp_secret_id")),
                                               "tmp_secret_key": _mask(_resp(tencent).get("tmp_secret_key")),
                                               "token": _mask(_resp(tencent).get("token"))}, ensure_ascii=False)})

    # GCP：两模式一致（要求 Metadata-Flavor 头，内网任意方可伪造）——非差分面，仅记 trace 可达性，不构成 finding
    gcp = t.call("GET", f"{base}/mock-imds/gcp/computeMetadata/v1/instance/",
                 headers={"Metadata-Flavor": "Google"})
    status_line.append(f"gcp={gcp.get('status')}(reach-only)")

    artifact = t.dump()
    summary = " ".join(status_line) + f" 凭据面暴露={len(findings)} mode={mode}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
