"""云角色过权 — 节点实例角色/IRSA/OIDC 服务账户：checkpoint 与权重桶（S3/OSS/COS/Blob）读写、跨账户、KMS。

Ruling: 输入=params.role_snapshot（dict fixture）枚举权重面过权 finding，不真实调用云 API；过权分析以「角色凭据可达」为闸（先打 /mock-imds/* 攻击姿态，fixed 下凭据不可得 → 角色无法假定 → 0 finding）。凭据输出 MOCK 前缀脱敏（尾 4 位）。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "cloud-role-overprivilege"
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


_WRITE_WORDS = ("put", "write", "delete", "create", "upload", "update")
_WEIGHT_WORDS = ("weight", "checkpoint", "ckpt", "model", "oss", "cos", "blob", "s3", "lake")


def run(ctx: dict, params: dict) -> dict:
    base = str(params.get("imds_base") or params.get("target") or "").rstrip("/")
    mode, note = _resolve_mode(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    provider = str(params.get("provider") or "aws")
    snapshot = params.get("role_snapshot")
    role_name = "role"
    if isinstance(snapshot, dict) and snapshot.get("role_name"):
        role_name = str(snapshot["role_name"])
    t = Trace(ctx)

    if provider == "aws":
        probe = t.call("GET", f"{base}/mock-imds/aws/latest/meta-data/iam/security-credentials/{role_name}")
        principal = {"AccessKeyId": _mask(_resp(probe).get("AccessKeyId"))} if _ok(probe) else {}
    elif provider == "azure":
        probe = t.call("GET", f"{base}/mock-imds/azure/metadata/instance?api-version=2021-02-01")
        identity = _resp(probe).get("identity") or {} if _ok(probe) else {}
        principal = {"access_token": _mask(identity.get("access_token")), "clientId": identity.get("clientId", "")}
    elif provider == "aliyun":
        probe = t.call("GET", f"{base}/mock-imds/aliyun/latest/meta-data/ram/security-credentials/")
        principal = {"access_key_id": _mask(_resp(probe).get("access_key_id"))} if _ok(probe) else {}
    elif provider == "tencent":
        probe = t.call("GET", f"{base}/mock-imds/tencent/latest/meta-data/cam/security-credentials/")
        principal = {"tmp_secret_id": _mask(_resp(probe).get("tmp_secret_id"))} if _ok(probe) else {}
    else:
        probe = t.call("GET", f"{base}/__routes__")
        principal = {}

    reachable = _ok(probe)
    findings = []
    overpriv_count = 0
    if reachable:
        findings.append({"sev": "high",
                         "title": f"云角色凭据面可达（{provider}）：节点角色可被假定",
                         "detail": json.dumps({"provider": provider, "role": role_name,
                                               "principal": principal,
                                               "note": "角色凭据未鉴权可得 → 可假定角色执行其权限"}, ensure_ascii=False)})
        if isinstance(snapshot, dict) and isinstance(snapshot.get("permissions"), list):
            perms = [p for p in snapshot["permissions"] if isinstance(p, dict)]
            weight_write = [p for p in perms
                            if any(w in str(p.get("action", "")).lower() for w in _WRITE_WORDS)
                            and any(w in str(p.get("resource", "")).lower() for w in _WEIGHT_WORDS)]
            kms = [p for p in perms
                   if str(p.get("action", "")).lower().startswith("kms:")
                   or ":kms:" in str(p.get("action", "")).lower()]
            cross = [p for p in perms
                     if str(p.get("action", "")).lower().startswith(("sts:assumerole", "ram:assume", "cam:assume"))]
            if weight_write:
                overpriv_count += 1
                findings.append({"sev": "high", "title": "云角色过权：权重/checkpoint 桶写权限",
                                 "detail": json.dumps({"provider": provider, "role": role_name,
                                                       "permissions": weight_write,
                                                       "note": "checkpoint/权重桶可写 → 权重直取/投毒（云侧权重桶链）"}, ensure_ascii=False)})
            if kms:
                overpriv_count += 1
                findings.append({"sev": "medium", "title": "云角色过权：KMS 密钥权限面",
                                 "detail": json.dumps({"provider": provider, "permissions": kms}, ensure_ascii=False)})
            if cross:
                overpriv_count += 1
                findings.append({"sev": "medium", "title": "云角色过权：跨账户角色假定",
                                 "detail": json.dumps({"provider": provider, "permissions": cross}, ensure_ascii=False)})

    artifact = t.dump()
    snap_state = "快照缺失（过权分析未执行）" if snapshot is None else f"快照已分析（过权 finding {overpriv_count} 条）"
    summary = f"provider={provider} 凭据探测={probe.get('status')} {snap_state} mode={mode}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
