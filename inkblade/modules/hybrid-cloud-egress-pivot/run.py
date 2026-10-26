"""混合云出网与回旋 — 云 API 端点可达性、私网互联网段暴露（本地↔云双向）、DNS 泄露通道 → 混合云横向路径图。

Ruling: 实验室打四云 /mock-imds/* 攻击姿态差分构造「私网→云面」pivot 边（200=未加固边，401/400/404=已加固无边）；GCP 非差分仅记可达性。DNS 泄露通道在 HTTP 靶场不可仿真 → 显式标注 not-simulated、不作为判定。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

KEY = "hybrid-cloud-egress-pivot"
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
    probes = {
        "aws": f"{base}/mock-imds/aws/latest/meta-data/iam/security-credentials/role",
        "azure": f"{base}/mock-imds/azure/metadata/instance?api-version=2021-02-01",
        "aliyun": f"{base}/mock-imds/aliyun/latest/meta-data/ram/security-credentials/",
        "tencent": f"{base}/mock-imds/tencent/latest/meta-data/cam/security-credentials/",
    }
    results = {}
    for provider, url in probes.items():
        results[provider] = t.call("GET", url)
    gcp = t.call("GET", f"{base}/mock-imds/gcp/computeMetadata/v1/instance/",
                 headers={"Metadata-Flavor": "Google"})

    edges = [{"from": "pod-network", "to": f"{provider}:imds", "via": "imds", "hardened": False}
             for provider, entry in results.items() if _ok(entry)]
    findings = []
    if edges:
        detail = {"edges": edges,
                  "lateral_paths": [f"pod→{e['to']}→云控制面/权重桶" for e in edges],
                  "dns_exfil_channel": "dns-exfil-not-simulated-in-http-lab",
                  "gcp_reach_only": gcp.get("status"),
                  "note": "私网→云元数据面未加固：混合云出网回旋路径成立（双向私网互联放大平网）"}
        findings.append({"sev": "high", "title": f"混合云出网回旋：私网→云元数据面未加固（pivot 边 {len(edges)} 条）",
                         "detail": json.dumps(detail, ensure_ascii=False)})
    artifact = t.dump()
    status_line = " ".join(f"{p}={e.get('status')}" for p, e in results.items())
    summary = (f"{status_line} gcp={gcp.get('status')}(reach-only) pivot边={len(edges)} "
               f"dns=dns-exfil-not-simulated-in-http-lab mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
