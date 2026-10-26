"""dify-control-plane-failopen — Dify 控制面默认放行（深度漏洞模块，已公开）。

检测流程（安全默认：先探测后动作）：
1. GET /__routes__ fingerprint（版本/路由语义），未命中不进入动作分支；
2. 无凭据良性探针 POST /api/v1/bindings（marker 命名，可归因可清理）；
3. 200 + created → finding(is_novel)（vulnerable 姿态）；401/403 → 加固态零发现。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

TARGET_SERVICE = "dify-agent"
TARGET_PATH = "/api/v1/bindings"


def _request(method: str, url: str, body=None, headers=None, timeout: int = 15):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return status, payload


def _fingerprint(base: str):
    status, manifest = _request("GET", base + "/__routes__")
    if status != 200 or not isinstance(manifest, dict):
        return None, "fingerprint 失败：目标无 /__routes__ 清单（非实验室 mock 语义），不进入动作分支"
    for route in manifest.get("routes", []):
        if route.get("service") == TARGET_SERVICE and route.get("path") == TARGET_PATH:
            return manifest, None
    return manifest, f"fingerprint 未命中：目标无 {TARGET_SERVICE} {TARGET_PATH} 路由"


def run(ctx: dict, params: dict) -> dict:
    base = str(params.get("base_url", "")).rstrip("/")
    if not base:
        raise ValueError("缺少 params.base_url（mock 靶场地址，仅限授权范围）")
    marker = str(params.get("marker") or ctx.get("marker") or "INKBLADE-probe")

    manifest, miss = _fingerprint(base)
    if miss is not None:
        return {"summary": miss, "findings": [], "artifacts": []}

    probe = f"{marker}-binding".lower()
    status, payload = _request("POST", base + TARGET_PATH, body={"name": probe})
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("created"):
        findings.append({
            "sev": "critical",
            "title": "Dify 控制面默认放行：未鉴权创建 binding 成功",
            "detail": "鉴权 fail-open × 默认公开开发令牌：无 Authorization 凭据即可创建/销毁 binding，并可链式驱动沙箱作业（见 dify-local-sandbox-unauth-rce）。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "created": payload.get("created"),
                "binding": payload.get("binding"), "mode": (manifest or {}).get("mode"), "probe": probe,
            }, ensure_ascii=False),
            "mapping": "内部登记册：智能体平台控制面；链「智能体平台零前置执行 → 训练集群横向」",
            "fix": "控制面鉴权改 fail-closed；更换全部默认开发/JWE 根密钥；管理路由仅内网网段可达并加审计",
            "is_novel": True,
        })
        summary = "fingerprint 命中 dify-agent；无凭据创建 binding 成功（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 dify-agent；无凭据动作被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
