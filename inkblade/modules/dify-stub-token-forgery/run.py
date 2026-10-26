"""dify-stub-token-forgery — Dify 存根令牌伪造（零日级漏洞模块，已公开）。

检测流程：/__routes__ fingerprint → 以离线铸造的存根凭据形态（公开默认根密钥可铸造的 marker 令牌）
POST /api/v1/bindings → 200 + created 即「伪造凭据被控制面接受」；401 → 加固态零发现。
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
    marker = str(params.get("marker") or ctx.get("marker") or "TRIDENT-zeroday")

    manifest, miss = _fingerprint(base)
    if miss is not None:
        return {"summary": miss, "findings": [], "artifacts": []}

    # 离线铸造形态的存根令牌（marker 可归因；不做真实 JWE 构造——实验室验证的是「凭据可伪造即被接受」语义）
    forged = f"MOCK-FORGED-STUB.{marker}"
    probe = f"{marker}-stub-binding".lower()
    status, payload = _request(
        "POST", base + TARGET_PATH,
        body={"name": probe},
        headers={"Authorization": f"Bearer {forged}"},
    )
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("created"):
        findings.append({
            "sev": "critical",
            "title": "Dify 存根令牌伪造：离线铸造的伪造存根凭据被控制面接受",
            "detail": "JWE 根密钥硬编码公开默认值：攻击者可离线铸造存根控制面凭据，控制面无法区分其与合法凭据（默认密钥未更换即长期有效）。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "forged_token_form": forged.split(".")[0] + ".<redacted>",
                "binding": payload.get("binding"), "mode": (manifest or {}).get("mode"), "probe": probe,
            }, ensure_ascii=False),
            "mapping": "零日登记册：智能体平台存根凭据条目；配套链「智能体平台零前置执行 → 训练集群横向」",
            "fix": "部署期强制更换 JWE 根密钥并校验唯一性（启动时拒绝默认值）；令牌短时效 + 撤销名单",
            "is_zeroday": True,
        })
        summary = "fingerprint 命中 dify-agent；伪造存根凭据被接受（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 dify-agent；伪造存根凭据被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
