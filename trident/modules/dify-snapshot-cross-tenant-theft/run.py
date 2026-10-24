"""dify-snapshot-cross-tenant-theft — Dify 赃快照跨租户窃取（私有零日模块）。

检测流程：/__routes__ fingerprint → 以良性 marker 形态提交「跨租户快照物化」作业到 /v1/jobs/run
（作业脚本仅描述物化语义、不触真实数据）→ 200 + SUCCEEDED 即「可写公共祖先根的快照作业被接受」；
401 → 加固态零发现。
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
    marker = str(params.get("marker") or ctx.get("marker") or "TRIDENT-zeroday")

    manifest, miss = _fingerprint(base)
    if miss is not None:
        return {"summary": miss, "findings": [], "artifacts": []}

    # 良性探针：脚本仅表达「快照物化」语义（marker 归因），不含任何真实窃取载荷
    script = (
        f"trident probe: snapshot materialize --lease-root <common-ancestor> "
        f"--from victim-binding --into {marker}-binding  # benign marker, no data exfil"
    )
    status, payload = _request("POST", base + TARGET_PATH, body={"script": script})
    findings: list[dict] = []
    if status == 200 and isinstance(payload, dict) and payload.get("status") == "SUCCEEDED":
        findings.append({
            "sev": "critical",
            "title": "Dify 赃快照跨租户窃取：跨租户快照物化作业被接受",
            "detail": "快照/绑定控制租约的可写根为公共祖先：攻击者 binding 可把任意（受害者）binding 家目录快照物化到自身目录后读出机密——租户边界在存储层失效。",
            "evidence": json.dumps({
                "route": TARGET_PATH, "status": status, "run_id": payload.get("run_id"),
                "script_path": payload.get("script_path"), "mode": (manifest or {}).get("mode"),
            }, ensure_ascii=False),
            "mapping": "零日登记册：智能体平台跨租户快照条目；链「智能体平台跨租户窃取 → 数据面串联」",
            "fix": "租约可写根按租户隔离（拒绝公共祖先）；快照物化校验目标归属；跨租户读路径加审计与阻断",
            "is_zeroday": True,
        })
        summary = "fingerprint 命中 dify-agent；跨租户快照物化作业被接受（vulnerable 姿态）"
    else:
        summary = f"fingerprint 命中 dify-agent；快照物化作业被拒（status={status}，fixed/加固态）"
    return {"summary": summary, "findings": findings, "artifacts": []}
