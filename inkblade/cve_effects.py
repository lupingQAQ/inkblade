# -*- coding: utf-8 -*-
"""verify-effects 的 CVE 实效检查（+5）：Ray marker、网关默认 key、IPMI、Redfish、runc 面。

全部在本机 127.0.0.1 mock 靶场真实 HTTP 完成；写面通过 runner 备份闸门，
marker 读回后显式清理。由 inkblade/verify-effects.py 调用，保持主脚本结构稳定。
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Callable

from inkblade.core.runner import run_module

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"
RUNC_FIXTURE = Path(__file__).resolve().parents[1] / "lab" / "fixtures" / "cve" / "host-surface.json"


def _load_trace(run, module_key: str) -> dict:
    path = Path(run.dir) / "traces" / f"{module_key}.json"
    if not path.is_file():
        raise AssertionError(f"缺少 trace：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _find(trace: dict, method: str, needle: str) -> dict:
    for entry in trace.get("entries", []):
        if entry.get("method") == method and needle in str(entry.get("url", "")):
            return entry
    raise AssertionError(f"trace 未命中 {method} {needle}")


def _detail_of(run, module_key: str) -> dict:
    rows = [f for f in run.findings if f.get("step_key") == module_key]
    if not rows:
        raise AssertionError(f"{module_key} 未产出 finding")
    return json.loads(rows[-1].get("detail") or "{}")


def _cleanup(base: str, marker: str) -> int:
    data = json.dumps({"marker": marker}).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + "/__cleanup__", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return int(body.get("deleted") or 0)


def run_cve_checks(checks, *, store, tester, run, lab_root: Path, cve_server) -> None:
    """把 5 项 CVE 实效检查注册到 verify-effects 的 _Checks 实例。"""
    base = cve_server.url("")

    def ray_job_rce_marker() -> dict[str, Any]:
        marker = f"INKBLADE-{run.name}"
        out = run_module(
            store, tester, "ray-job-marker-rce",
            {"target": base, "mode": "backup-write", "marker": marker,
             "backup_targets": [{"kind": "http", "url": base + "/ray/api/jobs/",
                                 "state": {"jobs": []}}], "cleanup": False},
            modules_dir=MODULES_DIR, run=run,
        )
        trace = _load_trace(run, "ray-job-marker-rce")
        submit = _find(trace, "POST", "/ray/api/jobs/")
        if submit.get("status") != 200:
            raise AssertionError(f"Ray Job 提交未 200（{submit.get('status')}）")
        resp = submit.get("response") or {}
        marker_path = Path(str(resp.get("marker_path") or ""))
        if not marker_path.is_file():
            raise AssertionError("Ray marker 未落盘")
        content = marker_path.read_text(encoding="utf-8", errors="replace")
        if "INKBLADE-" not in content or marker not in content:
            raise AssertionError("Ray marker 内容不含 run 标记")
        deleted = _cleanup(base, marker)
        if marker_path.exists():
            raise AssertionError("Ray marker 清理后仍存在")
        detail = _detail_of(run, "ray-job-marker-rce")
        return {"submit_status": submit["status"], "job_id": resp.get("job_id"),
                "marker": marker, "marker_present": True, "marker_path": str(marker_path),
                "marker_sha256": resp.get("marker_sha256"), "cleanup_deleted": deleted,
                "cleanup_removed": not marker_path.exists(), "cve": "CVE-2023-48022",
                "finding_cves": detail.get("cves"), "artifact": out.get("artifacts")}

    checks.run("ray-job-rce-marker",
               "Ray 未授权 Job RCE：提交 entrypoint → 服务端 marker 落盘并读回", ray_job_rce_marker)

    def gateway_default_key_exfil() -> dict[str, Any]:
        run_module(store, tester, "litellm-default-key-exfil", {"target": base},
                   modules_dir=MODULES_DIR, run=run)
        trace = _load_trace(run, "litellm-default-key-exfil")
        config = _find(trace, "GET", "/litellm/config")
        if config.get("status") != 200:
            raise AssertionError(f"默认 key 未被接受（{config.get('status')}）")
        detail = _detail_of(run, "litellm-default-key-exfil")
        full_keys = []
        response = config.get("response") or {}
        for upstream in response.get("upstreams") or []:
            full_keys.append(str(upstream.get("api_key") or ""))
        findings_text = json.dumps([f.get("detail") for f in run.findings if f.get("step_key") == "litellm-default-key-exfil"],
                                   ensure_ascii=False)
        leaked = [k for k in full_keys if k and k in findings_text]
        if leaked:
            raise AssertionError("finding 出现完整上游 key")
        if detail.get("upstream_key_count", 0) < 1:
            raise AssertionError("未读到上游 key")
        if not detail.get("masked_only"):
            raise AssertionError("上游 key 未脱敏")
        return {"http_status": config["status"], "key_class": detail.get("key_class"),
                "upstream_key_count": detail.get("upstream_key_count"),
                "upstream_key_tail4": detail.get("upstream_key_tail4"),
                "masked_only": detail.get("masked_only"),
                "full_key_in_finding": bool(leaked),
                "finding_cves": detail.get("cves")}

    checks.run("gateway-default-key-exfil",
               "AI 网关默认 key：sk-1234 → 上游 provider key 读取（仅尾 4 位入证据）",
               gateway_default_key_exfil)

    def ipmi_cipher_zero_bypass() -> dict[str, Any]:
        run_module(store, tester, "ipmi-cipher-zero-bypass", {"target": base},
                   modules_dir=MODULES_DIR, run=run)
        trace = _load_trace(run, "ipmi-cipher-zero-bypass")
        auth = _find(trace, "POST", "/ipmi/rmcp")
        if auth.get("status") != 200:
            raise AssertionError(f"cipher zero 未建立会话（{auth.get('status')}）")
        resp = auth.get("response") or {}
        if resp.get("cipher") != 0 or resp.get("privilege") != "admin":
            raise AssertionError("cipher/privilege 不符合绕过语义")
        detail = _detail_of(run, "ipmi-cipher-zero-bypass")
        return {"auth_status": auth["status"], "cipher": resp.get("cipher"),
                "privilege": resp.get("privilege"), "username": resp.get("username"),
                "session": resp.get("session"), "session_established": bool(resp.get("session")),
                "finding_cves": detail.get("cves")}

    checks.run("ipmi-cipher-zero-bypass",
               "IPMI cipher zero 认证绕过：mock BMC 建立 admin 会话（真实协议 UDP/623）",
               ipmi_cipher_zero_bypass)

    def redfish_default_credentials() -> dict[str, Any]:
        run_module(store, tester, "redfish-default-credentials", {"target": base},
                   modules_dir=MODULES_DIR, run=run)
        trace = _load_trace(run, "redfish-default-credentials")
        login = _find(trace, "POST", "/redfish/v1/SessionService/Sessions")
        systems = _find(trace, "GET", "/redfish/v1/Systems/1")
        if login.get("status") not in (200, 201):
            raise AssertionError(f"Redfish 默认凭据未登录（{login.get('status')}）")
        resp = login.get("response") or {}
        if not resp.get("Token"):
            raise AssertionError("未签发 Redfish 会话 token")
        if systems.get("status") != 200:
            raise AssertionError(f"持 token 读取 Systems 未 200（{systems.get('status')}）")
        detail = _detail_of(run, "redfish-default-credentials")
        return {"session_status": login["status"], "accepted_username": resp.get("UserName"),
                "token_issued": bool(resp.get("Token")), "systems_status": systems["status"],
                "systems_name": (systems.get("response") or {}).get("Name"),
                "finding_cves": detail.get("cves")}

    checks.run("redfish-default-credentials",
               "Redfish 默认凭据：admin/admin → BMC 管理员会话 + Systems 读取",
               redfish_default_credentials)

    def runc_surface_detection() -> dict[str, Any]:
        run_module(store, tester, "runc-escape-detect",
                   {"snapshot": str(RUNC_FIXTURE)},
                   modules_dir=MODULES_DIR, run=run)
        rows = [f for f in run.findings if f.get("step_key") == "runc-escape-detect"]
        if not rows:
            raise AssertionError("runc 面未产出 finding")
        cves = set()
        for row in rows:
            try:
                detail = json.loads(row.get("detail") or "{}")
            except ValueError:
                continue
            cves |= set(detail.get("cves") or [])
        cves = sorted(cves)
        for expected in ("CVE-2024-21626", "CVE-2025-31133"):
            if expected not in cves:
                raise AssertionError(f"缺少 {expected} 判定")
        return {"findings": len(rows), "cves": cves, "writes": False,
                "read_only": True, "fixture": RUNC_FIXTURE.name}

    checks.run("runc-surface-detection",
               "runc 逃逸面检测：只读快照判定 CVE-2024-21626 / CVE-2025-31133（unsupported 真硬件）",
               runc_surface_detection)
