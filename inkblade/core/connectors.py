# -*- coding: utf-8 -*-
"""工单/SIEM 直投连接器（CM-15）：finding + 修复建议 → Jira / SIEM / 通用 webhook。

- ``build_payload`` 生成三态目标载荷：``jira``（Issue fields）、``siem``（ECS/OCSF 风格
  alert）、``webhook``（原始结构化事件）；修复建议优先取 finding detail 内的 fix，其次
  引用 ``core/kb.py`` 的对应条目；
- ``deliver`` 默认 **dry_run=True**：只生成载荷并落 ``connectors.json``（status=planned），
  不发网络；``dry_run=False`` 才调用注入的 transport/HTTP；
- 外发要求 lead/admin（approve），载荷统一脱敏（token/secret/authorization 等）；
- 投递记录 + 审计（工作区 audit.jsonl），不做后台自动重试（与 notify 的重试通道分离）。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from . import jsonio, kb

CONNECTORS_RELPATH = "connectors.json"
TARGETS = ("jira", "siem", "webhook")
SEV_TO_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium",
                   "low": "Low", "info": "Lowest"}


class ConnectorError(ValueError):
    """目标/载荷参数非法。"""


def _fix_text(finding: dict) -> str:
    detail = str(finding.get("detail") or "")
    try:
        doc = json.loads(detail)
        if isinstance(doc, dict) and doc.get("fix"):
            return str(doc["fix"])
    except ValueError:
        pass
    return str(kb.cite(finding)["remediation"]["zh"])


def build_payload(finding: dict, *, target: str, run: str = "",
                  remediation: str = "") -> dict:
    if target not in TARGETS:
        raise ConnectorError(f"未知目标 {target!r}（支持 {', '.join(TARGETS)}）")
    sev = str(finding.get("severity") or "info").lower()
    title = str(finding.get("title") or "")
    module = str(finding.get("step_key") or "")
    evidence = str(finding.get("evidence_path") or "")
    fix = remediation or _fix_text(finding)
    fp = jsonio.fingerprint(f"{run}|{module}|{title}")
    body = (f"Run: {run}\nModule: {module}\nSeverity: {sev}\nEvidence: {evidence}\n\n"
            f"Detail:\n{str(finding.get('detail') or '')[:2000]}\n\nRemediation:\n{fix}\n\n"
            f"Fingerprint: {fp}")
    common = {"fingerprint": fp, "severity": sev, "title": title, "module": module,
              "run": run, "evidence_path": evidence, "remediation": fix,
              "is_zeroday": bool(finding.get("is_zeroday"))}
    if target == "jira":
        return {"target": "jira", "payload": {
            "fields": {
                "summary": f"[InkBlade][{sev}] {title}"[:250],
                "description": body,
                "issuetype": {"name": "Bug"},
                "priority": {"name": SEV_TO_PRIORITY.get(sev, "Medium")},
                "labels": ["inkblade", sev, module or "unknown"],
            }}, "meta": common}
    if target == "siem":
        return {"target": "siem", "payload": {
            "event": {"kind": "alert", "category": ["vulnerability"],
                      "severity": sev, "action": "penetration-test-finding",
                      "reason": title, "original": body[:4000]},
            "rule": {"name": f"inkblade/{module}", "id": fp},
            "inkblade": common,
        }, "meta": common}
    return {"target": "webhook", "payload": {
        "event": "inkblade.finding", "version": 1, **common, "text": body},
        "meta": common}


def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(str(k), str(v))
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"ok": 200 <= int(resp.status) < 300, "status": int(resp.status)}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": int(exc.code), "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": f"{type(exc).__name__}: {exc}"}


class Connector:
    def __init__(self, store, *, transport: Callable[[dict], dict] | None = None):
        self.store = store
        self.path = jsonio.ws_path(store, CONNECTORS_RELPATH)
        self._transport = transport or (lambda payload: {"ok": False, "error": "no transport"})

    def _load(self) -> dict:
        doc = jsonio.read_json(self.path, None)
        if not isinstance(doc, dict) or not isinstance(doc.get("deliveries"), list):
            doc = {"version": 1, "deliveries": []}
        return doc

    def deliver(self, session, run_name: str, *, titles: list[str] | None = None,
                target: str = "jira", dry_run: bool = True,
                transport: Callable[[dict, dict], dict] | None = None,
                url: str = "", headers: dict | None = None) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        if target not in TARGETS:
            raise ConnectorError(f"未知目标 {target!r}")
        try:
            run = self.store.open_run(run_name)
        except KeyError as exc:
            raise ConnectorError(f"run 不存在：{run_name}") from exc
        findings = run.findings
        if titles:
            wanted = set(titles)
            findings = [f for f in findings if f.get("title") in wanted]
        if not findings:
            raise ConnectorError("无可投递 finding（titles 过滤后为空）")
        items = []
        for f in findings:
            built = build_payload(f, target=target, run=run_name)
            # 统一脱敏（detail 可能含凭据片段）
            built["payload"] = jsonio.redact(built["payload"])
            built["meta"] = jsonio.redact(built["meta"])
            items.append(built)
        results = []
        now = time.time()
        if dry_run:
            status = "planned"
            results = [{"fingerprint": it["meta"]["fingerprint"], "ok": True,
                        "status": "planned"} for it in items]
        else:
            fn = transport
            if fn is None:
                if not url.startswith(("http://", "https://")):
                    raise ConnectorError("非 dry_run 需要 transport 或 http(s) url")
                fn = lambda built, _headers: _post(url, built["payload"], _headers or headers)
            for it in items:
                try:
                    res = fn(it, headers)
                except Exception as exc:
                    res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                results.append({"fingerprint": it["meta"]["fingerprint"],
                                "ok": bool(res.get("ok")), "status": "sent" if res.get("ok") else "failed",
                                "detail": res.get("detail") or res.get("error", "")})
            status = "sent" if all(r["ok"] for r in results) else "failed"
        delivery = {"id": f"cdlv-{len(self._load()['deliveries']) + 1:04d}",
                    "target": target, "run": run_name, "count": len(items),
                    "status": status, "dry_run": bool(dry_run), "actor": session.name,
                    "created_at": now, "results": results,
                    "fingerprints": [it["meta"]["fingerprint"] for it in items]}
        doc = self._load()
        doc["deliveries"].append(delivery)
        doc["deliveries"] = doc["deliveries"][-300:]
        jsonio.write_json(self.path, doc)
        jsonio.append_audit(self.store, session.name, "connector.deliver", target,
                            {"run": run_name, "count": len(items), "status": status,
                             "dry_run": bool(dry_run)}, status)
        return {"delivery": delivery, "items": items if dry_run else None}

    def list(self) -> list[dict]:
        return list(self._load()["deliveries"])


def render_md(items: list[dict]) -> str:
    lines = ["# 外发载荷预览", "", "| 目标 | Fingerprint | 严重度 | 标题 |", "|---|---|---|---|"]
    for it in items:
        m = it.get("meta", {})
        lines.append(f"| {it.get('target')} | {m.get('fingerprint')} | {m.get('severity')} | {m.get('title')} |")
    return "\n".join(lines) + "\n"
