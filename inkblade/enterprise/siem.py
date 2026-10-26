# -*- coding: utf-8 -*-
"""SIEM / ITSM 直投适配器：Splunk HEC、Elastic _bulk、Webhook(HMAC)、Jira、ServiceNow。

输入统一为 Trident OCSF 导出文档（``trident.export.build_ocsf``），输出为供应商
契约载荷。所有适配器默认不联网；``send`` 仅在显式调用时通过注入 transport 或 HTTP
发出。错误只返回结果，不记录 token/Authorization。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from ..core import jsonio

Transport = Callable[[str, bytes, dict], dict]


class DeliveryError(ValueError):
    """适配器配置/载荷错误。"""


def _events(doc: dict | list) -> list[dict]:
    if isinstance(doc, list):
        return [e for e in doc if isinstance(e, dict)]
    if isinstance(doc, dict):
        events = doc.get("events")
        if isinstance(events, list):
            return [e for e in events if isinstance(e, dict)]
        return [doc]
    raise DeliveryError("OCSF 文档必须是 object 或 events 列表")


def _post(url: str, body: bytes, headers: dict, *, timeout: int = 8) -> dict:
    req = urllib.request.Request(url, data=body, method="POST")
    for key, value in (headers or {}).items():
        req.add_header(str(key), str(value))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = int(resp.status)
            parsed = _safe_json(raw)
            return {"ok": 200 <= status < 300, "status": status, "response": parsed}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": int(exc.code),
                "error": f"HTTP {exc.code}", "response": _safe_json(exc.read())}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 0, "error": f"{type(exc).__name__}: {exc}"}


def _safe_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return raw.decode("utf-8", "replace")[:1000]


def _http_url(url: str) -> str:
    if not str(url or "").startswith(("http://", "https://")):
        raise DeliveryError("url 必须是 http(s)")
    return str(url).rstrip("/")


class SplunkHEC:
    kind = "splunk"

    def __init__(self, url: str, token: str, *, index: str = "trident",
                 source: str = "trident", sourcetype: str = "ocsf:detection_finding",
                 host: str = "trident", timeout: int = 8, transport: Transport | None = None):
        if not token:
            raise DeliveryError("Splunk HEC token 必填")
        self.url = _http_url(url)
        self.token = token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.host = host
        self.timeout = timeout
        self._transport = transport

    def endpoint(self) -> str:
        return self.url if self.url.endswith("/services/collector/event") else \
            self.url + "/services/collector/event"

    def build_payload(self, doc: dict | list) -> bytes:
        events = _events(doc)
        now = time.time()
        lines = []
        for event in events:
            envelope = {
                "time": int(event.get("time", now * 1000) or now * 1000) / 1000.0
                        if isinstance(event.get("time"), (int, float)) else now,
                "host": self.host,
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": jsonio.redact(event),
            }
            lines.append(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, doc: dict | list) -> dict:
        body = self.build_payload(doc)
        headers = {"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"}
        if self._transport is not None:
            res = self._transport(self.endpoint(), body, headers)
        else:
            res = _post(self.endpoint(), body, headers, timeout=self.timeout)
        return {"adapter": self.kind, "endpoint": self.endpoint(), "sent": len(_events(doc)),
                "bytes": len(body), **res}


class ElasticBulk:
    kind = "elastic"

    def __init__(self, url: str, *, index: str = "trident-findings", api_key: str = "",
                 timeout: int = 8, transport: Transport | None = None):
        self.url = _http_url(url)
        self.endpoint_url = self.url if self.url.endswith("/_bulk") else self.url + "/_bulk"
        self.index = index
        self.api_key = api_key
        self.timeout = timeout
        self._transport = transport

    def build_payload(self, doc: dict | list) -> bytes:
        lines = []
        for event in _events(doc):
            uid = str((event.get("finding_info") or {}).get("uid") or
                      hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:16])
            lines.append(json.dumps({"index": {"_index": self.index, "_id": uid}},
                                    ensure_ascii=False, separators=(",", ":")))
            lines.append(json.dumps(jsonio.redact(event), ensure_ascii=False,
                                    separators=(",", ":")))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, doc: dict | list) -> dict:
        body = self.build_payload(doc)
        headers = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        if self._transport is not None:
            res = self._transport(self.endpoint_url, body, headers)
        else:
            res = _post(self.endpoint_url, body, headers, timeout=self.timeout)
        parsed = res.get("response") or {}
        if isinstance(parsed, dict) and parsed.get("errors"):
            res = {**res, "ok": False, "error": "Elastic _bulk 返回 errors=true"}
        return {"adapter": self.kind, "endpoint": self.endpoint_url, "sent": len(_events(doc)),
                "bytes": len(body), **res}


class WebhookSink:
    kind = "webhook"

    def __init__(self, url: str, *, secret: str | bytes, timeout: int = 8,
                 transport: Transport | None = None, now=lambda: time.time()):
        self.url = _http_url(url)
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        if len(self.secret) < 8:
            raise DeliveryError("webhook HMAC secret 至少 8 字节")
        self.timeout = timeout
        self._transport = transport
        self._now = now

    def build_payload(self, doc: dict | list) -> bytes:
        events = _events(doc)
        payload = {
            "schema": "trident.webhook/1",
            "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._now())),
            "count": len(events),
            "events": [jsonio.redact(e) for e in events],
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def signature(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    def send(self, doc: dict | list) -> dict:
        body = self.build_payload(doc)
        ts = str(int(self._now()))
        headers = {
            "Content-Type": "application/json",
            "X-Trident-Timestamp": ts,
            "X-Trident-Signature": self.signature(body),
        }
        if self._transport is not None:
            res = self._transport(self.url, body, headers)
        else:
            res = _post(self.url, body, headers, timeout=self.timeout)
        return {"adapter": self.kind, "endpoint": self.url, "sent": len(_events(doc)),
                "bytes": len(body), **res}

    def verify(self, body: bytes | str, signature: str, timestamp: str, *,
               max_skew: int = 300) -> bool:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        if not hmac.compare_digest(self.signature(raw), str(signature)):
            return False
        try:
            ts = int(float(timestamp))
        except (TypeError, ValueError):
            return False
        return abs(self._now() - ts) <= max_skew


def _fingerprint(finding: dict, run: str) -> str:
    return jsonio.fingerprint(f"{run}|{finding.get('step_key') or finding.get('module') or ''}|"
                              f"{finding.get('title') or ''}")


SEV_TO_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium",
                   "low": "Low", "info": "Lowest"}
SEV_TO_SNOW = {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"}


class JiraSink:
    kind = "jira"

    def __init__(self, url: str, *, token: str = "", project: str = "TRIDENT",
                 timeout: int = 8, transport: Transport | None = None):
        self.url = _http_url(url)
        if not token:
            raise DeliveryError("Jira token 必填")
        self.token = token
        self.project = project
        self.timeout = timeout
        self._transport = transport

    def build(self, finding: dict, *, run: str = "", remediation: str = "") -> dict:
        sev = str(finding.get("severity") or "info").lower()
        fp = _fingerprint(finding, run)
        module = str(finding.get("step_key") or finding.get("module") or "unknown")
        fix = remediation or str(finding.get("fix") or "按报告修复建议处理并复测")
        body = (f"Run: {run}\nModule: {module}\nSeverity: {sev}\n"
                f"Evidence: {finding.get('evidence_path') or finding.get('evidence') or '-'}\n\n"
                f"Detail:\n{str(finding.get('detail') or '')[:2000]}\n\nRemediation:\n{fix}\n\n"
                f"Fingerprint: {fp}")
        return {"fields": {
            "project": {"key": self.project},
            "summary": f"[Trident][{sev}] {finding.get('title') or module}"[:250],
            "description": body,
            "issuetype": {"name": "Bug"},
            "priority": {"name": SEV_TO_PRIORITY.get(sev, "Medium")},
            "labels": ["trident", sev, module, f"fp:{fp}"],
        }}

    def send(self, finding: dict, *, run: str = "", remediation: str = "") -> dict:
        payload = self.build(finding, run=run, remediation=remediation)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        endpoint = self.url + "/rest/api/3/issue"
        res = (self._transport(endpoint, body, headers) if self._transport
               else _post(endpoint, body, headers, timeout=self.timeout))
        return {"adapter": self.kind, "endpoint": endpoint, "sent": 1, "bytes": len(body), **res}


class ServiceNowSink:
    kind = "servicenow"

    def __init__(self, url: str, *, token: str = "", table: str = "incident",
                 timeout: int = 8, transport: Transport | None = None):
        self.url = _http_url(url)
        if not token:
            raise DeliveryError("ServiceNow token 必填")
        self.token = token
        self.table = table
        self.timeout = timeout
        self._transport = transport

    def build(self, finding: dict, *, run: str = "") -> dict:
        sev = str(finding.get("severity") or "info").lower()
        fp = _fingerprint(finding, run)
        return {
            "short_description": f"[Trident][{sev}] {finding.get('title') or 'finding'}"[:160],
            "description": (f"Run: {run}\nModule: {finding.get('step_key') or '-'}\n"
                            f"Evidence: {finding.get('evidence_path') or '-'}\n\n"
                            f"{str(finding.get('detail') or '')[:3000]}"),
            "severity": SEV_TO_SNOW.get(sev, "5"),
            "category": "Security",
            "u_source": "trident",
            "correlation_id": fp,
            "u_trident_severity": sev,
        }

    def send(self, finding: dict, *, run: str = "") -> dict:
        payload = self.build(finding, run=run)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        endpoint = f"{self.url}/api/now/table/{self.table}"
        res = (self._transport(endpoint, body, headers) if self._transport
               else _post(endpoint, body, headers, timeout=self.timeout))
        return {"adapter": self.kind, "endpoint": endpoint, "sent": 1, "bytes": len(body), **res}


def adapter_for(kind: str, config: dict, *, transport: Transport | None = None):
    """配置驱动构造；未知 kind 显式报错。"""
    kind = str(kind or "").lower()
    if kind == "splunk":
        return SplunkHEC(config["url"], config["token"], index=config.get("index", "trident"),
                         transport=transport)
    if kind == "elastic":
        return ElasticBulk(config["url"], index=config.get("index", "trident-findings"),
                           api_key=config.get("api_key", ""), transport=transport)
    if kind == "webhook":
        return WebhookSink(config["url"], secret=config["secret"], transport=transport)
    if kind == "jira":
        return JiraSink(config["url"], token=config["token"],
                        project=config.get("project", "TRIDENT"), transport=transport)
    if kind == "servicenow":
        return ServiceNowSink(config["url"], token=config["token"],
                              table=config.get("table", "incident"), transport=transport)
    raise DeliveryError(f"未知适配器 {kind!r}")
