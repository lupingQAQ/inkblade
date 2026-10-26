# -*- coding: utf-8 -*-
"""通知渠道与事件规则（clean-room 等价实现）：webhook / Slack / 邮件 stub。

能力：
- 渠道 CRUD：``webhook``（任意 http(s) JSON 端点）、``slack``（Incoming Webhook 文本
  形态）、``email``（**stub**：只渲染 RFC822 风格文本并入库，不连 SMTP、不发信）；
- 事件规则：``finding.new`` / ``finding.critical`` / ``chain.complete`` /
  ``schedule.drift`` / ``zeroday.status`` / ``retest.conclusion`` / ``test``；
  规则可按最低 severity、渠道子集匹配；``event`` 支持 ``*`` 与 ``前缀.*``；
- 投递记录 + 重试：``pending``/``delivered``/``failed``/``suppressed`` 四态，
  默认禁用时全部 ``suppressed``（可审计的“未发送”），启用后指数退避重试；
- 审计：渠道/规则变更、每次发送尝试都进工作区 ``audit.jsonl``（只存摘要，不存密钥）。

默认关闭：``notify.json`` 的 ``enabled`` 为 false，且渠道/规则为空。发送动作只能由
显式启用 + lead/admin 审批触发；HTTP 传输仅在 ``dispatch/test`` 时发生。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from . import jsonio

NOTIFY_RELPATH = "notify.json"
SEVERITIES = ("info", "low", "medium", "high", "critical")
EVENTS = (
    "finding.new", "finding.critical", "chain.complete", "schedule.drift",
    "zeroday.status", "retest.conclusion", "test",
)
KINDS = ("webhook", "slack", "email")
MAX_ATTEMPTS = 3
MAX_PAYLOAD = 16 * 1024


class NotifyError(ValueError):
    """渠道/规则/投递参数非法。"""


def _sev_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(str(sev).lower())
    except ValueError:
        return 0


def _matches(pattern: str, event: str) -> bool:
    p = str(pattern or "")
    if p in ("*", ""):
        return True
    if p.endswith(".*"):
        return event.startswith(p[:-1])
    return p == event


def _event_text(event: str, payload: dict) -> str:
    title = payload.get("title") or payload.get("summary") or payload.get("message") or ""
    sev = payload.get("severity", "info")
    run = payload.get("run", "")
    return f"[InkBlade] {event} [{sev}] {title}" + (f" (run={run})" if run else "")


def _validate_channel(kind: str, config: dict) -> None:
    if kind not in KINDS:
        raise NotifyError(f"未知渠道类型 {kind!r}（支持 {', '.join(KINDS)}）")
    if not isinstance(config, dict):
        raise NotifyError("config 必须是对象")
    if kind == "webhook":
        url = config.get("url", "")
        if not str(url).startswith(("http://", "https://")):
            raise NotifyError("webhook.url 须为 http(s) 地址")
    elif kind == "slack":
        url = config.get("webhook_url") or config.get("url") or ""
        if not str(url).startswith(("http://", "https://")):
            raise NotifyError("slack.webhook_url 须为 http(s) 地址")
    else:  # email stub
        if not config.get("to"):
            raise NotifyError("email.to 必填（stub 不发信，仅入库）")
        if "@" not in str(config.get("to")):
            raise NotifyError("email.to 非法")


def _default_transport(channel: dict, event: str, payload: dict) -> dict:
    """真实 HTTP 投递（webhook/slack）；email 永远 stub，不产生网络连接。"""
    kind = channel.get("kind")
    cfg = channel.get("config") or {}
    if kind == "email":
        text = _event_text(event, payload)
        eml = (
            f"From: {cfg.get('from', 'inkblade@localhost')}\r\n"
            f"To: {cfg.get('to')}\r\n"
            f"Subject: {cfg.get('subject_prefix', '[InkBlade]')} {event}\r\n"
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"
        )
        return {"ok": True, "status": 0, "detail": "email-stub: no smtp transport", "eml": eml}
    if kind == "slack":
        url = cfg.get("webhook_url") or cfg.get("url")
        body = {"text": _event_text(event, payload),
                "attachments": [{"title": event, "text": json.dumps(payload, ensure_ascii=False)[:3000]}]}
    else:
        url = cfg.get("url")
        body = {"event": event, "text": _event_text(event, payload), "payload": payload}
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(str(url), data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (cfg.get("headers") or {}).items():
        req.add_header(str(k), str(v))
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"ok": 200 <= int(resp.status) < 300, "status": int(resp.status), "detail": ""}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": int(exc.code), "detail": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "status": 0, "detail": f"{type(exc).__name__}: {exc}"}


class NotifyManager:
    def __init__(self, store, *, transport: Callable[[dict, str, dict], dict] | None = None,
                 clock: Callable[[], float] = time.time):
        self.store = store
        self.path = jsonio.ws_path(store, NOTIFY_RELPATH)
        self._transport = transport or _default_transport
        self._clock = clock

    # ------------------------------------------------------------ 持久化
    def _load(self) -> dict:
        doc = jsonio.read_json(self.path, None)
        if not isinstance(doc, dict):
            doc = {}
        doc.setdefault("enabled", False)
        doc.setdefault("channels", [])
        doc.setdefault("rules", [])
        doc.setdefault("deliveries", [])
        return doc

    def _save(self, doc: dict) -> None:
        # 投递记录有界：保留最近 500 条，防工作区无限增长
        if len(doc["deliveries"]) > 500:
            doc["deliveries"] = doc["deliveries"][-500:]
        jsonio.write_json(self.path, doc)

    # ------------------------------------------------------------ 渠道 CRUD
    def add_channel(self, session, kind: str, name: str, config: dict, *,
                    enabled: bool = True, channel_id: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        _validate_channel(kind, config)
        if not str(name).strip():
            raise NotifyError("渠道 name 不能为空")
        doc = self._load()
        ids = {c.get("id") for c in doc["channels"]}
        cid = channel_id or f"ch-{len(ids) + 1:02d}"
        if cid in ids:
            raise NotifyError(f"渠道 id 重复 {cid}")
        channel = {
            "id": cid, "kind": kind, "name": str(name), "config": dict(config),
            "enabled": bool(enabled), "created_by": session.name,
            "created_at": self._clock(),
        }
        doc["channels"].append(channel)
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.channel.add", cid,
                            {"kind": kind, "name": name, "config": config}, "ok")
        return _mask_channel(channel)

    def update_channel(self, session, channel_id: str, **fields) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        channel = _find(doc["channels"], channel_id)
        if "kind" in fields:
            _validate_channel(fields["kind"], fields.get("config", channel.get("config") or {}))
            channel["kind"] = fields["kind"]
        for key in ("name", "enabled", "config"):
            if key in fields:
                channel[key] = fields[key]
        _validate_channel(channel["kind"], channel.get("config") or {})
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.channel.update", channel_id,
                            {k: v for k, v in fields.items() if k != "config"}, "ok")
        return _mask_channel(channel)

    def delete_channel(self, session, channel_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        _find(doc["channels"], channel_id)
        doc["channels"] = [c for c in doc["channels"] if c.get("id") != channel_id]
        for rule in doc["rules"]:
            rule["channel_ids"] = [c for c in rule.get("channel_ids", []) if c != channel_id]
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.channel.delete", channel_id, {}, "ok")
        return {"removed": channel_id}

    def list_channels(self) -> list[dict]:
        return [_mask_channel(c) for c in self._load()["channels"]]

    def get_channel(self, channel_id: str, *, raw: bool = False) -> dict:
        channel = _find(self._load()["channels"], channel_id)
        return dict(channel) if raw else _mask_channel(channel)

    # ------------------------------------------------------------ 规则
    def add_rule(self, session, event: str, channel_ids: list[str], *,
                 min_severity: str = "info", rule_id: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        if event not in EVENTS and not (event.endswith(".*") and event[:-2] in EVENTS):
            raise NotifyError(f"未知事件 {event!r}（支持 {', '.join(EVENTS)} 或 前缀.*）")
        if min_severity not in SEVERITIES:
            raise NotifyError(f"未知 severity {min_severity!r}")
        doc = self._load()
        known = {c.get("id") for c in doc["channels"]}
        for cid in channel_ids or []:
            if cid not in known:
                raise NotifyError(f"规则引用未知渠道 {cid}")
        rid = rule_id or f"rule-{len(doc['rules']) + 1:02d}"
        if any(r.get("id") == rid for r in doc["rules"]):
            raise NotifyError(f"规则 id 重复 {rid}")
        rule = {"id": rid, "event": event, "channel_ids": list(channel_ids),
                "min_severity": min_severity, "enabled": True,
                "created_by": session.name, "created_at": self._clock()}
        doc["rules"].append(rule)
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.rule.add", rid,
                            {"event": event, "channels": channel_ids,
                             "min_severity": min_severity}, "ok")
        return rule

    def delete_rule(self, session, rule_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        if not any(r.get("id") == rule_id for r in doc["rules"]):
            raise NotifyError(f"未知规则 {rule_id}")
        doc["rules"] = [r for r in doc["rules"] if r.get("id") != rule_id]
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.rule.delete", rule_id, {}, "ok")
        return {"removed": rule_id}

    def list_rules(self) -> list[dict]:
        return list(self._load()["rules"])

    def set_enabled(self, session, enabled: bool) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        doc["enabled"] = bool(enabled)
        doc["enabled_by"] = session.name
        doc["enabled_at"] = self._clock()
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.enable", "",
                            {"enabled": bool(enabled)}, "ok")
        return {"enabled": bool(enabled)}

    # ------------------------------------------------------------ 事件与投递
    def emit(self, event: str, payload: dict, *, severity: str = "", actor: str = "system",
             dispatch: bool = True, transport: Callable[[dict, str, dict], dict] | None = None) -> dict:
        if event not in EVENTS:
            raise NotifyError(f"未知事件 {event!r}")
        payload = dict(payload or {})
        sev = str(severity or payload.get("severity") or "info").lower()
        payload["severity"] = sev
        text = json.dumps(payload, ensure_ascii=False, default=str)
        if len(text) > MAX_PAYLOAD:
            payload = {"severity": sev, "title": str(payload.get("title", ""))[:500],
                       "truncated": True, "digest": jsonio.digest(text)}
            text = json.dumps(payload, ensure_ascii=False)
        doc = self._load()
        now = self._clock()
        matched: list[tuple[dict, dict]] = []
        for rule in doc["rules"]:
            if not rule.get("enabled", True) or not _matches(rule.get("event", ""), event):
                continue
            if _sev_rank(sev) < _sev_rank(rule.get("min_severity", "info")):
                continue
            targets = rule.get("channel_ids") or [c["id"] for c in doc["channels"]
                                                  if c.get("enabled", True)]
            for cid in targets:
                channel = next((c for c in doc["channels"] if c.get("id") == cid), None)
                if channel is not None:
                    matched.append((rule, channel))
        deliveries = []
        for rule, channel in matched:
            suppressed = not doc.get("enabled") or not channel.get("enabled", True)
            d = {
                "id": f"dlv-{len(doc['deliveries']) + len(deliveries) + 1:05d}",
                "event": event, "severity": sev, "rule_id": rule.get("id", ""),
                "channel_id": channel["id"], "channel_kind": channel["kind"],
                "created_at": now, "attempts": 0, "max_attempts": MAX_ATTEMPTS,
                "next_attempt_at": now, "status": "suppressed" if suppressed else "pending",
                "error": "", "payload": payload, "payload_digest": jsonio.digest(text),
                "suppressed_reason": ("notify disabled" if not doc.get("enabled")
                                      else ("channel disabled" if suppressed else "")),
            }
            doc["deliveries"].append(d)
            deliveries.append(d)
        if matched:
            self._save(doc)
        jsonio.append_audit(self.store, actor, "notify.emit", event,
                            {"severity": sev, "deliveries": len(deliveries),
                             "digest": jsonio.digest(text)}, "ok")
        result = {"event": event, "severity": sev, "matched": len(deliveries),
                  "deliveries": [_public_delivery(d) for d in deliveries]}
        if dispatch and any(d["status"] == "pending" for d in deliveries):
            result["dispatch"] = self.dispatch(transport=transport or self._transport)
            latest = {d["id"]: d for d in self._load()["deliveries"]}
            result["deliveries"] = [_public_delivery(latest.get(d["id"], d)) for d in deliveries]
        return result

    def dispatch(self, *, now: float | None = None, limit: int = 50,
                 transport: Callable[[dict, str, dict], dict] | None = None) -> dict:
        now = self._clock() if now is None else now
        transport = transport or self._transport
        doc = self._load()
        channels = {c["id"]: c for c in doc["channels"]}
        counts = {"attempted": 0, "delivered": 0, "failed": 0, "pending": 0, "skipped": 0}
        for d in doc["deliveries"]:
            if counts["attempted"] >= limit:
                break
            if d.get("status") != "pending":
                continue
            if float(d.get("next_attempt_at") or 0) > now:
                counts["skipped"] += 1
                continue
            channel = channels.get(d.get("channel_id"))
            if channel is None:
                d["status"] = "failed"
                d["error"] = "channel removed"
                counts["failed"] += 1
                continue
            counts["attempted"] += 1
            try:
                res = transport(channel, d["event"], dict(d.get("payload") or {}))
            except Exception as exc:
                res = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
            d["attempts"] = int(d.get("attempts", 0)) + 1
            if res.get("ok"):
                d["status"] = "delivered"
                d["delivered_at"] = now
                d["error"] = ""
                d["transport"] = {k: res.get(k) for k in ("status", "detail")}
                counts["delivered"] += 1
            else:
                d["error"] = str(res.get("detail") or "transport failed")[:300]
                if d["attempts"] >= int(d.get("max_attempts", MAX_ATTEMPTS)):
                    d["status"] = "failed"
                    counts["failed"] += 1
                else:
                    d["status"] = "pending"
                    d["next_attempt_at"] = now + min(300, 5 * (2 ** (d["attempts"] - 1)))
                    counts["pending"] += 1
            jsonio.append_audit(self.store, "notify", "notify.delivery", d["id"],
                                {"event": d["event"], "channel": d["channel_id"],
                                 "attempt": d["attempts"], "status": d["status"],
                                 "error": d["error"]}, d["status"])
        self._save(doc)
        return counts

    def retry(self, session, delivery_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        d = next((x for x in doc["deliveries"] if x.get("id") == delivery_id), None)
        if d is None:
            raise NotifyError(f"未知投递 {delivery_id}")
        if d.get("status") == "suppressed":
            raise NotifyError("suppressed 投递（通知未启用/渠道禁用）不可重试；先启用")
        d["status"] = "pending"
        d["attempts"] = 0
        d["next_attempt_at"] = self._clock()
        d["error"] = ""
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.retry", delivery_id, {}, "ok")
        return _public_delivery(d)

    def test_channel(self, session, channel_id: str, *,
                     transport: Callable[[dict, str, dict], dict] | None = None) -> dict:
        """单渠道测试投递（不依赖规则）：渠道可用则直投，禁用/全局禁用则 suppressed。"""
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        channel = _find(doc["channels"], channel_id)
        payload = {"title": f"test channel {channel_id}", "message": "InkBlade notify test",
                   "workspace": getattr(self.store, "workspace", ""), "severity": "info"}
        suppressed = not doc.get("enabled") or not channel.get("enabled", True)
        d = {
            "id": f"dlv-{len(doc['deliveries']) + 1:05d}", "event": "test",
            "severity": "info", "rule_id": "channel-test",
            "channel_id": channel_id, "channel_kind": channel["kind"],
            "created_at": self._clock(), "attempts": 0, "max_attempts": 1,
            "next_attempt_at": self._clock(),
            "status": "suppressed" if suppressed else "pending", "error": "",
            "payload": payload, "payload_digest": jsonio.digest(json.dumps(payload, ensure_ascii=False)),
            "suppressed_reason": ("notify disabled" if not doc.get("enabled")
                                  else ("channel disabled" if suppressed else "")),
        }
        doc["deliveries"].append(d)
        if not suppressed:
            res = (transport or self._transport)(channel, "test", payload)
            d["attempts"] = 1
            if res.get("ok"):
                d["status"] = "delivered"
                d["delivered_at"] = self._clock()
            else:
                d["status"] = "failed"
                d["error"] = str(res.get("detail") or "")[:300]
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "notify.channel.test", channel_id,
                            {"delivery": d["id"], "status": d["status"]}, d["status"])
        return _public_delivery(d)

    def deliveries(self, *, event: str = "", status: str = "", limit: int = 100) -> list[dict]:
        rows = self._load()["deliveries"]
        if event:
            rows = [d for d in rows if d.get("event") == event]
        if status:
            rows = [d for d in rows if d.get("status") == status]
        return [_public_delivery(d) for d in rows[-limit:]]

    def meta(self) -> dict:
        doc = self._load()
        return {"enabled": bool(doc.get("enabled")), "kinds": list(KINDS),
                "events": list(EVENTS), "severities": list(SEVERITIES),
                "channels": len(doc["channels"]), "rules": len(doc["rules"]),
                "deliveries": len(doc["deliveries"]),
                "email_transport": "stub (no smtp)"}


def _find(items: list[dict], item_id: str) -> dict:
    for it in items:
        if it.get("id") == item_id:
            return it
    raise NotifyError(f"未知 id {item_id}")


def _mask_channel(channel: dict) -> dict:
    out = dict(channel)
    out["config"] = jsonio.redact(channel.get("config") or {})
    return out


def _public_delivery(d: dict) -> dict:
    out = {k: d.get(k) for k in
           ("id", "event", "severity", "rule_id", "channel_id", "channel_kind",
            "created_at", "attempts", "max_attempts", "next_attempt_at", "status",
            "error", "payload_digest", "suppressed_reason", "delivered_at")}
    out["payload_summary"] = str((d.get("payload") or {}).get("title", ""))[:200]
    return out


# ---------------------------------------------------------------- 事件便捷入口
def emit_finding(manager: NotifyManager, run, finding: dict, *, actor: str = "runner") -> dict:
    sev = str(finding.get("severity") or "info").lower()
    event = "finding.critical" if sev == "critical" else "finding.new"
    payload = {"title": finding.get("title", ""), "severity": sev,
               "run": getattr(run, "name", ""), "module": finding.get("step_key", ""),
               "evidence_path": finding.get("evidence_path", "")}
    return manager.emit(event, payload, severity=sev, actor=actor)


def emit_chain_complete(manager: NotifyManager, run_name: str, chain: str,
                        *, ok: bool, actor: str = "chains") -> dict:
    return manager.emit("chain.complete",
                        {"title": f"chain {chain} {'完成' if ok else '失败'}",
                         "chain": chain, "run": run_name, "ok": ok, "severity": "info"},
                        actor=actor)


def emit_schedule_drift(manager: NotifyManager, schedule_id: str, run_name: str,
                        drift: dict, *, actor: str = "scheduler") -> dict:
    counts = (drift or {}).get("counts", {})
    sev = "high" if int(counts.get("new", 0)) else "info"
    return manager.emit("schedule.drift",
                        {"title": f"schedule {schedule_id} drift new={counts.get('new', 0)}",
                         "schedule": schedule_id, "run": run_name,
                         "counts": counts, "severity": sev},
                        severity=sev, actor=actor)


def emit_zeroday_status(manager: NotifyManager, enabled: bool, *, actor: str = "zeroday") -> dict:
    return manager.emit("zeroday.status",
                        {"title": f"zeroday {'enabled' if enabled else 'disabled'}",
                         "enabled": bool(enabled), "severity": "info"}, actor=actor)
