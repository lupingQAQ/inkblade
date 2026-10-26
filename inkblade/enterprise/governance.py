# -*- coding: utf-8 -*-
"""变更治理本地可验证部分（ER-26 / ER-34 / ER-40）。

- ChangeCalendar：变更冻结窗口，拒绝与冻结期重叠的扫描窗口，导出 ICS；
- ExceptionPolicy：云厂商 DaemonSet 例外，要求 digest 钉住、命名空间精确、
  SA、审批人与到期时间，拒绝 tag-only/通配/过期；
- RuleRegression：规则包升级回归，旧包已拦截/检测的链在新包不得漏过。
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


class GovernanceError(ValueError):
    """治理对象参数非法。"""


def _ts(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise GovernanceError(f"无法解析时间 {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ChangeCalendar:
    """冻结窗口 + 扫描窗口冲突检查；可选持久化 JSON。"""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._items: list[dict] = []
        if self.path and self.path.is_file():
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            self._items = list(doc.get("freezes") or [])

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"schema": "inkblade-change-calendar/1",
                                             "freezes": self._items},
                                            ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")

    def add_freeze(self, name: str, start, end, *, reason: str = "", ticket: str = "",
                   owner: str = "", allow_past: bool = False,
                   now: float | None = None) -> dict:
        start_ts, end_ts = _ts(start), _ts(end)
        now = time.time() if now is None else float(now)
        if end_ts <= start_ts:
            raise GovernanceError("冻结窗口 end 必须晚于 start")
        if end_ts <= now and not allow_past:
            raise GovernanceError("冻结窗口已过期；历史导入需 allow_past")
        if not str(owner or "").strip():
            raise GovernanceError("冻结窗口 owner 必填")
        for item in self._items:
            if start_ts < float(item["end"]) and end_ts > float(item["start"]):
                raise GovernanceError(f"与既有冻结窗口重叠：{item['name']}")
        item = {"name": str(name), "start": start_ts, "end": end_ts,
                "reason": str(reason), "ticket": str(ticket), "owner": str(owner),
                "created_at": now}
        self._items.append(item)
        self._save()
        return self._view(item)

    def _view(self, item: dict) -> dict:
        return {**item, "start_iso": _iso(item["start"]), "end_iso": _iso(item["end"]),
                "status": self.status(item)}

    def status(self, item: dict, now: float | None = None) -> str:
        now = time.time() if now is None else float(now)
        if now < float(item["start"]):
            return "scheduled"
        if now >= float(item["end"]):
            return "expired"
        return "active"

    def is_frozen(self, ts=None, now: float | None = None) -> dict | None:
        ts = time.time() if ts is None else _ts(ts)
        for item in self._items:
            if float(item["start"]) <= ts < float(item["end"]):
                return self._view(item)
        return None

    def assert_change_allowed(self, start, end, *, now: float | None = None) -> dict:
        start_ts, end_ts = _ts(start), _ts(end)
        if end_ts <= start_ts:
            raise GovernanceError("变更窗口 end 必须晚于 start")
        for item in self._items:
            if start_ts < float(item["end"]) and end_ts > float(item["start"]):
                raise GovernanceError(f"变更窗口与冻结期重叠：{item['name']} ({item['ticket']})")
        return {"ok": True, "start": start_ts, "end": end_ts}

    def upcoming(self, *, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else float(now)
        return [self._view(i) for i in sorted(self._items, key=lambda x: x["start"])
                if float(i["end"]) >= now]

    def ics(self) -> str:
        lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//InkBlade//ChangeCalendar//EN"]
        for item in self._items:
            lines += ["BEGIN:VEVENT",
                      f"UID:{item['name']}@inkblade",
                      f"DTSTART:{datetime.fromtimestamp(float(item['start']), tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
                      f"DTEND:{datetime.fromtimestamp(float(item['end']), tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
                      f"SUMMARY:{item['name']}",
                      f"DESCRIPTION:{item.get('reason', '')} ticket={item.get('ticket', '')}",
                      "END:VEVENT"]
        lines.append("END:VCALENDAR")
        return "\r\n".join(lines) + "\r\n"


class ExceptionPolicy:
    """云厂商 DaemonSet 例外：digest + 精确 ns/SA + 审批 + 到期。"""

    def __init__(self):
        self._items: list[dict] = []

    def add(self, *, image: str, digest: str, namespace: str, service_account: str,
            approver: str, expires_at, reason: str = "", now: float | None = None) -> dict:
        if not str(digest or "").startswith("sha256:") or len(digest) != 71:
            raise GovernanceError("digest 必须是 sha256:<64 hex>")
        if not namespace or "*" in namespace:
            raise GovernanceError("namespace 必须精确，禁止通配")
        if not service_account or "*" in service_account:
            raise GovernanceError("service_account 必须精确，禁止通配")
        if not str(approver or "").strip():
            raise GovernanceError("approver 必填")
        now = time.time() if now is None else float(now)
        expires = _ts(expires_at)
        if expires <= now:
            raise GovernanceError("例外已过期")
        if ":" in image.rsplit("/", 1)[-1] or "@" in image:
            raise GovernanceError("image 传仓库名（不含 tag/digest），digest 单独字段")
        item = {"id": f"exc-{len(self._items) + 1:03d}", "image": image, "digest": digest,
                "namespace": namespace, "service_account": service_account,
                "approver": approver, "reason": reason, "expires_at": expires,
                "created_at": now}
        self._items.append(item)
        return item

    def evaluate(self, workload: dict, *, now: float | None = None) -> dict:
        now = time.time() if now is None else float(now)
        image = str(workload.get("image") or "")
        digest = str(workload.get("digest") or "")
        ns = str(workload.get("namespace") or "")
        sa = str(workload.get("service_account") or "")
        if not digest:
            return {"allowed": False, "reason": "tag-only image"}
        for item in self._items:
            if item["image"] == image and item["digest"] == digest \
                    and item["namespace"] == ns and item["service_account"] == sa:
                if float(item["expires_at"]) <= now:
                    return {"allowed": False, "reason": "exception expired", "exception_id": item["id"]}
                return {"allowed": True, "reason": "exception matched",
                        "exception_id": item["id"], "approver": item["approver"]}
        return {"allowed": False, "reason": "no matching exception"}

    def active(self, *, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else float(now)
        return [{**i, "status": "active" if float(i["expires_at"]) > now else "expired"}
                for i in self._items]


def compare_rule_packs(baseline: dict, candidate: dict) -> dict:
    """比较两版规则包/紫队矩阵；返回 regressions。

    结构：``{"rules": {rule_id: {"chains": [...]}}, "coverage": {chain: status}}``。
    状态序：拦截 > 拦截+检测 > 检测 > 漏过。任何链从非漏过变漏过即为回归。
    """
    rank = {"拦截": 4, "拦截+检测": 4, "检测": 3, "漏过": 1, "": 1}
    old_cov = baseline.get("coverage") or {}
    new_cov = candidate.get("coverage") or {}
    regressions = []
    for chain, old in old_cov.items():
        new = new_cov.get(chain, "")
        if rank.get(str(new), 1) < rank.get(str(old), 1):
            regressions.append({"type": "coverage", "chain": chain,
                                "from": old, "to": new or "missing"})
    old_rules = baseline.get("rules") or {}
    new_rules = candidate.get("rules") or {}
    for rule_id in old_rules:
        if rule_id not in new_rules:
            regressions.append({"type": "rule-removed", "rule": rule_id,
                                "chains": (old_rules.get(rule_id) or {}).get("chains", [])})
    return {
        "schema": "inkblade-rule-regression/1",
        "baseline_rules": len(old_rules),
        "candidate_rules": len(new_rules),
        "chains": len(old_cov),
        "regressions": regressions,
        "ok": not regressions,
    }


def assert_no_regression(baseline: dict, candidate: dict) -> dict:
    result = compare_rule_packs(baseline, candidate)
    if result["regressions"]:
        raise GovernanceError(
            "规则升级回归：" + json.dumps(result["regressions"][:5], ensure_ascii=False))
    return result
