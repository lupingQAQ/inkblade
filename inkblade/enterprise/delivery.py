# -*- coding: utf-8 -*-
"""SIEM/ITSM 告警闭环与出网治理（ER-39 / ER-50）。

- Deduplicator：按租户+模块+标题+资源指纹去重，窗口内重复只投递一次；
- DeliveryQueue：重试/退避/死信 JSONL/幂等键，不静默丢事件；
- EgressPolicy：host allowlist、非回环强制 TLS、自定义 CA、代理与超时；
- 所有状态只落本地 JSON/JSONL，不访问真实 SIEM。
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.parse
import urllib.request
from pathlib import Path


class DeliveryPolicyError(ValueError):
    """投递/出网策略不满足。"""


def event_fingerprint(event: dict, *, tenant: str = "") -> str:
    basis = "|".join(str(x or "") for x in (
        tenant,
        event.get("step_key") or event.get("module") or "",
        event.get("title") or "",
        event.get("resource") or event.get("evidence_path") or "",
    ))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class Deduplicator:
    def __init__(self, *, window_seconds: int = 3600, path: str | Path | None = None,
                 clock=time.time):
        self.window = max(0, int(window_seconds))
        self.path = Path(path) if path else None
        self.clock = clock
        self._seen: dict[str, float] = {}
        if self.path and self.path.is_file():
            try:
                doc = json.loads(self.path.read_text(encoding="utf-8"))
                self._seen = {str(k): float(v) for k, v in (doc.get("seen") or {}).items()}
            except (OSError, ValueError):
                self._seen = {}

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"schema": "inkblade-dedupe/1",
                                             "seen": self._seen},
                                            ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")

    def check(self, fingerprint: str) -> bool:
        now = self.clock()
        last = self._seen.get(fingerprint)
        if last is not None and now - last < self.window:
            return False
        self._seen[fingerprint] = now
        self._save()
        return True

    def prune(self) -> int:
        now = self.clock()
        stale = [k for k, v in self._seen.items() if now - v >= self.window]
        for key in stale:
            self._seen.pop(key, None)
        if stale:
            self._save()
        return len(stale)


class DeliveryQueue:
    """适配器逐条投递；失败重试后写死信，返回可核对的统计。"""

    def __init__(self, adapter, *, dedupe: Deduplicator | None = None,
                 max_attempts: int = 3, backoff: float = 0.0,
                 dead_letter_path: str | Path | None = None, sleep=time.sleep):
        self.adapter = adapter
        self.dedupe = dedupe
        self.max_attempts = max(1, int(max_attempts))
        self.backoff = max(0.0, float(backoff))
        self.dead_letter_path = Path(dead_letter_path) if dead_letter_path else None
        self.sleep = sleep

    def _dead_letter(self, event: dict, error: str) -> None:
        if not self.dead_letter_path:
            return
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dead_letter_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": time.time(), "error": error,
                                 "event": event}, ensure_ascii=False) + "\n")

    def send(self, events: list[dict], *, tenant: str = "") -> dict:
        stats = {"sent": 0, "duplicates": 0, "failed": 0, "attempts": 0, "dead_letters": 0}
        for event in events:
            fp = event_fingerprint(event, tenant=tenant)
            if self.dedupe is not None and not self.dedupe.check(fp):
                stats["duplicates"] += 1
                continue
            event = {**event, "idempotency_key": fp, "tenant": tenant}
            last_error = ""
            for attempt in range(1, self.max_attempts + 1):
                stats["attempts"] += 1
                try:
                    result = self.adapter.send(event)
                except Exception as exc:  # noqa: BLE001
                    result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                if result.get("ok"):
                    stats["sent"] += 1
                    break
                last_error = str(result.get("error") or result.get("status") or "failed")
                if attempt < self.max_attempts and self.backoff:
                    self.sleep(self.backoff * attempt)
            else:
                stats["failed"] += 1
                stats["dead_letters"] += 1
                self._dead_letter(event, last_error)
        return stats

    def replay_dead_letters(self, *, limit: int = 100) -> dict:
        if not self.dead_letter_path or not self.dead_letter_path.is_file():
            return {"replayed": 0, "failed": 0, "remaining": 0}
        rows = [json.loads(line) for line in
                self.dead_letter_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        keep, replayed, failed = [], 0, 0
        for row in rows[:limit]:
            event = row.get("event") or {}
            try:
                result = self.adapter.send(event)
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if result.get("ok"):
                replayed += 1
            else:
                failed += 1
                keep.append({"at": time.time(), "error": str(result.get("error")),
                             "event": event})
        keep.extend(rows[limit:])
        if keep:
            self.dead_letter_path.write_text(
                "\n".join(json.dumps(r, ensure_ascii=False) for r in keep) + "\n",
                encoding="utf-8")
        else:
            self.dead_letter_path.unlink(missing_ok=True)
        return {"replayed": replayed, "failed": failed, "remaining": len(keep)}


class EgressPolicy:
    """SIEM/ITSM 出网策略：allowlist、TLS、CA、代理。"""

    def __init__(self, allowed_hosts: list[str], *, require_tls: bool = True,
                 ca_bundle: str | Path | None = None,
                 http_proxy: str = "", https_proxy: str = "", no_proxy: str = ""):
        self.allowed_hosts = [h.lower().strip() for h in allowed_hosts if h]
        if not self.allowed_hosts:
            raise DeliveryPolicyError("allowed_hosts 不能为空")
        self.require_tls = bool(require_tls)
        self.ca_bundle = str(ca_bundle) if ca_bundle else ""
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy
        self.no_proxy = no_proxy

    def check_url(self, url: str) -> dict:
        parsed = urllib.parse.urlsplit(str(url or ""))
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https"):
            raise DeliveryPolicyError("只允许 http(s)")
        if host not in self.allowed_hosts:
            raise DeliveryPolicyError(f"host {host} 不在 allowlist")
        loopback = host in ("127.0.0.1", "::1", "localhost")
        if self.require_tls and parsed.scheme != "https" and not loopback:
            raise DeliveryPolicyError("非回环地址必须 HTTPS")
        return {"ok": True, "scheme": parsed.scheme, "host": host,
                "port": parsed.port, "loopback": loopback,
                "tls_required": self.require_tls and not loopback,
                "ca_bundle": bool(self.ca_bundle)}

    def opener(self) -> urllib.request.OpenerDirector:
        proxies = {}
        if self.http_proxy:
            proxies["http"] = self.http_proxy
        if self.https_proxy:
            proxies["https"] = self.https_proxy
        handlers = [urllib.request.ProxyHandler(proxies)]
        if self.ca_bundle:
            handlers.append(urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=self.ca_bundle)))
        return urllib.request.build_opener(*handlers)
