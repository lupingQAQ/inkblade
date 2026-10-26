"""_infra2026-common — 2026 会议 infra 缺口模块共享库（仅标准库）。

与 _hardware-common 同构：GET-only trace、finding/summary/artifact、快照与 JSON 工具。
所有模块 writes=false：不发送 POST/PUT/PATCH/DELETE，不修改目标。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TIMEOUT = 8
SEVS = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVS)}


def finding(sev: str, title: str, detail: dict | str = "", *,
            evidence: str = "", mapping: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {
        "sev": sev,
        "title": title,
        "detail": json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail),
    }
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def summary_json(family: str, findings: list[dict], *, extra: dict | None = None,
                 source: str = "") -> str:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("sev", "info")
        counts[sev] = counts.get(sev, 0) + 1
    top = min((f.get("sev", "info") for f in findings),
              key=lambda s: _SEV_RANK.get(s, len(_SEV_RANK)), default="none")
    payload = {
        "family": family,
        "findings": len(findings),
        "severity": {s: counts[s] for s in SEVS if counts.get(s)},
        "top": top,
        "source": source,
    }
    payload.update(extra or {})
    return json.dumps(payload, ensure_ascii=False)


def load_snapshot(params: dict) -> dict:
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 JSON 路径）")
    if isinstance(snap, dict):
        return snap
    return json.loads(Path(str(snap)).read_text(encoding="utf-8"))


def resp(entry: dict | None) -> dict:
    payload = (entry or {}).get("response")
    return payload if isinstance(payload, dict) else {}


def is_ok(entry: dict | None) -> bool:
    return bool(entry) and entry.get("status") == 200


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_list(value) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def parse_ts(value: str) -> datetime | None:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def expired(not_after: str, now: str | None = None) -> bool:
    end = parse_ts(not_after)
    current = parse_ts(now) if now else datetime.now(timezone.utc)
    if end is None or current is None:
        return False
    return end <= current


def days_left(not_after: str, now: str | None = None) -> int | None:
    end = parse_ts(not_after)
    current = parse_ts(now) if now else datetime.now(timezone.utc)
    if end is None or current is None:
        return None
    return int((end - current).total_seconds() // 86400)


def wildcard_id(value: str) -> bool:
    return "*" in str(value or "")


def sha256_ref(value: str) -> str:
    text = str(value or "")
    match = re.search(r"sha256:[0-9a-fA-F]{16,}", text)
    return match.group(0) if match else ""


class Trace:
    """GET-only HTTP trace；无 ctx['run'] 时仅内存记录。"""

    def __init__(self, ctx: dict, key: str):
        self.key = key
        run = ctx.get("run") if isinstance(ctx, dict) else None
        self.path = Path(run.dir) / "traces" / f"{key}.json" if run is not None else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def get(self, url: str, headers: dict | None = None):
        return self.call("GET", url, headers=headers)

    def call(self, method: str, url: str, body=None, headers: dict | None = None):
        if str(method).upper() != "GET":
            raise ValueError("infra2026 modules are read-only: only GET is allowed")
        entry = {"ts": round(time.time(), 3), "method": "GET", "url": url,
                 "body": body, "headers": dict(headers or {})}
        req = urllib.request.Request(url, method="GET")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                raw, status = response.read(), response.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except Exception as exc:  # noqa: BLE001 -- 不可达也作为 trace 证据
            entry.update(status=0, error=f"{type(exc).__name__}: {exc}")
            self.entries.append(entry)
            return entry
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text
        entry.update(status=status, response=payload, response_text=text)
        self.entries.append(entry)
        return entry

    def dump(self) -> Path | None:
        if self.path is None:
            return None
        self.path.write_text(
            json.dumps({"module": self.key, "entries": self.entries},
                       ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        return self.path


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run") if isinstance(ctx, dict) else None
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def no_target() -> dict:
    return {"summary": json.dumps({"summary": "no-target"}, ensure_ascii=False),
            "artifacts": [], "findings": []}
