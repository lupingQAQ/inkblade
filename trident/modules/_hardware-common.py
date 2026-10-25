"""_hardware_common — 硬件/交换机只读模块共享库（仅标准库）。

职责：
- fixture 装载（dict / JSON 路径 / 文本路径）；
- HTTP 只读 trace（GET-only），落 ``<run>/traces/<module>.json``；
- finding/summary/artifact 构造；
- 哈希与版本解析小工具。

所有硬件模块 ``writes=false``：不调用任何 POST/PUT/PATCH/DELETE，不登录设备改配置。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
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
    return load_json_ref(snap)


def load_json_ref(value) -> dict:
    if isinstance(value, dict):
        return value
    path = Path(str(value))
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_ref(value) -> str:
    if isinstance(value, str) and "\n" not in value:
        path = Path(value)
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return str(value)


def read_text_file(path: Path | str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def sha256_file(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def int_of(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def float_of(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def version_tuple(text: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in nums[:4]) if nums else ()


def version_lt(value: str, baseline: tuple[int, ...]) -> bool:
    got = version_tuple(value)
    if not got:
        return False
    width = max(len(got), len(baseline))
    left = got + (0,) * (width - len(got))
    right = baseline + (0,) * (width - len(baseline))
    return left < right


def first_int(text: str) -> int | None:
    match = re.search(r"\d+", str(text or ""))
    return int(match.group(0)) if match else None


def is_truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "enabled", "enable", "on", "detect")


def basic_auth(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def resp(entry: dict | None) -> dict:
    payload = (entry or {}).get("response")
    return payload if isinstance(payload, dict) else {}


def is_ok(entry: dict | None) -> bool:
    return bool(entry) and entry.get("status") == 200


class Trace:
    """GET-only HTTP trace；无 ctx["run"] 时仅内存记录（便于单测直接调 run）。"""

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
            raise ValueError("hardware modules are read-only: only GET is allowed")
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
    return {"summary": "no-target", "artifacts": [], "findings": []}
