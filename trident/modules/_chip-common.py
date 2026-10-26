"""_chip_common — 芯片/加速器姿态模块共享库（仅标准库，只读优先）。

职责：
- fixture/导出装载（dict / JSON 路径 / 文本路径）；
- finding/summary/artifact 构造（与硬件模块一致的证据形态）；
- base64 / 十六进制 / 规范化 JSON 与哈希工具；
- 受限 HTTP trace：默认 GET-only；写类模块必须显式 ``allow_write=True`` 且由
  runner 的备份闸门先行批准。

边界：本文件不包含任何仿真器答案、不执行 nvidia-smi、不写 sysfs/PCI 配置空间。
"""

from __future__ import annotations

import base64
import binascii
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
_HEX_RE = re.compile(r"^[0-9a-f]+$")


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


def load_snapshot(params: dict, *keys: str) -> tuple[dict, str]:
    for key in keys or ("snapshot", "export"):
        if params.get(key) is not None:
            value = params[key]
            if isinstance(value, dict):
                return value, f"<inline {key}>"
            return load_json_ref(value), str(value)
    raise ValueError("缺少 params.snapshot / params.export（设备导出 JSON 或 fixture 路径）")


def load_manifest(params: dict) -> tuple[dict, Path, str]:
    raw = params.get("manifest") or params.get("snapshot")
    if raw is None:
        raise ValueError("缺少 params.manifest（厂商固件清单 JSON）")
    if isinstance(raw, dict):
        return raw, Path(params.get("blobs_dir") or "."), "<inline manifest>"
    path = Path(str(raw))
    return (json.loads(path.read_text(encoding="utf-8")),
            Path(params.get("blobs_dir") or path.parent), str(path))


def b64decode_any(text: str) -> bytes:
    value = "".join(str(text or "").split())
    if not value:
        return b""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError):
        try:
            return base64.b64decode(padded.encode("ascii"), validate=False)
        except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
            raise ValueError(f"非法 base64: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canon_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def norm_hex(value) -> str:
    text = str(value or "").strip().lower().replace("0x", "").replace(":", "")
    text = re.sub(r"\s+", "", text)
    if text and not _HEX_RE.match(text):
        return ""
    return text


def hex_bytes(value) -> bytes:
    text = norm_hex(value)
    if not text or len(text) % 2:
        return b""
    return bytes.fromhex(text)


def int_of(value, default: int = 0) -> int:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def version_tuple(text) -> tuple[int, ...]:
    nums = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in nums[:4]) if nums else ()


def version_lt(value, baseline: tuple[int, ...]) -> bool:
    got = version_tuple(value)
    if not got:
        return False
    width = max(len(got), len(baseline))
    left = got + (0,) * (width - len(got))
    right = tuple(baseline) + (0,) * (width - len(baseline))
    return left < right


def now_ts(params: dict) -> float:
    value = params.get("now")
    if value is None:
        return time.time()
    if isinstance(value, (int, float)):
        return float(value)
    from datetime import datetime
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run") if isinstance(ctx, dict) else None
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


class Trace:
    """受限 HTTP trace；默认 GET-only，写类模块必须显式 allow_write=True。"""

    def __init__(self, ctx: dict, key: str):
        self.key = key
        run = ctx.get("run") if isinstance(ctx, dict) else None
        self.path = Path(run.dir) / "traces" / f"{key}.json" if run is not None else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def get(self, url: str, headers: dict | None = None):
        return self.call("GET", url, headers=headers)

    def post(self, url: str, body=None, headers: dict | None = None):
        return self.call("POST", url, body=body, headers=headers, allow_write=True)

    def call(self, method: str, url: str, body=None, headers: dict | None = None,
             allow_write: bool = False):
        method = str(method).upper()
        if method != "GET" and not (allow_write and method == "POST"):
            raise ValueError("chip modules are read-only by default: only GET is allowed")
        entry = {"ts": round(time.time(), 3), "method": method, "url": url,
                 "body": body, "headers": dict(headers or {})}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
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
        entry.update(status=status, response=payload)
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
