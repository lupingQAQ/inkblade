"""授权治理：同意数据模型、技术级别闸门、范围（命名空间/CIDR）校验、时间窗与执行许可断言。

签名链（终审 Important#1）：
- 工作区密钥在首次签发授权时生成，落 ``<ws>/workspace.json`` 的 ``consent_key``
  （32 字节 hex；POSIX 上 chmod 0600，Windows 由 ACL 继承，语义等同「仅属主可读」）；
- ``consent.json`` = ``{fields, sha256, hmac_sha256, ts, status}``，HMAC-SHA256 覆盖
  ``fields`` 的规范化 JSON（sort_keys + 紧凑分隔符）；密钥不出现在 consent.json；
- 读取时逐次验签：任何字段被改（含 level 提升）→ status=tampered → 一切执行路径拒绝。
- 时间窗（终审 Minor#6）：``fields.window`` 支持 dict ``{start,end}`` / 字符串区间 /
  单日窗；过期或未开始 → ExecutionLocked。未声明或自由文本无法解析 → 不阻断
  （存量授权兼容：effects/qemu 等以标签形式登记窗口，不得因此假阴性锁死）。
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .evidence import EvidenceStore

LEVELS = ["只读侦察", "主动探测", "利用验证", "全影响演示"]

_KEY_FIELD = "consent_key"


class ExecutionLocked(Exception):
    """授权未完成/级别不足/范围外/时间窗外/被篡改：一切执行路径必须拒绝。"""


def allowed(module_level: str, roe_level: str) -> bool:
    return LEVELS.index(module_level) <= LEVELS.index(roe_level)


# ---------- 工作区密钥与 consent 签名 ----------

def _ws_config_path(store: EvidenceStore) -> Path:
    return store.ws_dir / "workspace.json"


def read_workspace_config(store: EvidenceStore) -> dict[str, Any]:
    """读工作区级配置（workspace.json）；损坏/缺失返回 {}（不抛，交由调用方判定）。"""
    p = _ws_config_path(store)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def write_workspace_config(store: EvidenceStore, cfg: dict[str, Any]) -> None:
    """原子写 workspace.json，并施加 0600 语义（Windows 无 POSIX 位，退化为只读位）。"""
    p = _ws_config_path(store)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:  # Windows / 受限文件系统：语义上仍为工作区私有目录内文件
        pass


def workspace_key(store: EvidenceStore) -> bytes:
    """取工作区签名密钥；首次调用生成并持久化（不因重复签发而轮换）。"""
    cfg = read_workspace_config(store)
    raw = cfg.get(_KEY_FIELD)
    if isinstance(raw, str) and len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass  # 损坏 → 走重建（旧 consent 将验签失败，安全侧）
    key = secrets.token_bytes(32)
    cfg[_KEY_FIELD] = key.hex()
    cfg.setdefault("created_at", time.time())
    write_workspace_config(store, cfg)
    return key


def canonical_fields(fields: dict[str, Any]) -> str:
    return json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def signature(fields: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_fields(fields).encode("utf-8"), hashlib.sha256).hexdigest()


def sign_consent(store: EvidenceStore, fields: dict[str, Any]) -> dict[str, Any]:
    """生成 consent.json 文档（调用方负责落盘；pin_roe 会写后验签）。"""
    payload = canonical_fields(fields)
    return {
        "fields": fields,
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "hmac_sha256": signature(fields, workspace_key(store)),
        "ts": time.time(),
        "status": "complete",
    }


def verify_consent_doc(store: EvidenceStore, doc: dict[str, Any] | None) -> bool:
    """校验 consent 文档：sha256 与 HMAC 双校验，常量时间比较。"""
    if not isinstance(doc, dict):
        return False
    fields = doc.get("fields")
    if not isinstance(fields, dict):
        return False
    payload = canonical_fields(fields)
    expect_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(str(doc.get("sha256") or ""), expect_sha):
        return False
    expect_mac = signature(fields, workspace_key(store))
    return hmac.compare_digest(str(doc.get("hmac_sha256") or ""), expect_mac)


def init_roe(store: EvidenceStore, fields: dict[str, Any]) -> None:
    store.pin_roe(fields)


def roe_status(store: EvidenceStore) -> str:
    """'complete' | 'tampered' | 'absent'（调用方一律以 != 'complete' 为拒绝）。"""
    c = store.consent()
    if not c:
        return "absent"
    if c.get("status") == "complete":
        return "complete"
    return str(c.get("status") or "absent")


def _fields(store: EvidenceStore) -> dict[str, Any]:
    c = store.consent()
    return c.get("fields", {}) if c else {}


# ---------- 时间窗 ----------

_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?")


def _bound(text: str, *, is_end: bool) -> float | None:
    m = _DATE_RE.search(str(text or ""))
    if not m:
        return None
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour = int(m.group(4)) if m.group(4) is not None else (23 if is_end else 0)
    minute = int(m.group(5)) if m.group(5) is not None else (59 if is_end else 0)
    second = int(m.group(6)) if m.group(6) is not None else (59 if is_end else 0)
    try:
        return _dt.datetime(year, month, day, hour, minute, second).timestamp()
    except ValueError:
        return None


def _window_bounds(window: Any) -> tuple[float | None, float | None, str]:
    """归一 window → (start_ts, end_ts, 原文说明)。无法解析返回 (None, None, text)。"""
    if window is None or window == "":
        return None, None, ""
    if isinstance(window, dict):
        start = _bound(window.get("start"), is_end=False) if window.get("start") else None
        end = _bound(window.get("end"), is_end=True) if window.get("end") else None
        if start is not None and end is None:
            end = start + 86400
        return start, end, f"{window.get('start', '')} – {window.get('end', '')}"
    if isinstance(window, (list, tuple)) and len(window) == 2:
        start = _bound(window[0], is_end=False)
        end = _bound(window[1], is_end=True)
        return start, end, f"{window[0]} – {window[1]}"
    text = str(window)
    hits = list(_DATE_RE.finditer(text))
    if not hits:
        return None, None, text
    if len(hits) >= 2:
        start = _bound(hits[0].group(0), is_end=False)
        end = _bound(hits[-1].group(0), is_end=True)
        return start, end, text
    # 单日窗：同一日期上可能再出现「– 23:59」这类仅时刻的结束边界
    start = _bound(hits[0].group(0), is_end=False)
    day = _dt.datetime.fromtimestamp(start).strftime("%Y-%m-%d") if start else ""
    times = re.findall(r"\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b", text)
    if start is not None and len(times) >= 2:
        h, mi, se = times[-1]
        try:
            end = _dt.datetime.strptime(day, "%Y-%m-%d").replace(
                hour=int(h), minute=int(mi), second=int(se) if se else 59).timestamp()
        except ValueError:
            end = start + 86400
        return start, end, text
    return start, (start + 86400 if start is not None else None), text


def window_status(fields: dict[str, Any], now: float | None = None) -> tuple[bool, str]:
    """返回 (是否在窗内, 说明)。未声明/不可解析 → 放行（兼容存量自由文本窗）。"""
    start, end, text = _window_bounds(fields.get("window"))
    if start is None and end is None:
        return True, ("未声明时间窗" if not text else f"时间窗无法解析（不阻断）: {text}")
    ts = time.time() if now is None else now
    fmt = lambda t: _dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
    if start is not None and ts < start:
        return False, f"时间窗未开始（{fmt(start)} 起）"
    if end is not None and ts > end:
        return False, f"时间窗已过期（截至 {fmt(end)}）"
    return True, f"时间窗有效（{fmt(start) if start else '不限'} – {fmt(end) if end else '不限'}）"


# ---------- 范围 ----------

def _addr_of(value: str) -> str:
    """target 值 → IP 字面量：支持裸 IP / host:port / URL。"""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = urlparse(text).hostname or ""
    else:
        text = text.split("/", 1)[0]
        if text.count(":") == 1 and not text.startswith("["):
            text = text.split(":", 1)[0]
    return text.strip("[]")


def in_scope(store: EvidenceStore, target_ns: str | None, target_addr: str | None) -> bool:
    if roe_status(store) != "complete":
        return False
    f = _fields(store)
    if target_ns:
        if target_ns not in set(f.get("namespaces", [])):
            return False
    if target_addr:
        addr_text = _addr_of(target_addr)
        try:
            addr = ipaddress.ip_address(addr_text)
        except ValueError:
            return False
        nets = [ipaddress.ip_network(c) for c in f.get("cidrs", []) if c]
        if not any(addr in n for n in nets):
            return False
    return True


def scope_violation(store: EvidenceStore, params: dict[str, Any]) -> str | None:
    """runner 接线用：只检查 params 里显式出现的 host/target_ns/namespace。"""
    if not isinstance(params, dict):
        return None
    checks: list[tuple[str, Any]] = []
    if params.get("host"):
        checks.append(("host", params["host"]))
    ns = params.get("target_ns") or params.get("namespace")
    if ns:
        checks.append(("namespace", ns))
    for label, value in checks:
        if label == "host":
            ok = in_scope(store, target_ns=None, target_addr=str(value))
        else:
            ok = in_scope(store, target_ns=str(value), target_addr=None)
        if not ok:
            return f"目标 {label}={value} 不在授权范围（namespaces={_fields(store).get('namespaces', [])} / cidrs={_fields(store).get('cidrs', [])}）"
    return None


def assert_execution_allowed(store: EvidenceStore, module_meta: dict[str, Any]) -> None:
    if roe_status(store) != "complete":
        raise ExecutionLocked("工作区授权未完成（consent 未签署或签名校验失败）")
    fields = _fields(store)
    ok, reason = window_status(fields)
    if not ok:
        raise ExecutionLocked(f"授权时间窗外：{reason}")
    if not allowed(module_meta.get("min_level", "只读侦察"), fields.get("level", "只读侦察")):
        raise ExecutionLocked(
            f"级别不足：模块要求 {module_meta.get('min_level')}，授权为 {fields.get('level')}"
        )
