# -*- coding: utf-8 -*-
"""工作区 JSON/JSONL 小工具：原子读写、摘要、密钥脱敏与追加式审计。

新功能（clean-room 扩展）共用，落盘范围限定在工作区目录：
- ``*_store.json`` / ``*.json``：工作区级实体（通知、模板、日历、黑板等）；
- ``audit.jsonl``：工作区级追加审计（run 内动作仍写 evidence.db actions 表）。

设计约束：只做本地文件 IO，不发网络、不执行命令；写入使用临时文件 + 原子替换，
避免并行读看到半截 JSON。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = (
    "api_key", "apikey", "token", "secret", "password", "passwd",
    "authorization", "cookie", "private_key", "access_key", "session_key",
)


def ws_path(store, name: str) -> Path:
    p = Path(store.ws_dir) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def read_json(path: Path | str, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return default


def write_json(path: Path | str, obj: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)
    return p


def digest(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def fingerprint(text: str) -> str:
    """可引用的短指纹（证据锚/审计），不泄露原文。"""
    return digest(text)[:24]


def _sensitive_key(key: str) -> bool:
    k = str(key).lower()
    return any(s in k for s in SENSITIVE_KEYS)


def redact(obj: Any) -> Any:
    """递归脱敏：敏感键值替换为 ``***``；保留结构以便审计对账。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _sensitive_key(k) and v not in (None, ""):
                out[k] = "***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def append_audit(store, actor: str, action: str, target: str = "",
                 params: dict | None = None, result: str = "ok") -> dict:
    """工作区级追加审计；参数脱敏后落盘，返回可回链的摘要。"""
    safe = redact(params or {})
    row = {
        "ts": time.time(),
        "actor": str(actor),
        "workspace": getattr(store, "workspace", ""),
        "action": str(action),
        "target": str(target),
        "params": safe,
        "result": str(result),
    }
    line = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
    path = ws_path(store, "audit.jsonl")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    row["digest"] = fingerprint(line)
    row["path"] = str(path)
    return row


def tail_jsonl(path: Path | str, limit: int = 100) -> list[dict]:
    """读取 JSONL 末尾 N 条（坏行跳过）；只读。"""
    p = Path(path)
    if not p.exists() or limit <= 0:
        return []
    rows: list[dict] = []
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows[-limit:]
