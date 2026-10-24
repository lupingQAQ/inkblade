"""授权治理：同意数据模型、技术级别闸门、范围（命名空间/CIDR）校验、执行许可断言。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore

LEVELS = ["只读侦察", "主动探测", "利用验证", "全影响演示"]


class ExecutionLocked(Exception):
    """授权未完成/级别不足/范围外：一切执行路径必须拒绝。"""


def allowed(module_level: str, roe_level: str) -> bool:
    return LEVELS.index(module_level) <= LEVELS.index(roe_level)


def _scope_file(store: EvidenceStore) -> Path:
    p = store.ws_dir / "scope.json"
    return p


def init_roe(store: EvidenceStore, fields: dict[str, Any]) -> None:
    payload = json.dumps(fields, ensure_ascii=False, sort_keys=True)
    sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    _scope_file(store).write_text(
        json.dumps({"fields": fields, "sha256": sha}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    run = store.create_run("_roe")
    with run._tx() as conn:
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS roe(id INTEGER PRIMARY KEY, workspace TEXT,"
            " scope_sha256 TEXT, status TEXT, fields TEXT, created_at REAL)"
        )
        conn.execute(
            "INSERT INTO roe(workspace, scope_sha256, status, fields, created_at) VALUES(?,?,?,?,?)",
            (store.workspace, sha, "complete", payload, time.time()),
        )


def roe_status(store: EvidenceStore) -> str:
    if not _scope_file(store).exists():
        return "absent"
    try:
        run = store.open_run("_roe")
        rows = run.query("SELECT status FROM roe ORDER BY id DESC LIMIT 1")
        if rows and rows[0][0] == "complete":
            return "complete"
    except KeyError:
        pass
    return "absent"


def _fields(store: EvidenceStore) -> dict[str, Any]:
    data = json.loads(_scope_file(store).read_text(encoding="utf-8"))
    return data.get("fields", {})


def in_scope(store: EvidenceStore, target_ns: str | None, target_addr: str | None) -> bool:
    if roe_status(store) != "complete":
        return False
    f = _fields(store)
    if target_ns is not None:
        if target_ns not in set(f.get("namespaces", [])):
            return False
    if target_addr is not None:
        try:
            addr = ipaddress.ip_address(target_addr)
        except ValueError:
            return False
        nets = [ipaddress.ip_network(c) for c in f.get("cidrs", []) if c]
        if not any(addr in n for n in nets):
            return False
    return True


def assert_execution_allowed(store: EvidenceStore, module_meta: dict[str, Any]) -> None:
    if roe_status(store) != "complete":
        raise ExecutionLocked("工作区授权未完成（consent 未签署）")
    if not allowed(module_meta.get("min_level", "只读侦察"), _fields(store).get("level", "只读侦察")):
        raise ExecutionLocked(
            f"级别不足：模块要求 {module_meta.get('min_level')}，授权为 {_fields(store).get('level')}"
        )
