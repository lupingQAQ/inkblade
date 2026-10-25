"""工作区级紧急停止（kill switch）：CLI/API/runner 共用一个落盘标志。

语义：
- ``trident abort`` 写 ``<ws>/abort.json`` ``{requested: true, actor, reason, ts}``；
- 所有新的执行路径（runner/链/单模块）在读授权后立即检查，命中即 ExecutionLocked；
- ``trident abort --clear`` 写 ``requested: false``（保留操作者与时间，审计可追溯）。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .roe import ExecutionLocked


def _path(store) -> Path:
    return store.ws_dir / "abort.json"


def abort_info(store) -> dict[str, Any]:
    p = _path(store)
    if not p.exists():
        return {"requested": False}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return {"requested": True, "actor": "unknown", "reason": "abort.json 损坏（按已中止处理）"}
    return doc if isinstance(doc, dict) else {"requested": True}


def abort_requested(store) -> bool:
    return bool(abort_info(store).get("requested"))


def request_abort(store, actor: str, reason: str = "") -> dict[str, Any]:
    doc = {"requested": True, "actor": actor, "reason": reason, "ts": time.time()}
    p = _path(store)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return doc


def clear_abort(store, actor: str) -> dict[str, Any]:
    doc = {"requested": False, "cleared_by": actor, "ts": time.time()}
    p = _path(store)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return doc


def assert_not_aborted(store) -> None:
    info = abort_info(store)
    if info.get("requested"):
        who = info.get("actor") or "unknown"
        when = info.get("ts")
        detail = f"由 {who} 请求" + (f" @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(when))}" if when else "")
        raise ExecutionLocked(f"工作区已请求紧急停止（{detail}）：拒绝新执行，请先 `trident abort --clear`")
