# -*- coding: utf-8 -*-
"""规则/告警多路分发（CM-10）：stdout / file / syslog / program / http(s)。

安全默认（全部需要显式开关，避免“记录即外联”）：
- ``stdout``：只在返回值中生成一行 JSON，不直接打印；
- ``file``：默认只计划；``allow_write=True`` 才追加 JSONL，且默认限制在工作区内；
- ``syslog``：默认只计划；``allow_network=True`` 才发 UDP；
- ``http(s)``：默认只计划；``allow_network=True`` 才 POST；
- ``program``：默认拒绝；须 ``allow_program=True`` 且环境 ``INKBLADE_ALLOW_PROGRAM_SINK=1``，
  程序路径默认限制在工作区内，``shell=False``、stdin 传事件 JSON、5s 超时。

本模块可被 notify（IM 推送）与规则生成器复用；不读取/执行规则内容本身。
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import jsonio
from .env import getenv

SINKS = ("stdout", "file", "syslog", "program", "http", "https")


class DispatchError(ValueError):
    """sink 参数非法。"""


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _send_http(url: str, payload: dict, timeout: float = 5.0) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": 200 <= int(resp.status) < 300, "status": int(resp.status)}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": int(exc.code), "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": f"{type(exc).__name__}: {exc}"}


def dispatch(store, event: str, payload: dict, sinks: list[dict], *,
             allow_write: bool = False, allow_network: bool = False,
             allow_program: bool = False, allow_outside_write: bool = False,
             actor: str = "dispatch") -> dict:
    if not isinstance(sinks, list) or not sinks:
        raise DispatchError("sinks 不能为空")
    ws_root = Path(store.ws_dir)
    now = time.time()
    line = json.dumps({"ts": now, "workspace": getattr(store, "workspace", ""),
                       "event": event, "payload": payload}, ensure_ascii=False, default=str)
    results = []
    for sink in sinks:
        if not isinstance(sink, dict):
            raise DispatchError("sink 必须是对象")
        kind = str(sink.get("type") or "")
        if kind not in SINKS:
            raise DispatchError(f"未知 sink 类型 {kind!r}（支持 {', '.join(SINKS)}）")
        start = {"type": kind}
        try:
            if kind == "stdout":
                results.append({**start, "ok": True, "planned": False, "line": line})
            elif kind == "file":
                path = Path(str(sink.get("path") or "dispatch.jsonl"))
                target = path if path.is_absolute() else ws_root / path
                if not allow_outside_write and not _inside(target, ws_root):
                    results.append({**start, "ok": False, "planned": True,
                                    "error": "目标在工作区外（需 allow_outside_write）"})
                elif not allow_write:
                    results.append({**start, "ok": True, "planned": True,
                                    "path": str(target), "bytes": len(line.encode('utf-8'))})
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                    results.append({**start, "ok": True, "planned": False,
                                    "path": str(target)})
            elif kind == "syslog":
                host = str(sink.get("host") or "127.0.0.1")
                port = int(sink.get("port") or 514)
                msg = f"<134>inkblade {event} {json.dumps(payload, ensure_ascii=False)[:2000]}"
                if not allow_network:
                    results.append({**start, "ok": True, "planned": True,
                                    "host": host, "port": port, "bytes": len(msg)})
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2)
                        s.sendto(msg.encode("utf-8"), (host, port))
                    results.append({**start, "ok": True, "planned": False,
                                    "host": host, "port": port})
            elif kind in ("http", "https"):
                url = str(sink.get("url") or "")
                if not url.startswith(("http://", "https://")):
                    raise DispatchError(f"{kind} sink 需要 http(s) url")
                if not allow_network:
                    results.append({**start, "ok": True, "planned": True, "url": url,
                                    "bytes": len(line)})
                else:
                    res = _send_http(url, json.loads(line))
                    results.append({**start, **res, "planned": False, "url": url})
            else:  # program
                if not allow_program:
                    results.append({**start, "ok": False, "planned": True,
                                    "error": "program sink 需 allow_program=True"})
                    continue
                if getenv("ALLOW_PROGRAM_SINK") != "1":
                    results.append({**start, "ok": False, "planned": True,
                                    "error": "program sink 未启用（INKBLADE_ALLOW_PROGRAM_SINK!=1）"})
                    continue
                program = Path(str(sink.get("path") or ""))
                if not program.is_file():
                    results.append({**start, "ok": False, "planned": False,
                                    "error": "program 不存在"})
                    continue
                if not allow_outside_write and not _inside(program, ws_root):
                    results.append({**start, "ok": False, "planned": True,
                                    "error": "program 在工作区外（需 allow_outside_write）"})
                    continue
                try:
                    proc = subprocess.run([str(program)], input=line.encode("utf-8"),
                                          capture_output=True, timeout=5, shell=False)
                    results.append({**start, "ok": proc.returncode == 0, "planned": False,
                                    "exit": proc.returncode,
                                    "stdout": proc.stdout.decode("utf-8", "replace")[:500]})
                except Exception as exc:
                    results.append({**start, "ok": False, "planned": False,
                                    "error": f"{type(exc).__name__}: {exc}"})
        except DispatchError:
            raise
        except Exception as exc:
            results.append({**start, "ok": False, "planned": False,
                            "error": f"{type(exc).__name__}: {exc}"})
    out = {"event": event, "count": len(results),
           "ok": all(r.get("ok") for r in results),
           "planned": sum(1 for r in results if r.get("planned")),
           "results": results}
    jsonio.append_audit(store, actor, "dispatch", event,
                        {"sinks": [s.get("type") for s in sinks],
                         "ok": out["ok"], "planned": out["planned"],
                         "digest": jsonio.digest(line)}, "ok" if out["ok"] else "partial")
    return out
