"""client — 仅标准库的计时 HTTP 客户端（延迟扫掠/并发扫掠共用）。

- request_once(): 单请求 → (status, ms, bytes, body, err)；流式端点读首块后即关（SSE 只计首响应）。
- login(): Trident POST /api/login {name,password}→{token,role}；
  ARTEX  POST /api/auth/login {username,password}→{token}。返回 Bearer 头字典。
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request


def request_once(url: str, *, method: str = "GET", body: dict | None = None,
                 headers: dict | None = None, timeout_s: float = 10.0,
                 read_limit: int = 262144) -> dict:
    """单次请求计时。4xx/5xx 也算到达（status 如实记录）；异常记录 err。

    流式/SSE：读到 read_limit 或超时即断开 —— 首响应时延有意义、总时长无意义。
    返回 {method,url,status,ms,bytes,body,err,ok}。
    """
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    t0 = time.perf_counter()
    status, nbytes, raw, err = 0, 0, b"", None
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = int(resp.status)
            try:
                raw = resp.read(read_limit)
            except (socket.timeout, TimeoutError):
                err = "read-timeout(partial)"
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        try:
            raw = exc.read(read_limit)
        except Exception:
            pass
    except Exception as exc:  # 连接拒绝/超时/DNS
        err = f"{type(exc).__name__}: {exc}"[:200]
    ms = (time.perf_counter() - t0) * 1000.0
    nbytes = len(raw)
    parsed: object = None
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            parsed = None
    return {"method": method, "url": url, "status": status, "ms": round(ms, 3),
            "bytes": nbytes, "body": parsed, "raw_head": raw[:120].decode("utf-8", "replace"),
            "err": err, "ok": err is None and 200 <= status < 300}


def login(base_url: str, kind: str, name: str, password: str,
          timeout_s: float = 10.0) -> tuple[str | None, dict]:
    """登录拿 Bearer。kind='trident'（/api/login）或 'artex'（/api/auth/login）。"""
    if kind == "trident":
        path, payload = "/api/login", {"name": name, "password": password}
    else:
        path, payload = "/api/auth/login", {"username": name, "password": password}
    r = request_once(base_url.rstrip("/") + path, method="POST", body=payload,
                     timeout_s=timeout_s)
    token = (r["body"] or {}).get("token") if isinstance(r["body"], dict) else None
    if not token:
        return None, r
    return token, {"Authorization": f"Bearer {token}"}
