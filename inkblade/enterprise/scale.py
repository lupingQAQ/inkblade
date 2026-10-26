# -*- coding: utf-8 -*-
"""审计事件流本地吞吐验证（ER-16）：合成事件 → SQLite WAL 批量写入 → 读回统计。

只证明本机单进程写入/去重/索引的算法与资源量级，不代表客户日均百万事件流；
不读取客户真实数据。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
import tracemalloc
from pathlib import Path


def synthetic_events(count: int, *, seed: int = 1):
    verbs = ("get", "list", "create", "update", "delete", "exec")
    users = (f"user-{i}" for i in range(97))
    namespaces = (f"ns-{i}" for i in range(13))
    resources = ("pods", "secrets", "deployments", "serviceaccounts", "configmaps")
    base = int(time.time()) - int(count)
    for i in range(max(0, int(count))):
        verb = verbs[(i + seed) % len(verbs)]
        user = f"user-{(i * 7 + seed) % 97}"
        ns = f"ns-{(i * 3 + seed) % 13}"
        resource = resources[(i * 5 + seed) % len(resources)]
        allowed = 0 if i % 17 == 0 else 1
        raw = f"{base + i}|{verb}|{user}|{ns}|{resource}|{allowed}".encode()
        yield (base + i, verb, user, ns, resource, allowed, hashlib.sha256(raw).hexdigest())


def run_scale(count: int = 100_000, *, db_path: str | Path | None = None,
              batch_size: int = 5000, dedupe: bool = True) -> dict:
    count = max(1, int(count))
    tmp = None
    if db_path is None:
        tmp = tempfile.TemporaryDirectory(prefix="inkblade-scale-")
        db_path = Path(tmp.name) / "audit.db"
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tracemalloc.start()
    started = time.perf_counter()
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        unique = ", UNIQUE(raw_sha256)" if dedupe else ""
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER, verb TEXT, user TEXT,"
            " namespace TEXT, resource TEXT, allowed INTEGER, raw_sha256 TEXT"
            + unique + ")")
        inserted = duplicates = 0
        batch: list[tuple] = []
        for event in synthetic_events(count):
            batch.append(event)
            if len(batch) >= batch_size:
                before = conn.total_changes
                conn.executemany(
                    "INSERT OR IGNORE INTO events (ts,verb,user,namespace,resource,allowed,raw_sha256)"
                    " VALUES (?,?,?,?,?,?,?)" if dedupe else
                    "INSERT INTO events (ts,verb,user,namespace,resource,allowed,raw_sha256)"
                    " VALUES (?,?,?,?,?,?,?)", batch)
                changed = conn.total_changes - before
                inserted += changed
                duplicates += len(batch) - changed if dedupe else 0
                batch.clear()
        if batch:
            before = conn.total_changes
            conn.executemany(
                "INSERT OR IGNORE INTO events (ts,verb,user,namespace,resource,allowed,raw_sha256)"
                " VALUES (?,?,?,?,?,?,?)" if dedupe else
                "INSERT INTO events (ts,verb,user,namespace,resource,allowed,raw_sha256)"
                " VALUES (?,?,?,?,?,?,?)", batch)
            changed = conn.total_changes - before
            inserted += changed
            duplicates += len(batch) - changed if dedupe else 0
        conn.commit()
        elapsed = time.perf_counter() - started
        current, peak = tracemalloc.get_traced_memory()
        rows = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_verb = dict(conn.execute(
            "SELECT verb, COUNT(*) FROM events GROUP BY verb ORDER BY verb").fetchall())
        denied = conn.execute("SELECT COUNT(*) FROM events WHERE allowed=0").fetchone()[0]
        size = path.stat().st_size
    finally:
        conn.close()
        tracemalloc.stop()
        if tmp is not None:
            tmp.cleanup()
    return {
        "schema": "inkblade-audit-scale/1",
        "requested": count,
        "inserted": inserted,
        "duplicates": duplicates,
        "rows": rows,
        "denied": denied,
        "by_verb": by_verb,
        "elapsed_seconds": round(elapsed, 3),
        "events_per_second": round(inserted / elapsed, 1) if elapsed > 0 else 0.0,
        "db_bytes": size,
        "peak_traced_bytes": peak,
        "dedupe": bool(dedupe),
        "note": "本机合成事件；不代表客户生产事件流/SLA。",
    }


def daily_million_projection(result: dict) -> dict:
    per_sec = float(result.get("events_per_second") or 0)
    day = 86_400
    capacity = per_sec * day
    return {
        "events_per_second": per_sec,
        "projected_daily_capacity": int(capacity),
        "meets_one_million_per_day": capacity >= 1_000_000,
        "headroom_factor": round(capacity / 1_000_000, 2) if per_sec else 0.0,
        "note": "线性外推仅用于容量规划，需客户峰值/长稳实测复核。",
    }
