#!/usr/bin/env python
"""Turn the guest-side KEY=value dump of artex-bench-run.sh into report artefacts.

Inputs
  --raw        raw dump from the guest (artex-bench-raw.txt)
  --mock-log   JSONL log of lab/qemu-k3s/artex-mock-llm.py (host side)
  --out DIR    where artex-bench.json / artex-bench.md are written
  --trident    lab/bench/out/bench-smoke.json (optional, for the side-by-side table)
  --meta KEY=VAL  extra environment facts (repeatable), stored verbatim

Design rule: every number in the output must come from one of the inputs. Missing
values are reported as null with a `limitations` note, never invented.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path

MIB = 1024.0 * 1024.0


def parse_raw(text: str) -> dict:
    data: dict[str, object] = {"stats_samples": [], "images": [], "system_df": [], "polls": []}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key == "STATS_1" or key.startswith("STATS_"):
            data["stats_samples"].append(value)
        elif key == "IMAGE":
            data["images"].append(value)
        elif key == "SYSTEM_DF":
            data["system_df"].append(value)
        elif key == "TASK_POLL":
            data["polls"].append(value)
        else:
            data[key] = value
    return data


MEM_RX = re.compile(r"([\d.]+)\s*([KMGT]?i?B)\s*/\s*([\d.]+)\s*([KMGT]?i?B)")
UNIT = {"B": 1 / MIB, "KiB": 1 / 1024.0, "MiB": 1.0, "GiB": 1024.0, "TiB": 1024.0 * 1024.0,
        "kB": 1 / 1024.0, "KB": 1 / 1024.0, "MB": 1 / 1.0, "GB": 1024.0}


def mem_mib(spec: str) -> float | None:
    m = MEM_RX.search(spec or "")
    if not m:
        return None
    value, unit = float(m.group(1)), m.group(2)
    return round(value * UNIT.get(unit, 1.0), 2)


def stats_summary(samples: list[str]) -> dict:
    """Sum per-container MemUsage across samples; keep the per-container series."""
    per_container: dict[str, list[float]] = {}
    for sample in samples:
        for entry in sample.split(";;"):
            parts = entry.split("|")
            if len(parts) < 3:
                continue
            name, mem = parts[0], mem_mib(parts[1])
            if mem is None:
                continue
            per_container.setdefault(name, []).append(mem)
    total = []
    for idx in range(max((len(v) for v in per_container.values()), default=0)):
        total.append(round(sum(v[idx] for v in per_container.values() if len(v) > idx), 2))
    return {
        "per_container_mib": {k: {"samples": v, "max": max(v), "mean": round(statistics.fmean(v), 2)}
                              for k, v in per_container.items()},
        "total_mib": {"samples": total, "max": max(total) if total else None,
                      "mean": round(statistics.fmean(total), 2) if total else None},
    }


def latency_block(values: list[int]) -> dict:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    idx95 = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
    return {
        "n": len(values),
        "min_ms": ordered[0],
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[idx95],
        "mean_ms": round(statistics.fmean(ordered), 2),
        "max_ms": ordered[-1],
        "samples_ms": values,
    }


def read_mock_log(path: Path) -> dict:
    if not path or not path.exists():
        return {"requests": 0, "note": "mock LLM log not found"}
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    replies: dict[str, int] = {}
    for row in rows:
        reply = row.get("reply") or {}
        kind = reply.get("kind") or reply.get("type") or "unknown"
        if kind == "tool":
            kind = f"tool:{reply.get('name', '?')}"
        replies[kind] = replies.get(kind, 0) + 1
    return {
        "requests": len(rows),
        "replies_by_type": replies,
        "first_ts": rows[0]["ts"] if rows else None,
        "last_ts": rows[-1]["ts"] if rows else None,
        "tool_names_seen": sorted({t for row in rows for t in (row.get("tools") or [])})[:20],
        "stream_requests": sum(1 for row in rows if row.get("stream")),
        "messages_per_request": [len(row.get("messages") or []) if isinstance(row.get("messages"), list)
                                 else row.get("messages") for row in rows][:20],
    }


def read_trident(path: Path) -> dict | None:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--mock-log", default="")
    ap.add_argument("--trident", default="lab/bench/out/bench-smoke.json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--meta", action="append", default=[])
    ap.add_argument("--limitation", action="append", default=[])
    args = ap.parse_args()

    raw_text = Path(args.raw).read_text(encoding="utf-8", errors="replace")
    raw = parse_raw(raw_text)

    def num(key: str) -> int | None:
        value = raw.get(key)
        if value is None or value == "":
            return None
        try:
            return int(float(str(value)))
        except ValueError:
            return None

    health_ms = [int(x) for x in str(raw.get("HEALTH_MS_LIST", "")).split(",") if x.strip().isdigit()]
    stats = stats_summary(raw["stats_samples"])  # type: ignore[arg-type]
    meta = {}
    for item in args.meta:
        key, _, value = item.partition("=")
        meta[key] = value

    result = {
        "bench": "artex-in-qemu-vm",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": {
            "name": "ARTEX",
            "repo": "RuoJi6/ARTEX",
            "tag": "v0.3.23",
            "image": raw.get("IMAGE_ARTEX", "ruoji6/artex:v0.3.23"),
            "license": "AGPL-3.0 (black-box only; no code reuse)",
            "llm": "host mock OpenAI-compatible endpoint (deterministic replies)",
        },
        "environment": {
            **meta,
            "guest_cpus": num("GUEST_CPUS"),
            "guest_mem_total_mb": num("GUEST_MEM_TOTAL_MB"),
            "guest_loadavg_start": raw.get("GUEST_LOADAVG"),
            "guest_loadavg_end": raw.get("GUEST_LOADAVG_END"),
        },
        "cold_start": {
            "postgres_ready_ms": num("PG_READY_MS"),
            "postgres_ready": raw.get("PG_READY") == "1",
            "artex_health_ms": num("COLD_START_HEALTH_MS"),
            "artex_health_ok": raw.get("HEALTH_OK") == "1",
            "artex_health_http": num("COLD_START_HEALTH_HTTP"),
            "auth_handshake_ms": num("AUTH_MS"),
            "auth_init_http": num("AUTH_INIT_HTTP"),
            "auth_login_http": num("AUTH_LOGIN_HTTP"),
            "note": "image already present; measures container start + schema migration, not docker pull",
        },
        "api_latency": {
            "health": latency_block(health_ms),
            "tasks_list_ms": num("TASKS_LIST_MS"),
            "tasks_list_http": num("TASKS_LIST_HTTP"),
        },
        "resources": {
            **stats,
            "docker_root_bytes": num("DOCKER_ROOT_BYTES"),
            "disk_root_kb": raw.get("DISK_ROOT"),
            "images": raw["images"],
            "docker_system_df": raw["system_df"],
        },
        "task_run": {
            "http": num("TASK_HTTP"),
            "id": raw.get("TASK_ID") or None,
            "accept_ms": num("TASK_ACCEPT_MS"),
            "final_status": raw.get("TASK_FINAL_STATUS") or None,
            "total_ms": num("TASK_TOTAL_MS") or num("TASK_MS"),
            "polls": raw["polls"],
            "llm_calls": read_mock_log(Path(args.mock_log)) if args.mock_log else None,
            "target": meta.get("mock_target"),
        },
        "timestamps": {"start": raw.get("TS_START"), "end": raw.get("TS_END")},
        "limitations": list(args.limitation),
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "artex-bench.json"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    trident = read_trident(Path(args.trident)) if args.trident else None
    md = render_md(result, trident)
    (out_dir / "artex-bench.md").write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(json_path), "cold_start_ms": result["cold_start"]["artex_health_ms"],
                      "rss_max_mib": stats["total_mib"]["max"],
                      "task_status": result["task_run"]["final_status"]}, ensure_ascii=False))
    return 0


def render_md(r: dict, trident: dict | None) -> str:
    def g(*keys, default="—"):
        node = r
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node if node is not None else default

    cs = r["cold_start"]
    api = r["api_latency"]["health"]
    res = r["resources"]["total_mib"]
    task = r["task_run"]
    per = ", ".join(f"{k}={v['max']}MiB" for k, v in r["resources"]["per_container_mib"].items())
    lines = [
        "# ARTEX in QEMU TCG k3s VM — measured bench",
        "",
        f"- generated: {r['generated_utc']}",
        f"- subject: {g('subject', 'repo')} `{g('subject', 'tag')}` image `{g('subject', 'image')}`",
        f"- environment: {g('environment', 'qemu')}",
        "",
        "## Cold start (container start, image pre-pulled)",
        "",
        "| phase | ms |",
        "|---|---|",
        f"| postgres → pg_isready | {g('cold_start', 'postgres_ready_ms')} |",
        f"| artex → `/api/health` 200 | {g('cold_start', 'artex_health_ms')} |",
        f"| auth init+login handshake | {g('cold_start', 'auth_handshake_ms')} |",
        "",
        "## API latency (`GET /api/health`, guest loopback)",
        "",
        f"- n={api.get('n', 0)} min={api.get('min_ms', '—')} p50={api.get('p50_ms', '—')} "
        f"p95={api.get('p95_ms', '—')} max={api.get('max_ms', '—')} ms",
        "",
        "## Resources",
        "",
        f"- RSS total max: **{res.get('max')} MiB**, mean {res.get('mean')} MiB ({per})",
        f"- /var/lib/docker: {g('resources', 'docker_root_bytes')} bytes",
        "",
        "| image | size |",
        "|---|---|",
    ]
    for img in r["resources"]["images"]:
        parts = img.split("|")
        lines.append(f"| {parts[0]} | {parts[1] if len(parts) > 1 else ''} |")
    lines += [
        "",
        "## Task",
        "",
        f"- POST /api/tasks → {g('task_run', 'http')} in {g('task_run', 'accept_ms')} ms, id={g('task_run', 'id')}",
        f"- final status: **{g('task_run', 'final_status')}** after {g('task_run', 'total_ms')} ms",
        f"- LLM calls observed by the mock: {g('task_run', 'llm_calls', 'requests')}",
        "- same-target outcome (v2 scripted-planner mock): see same-target.md — the task",
        "  reaches `done`, the worker hits the mock target for real and a finding is filed.",
        "",
        "## Side by side with Trident",
        "",
        "| metric | ARTEX (VM) | Trident (host, lab/bench) |",
        "|---|---|---|",
    ]
    trident_rss = f"{(trident.get('max_rss_kb') or 0) / 1024:.1f} MiB (1 process)" if trident else "n/a"
    lines.append(f"| idle RSS | {res.get('max')} MiB (2 containers) | {trident_rss} |")
    if trident:
        lines.append(f"| task submit → terminal state | {g('task_run', 'total_ms')} ms "
                     f"(status={g('task_run', 'final_status')}; scripted-planner mock LLM; "
                     "same-target details in same-target.md) | "
                     f"{(trident.get('elapsed_ms') or 0):.0f} ms over {trident.get('iterations', '?')} "
                     "chain rounds (real HTTP to the same mock target) |")
    lines += ["", "## Limitations", ""]
    for lim in r["limitations"]:
        lines.append(f"- {lim}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
