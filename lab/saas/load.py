# -*- coding: utf-8 -*-
"""本地多租户压测：8 租户 × 并发客户端；Python 压测（k6 不可用）。

指标：submit/complete 延迟分位、吞吐、HTTP 错误、配额拒绝、跨租户隔离违规、
审批重复/越权拒绝。**本地模拟，不是商业 SLA。**
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(REPO))
    from lab.saas.service import Service
else:
    from .service import Service

DEFAULT_OUT = REPO / "reports" / "samples" / "saas" / "load.json"


def _req(base: str, method: str, path: str, token: str | None = None,
         body: dict | None = None, timeout: float = 15) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except ValueError:
                return exc.code, {}
        except urllib.error.URLError:
            if attempt == 2:
                return 0, {"error": "connection refused"}
            time.sleep(0.02)
    return 0, {"error": "unreachable"}


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return round(ordered[idx], 3)


def run_load(*, tenants: int = 8, concurrency: int = 8, requests: int = 20,
             workers: int = 4, work_ms: int = 30, out: Path | str | None = None,
             port: int | None = None) -> dict:
    root = Path(tempfile.mkdtemp(prefix="trident-saas-"))
    max_concurrent = max(1, concurrency // 2)
    svc = Service(root, tenants=tenants, workers=workers, work_ms=work_ms, port=port or 0)
    for i in range(tenants):
        svc.configure_tenant(f"tenant-{i:02d}", max_concurrent=max_concurrent, max_runs=1000,
                             max_evidence_bytes=1 << 20, work_ms=work_ms)
    svc.start()
    base = svc.url
    stats = {
        "submit_latency_ms": [], "complete_latency_ms": [], "http_errors": {},
        "quota_rejects": 0, "isolation_violations": 0, "runs_done": 0,
        "runs_submitted": 0, "approval_created": 0, "approval_ok": 0,
        "duplicate_approval_blocked": 0, "approval_role_denied": 0,
        "cross_tenant_denied": 0,
    }
    stats_lock = threading.Lock()
    tenant_rows: dict[str, dict] = {}
    sample_runs: dict[str, str] = {}
    tester_token = "tok-tenant-tester"

    def http_error(status: int) -> None:
        with stats_lock:
            stats["http_errors"][str(status)] = stats["http_errors"].get(str(status), 0) + 1

    def wait_done(tid: str, rid: str, timeout: float = 15) -> tuple[bool, float]:
        start = time.perf_counter()
        while time.perf_counter() - start < timeout:
            status, doc = _req(base, "GET", f"/v1/runs/{rid}", f"tok-{tid}")
            if status == 200 and doc.get("status") in ("done", "failed"):
                return doc.get("status") == "done", (time.perf_counter() - start) * 1000
            time.sleep(0.01)
        return False, (time.perf_counter() - start) * 1000

    def client(tid: str, cid: int) -> dict:
        local = {"submitted": 0, "done": 0, "rejected": 0, "errors": 0}
        for i in range(requests):
            t0 = time.perf_counter()
            status, doc = _req(base, "POST", "/v1/runs", f"tok-{tid}",
                               {"module": f"sim-{i % 4}", "evidence_bytes": 2048})
            submit_ms = (time.perf_counter() - t0) * 1000
            with stats_lock:
                stats["submit_latency_ms"].append(submit_ms)
            if status == 202:
                local["submitted"] += 1
                with stats_lock:
                    stats["runs_submitted"] += 1
                ok, wait_ms = wait_done(tid, doc["run_id"])
                if ok:
                    local["done"] += 1
                    with stats_lock:
                        stats["runs_done"] += 1
                        stats["complete_latency_ms"].append(wait_ms)
                else:
                    local["errors"] += 1
                    http_error(599)
                sample_runs.setdefault(tid, doc["run_id"])
            elif status == 429:
                local["rejected"] += 1
                with stats_lock:
                    stats["quota_rejects"] += 1
                time.sleep(0.02)
            else:
                local["errors"] += 1
                http_error(status)
            # 每 7 次做一次跨租户读取（必须 403）
            if i % 7 == 0:
                other = f"tenant-{(int(tid[-2:]) + 1) % tenants:02d}"
                rid = sample_runs.get(other)
                if rid:
                    st, _ = _req(base, "GET", f"/v1/runs/{rid}", f"tok-{tid}")
                    with stats_lock:
                        if st == 200:
                            stats["isolation_violations"] += 1
                        elif st == 403:
                            stats["cross_tenant_denied"] += 1
        return local

    started = time.perf_counter()
    try:
        # 预热：每租户一个 run，供跨租户探测
        for i in range(tenants):
            tid = f"tenant-{i:02d}"
            st, doc = _req(base, "POST", "/v1/runs", f"tok-{tid}",
                           {"module": "warmup", "evidence_bytes": 512})
            if st == 202:
                sample_runs[tid] = doc["run_id"]
                wait_done(tid, doc["run_id"])
        with ThreadPoolExecutor(max_workers=tenants * concurrency) as pool:
            futures = [pool.submit(client, f"tenant-{i:02d}", c)
                       for i in range(tenants) for c in range(concurrency)]
            for fut in futures:
                fut.result()
        # 审批：创建/批准/重复批准/越权
        for i in range(tenants):
            tid = f"tenant-{i:02d}"
            st, doc = _req(base, "POST", "/v1/approvals", f"tok-{tid}",
                           {"action": f"approve-chain-{i}"})
            if st == 201:
                stats["approval_created"] += 1
                aid = doc["approval_id"]
                st1, _ = _req(base, "POST", f"/v1/approvals/{aid}/approve", f"tok-{tid}", {})
                if st1 == 200:
                    stats["approval_ok"] += 1
                st2, _ = _req(base, "POST", f"/v1/approvals/{aid}/approve", f"tok-{tid}", {})
                if st2 == 409:
                    stats["duplicate_approval_blocked"] += 1
        st, doc = _req(base, "POST", "/v1/approvals", tester_token,
                       {"action": "tester-approve"})
        if st == 201:
            st2, _ = _req(base, "POST", f"/v1/approvals/{doc['approval_id']}/approve",
                          tester_token, {})
            if st2 == 403:
                stats["approval_role_denied"] += 1
        # 汇总每租户 usage
        for i in range(tenants):
            tid = f"tenant-{i:02d}"
            st, doc = _req(base, "GET", "/v1/usage", f"tok-{tid}")
            tenant_rows[tid] = doc if st == 200 else {"error": st}
    finally:
        svc.stop()
    elapsed = max(0.001, time.perf_counter() - started)
    submit = stats["submit_latency_ms"]
    complete = stats["complete_latency_ms"]
    metrics = {
        "elapsed_s": round(elapsed, 3),
        "throughput_runs_s": round(stats["runs_done"] / elapsed, 3),
        "submit_p50_ms": _pct(submit, 50), "submit_p95_ms": _pct(submit, 95),
        "submit_p99_ms": _pct(submit, 99),
        "complete_p50_ms": _pct(complete, 50), "complete_p95_ms": _pct(complete, 95),
        "complete_p99_ms": _pct(complete, 99),
        "runs_submitted": stats["runs_submitted"], "runs_done": stats["runs_done"],
        "quota_rejects": stats["quota_rejects"],
        "isolation_violations": stats["isolation_violations"],
        "cross_tenant_denied": stats["cross_tenant_denied"],
        "http_errors": stats["http_errors"],
        "approval_created": stats["approval_created"],
        "approval_ok": stats["approval_ok"],
        "duplicate_approval_blocked": stats["duplicate_approval_blocked"],
        "approval_role_denied": stats["approval_role_denied"],
    }
    doc = {
        "schema": "trident-saas-load/2026-10",
        "mode": "local simulation (single host, SQLite, simulated module work)",
        "disclaimer": "本地模拟，非商业 SLA；不是分布式集群/跨 region 测试",
        "config": {"tenants": tenants, "concurrency_per_tenant": concurrency,
                   "requests_per_client": requests, "workers": workers,
                   "work_ms": work_ms, "max_concurrent_per_tenant": max_concurrent,
                   "max_runs_per_tenant": 1000, "evidence_bytes_per_run": 2048},
        "metrics": metrics,
        "tenants": tenant_rows,
        "checks": {
            "tenant_isolation": metrics["isolation_violations"] == 0,
            "quota_enforced": metrics["quota_rejects"] > 0,
            "approval_single_use": metrics["duplicate_approval_blocked"] == tenants,
            "approval_role_gate": metrics["approval_role_denied"] == 1,
            "all_submitted_eventually_done_or_rejected":
                metrics["runs_done"] + metrics["quota_rejects"] >= metrics["runs_submitted"],
        },
    }
    path = Path(out) if out else DEFAULT_OUT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_summary(doc, path.with_name("summary.md"))
    return doc


def write_summary(doc: dict, path: Path) -> None:
    m = doc["metrics"]
    rows = "\n".join(
        f"| {tenant} | {v.get('runs_total', '-')} | {v.get('done', '-')} | "
        f"{v.get('active', '-')} | {v.get('evidence_bytes', '-')} |"
        for tenant, v in doc["tenants"].items())
    checks = "\n".join(f"- {k}: {'PASS' if v else 'FAIL'}" for k, v in doc["checks"].items())
    text = f"""# SaaS 本地压测摘要

**本地模拟，非商业 SLA。**

- 配置：{doc['config']}
- 运行：{m['runs_submitted']} submitted / {m['runs_done']} done / {m['quota_rejects']} quota rejects
- 吞吐：{m['throughput_runs_s']} runs/s，总耗时 {m['elapsed_s']}s
- submit p50/p95/p99：{m['submit_p50_ms']}/{m['submit_p95_ms']}/{m['submit_p99_ms']} ms
- complete p50/p95/p99：{m['complete_p50_ms']}/{m['complete_p95_ms']}/{m['complete_p99_ms']} ms
- 隔离违规：{m['isolation_violations']}（跨租户 403：{m['cross_tenant_denied']}）
- 审批：创建 {m['approval_created']} / 成功 {m['approval_ok']} / 重复拒绝 {m['duplicate_approval_blocked']} / 越权拒绝 {m['approval_role_denied']}

## 每租户

| tenant | runs_total | done | active | evidence_bytes |
|---|---:|---:|---:|---:|
{rows}

## Checks
{checks}
"""
    path.write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenants", type=int, default=8)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--requests", type=int, default=20)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--work-ms", type=int, default=30)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    doc = run_load(tenants=args.tenants, concurrency=args.concurrency,
                   requests=args.requests, workers=args.workers,
                   work_ms=args.work_ms, out=args.out)
    print(json.dumps(doc["metrics"], ensure_ascii=False, indent=2))
    print(json.dumps(doc["checks"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
