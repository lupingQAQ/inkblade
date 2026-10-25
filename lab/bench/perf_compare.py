"""性能扫掠器：端点全量延迟 / 并发吞吐 / 统计分布。

用法：
  python -m lab.bench.perf-compare --routes reports/samples/perf/grid/routes-artex.json \
      --base http://127.0.0.1:18787 --token <session> --n 10 --out reports/samples/perf/grid/live-artex.json
离线模式（不发请求）：--offline 仅校验路由清单并输出统计骨架。

测量口径：GET 路由逐端点 N 次 → min/median/p95/p99/max/mean/stdev；并发 1/4/16 对首个只读端点
测吞吐与错误率。所有结果附 measured_at 与 base，未测项必须由调用方标 N/A，不得编造。
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def stats(samples: list[float]) -> dict:
    if not samples:
        return {}
    s = sorted(samples)
    def pct(p):
        idx = min(len(s) - 1, max(0, int(round((len(s) - 1) * p))))
        return s[idx]
    return {
        "n": len(s),
        "min_ms": round(s[0], 3),
        "median_ms": round(statistics.median(s), 3),
        "p95_ms": round(pct(0.95), 3),
        "p99_ms": round(pct(0.99), 3),
        "max_ms": round(s[-1], 3),
        "mean_ms": round(statistics.fmean(s), 3),
        "stdev_ms": round(statistics.pstdev(s), 3) if len(s) > 1 else 0.0,
    }


def _one(url: str, token: str | None, timeout: float) -> tuple[bool, float]:
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(1024)
        return True, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError:
        # 4xx/5xx 也计入可达性（延迟有效），错误率另计
        return False, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000


def measure_endpoint(base: str, route: dict, token: str | None, n: int, timeout: float = 5.0) -> dict:
    path = route.get("path") or route.get("id", "")
    if not path.startswith("/"):
        return {"route": route.get("id"), "skipped": "non-http-route"}
    if (route.get("method") or "GET").upper() != "GET":
        return {"route": route.get("id"), "skipped": "mutating-method"}
    samples, ok = [], 0
    for _ in range(n):
        good, ms = _one(base + path, token, timeout)
        samples.append(ms)
        ok += int(good)
    out = {"route": route.get("id"), "path": path, "ok_rate": round(ok / n, 3)}
    out.update(stats(samples))
    return out


def concurrency_sweep(base: str, path: str, token: str | None, levels: list[int],
                      per_level: int = 50, timeout: float = 5.0) -> list[dict]:
    rows = []
    for level in levels:
        t0 = time.perf_counter()
        errors = 0
        def task(_):
            nonlocal errors
            good, _ms = _one(base + path, token, timeout)
            if not good:
                errors += 1
        with ThreadPoolExecutor(max_workers=level) as ex:
            list(ex.map(task, range(per_level)))
        dt = time.perf_counter() - t0
        rows.append({
            "concurrency": level, "requests": per_level,
            "throughput_rps": round(per_level / dt, 2) if dt else None,
            "error_rate": round(errors / per_level, 3),
        })
    return rows


def load_routes(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    for key in ("endpoints", "routes", "rows", "items"):
        if isinstance(data.get(key), list):
            return data[key]
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--routes", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--token", default=None)
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--levels", default="1,4,16")
    ap.add_argument("--out", required=True)
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args(argv)

    routes = load_routes(Path(args.routes))
    result = {
        "routes_file": args.routes, "route_count": len(routes),
        "base": args.base or None, "n": args.n,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "offline" if args.offline or not args.base else "live",
    }
    if result["mode"] == "offline":
        result["endpoints"] = [{"route": r.get("id"), "skipped": "offline"} for r in routes]
        result["concurrency"] = []
    else:
        result["endpoints"] = [measure_endpoint(args.base, r, args.token, args.n) for r in routes]
        read_routes = [r for r in routes if (r.get("method") or "GET").upper() == "GET" and str(r.get("path", "")).startswith("/")]
        if read_routes:
            levels = [int(x) for x in args.levels.split(",") if x]
            result["concurrency"] = concurrency_sweep(args.base, read_routes[0]["path"], args.token, levels)
        else:
            result["concurrency"] = []

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    measured = [e for e in result["endpoints"] if "median_ms" in e]
    print(f"perf: {result['mode']} routes={len(routes)} measured={len(measured)} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
