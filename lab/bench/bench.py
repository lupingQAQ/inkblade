"""lab/bench/bench.py — Trident bench 冒烟（spec 第 11 节对标 ARTEX / 第 13 节实验室）。

smoke 模式：对 lab mock 靶场（lab/mock_targets.py start_all，vulnerable 姿态）跑一条
最小链探测计时 + 内存采样 + 请求数统计。

路径选择（记录 Ruling）：
1. 链路径（优先）：trident/core/chains.load_chains 选一条「只读链」——全部步骤引用的
   模块已在 trident/modules 就绪（writes=false、非私有零日），用 chains.execute 计时；
2. 兜底路径：链模块未就绪（当前侦察/横向利用模块族尚未落地）时，urllib 直探
   5 条只读路由（ROUTE_TABLE writes=false，覆盖侦察发现/观测面/插件面/中继面/管理面）。

内存采样：psutil 不可用（运行时仅标准库）→ Windows 用 ctypes GetProcessMemoryInfo
（WorkingSet 采样 + PeakWorkingSetSize），POSIX 用 resource.getrusage(RUSAGE_SELF).ru_maxrss。

输出：JSON + Markdown（elapsed_ms / max_rss_kb / peak_rss_kb / requests / mode / ruling）。
命令行（仓库根目录）：
    python lab/bench/bench.py smoke [--iterations N] [--mode vulnerable|fixed] [--json P] [--md P]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import platform
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.mock_targets import start_all  # noqa: E402

CHAINS_DIR = REPO_ROOT / "trident" / "chains"
MODULES_DIR = REPO_ROOT / "trident" / "modules"
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "out"

# 兜底五路由：全部取自 lab/mock_targets.ROUTE_TABLE 且 writes=false（对靶场零写入），
# 覆盖一条最小链的等价探测面：侦察发现 → 观测面 → 插件面 → 开放代理面 → 管理面。
FALLBACK_ROUTES = [
    {"method": "GET", "path": "/__routes__", "title": "路由清单（侦察发现）", "expect": 200},
    {"method": "GET", "path": "/api/jobs/", "title": "Ray dashboard 作业列表（观测面）", "expect": 200},
    {"method": "GET", "path": "/plugins/list", "title": "vLLM 插件清单（插件面）", "expect": 200},
    {"method": "GET", "path": "/v1/models", "title": "djev 模型中继（开放代理面）", "expect": 200},
    {"method": "POST", "path": "/pause", "title": "SGLang 管理面暂停（fail-open 探测）", "expect": 200},
]

HTTP_TIMEOUT_S = 5.0


# ---------------------------------------------------------------- 内存采样


class _WinMem:
    """Windows：ctypes + psapi GetProcessMemoryInfo（psutil 不可用的降级实现）。"""

    def __init__(self):
        import ctypes.wintypes as wt

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wt.DWORD),
                ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        self._pmc = PMC()
        self._pmc.cb = ctypes.sizeof(PMC)
        self._psapi = ctypes.WinDLL("psapi")
        self._psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(PMC), wt.DWORD]
        self._psapi.GetProcessMemoryInfo.restype = wt.BOOL
        self._kernel32 = ctypes.WinDLL("kernel32")
        self._kernel32.GetCurrentProcess.restype = wt.HANDLE
        self._proc = self._kernel32.GetCurrentProcess()

    def sample(self) -> tuple[int, int] | None:
        """返回 (当前工作集 KB, 峰值工作集 KB)；失败返回 None。"""
        if not self._psapi.GetProcessMemoryInfo(self._proc, ctypes.byref(self._pmc), self._pmc.cb):
            return None
        return int(self._pmc.WorkingSetSize) // 1024, int(self._pmc.PeakWorkingSetSize) // 1024


class _PosixMem:
    """POSIX：resource.getrusage(RUSAGE_SELF).ru_maxrss（Linux 单位 KiB）。"""

    def __init__(self):
        import resource

        self._resource = resource

    def sample(self) -> tuple[int, int] | None:
        kb = int(self._resource.getrusage(self._resource.RUSAGE_SELF).ru_maxrss)
        return kb, kb  # ru_maxrss 本身即生命周期峰值（单调）


class MemorySampler:
    """后台线程按固定间隔采样本进程 RSS（KB），记录观测最大值与峰值。"""

    def __init__(self, interval_s: float = 0.02):
        self._interval = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.max_rss_kb = 0
        self.peak_rss_kb = 0
        self.backend = "unavailable"
        self._impl = None
        if platform.system() == "Windows":
            try:
                self._impl = _WinMem()
                self.backend = "ctypes-GetProcessMemoryInfo"
            except Exception:
                self._impl = None
        else:
            try:
                self._impl = _PosixMem()
                self.backend = "resource-ru_maxrss"
            except Exception:
                self._impl = None

    def _update(self) -> None:
        if self._impl is None:
            return
        try:
            got = self._impl.sample()
        except Exception:
            return
        if not got:
            return
        current_kb, peak_kb = got
        self.max_rss_kb = max(self.max_rss_kb, current_kb)
        self.peak_rss_kb = max(self.peak_rss_kb, peak_kb)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self._update()

    def start(self) -> None:
        self._update()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._update()


# ---------------------------------------------------------------- 链路径选择


def select_readonly_chain(chains_dir: Path | str = CHAINS_DIR,
                          modules_dir: Path | str = MODULES_DIR) -> tuple[dict | None, str]:
    """选一条最小只读链：步骤引用模块全部就绪且 writes=false、非私有零日。

    返回 (chain, ruling_reason)；chain=None 时 reason 说明兜底原因（含最近候选及其缺失模块键）。
    """
    chains_dir = Path(chains_dir)
    modules_dir = Path(modules_dir)
    try:
        from trident.core.chains import load_chains

        chains = load_chains(chains_dir)
    except Exception as exc:  # 链目录未就绪/校验失败都不应阻断 bench
        return None, f"链目录加载失败（{type(exc).__name__}: {exc}），降级 urllib 五路由直探计时"
    if not chains:
        return None, "链目录为空，降级 urllib 五路由直探计时"

    registry_note = ""
    mods: dict = {}
    try:
        from trident.core.registry import load_modules

        mods = load_modules(modules_dir)
    except Exception as exc:
        registry_note = f"（模块注册表不可用: {type(exc).__name__}: {exc}）"

    def _order(chain: dict):
        return (
            len(chain.get("steps") or []),
            0 if chain.get("category") == "经典攻击链" else 1,  # 先经典链，零日链殿后
            chain["id"],
        )

    candidates = sorted(
        (c for c in chains.values()
         if c.get("steps") and not any(st.get("writes") for st in c["steps"])),
        key=_order,
    )
    first_missing: tuple[dict, list[str]] | None = None
    for chain in candidates:
        keys = sorted({st["module"] for st in chain["steps"]})
        missing = [k for k in keys if k not in mods]
        if missing:
            if first_missing is None:
                first_missing = (chain, missing)
            continue
        if all(not mods[k].writes and not mods[k].private for k in keys):
            return chain, f"选中只读链 {chain['id']}（{len(keys)} 个模块全就绪，链路径计时）"
    if first_missing is not None:
        chain, missing = first_missing
        return None, (f"最近只读链 {chain['id']} 模块未就绪（缺 {', '.join(missing)}）{registry_note}，"
                      f"降级 urllib 五路由直探计时")
    return None, f"链目录无只读链候选（{len(chains)} 条均含写步骤或空步骤）{registry_note}，降级 urllib 五路由直探计时"


def _run_chain_probe(server, chain: dict, iterations: int) -> tuple[float, int]:
    """链路径计时：搭最小基建（证据库/用户/ROE 主动探测级）后执行 chains.execute。"""
    from tempfile import TemporaryDirectory

    from trident.core.chains import execute
    from trident.core.evidence import EvidenceStore
    from trident.core.roe import init_roe
    from trident.core.users import UserStore

    base = server.url("/")
    steps_done = 0
    with TemporaryDirectory(prefix="trident-bench-") as tmp:
        root = Path(tmp)
        store = EvidenceStore(root, workspace="local-lab")
        users = UserStore(root / "users.json")
        users.create_user("bench", "x", "tester", ["local-lab"])
        session = users.verify("bench", "x")
        init_roe(store, fields={"level": "主动探测",
                                "namespaces": ["trident-lab"], "cidrs": ["127.0.0.0/8"]})
        t0 = time.perf_counter()
        for i in range(iterations):
            snapshot = json.loads(json.dumps(chain))  # 深拷贝后注入靶场地址
            for st in snapshot["steps"]:
                params = dict(st.get("params") or {})
                params.setdefault("base_url", base)
                params.setdefault("target", base)
                st["params"] = params
            outcome = execute(snapshot, store, session, str(MODULES_DIR), findings=[])
            if not outcome.get("ok"):
                # 步骤失败（如模块要求 fixture 参数）= 该链对 HTTP 靶场未就绪，交由兜底
                failed = {sid: res.get("error", res.get("status"))
                          for sid, res in (outcome.get("steps") or {}).items()
                          if res.get("status") != "success"}
                raise RuntimeError(f"链 {chain['id']} 第 {i + 1} 轮步骤失败: {failed}")
            steps_done += len(outcome.get("steps") or {})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return elapsed_ms, steps_done


# ---------------------------------------------------------------- 兜底直探


def _http_probe(base_url: str, route: dict, timeout_s: float = HTTP_TIMEOUT_S) -> tuple[int, float]:
    """单次探测：返回 (HTTP 状态码, 耗时 ms)。4xx/5xx 也算「已到达并计时」。"""
    url = base_url.rstrip("/") + route["path"]
    data = json.dumps({}).encode("utf-8") if route["method"] == "POST" else None
    req = urllib.request.Request(
        url, data=data, method=route["method"],
        headers={"Content-Type": "application/json"} if data else {},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = int(resp.status)
            resp.read()
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.read()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return status, elapsed_ms


def _run_fallback_probe(server, iterations: int) -> tuple[float, int, list[dict]]:
    acc = {rt["path"]: {"ms": [], "status": set()} for rt in FALLBACK_ROUTES}
    t0 = time.perf_counter()
    for _ in range(iterations):
        for route in FALLBACK_ROUTES:
            status, ms = _http_probe(server.url("/"), route)
            acc[route["path"]]["ms"].append(ms)
            acc[route["path"]]["status"].add(status)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    routes_out = []
    for route in FALLBACK_ROUTES:
        samples = acc[route["path"]]["ms"]
        statuses = sorted(acc[route["path"]]["status"])
        routes_out.append({
            **{k: route[k] for k in ("method", "path", "title", "expect")},
            "status": statuses[0] if len(statuses) == 1 else statuses,
            "expect_ok": all(s == route["expect"] for s in statuses),
            "avg_ms": round(sum(samples) / len(samples), 3),
            "min_ms": round(min(samples), 3),
            "max_ms": round(max(samples), 3),
            "n": len(samples),
        })
    return elapsed_ms, iterations * len(FALLBACK_ROUTES), routes_out


# ---------------------------------------------------------------- smoke 主流程


def run_smoke(iterations: int = 5, mode: str = "vulnerable",
              chains_dir: Path | str = CHAINS_DIR, modules_dir: Path | str = MODULES_DIR) -> dict:
    """冒烟一轮：链优先、urllib 兜底，返回可 JSON 化的结果字典。"""
    if iterations < 1:
        raise ValueError("iterations 须 >= 1")
    chain, ruling = select_readonly_chain(chains_dir, modules_dir)
    sampler = MemorySampler()
    sampler.start()
    routes_out: list[dict] = []
    requests_done = 0
    used_mode = "fallback-urllib"
    chain_id: str | None = None
    with start_all(mode=mode) as server:
        base = server.url("/")
        if chain is not None:
            try:
                elapsed_ms, requests_done = _run_chain_probe(server, chain, iterations)
                used_mode = "chain"
                chain_id = chain["id"]
            except Exception as exc:
                ruling = (f"{ruling}；链执行失败（{type(exc).__name__}: {exc}）→ urllib 五路由兜底")
                chain = None
        if chain is None:
            used_mode = "fallback-urllib"
            elapsed_ms, requests_done, routes_out = _run_fallback_probe(server, iterations)
    sampler.stop()
    return {
        "bench": "trident-smoke",
        "mode": used_mode,
        "chain": chain_id,
        "ruling": ruling,
        "iterations": iterations,
        "elapsed_ms": round(elapsed_ms, 3),
        "elapsed_ms_per_sweep": round(elapsed_ms / iterations, 3),
        "max_rss_kb": int(max(sampler.max_rss_kb, sampler.peak_rss_kb)),
        "peak_rss_kb": int(sampler.peak_rss_kb),
        "memory_backend": sampler.backend,
        "requests": int(requests_done),
        "requests_source": "chain-steps" if used_mode == "chain" else "http-probes",
        "routes": routes_out,
        "target": {"url": base, "mode": mode},
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


def _render_md(r: dict) -> str:
    lines = [
        "# Trident bench 冒烟结果（smoke）",
        "",
        f"- 模式: **{r['mode']}**" + (f"（链 `{r['chain']}`）" if r["chain"] else "（urllib 五路由兜底）"),
        f"- Ruling: {r['ruling']}",
        f"- 迭代: {r['iterations']}",
        f"- elapsed_ms（总 / 每轮）: {r['elapsed_ms']} / {r['elapsed_ms_per_sweep']}",
        f"- max_rss_kb: {r['max_rss_kb']}（peak_rss_kb {r['peak_rss_kb']}，采样后端 {r['memory_backend']}）",
        f"- requests: {r['requests']}（来源 {r['requests_source']}）",
        f"- 靶场: {r['target']['url']}（mode={r['target']['mode']}）",
        f"- 环境: {r['environment']['platform']} / Python {r['environment']['python']} / {r['environment']['timestamp_utc']}",
        "",
    ]
    if r["routes"]:
        lines += [
            "| 路由 | 方法 | 状态 | 预期 | avg_ms | min_ms | max_ms | n |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for rt in r["routes"]:
            lines.append(
                f"| {rt['path']} | {rt['method']} | {rt['status']} | {rt['expect']}"
                f" | {rt['avg_ms']} | {rt['min_ms']} | {rt['max_ms']} | {rt['n']} |"
            )
    lines += [
        "",
        "说明：ARTEX 同靶场对比方法与 Windows 冒烟初值见本目录 `BENCH-RESULT.md`。",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(prog="bench.py", description="Trident bench（对标 ARTEX，仅标准库）")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_smoke = sub.add_parser("smoke", help="mock 靶场最小链冒烟计时（链优先，urllib 兜底并记录 Ruling）")
    p_smoke.add_argument("--iterations", type=int, default=5, help="探测轮数（默认 5）")
    p_smoke.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable",
                         help="mock 靶场姿态（默认 vulnerable）")
    p_smoke.add_argument("--json", default=str(DEFAULT_OUT_DIR / "bench-smoke.json"), help="JSON 输出路径")
    p_smoke.add_argument("--md", default=str(DEFAULT_OUT_DIR / "bench-smoke.md"), help="Markdown 输出路径")
    args = parser.parse_args(argv)

    result = run_smoke(iterations=args.iterations, mode=args.mode)
    json_path = Path(args.json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path = Path(args.md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(_render_md(result), encoding="utf-8")

    print(f"bench smoke: mode={result['mode']} elapsed_ms={result['elapsed_ms']} "
          f"elapsed_ms_per_sweep={result['elapsed_ms_per_sweep']} "
          f"max_rss_kb={result['max_rss_kb']} requests={result['requests']}")
    print(f"Ruling: {result['ruling']}")
    print(f"JSON -> {json_path}")
    print(f"MD   -> {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
