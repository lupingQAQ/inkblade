"""混沌运行时：目标引导（本地仿真靶场）+ FaultProxy + DNS shim + 探测/动作执行。

一切注入只发生在本地：

- ``fabric-dos`` / ``fabric-sim`` / ``longctx`` / ``mock``：按需进程内拉起
  ``lab/`` 下的仿真服务（vulnerable 态），端口随机、仅 127.0.0.1；
- ``FaultProxy``：客户端可配置的故障代理（延迟/丢包/分区），probe 流量经它
  转发到上游靶场 —— 等效 Chaos Mesh NetworkChaos 的 tc/netem 语义，但不碰
  操作系统网络栈；
- ``DnsShim``：``*.chaos.test`` 域名的客户端解析层仿真（DNS 故障注入）。
"""

from __future__ import annotations

import importlib.util
import json
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .catalog import Action, ChaosExperiment, Probe

DEFAULT_TIMEOUT_S = 5.0
DNS_SUFFIX = ".chaos.test"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- 目标


@dataclass
class TargetHandle:
    name: str
    base_url: str
    shutdown: Any = None  # callable | None（自启的仿真服务由编排器统一关停）


class _SimLoader:
    """进程内加载 lab 仿真模块（与 onboarding._load_mock_module 同构）。"""

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    def load(self, rel: str) -> Any:
        if rel in self._cache:
            return self._cache[rel]
        path = repo_root() / rel
        if not path.is_file():
            raise FileNotFoundError(f"找不到仿真靶场源码：{path}（需在完整仓库内运行）")
        spec = importlib.util.spec_from_file_location("inkblade_chaos_" + path.stem, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"无法加载仿真靶场：{path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self._cache[rel] = mod
        return mod


_SIMS = _SimLoader()


def _start_fabric_dos() -> TargetHandle:
    mod = _SIMS.load("lab/fabric_dos_sim.py")
    server = mod.start_all(port=0, mode="vulnerable")
    return TargetHandle("fabric-dos", f"http://127.0.0.1:{server.port}", server.shutdown)


def _start_longctx() -> TargetHandle:
    mod = _SIMS.load("lab/longctx_sim.py")
    server = mod.start_all(port=0, mode="vulnerable")
    return TargetHandle("longctx", f"http://127.0.0.1:{server.port}", server.shutdown)


def _start_mock() -> TargetHandle:
    mod = _SIMS.load("lab/mock_targets.py")
    server = mod.start_all(port=0, mode="vulnerable")
    return TargetHandle("mock", f"http://127.0.0.1:{server.port}", server.shutdown)


def _start_fabric_sim() -> TargetHandle:
    root = repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from lab.fabric_sim.server import TelemetryServer  # noqa: PLC0415 —— 命名空间包延迟导入
    from lab.fabric_sim.sim import simulate  # noqa: PLC0415
    from lab.fabric_sim.topology import Topology  # noqa: PLC0415

    telemetry = simulate(Topology.build(64), "baseline", seed=7)
    ts = TelemetryServer(telemetry, host="127.0.0.1", port=0)
    ts.start()
    return TargetHandle("fabric-sim", ts.url, ts.stop)


_STARTERS = {
    "fabric-dos": _start_fabric_dos,
    "fabric-sim": _start_fabric_sim,
    "longctx": _start_longctx,
    "mock": _start_mock,
}


class TargetRegistry:
    """逻辑目标名 → base URL；可外部注入（--target）或按需自启本地仿真。"""

    def __init__(self, overrides: dict[str, str] | None = None, *, auto_start: bool = True):
        self._handles: dict[str, TargetHandle] = {}
        self._proxies: dict[str, "FaultProxy"] = {}
        for name, url in (overrides or {}).items():
            self._handles[name] = TargetHandle(name, url.rstrip("/"), None)
        self._auto_start = auto_start

    def get(self, name: str) -> TargetHandle:
        if name not in self._handles:
            if not self._auto_start:
                raise KeyError(f"目标未注册且禁用自启: {name}")
            starter = _STARTERS.get(name)
            if starter is None:
                raise KeyError(f"未知目标: {name}（可用: {', '.join(sorted(_STARTERS))}）")
            self._handles[name] = starter()
        return self._handles[name]

    def proxy_for(self, name: str) -> "FaultProxy":
        if name not in self._proxies:
            upstream = self.get(name)
            proxy = FaultProxy(upstream.base_url)
            proxy.start()
            self._proxies[name] = proxy
        return self._proxies[name]

    def shutdown_all(self) -> None:
        for proxy in self._proxies.values():
            proxy.stop()
        self._proxies.clear()
        for handle in self._handles.values():
            if handle.shutdown is not None:
                try:
                    handle.shutdown()
                except Exception:  # noqa: BLE001 —— 关停尽力而为
                    pass
        self._handles.clear()


# --------------------------------------------------------------------------- FaultProxy


@dataclass
class FaultProfile:
    delay_ms: int = 0
    drop_rate: float = 0.0
    block_groups: tuple[str, ...] = ()
    seed: int = 7

    def apply(self, faults: dict[str, Any]) -> None:
        if "delay_ms" in faults:
            self.delay_ms = int(faults["delay_ms"])
        if "drop_rate" in faults:
            self.drop_rate = float(faults["drop_rate"])
        if "block_groups" in faults:
            self.block_groups = tuple(faults["block_groups"] or ())
        if "seed" in faults:
            self.seed = int(faults["seed"])
            self._rng = random.Random(self.seed)

    def snapshot(self) -> dict:
        return {"delay_ms": self.delay_ms, "drop_rate": self.drop_rate,
                "block_groups": list(self.block_groups), "seed": self.seed}

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeFaultProxy/1.0"
    proxy: "FaultProxy" = None  # type: ignore[assignment]

    def log_message(self, *args):  # 静默
        return

    def _control(self) -> bool:
        if self.path == "/__chaos__":
            body = self.proxy._read_body(self) if self.command == "POST" else {}
            if body:
                self.proxy.profile.apply(body)
            self._reply(200, {"service": "inkblade-fault-proxy",
                              "profile": self.proxy.profile.snapshot()})
            return True
        return False

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _reply(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, method: str) -> None:
        prof = self.proxy.profile
        group = self.headers.get("X-Chaos-Group", "default")
        if prof.block_groups and group in prof.block_groups:
            # 分区：直接掐断（不转发），返回 503 并关闭连接
            self._reply(503, {"chaos_fault": "partition", "group": group})
            self.close_connection = True
            return
        if prof.drop_rate > 0 and prof._rng.random() < prof.drop_rate:
            # 丢包/断连：不发任何响应直接断开（客户端看到连接层错误）
            self.close_connection = True
            try:
                self.connection.close()
            except Exception:  # noqa: BLE001
                pass
            return
        if prof.delay_ms > 0:
            time.sleep(prof.delay_ms / 1000.0)
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
        url = self.proxy.upstream + self.path
        req = urllib.request.Request(url, data=body, method=method)
        for key in ("Content-Type", "X-Chaos-Group", "X-Tenant", "X-Job-Token",
                    "Authorization"):
            if self.headers.get(key):
                req.add_header(key, self.headers[key])
        try:
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_S) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                ctype = resp.headers.get("Content-Type", "application/json")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception:  # noqa: BLE001 —— 上游不可达
            self._reply(502, {"chaos_fault": "upstream-unreachable",
                              "upstream": self.proxy.upstream})

    def do_GET(self):  # noqa: N802 —— http.server 约定
        if not self._control():
            self._forward("GET")

    def do_POST(self):  # noqa: N802
        if not self._control():
            self._forward("POST")


class FaultProxy:
    """可配置故障代理：probe 流量经此转发到上游（延迟/丢包/分区）。"""

    def __init__(self, upstream: str, profile: FaultProfile | None = None):
        self.upstream = upstream.rstrip("/")
        self.profile = profile or FaultProfile()
        handler = type("BoundProxyHandler", (_ProxyHandler,), {"proxy": self})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def start(self) -> "FaultProxy":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


# --------------------------------------------------------------------------- DNS shim


@dataclass
class DnsShim:
    """*.chaos.test 的客户端解析层仿真：fail=true 时解析失败。"""

    fail_hosts: set[str] = field(default_factory=set)

    def resolve(self, host: str) -> str:
        if host in self.fail_hosts:
            raise ConnectionError(f"dns_failure: {host} 解析失败（DNS 故障注入中）")
        return "127.0.0.1"

    def set_fail(self, host: str, fail: bool) -> None:
        if fail:
            self.fail_hosts.add(host)
        else:
            self.fail_hosts.discard(host)


# --------------------------------------------------------------------------- HTTP 探测


@dataclass
class Sample:
    status: int = 0
    body: dict | None = None
    latency_ms: float = 0.0
    error: str = ""


def _dotted(doc: Any, path: str) -> Any:
    cur = doc
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
                continue
            except (ValueError, IndexError):
                raise KeyError(f"提取路径失败: {path}（列表索引 {part}）") from None
        if not isinstance(cur, dict) or part not in cur:
            raise KeyError(f"提取路径失败: {path}")
        cur = cur[part]
    return cur


def _coerce(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    raise KeyError(f"值不是数值: {value!r}")


_OPS = {
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
    "eq": lambda a, b: abs(a - b) < 1e-9,
    "ne": lambda a, b: abs(a - b) >= 1e-9,
}


def http_json(base_url: str, path: str, method: str = "GET", body: dict | None = None,
              headers: dict[str, str] | None = None, host: str | None = None,
              timeout: float = DEFAULT_TIMEOUT_S) -> Sample:
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if host:
        req.add_header("Host", host)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            latency = (time.perf_counter() - started) * 1000
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else {}
            except ValueError:
                parsed = None
            return Sample(resp.status, parsed if isinstance(parsed, dict) else {}, latency, "")
    except Exception as exc:  # noqa: BLE001 —— 探测失败是数据，不是异常
        latency = (time.perf_counter() - started) * 1000
        return Sample(0, None, latency, f"{type(exc).__name__}: {exc}")


def eval_probe(probe: Probe, *, targets: TargetRegistry, default_target: str,
               via_proxy: bool, dns: DnsShim) -> dict:
    """执行探测并判定；返回 {name, ok, value, op, threshold, detail, samples}。"""
    tname = probe.target or default_target
    base = targets.proxy_for(tname).url if via_proxy else targets.get(tname).base_url
    try:
        if probe.host and probe.host.endswith(DNS_SUFFIX):
            dns.resolve(probe.host)  # 故障态在此抛出 → 记为失败样本
        samples = [http_json(base, probe.path, probe.method, probe.body,
                             probe.headers, probe.host) for _ in range(max(1, probe.samples))]
    except ConnectionError as exc:  # DNS 故障：整组样本失败
        samples = [Sample(0, None, 0.0, str(exc))] * max(1, probe.samples)
    value, ok, detail = _judge(probe, samples)
    return {"name": probe.name, "ok": ok, "value": value, "op": probe.op,
            "threshold": probe.value, "detail": detail, "samples": len(samples)}


def _judge(probe: Probe, samples: list[Sample]) -> tuple[float, bool, str]:
    extract = probe.extract
    errors = [s.error for s in samples if s.error]
    if extract == "status":
        last = samples[-1]
        value = float(last.status)
        return value, _compare(value, probe), (last.error or f"HTTP {last.status}")
    if extract == "latency_ms":
        value = sum(s.latency_ms for s in samples) / len(samples)
        return value, _compare(value, probe), f"{value:.1f}ms (mean of {len(samples)})"
    if extract in ("success_rate", "error_rate"):
        good = sum(1 for s in samples if not s.error and 200 <= s.status < 300)
        rate = good / len(samples)
        value = rate if extract == "success_rate" else 1 - rate
        return value, _compare(value, probe), f"{extract}={value:.2f} errors={len(errors)}"
    # 需要成功响应体的特殊提取器
    good = [s for s in samples if not s.error and s.body is not None and s.status < 300]
    if not good:
        return 0.0, False, f"无成功响应样本（errors={len(errors)}）"
    body = good[-1].body
    if extract == "step_ms_ratio":
        step = _coerce(_dotted(body, "step_ms"))
        base = _coerce(_dotted(body, "base_step_ms")) or 1.0
        value = step / base
        return value, _compare(value, probe), f"step_ms_ratio={value:.2f}"
    if extract == "kv_usage_ratio":
        used = _coerce(_dotted(body, "memory.kv_bytes"))
        cap = _coerce(_dotted(body, "memory.capacity_bytes")) or 1.0
        value = used / cap
        return value, _compare(value, probe), f"kv_usage_ratio={value:.4f}"
    if extract == "loss_divergence_ratio":
        after = _coerce(_dotted(body, "loss_after"))
        before = _coerce(_dotted(body, "loss_before")) or 1e-9
        value = after / before
        return value, _compare(value, probe), f"loss_divergence_ratio={value:.2f}"
    raw = _dotted(body, extract)
    value = _coerce(raw)
    return value, _compare(value, probe), f"{extract}={value}"


def _compare(value: float, probe: Probe) -> bool:
    fn = _OPS.get(probe.op)
    if fn is None:
        raise ValueError(f"未知比较算子: {probe.op}（可用: {', '.join(sorted(_OPS))}）")
    return fn(value, float(probe.value))


def _iter_body(body: dict | None, index: int) -> dict | None:
    """repeat 时把 body 中的 {i} 占位替换为轮次索引（churn 类注入用）。"""
    if body is None:
        return None
    out = {}
    for key, value in body.items():
        if isinstance(value, str) and "{i}" in value:
            out[key] = value.replace("{i}", str(index))
        else:
            out[key] = value
    return out


def apply_action(action: Action, *, targets: TargetRegistry, experiment: ChaosExperiment,
                 dns: DnsShim) -> dict:
    """执行注入/回滚动作，返回动作记录（含每轮响应摘要）。"""
    record: dict[str, Any] = {"kind": action.kind, "detail": ""}
    if action.kind == "noop":
        record["detail"] = "无需回滚动作（无状态指标）"
        return record
    if action.kind == "proxy":
        proxy = targets.proxy_for(experiment.target)
        proxy.profile.apply(action.faults or {})
        record["detail"] = f"fault profile → {proxy.profile.snapshot()}"
        return record
    if action.kind == "dns":
        dns.set_fail(action.host, action.fail)
        record["detail"] = f"dns {action.host} fail={action.fail}"
        return record
    if action.kind == "admin-reset":
        base = targets.get(action.target or experiment.target).base_url
        sample = http_json(base, "/admin/reset", "POST",
                           {"keys": list(action.keys or ["all"])})
        record["detail"] = f"admin/reset keys={list(action.keys)} → HTTP {sample.status}"
        record["status"] = sample.status
        if sample.error or sample.status != 200:
            record["error"] = sample.error or f"HTTP {sample.status}"
        return record
    if action.kind == "http":
        base = (targets.proxy_for(action.target or experiment.target).url
                if experiment.via_proxy else targets.get(action.target or experiment.target).base_url)
        results = []
        for i in range(max(1, action.repeat)):
            sample = http_json(base, action.path, action.method, _iter_body(action.body, i),
                               action.headers)
            results.append({"i": i, "status": sample.status, "error": sample.error})
        record["detail"] = (f"{action.method} {action.path} ×{len(results)} → "
                            f"last HTTP {results[-1]['status']}")
        record["repeat_results"] = results
        if all(r["error"] or r["status"] >= 500 for r in results):
            record["error"] = results[-1]["error"] or f"HTTP {results[-1]['status']}"
        return record
    raise ValueError(f"未知动作类型: {action.kind}")
