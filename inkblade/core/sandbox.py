# -*- coding: utf-8 -*-
"""工具执行沙箱：隔离子进程 + 资源限制 + 禁网开关 + 审计。

默认用于 **不可信代码**（``run_untrusted``）：禁网、无继承 site 包（``python -I``）、
墙钟超时强杀；POSIX 上额外 ``RLIMIT_AS``/``RLIMIT_CPU``（Windows 无等价能力，如实标注）。

禁网实现：子进程 bootstrap 在 exec 前 monkeypatch
``socket.socket.connect/connect_ex``、``socket.create_connection``、``socket.getaddrinfo``，
连接尝试抛 ``NetworkDisabled``（``socket.socket()`` 构造本身仍允许，便于代码自检）。

审计：每次执行产出 ``{code_sha256, untrusted, network, ok, exit_code, timed_out,
duration_ms, limits, cwd}``，由调用方落盘（evidence actions/journal）。

边界：沙箱是「降低风险」而非「证明安全」——不提供内核级隔离；注释与文档必须如实。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_CODE_BYTES = 2 * 1024 * 1024

_BOOTSTRAP = r"""
import json, os, sys, io, contextlib

def _limits():
    info = {"memory": False, "cpu": False, "backend": "none"}
    try:
        import resource
    except Exception:
        return info
    info["backend"] = "rlimit"
    mb = int(os.environ.get("TRIDENT_SANDBOX_MEM_MB", "0") or 0)
    cpu = int(os.environ.get("TRIDENT_SANDBOX_CPU", "0") or 0)
    if mb > 0:
        resource.setrlimit(resource.RLIMIT_AS, (mb * 1024 * 1024, mb * 1024 * 1024))
        info["memory"] = True
    if cpu > 0:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        info["cpu"] = True
    return info

def _block_network():
    import socket
    class NetworkDisabled(PermissionError):
        pass
    def deny(*a, **k):
        raise NetworkDisabled("NetworkDisabled: sandbox deny-network (untrusted code)")
    socket.socket.connect = deny
    socket.socket.connect_ex = deny
    socket.create_connection = deny
    socket.getaddrinfo = deny
    socket.socketpair = deny
    return NetworkDisabled

info = _limits()
network = os.environ.get("TRIDENT_SANDBOX_NETWORK", "blocked")
if network == "blocked":
    _block_network()

code = sys.stdin.read()
buf = io.StringIO()
record = {"ok": True, "stdout": "", "error": "", "limits": info, "network": network}
try:
    with contextlib.redirect_stdout(buf):
        exec(compile(code, "<sandbox>", "exec"), {"__name__": "__sandbox__", "__builtins__": __builtins__})
except BaseException as exc:
    record["ok"] = False
    record["error"] = type(exc).__name__ + ": " + str(exc)
record["stdout"] = buf.getvalue()
sys.stdout.write(json.dumps(record))
sys.stdout.flush()
"""


class SandboxError(ValueError):
    """沙箱参数非法。"""


@dataclass
class SandboxResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    network: str
    limits: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class Sandbox:
    def __init__(self, *, timeout: float = 5.0, memory_mb: int = 256,
                 allow_network: bool = False, cwd: Path | str | None = None,
                 audit=None):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise SandboxError(f"timeout 须为正数，得到 {timeout!r}")
        if not isinstance(memory_mb, int) or memory_mb < 16:
            raise SandboxError(f"memory_mb 须 ≥16，得到 {memory_mb!r}")
        self.timeout = float(timeout)
        self.memory_mb = int(memory_mb)
        self.allow_network = bool(allow_network)
        self.cwd = Path(cwd) if cwd else None
        self.audit = audit

    # ---------------------------------------------------------------- 执行
    def run_python(self, code: str, *, untrusted: bool | None = None) -> SandboxResult:
        if not isinstance(code, str) or not code.strip():
            raise SandboxError("code 为空")
        if len(code.encode("utf-8")) > MAX_CODE_BYTES:
            raise SandboxError("code 超过 2MiB 上限")
        # 显式 allow_network 是运维开关；未显式指定 untrusted 时按该开关推断
        if untrusted is None:
            untrusted = not self.allow_network
        allow_network = self.allow_network and not untrusted
        network = "allowed" if allow_network else "blocked"
        env = dict(os.environ)
        env.update({
            "TRIDENT_SANDBOX_NETWORK": network,
            "TRIDENT_SANDBOX_MEM_MB": str(self.memory_mb),
            "TRIDENT_SANDBOX_CPU": str(max(1, int(self.timeout) + 1)),
        })
        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _BOOTSTRAP],
                input=code.encode("utf-8"),
                capture_output=True,
                text=False,
                timeout=self.timeout,
                cwd=str(self.cwd) if self.cwd else None,
                env=env,
            )
            raw_out = proc.stdout.decode("utf-8", "replace")
            raw_err = proc.stderr.decode("utf-8", "replace")
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            raw_out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            raw_err = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            exit_code = 124
        duration_ms = int((time.monotonic() - started) * 1000)

        record: dict = {}
        for line in reversed([ln for ln in raw_out.splitlines() if ln.strip()]):
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if isinstance(candidate, dict) and "ok" in candidate:
                record = candidate
                break
        ok = bool(record.get("ok")) and not timed_out
        stdout = str(record.get("stdout", ""))
        stderr = str(record.get("error", "")) + ("\n" + raw_err if raw_err and not record else "")
        if not record and not timed_out:
            stderr = (raw_err or "sandbox bootstrap 无输出").strip()
        result = SandboxResult(
            ok=ok,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr.strip(),
            timed_out=timed_out,
            duration_ms=duration_ms,
            network=network,
            limits=dict(record.get("limits") or {}),
        )
        if self.audit is not None:
            self.audit({
                "ts": time.time(),
                "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
                "untrusted": bool(untrusted),
                "network": network,
                "ok": result.ok,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "duration_ms": result.duration_ms,
                "limits": result.limits,
                "cwd": str(self.cwd) if self.cwd else "",
            })
        return result

    def run_file(self, path: Path | str, *, untrusted: bool | None = None) -> SandboxResult:
        source = Path(path).read_text(encoding="utf-8")
        return self.run_python(source, untrusted=untrusted)


def run_untrusted(code: str, *, timeout: float = 5.0, memory_mb: int = 256,
                  cwd: Path | str | None = None, audit=None) -> SandboxResult:
    """不可信代码默认入口：禁网 + 超时 + 内存限制（可用时）+ 审计。"""
    sandbox = Sandbox(timeout=timeout, memory_mb=memory_mb, allow_network=False,
                      cwd=cwd, audit=audit)
    return sandbox.run_python(code, untrusted=True)
