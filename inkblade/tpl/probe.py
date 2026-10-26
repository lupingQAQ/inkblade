# -*- coding: utf-8 -*-
"""Host-side orchestration for declarative probe templates.

The host never executes module logic.  It resolves one probe transport and sends
the template plus parameters to the Rust probe, which evaluates every operation
natively inside the target Pod.  When no probe transport is available the call
fails with :class:`ProbeUnavailable`; there is deliberately no host fallback.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

PROTOCOL = "inkblade-probe/1"
RESULT_SCHEMA = "inkblade-probe-result-v1"
MAX_TEMPLATE_BYTES = 512 * 1024


class ProbeUnavailable(RuntimeError):
    """No Rust probe could execute the template (never falls back to host)."""


class ProbeFailed(RuntimeError):
    """The probe ran but returned an error result."""

    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result or {}


class ProbeTransport(Protocol):
    runtime: str

    def run(self, template: dict, params: dict, context: dict) -> dict: ...


# --------------------------------------------------------------------------
# probe backends
# --------------------------------------------------------------------------
@dataclass
class RustProbe:
    """Executes canonical templates through the Rust probe's ``task`` op.

    ``client`` implements ``task(template, params, task_id) -> dict`` in the
    probe's native dialect (see ``probe/TEMPLATE-ENGINE.md``).  The controller
    lowers the canonical template and folds findings/artifacts from the returned
    evidence.
    """

    client: Any
    runtime: str = "rust"

    def run(self, template: dict, params: dict, context: dict) -> dict:
        from .lower import compile_template, fold_result

        compilation = compile_template(template, params, context)
        if not compilation.native_ready:
            reasons = "; ".join(f"{g['step']}: {g['reason']}" for g in compilation.gaps[:4])
            raise ProbeUnavailable(
                f"template {template.get('key')} needs probe capabilities that are not "
                f"implemented yet: {reasons}")
        task_id = f"{template.get('key')}-{int(time.time() * 1000)}"
        native = self.client.task(compilation.native_template, compilation.params, task_id)
        result = fold_result(compilation, native)
        result["native"] = compilation.as_dict()
        return validate_result(result, template)


class ReferenceRuntime:
    """Explicit conformance runtime for CI/mock range only."""

    runtime = "reference"

    def __init__(self, backend=None):
        from .backends import LocalBackend
        from .engine import ReferenceProbe

        self._probe = ReferenceProbe(backend or LocalBackend())

    def run(self, template: dict, params: dict, context: dict) -> dict:
        return self._probe.run(template, params, context)


def reference_allowed() -> bool:
    return os.environ.get("INKBLADE_ALLOW_REFERENCE_PROBE") == "1"


# --------------------------------------------------------------------------
# framed probe client (probe/src/protocol.rs + server.rs)
# --------------------------------------------------------------------------
def _frame_write(stream, value: dict) -> None:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    stream.write(len(raw).to_bytes(4, "big"))
    stream.write(raw)
    stream.flush()


def _frame_read(stream, max_frame: int = 8 * 1024 * 1024) -> dict:
    header = stream.read(4)
    if not header:
        raise ProbeFailed("probe closed the channel")
    if len(header) < 4:
        raise ProbeFailed("truncated frame header")
    length = int.from_bytes(header, "big")
    if length <= 0 or length > max_frame:
        raise ProbeFailed(f"invalid frame length {length}")
    payload = b""
    while len(payload) < length:
        chunk = stream.read(length - len(payload))
        if not chunk:
            raise ProbeFailed("truncated frame payload")
        payload += chunk
    return json.loads(payload.decode("utf-8"))


class LocalFramedClient:
    """Runs the probe binary locally (Linux CI / kind lab) and speaks frames."""

    def __init__(self, binary: str, token: str, *, timeout_ms: int = 120000):
        self.binary = binary
        self.token = token
        self.timeout_ms = timeout_ms

    def task(self, template: dict, params: dict, task_id: str) -> dict:
        import hmac
        import secrets
        import threading

        proc = subprocess.Popen(
            [self.binary, "run", "--stdio", "--token", self.token, "--allow-write"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        killer = threading.Timer(max(1.0, self.timeout_ms / 1000.0),
                                 lambda: proc.kill())
        killer.daemon = True
        killer.start()
        try:
            challenge = _frame_read(proc.stdout)
            nonce = secrets.token_hex(8)
            message = f"inkblade-probe/v1|{nonce}|{challenge.get('challenge')}"
            mac = hmac.new(self.token.encode("utf-8"), message.encode("utf-8"),
                           "sha256").hexdigest()
            _frame_write(proc.stdin, {"v": 1, "type": "auth", "nonce": nonce, "mac": mac})
            ready = _frame_read(proc.stdout)
            if ready.get("type") != "ready":
                raise ProbeFailed(f"probe handshake failed: {ready}")
            _frame_write(proc.stdin, {"v": 1, "type": "req", "id": task_id, "op": "task",
                                      "args": {"task_id": task_id, "template": template,
                                               "params": params}})
            response = _frame_read(proc.stdout)
            if response.get("type") != "resp" or response.get("id") != task_id:
                raise ProbeFailed(f"unexpected probe response: {response}")
            if not response.get("ok"):
                error = response.get("error") or {}
                raise ProbeFailed(f"{error.get('code')}: {error.get('message')}")
            return response.get("data") or {}
        finally:
            killer.cancel()
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()


class SessionFramedClient:
    """Adapts a delivered session/channel to the frame protocol."""

    def __init__(self, session):
        self.session = session

    def task(self, template: dict, params: dict, task_id: str) -> dict:
        for name in ("task", "probe_task", "request"):
            fn = getattr(self.session, name, None)
            if callable(fn):
                try:
                    value = fn("task", {"task_id": task_id, "template": template,
                                        "params": params})
                except TypeError:
                    try:
                        value = fn(template, params, task_id)
                    except TypeError:
                        continue
                if isinstance(value, dict) and value.get("ok") is False:
                    raise ProbeFailed(str(value.get("error") or "probe task failed"))
                return value.get("data", value) if isinstance(value, dict) else value
        channel = getattr(self.session, "channel", None)
        for name in ("task", "request"):
            fn = getattr(channel, name, None)
            if callable(fn):
                value = fn("task", {"task_id": task_id, "template": template,
                                    "params": params})
                return value.get("data", value) if isinstance(value, dict) else value
        raise ProbeUnavailable("session exposes no probe task transport")


# --------------------------------------------------------------------------
# result validation
# --------------------------------------------------------------------------
def validate_result(result: dict, template: dict) -> dict:
    if not isinstance(result, dict):
        raise ProbeFailed("probe result must be an object")
    if result.get("schema") != RESULT_SCHEMA:
        raise ProbeFailed(f"unexpected probe result schema: {result.get('schema')!r}")
    if result.get("key") != template.get("key"):
        raise ProbeFailed(f"probe returned result for {result.get('key')!r}, "
                          f"expected {template.get('key')!r}")
    for finding in result.get("findings") or []:
        if finding.get("sev") not in ("info", "low", "medium", "high", "critical"):
            finding["sev"] = "info"
    result.setdefault("artifacts", [])
    result.setdefault("steps", [])
    result.setdefault("status", "ok")
    return result


# --------------------------------------------------------------------------
# session adapters
# --------------------------------------------------------------------------
def _exec_callable(session) -> Any:
    """Find a usable ``exec`` entry point on a session/channel object."""
    candidates = []
    for owner in (session, getattr(session, "channel", None),
                  getattr(session, "transport", None)):
        if owner is None:
            continue
        for name in ("exec_bytes", "exec", "execute", "run_argv"):
            fn = getattr(owner, name, None)
            if callable(fn):
                candidates.append(fn)
    for fn in candidates:
        return _wrap_exec(fn)
    return None


def _wrap_exec(fn):
    def call(argv: list[str], stdin: bytes, timeout_ms: int):
        timeout = max(0.001, timeout_ms / 1000.0)
        attempts = (
            lambda: fn(argv, stdin=stdin, timeout=timeout),
            lambda: fn(argv, stdin, timeout),
            lambda: fn(argv, stdin),
            lambda: fn(argv),
        )
        last: Exception | None = None
        for attempt in attempts:
            try:
                value = attempt()
            except TypeError as exc:
                last = exc
                continue
            return _normalise_exec(value)
        raise ProbeUnavailable(f"session exec signature unsupported: {last}")

    return call


def _normalise_exec(value) -> tuple[int, str, str]:
    if value is None:
        return 0, "", ""
    if isinstance(value, tuple):
        if len(value) == 3:
            return int(value[0]), _text(value[1]), _text(value[2])
        if len(value) == 2:
            return int(value[0]), _text(value[1]), ""
    if isinstance(value, dict):
        rc = int(value.get("rc", value.get("returncode", 0)))
        return rc, _text(value.get("stdout", value.get("out", ""))), \
            _text(value.get("stderr", value.get("err", "")))
    rc = int(getattr(value, "rc", getattr(value, "returncode", 0)))
    return rc, _text(getattr(value, "stdout", "")), _text(getattr(value, "stderr", ""))


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def session_probe(session) -> ProbeTransport | None:
    """Return a probe implementation exposed by the session, if any."""
    if session is None:
        return _env_probe()
    for name in ("probe", "template_probe", "probe_backend"):
        candidate = getattr(session, name, None)
        if callable(candidate):
            try:
                candidate = candidate()
            except TypeError:
                continue
        if candidate is not None and callable(getattr(candidate, "run", None)):
            return candidate
    if any(callable(getattr(session, name, None)) for name in ("task", "probe_task", "request")):
        return RustProbe(SessionFramedClient(session))
    channel = getattr(session, "channel", None)
    if channel is not None and any(callable(getattr(channel, name, None))
                                   for name in ("task", "request")):
        return RustProbe(SessionFramedClient(session))
    return _env_probe()


def _env_probe() -> ProbeTransport | None:
    binary = os.environ.get("INKBLADE_PROBE_BIN") or ""
    token = os.environ.get("INKBLADE_PROBE_TOKEN") or ""
    if binary and token and Path(binary).is_file():
        return RustProbe(LocalFramedClient(binary, token))
    return None


def resolve_probe(session=None, explicit: ProbeTransport | None = None) -> ProbeTransport:
    if explicit is not None:
        return explicit
    probe = session_probe(session)
    if probe is not None:
        return probe
    if reference_allowed():
        return ReferenceRuntime()
    raise ProbeUnavailable(
        "no Rust probe available: start a probe session (inkblade probe session start) "
        "or set INKBLADE_ALLOW_REFERENCE_PROBE=1 for the mock range. "
        "Modules are never executed on the host."
    )


# --------------------------------------------------------------------------
# local process executor (used by the bootstrap/drop path and by tests)
# --------------------------------------------------------------------------
def local_executor(binary: str):
    def run(argv: list[str], stdin: bytes, timeout_ms: int):
        proc = subprocess.run([binary, *argv[1:]], input=stdin, capture_output=True,
                              timeout=max(0.001, timeout_ms / 1000.0))
        return proc.returncode, _text(proc.stdout), _text(proc.stderr)

    return run


def require_binary(path: str | Path) -> Path:
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise ProbeUnavailable(f"probe binary not found: {resolved}")
    return resolved


# --------------------------------------------------------------------------
# bootstrap registry: the only host-executed path, and it only drops the probe
# --------------------------------------------------------------------------
BOOTSTRAP_REGISTRY = Path(__file__).resolve().parents[1] / "probe-bootstrap.json"


def bootstrap_registry() -> dict:
    try:
        return json.loads(BOOTSTRAP_REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema": "inkblade-probe-bootstrap-v1", "modules": [], "artifacts": []}


def bootstrap_modules() -> list[dict]:
    return list(bootstrap_registry().get("modules") or [])


def is_bootstrap(module_key: str) -> bool:
    return any(entry.get("key") == module_key for entry in bootstrap_modules())


def probe_artifact(platform: str = "linux/amd64") -> dict | None:
    for artifact in bootstrap_registry().get("artifacts") or []:
        if platform in (artifact.get("platforms") or []):
            return artifact
    return None


def install_probe(session, artifact: dict | None = None, *,
                  binary: str | Path | None = None, remote: str | None = None) -> dict:
    """Drop the Rust probe into the target Pod (first foothold only).

    This is the sole bootstrap action. It uploads a static Rust binary through
    the session channel; it never uploads Python and never executes module code.
    """
    artifact = artifact or probe_artifact()
    remote = remote or (artifact or {}).get("remote_path") or "/tmp/inkblade-probe"
    if binary is None:
        if not artifact or not artifact.get("source"):
            raise ProbeUnavailable("no probe artifact registered in probe-bootstrap.json")
        binary = Path(artifact["source"])
    binary = require_binary(binary)
    data = binary.read_bytes()
    upload = None
    for name in ("upload", "put", "write_bytes"):
        fn = getattr(session, name, None)
        if callable(fn):
            upload = fn
            break
    if upload is None:
        channel = getattr(session, "channel", None)
        for name in ("upload", "put", "write_bytes"):
            fn = getattr(channel, name, None)
            if callable(fn):
                upload = fn
                break
    if upload is None:
        raise ProbeUnavailable("session has no upload primitive for the probe binary")
    try:
        upload(data, remote)
    except TypeError:
        upload(remote, data)
    executor = _exec_callable(session)
    if executor is not None:
        rc, _, err = executor(["chmod", "0755", remote], b"", 10000)
        if rc != 0:
            raise ProbeUnavailable(f"chmod failed: {err[:200]}")
    return {"schema": "inkblade-probe-install-v1", "binary": remote,
            "sha256": (artifact or {}).get("sha256") or _sha256_bytes(data),
            "bytes": len(data)}


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# mock-range helpers
# --------------------------------------------------------------------------
def run_reference(template: dict, params: dict, context: dict | None = None,
                  *, backend=None) -> dict:
    """Run a template through the conformance runtime (tests/lab only)."""
    if not reference_allowed():
        raise ProbeUnavailable(
            "reference runtime is disabled; set INKBLADE_ALLOW_REFERENCE_PROBE=1 "
            "explicitly for the mock range")
    return ReferenceRuntime(backend).run(template, params, context or {})


def result_evidence(result: dict) -> dict:
    """Compact, report-safe summary of a probe result."""
    return {
        "runtime": result.get("runtime"),
        "status": result.get("status"),
        "duration_ms": result.get("duration_ms"),
        "steps": [{k: s.get(k) for k in ("id", "op", "ok", "status", "skipped", "error") if s.get(k) is not None}
                  for s in result.get("steps") or []],
        "checks": result.get("checks") or [],
        "findings": len(result.get("findings") or []),
        "artifacts": [{"name": a.get("name"), "sha256": a.get("sha256"),
                       "bytes": a.get("bytes")} for a in result.get("artifacts") or []],
    }
