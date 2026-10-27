# -*- coding: utf-8 -*-
"""Cross-cluster relay: multiple kubeconfigs/contexts, child probe deployment.

A relay session is a small, durable registry of clusters and probes.  It never
implements a new wire protocol: a target API is reached with the existing
probe ``dial`` stream (or a loopback SOCKS5 listener backed by that stream), and
a new probe is deployed with the operator's ``kubectl``/SA token/exec surface.
The Rust probe protocol (framed JSON, ``dial``/``exec``/``spawn``) is unchanged.

Guarantees:

* **loop prevention** — a cluster id is registered once, a
  ``(cluster_id, probe_id)`` pair is deployed once, and cluster/probe parent
  chains reject cycles;
* **per-cluster RoE and budget** — every cluster carries its own consent level
  and step/action caps; exhausting one cluster never stops another;
* **fallback** — a deployment tries the requested transport and then the
  cluster's fallback list, recording every failed attempt and the transport
  that finally succeeded;
* **coverage integration** — registered probes and baseline ``collect`` are
  written into :mod:`inkblade.agent.coverage`, so relay actions count toward
  the closure proof (or appear as explicit gaps when they fail).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import unquote, urlparse

from ..core.roe import LEVELS, allowed, roe_status
from .coverage import CoverageGraph

RELAY_SCHEMA = "inkblade-agent-relay/1"
RELAY_RELPATH = "agent/relay.json"
TRANSPORTS = ("kubectl", "sa-token", "exec")
CLUSTER_STATUSES = ("pending", "reachable", "deployed", "degraded", "failed",
                    "exhausted")
DEFAULT_ROE = LEVELS[0]
_MAX_ATTEMPTS = 40


class RelayError(ValueError):
    """Invalid relay operation."""


class RelayLoopError(RelayError):
    """A cluster/probe parent chain would loop."""


class RelayRefused(RelayError):
    """Per-cluster RoE / consent gate refused the action."""


class RelayBudgetExceeded(RelayError):
    """A per-cluster budget dimension was exhausted."""

    def __init__(self, cluster_id: str, kind: str, spent: int, limit: int):
        super().__init__(f"cluster {cluster_id} budget {kind} exceeded: "
                         f"spent={spent} limit={limit}")
        self.cluster_id = str(cluster_id)
        self.kind = str(kind)
        self.spent = int(spent)
        self.limit = int(limit)


class RelayUnreachable(RelayError):
    """No transport could reach/deploy to the target."""


class RelayTimeout(RelayError):
    """A dial/HTTP operation timed out."""


def _digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _mask(value: str) -> str:
    text = str(value or "")
    return "***" if len(text) <= 8 else f"***{text[-4:]}"


def _cluster_id(value: str) -> str:
    cid = str(value or "").strip()
    if not cid:
        raise RelayError("cluster_id 不能为空")
    if len(cid) > 96 or not all(ch.isalnum() or ch in "_.:-" for ch in cid):
        raise RelayError(f"非法 cluster_id: {value!r}")
    return cid


@dataclass
class ClusterBudget:
    """Independent hard caps for one cluster (0 = unlimited)."""

    steps: int = 0
    actions: int = 0
    spent_steps: int = 0
    spent_actions: int = 0

    def _limits(self) -> dict[str, int]:
        return {"steps": int(self.steps), "actions": int(self.actions)}

    def _spent(self) -> dict[str, int]:
        return {"steps": int(self.spent_steps), "actions": int(self.spent_actions)}

    def check(self, cluster_id: str, kind: str, amount: int = 1) -> None:
        limit = self._limits().get(kind, 0)
        spent = self._spent().get(kind, 0)
        if limit and spent + int(amount) > limit:
            raise RelayBudgetExceeded(cluster_id, kind, spent + int(amount), limit)

    def consume(self, cluster_id: str, kind: str, amount: int = 1) -> int:
        self.check(cluster_id, kind, amount)
        if kind == "steps":
            self.spent_steps += int(amount)
            return self.spent_steps
        if kind == "actions":
            self.spent_actions += int(amount)
            return self.spent_actions
        raise RelayError(f"未知预算维度: {kind!r}")

    def exhausted(self) -> bool:
        limits = self._limits()
        spent = self._spent()
        return any(limit and spent[key] >= limit for key, limit in limits.items())

    def to_dict(self) -> dict:
        return {"limits": self._limits(), "spent": self._spent(),
                "exhausted": self.exhausted()}

    @classmethod
    def from_dict(cls, doc: dict | None) -> "ClusterBudget":
        doc = doc or {}
        limits = doc.get("limits") or doc
        spent = doc.get("spent") or {}
        return cls(steps=int(limits.get("steps", 0) or 0),
                   actions=int(limits.get("actions", 0) or 0),
                   spent_steps=int(spent.get("steps", 0) or 0),
                   spent_actions=int(spent.get("actions", 0) or 0))


def _as_budget(value: Any) -> ClusterBudget:
    if isinstance(value, ClusterBudget):
        return value
    return ClusterBudget.from_dict(dict(value or {}))


@dataclass
class ClusterTarget:
    cluster_id: str
    kubeconfig: str = ""
    context: str = ""
    api_server: str = ""
    namespace: str = "default"
    parent_id: str = ""
    roe_level: str = DEFAULT_ROE
    transport: str = "kubectl"
    fallback: list[str] = field(default_factory=list)
    proxies: list[str] = field(default_factory=list)
    status: str = "pending"
    labels: dict[str, str] = field(default_factory=dict)
    insecure_tls: bool = False
    last_error: str = ""
    attempts: list[dict] = field(default_factory=list)
    budget: ClusterBudget = field(default_factory=ClusterBudget)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transports(self) -> list[str]:
        out = [self.transport] if self.transport else []
        for item in self.fallback:
            if item and item not in out:
                out.append(item)
        return out

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id, "kubeconfig": self.kubeconfig,
            "context": self.context, "api_server": self.api_server,
            "namespace": self.namespace, "parent_id": self.parent_id,
            "roe_level": self.roe_level, "transport": self.transport,
            "fallback": list(self.fallback), "proxies": list(self.proxies),
            "status": self.status, "labels": dict(self.labels),
            "insecure_tls": bool(self.insecure_tls),
            "last_error": self.last_error,
            "attempts": copy.deepcopy(self.attempts[-_MAX_ATTEMPTS:]),
            "budget": self.budget.to_dict(),
            "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "ClusterTarget":
        return cls(
            cluster_id=str(doc.get("cluster_id") or ""),
            kubeconfig=str(doc.get("kubeconfig") or ""),
            context=str(doc.get("context") or ""),
            api_server=str(doc.get("api_server") or ""),
            namespace=str(doc.get("namespace") or "default"),
            parent_id=str(doc.get("parent_id") or ""),
            roe_level=str(doc.get("roe_level") or DEFAULT_ROE),
            transport=str(doc.get("transport") or "kubectl"),
            fallback=[str(x) for x in doc.get("fallback") or []],
            proxies=[str(x) for x in doc.get("proxies") or []],
            status=str(doc.get("status") or "pending"),
            labels={str(k): str(v) for k, v in (doc.get("labels") or {}).items()},
            insecure_tls=bool(doc.get("insecure_tls", False)),
            last_error=str(doc.get("last_error") or ""),
            attempts=[copy.deepcopy(x) for x in doc.get("attempts") or []
                      if isinstance(x, dict)],
            budget=ClusterBudget.from_dict(doc.get("budget") or {}),
            created_at=float(doc.get("created_at") or time.time()),
            updated_at=float(doc.get("updated_at") or time.time()),
        )

    def summary(self) -> dict:
        return {
            "cluster_id": self.cluster_id, "kubeconfig": self.kubeconfig,
            "context": self.context, "api_server": self.api_server,
            "namespace": self.namespace, "parent_id": self.parent_id,
            "roe_level": self.roe_level, "transport": self.transport,
            "fallback": list(self.fallback), "proxies": list(self.proxies),
            "status": self.status, "last_error": self.last_error,
            "budget": self.budget.to_dict(),
        }


@dataclass
class ProbeRecord:
    cluster_id: str
    probe_id: str
    parent_id: str = ""
    parent_cluster_id: str = ""
    transport: str = ""
    status: str = "pending"
    registered: bool = False
    endpoint: str = ""
    evidence: str = ""
    baseline: dict = field(default_factory=dict)
    attempts: list[dict] = field(default_factory=list)
    last_error: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def key(self) -> tuple[str, str]:
        return (self.cluster_id, self.probe_id)

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id, "probe_id": self.probe_id,
            "parent_id": self.parent_id,
            "parent_cluster_id": self.parent_cluster_id,
            "transport": self.transport, "status": self.status,
            "registered": bool(self.registered), "endpoint": self.endpoint,
            "evidence": self.evidence, "baseline": copy.deepcopy(self.baseline),
            "attempts": copy.deepcopy(self.attempts[-_MAX_ATTEMPTS:]),
            "last_error": self.last_error, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "ProbeRecord":
        return cls(
            cluster_id=str(doc.get("cluster_id") or ""),
            probe_id=str(doc.get("probe_id") or ""),
            parent_id=str(doc.get("parent_id") or ""),
            parent_cluster_id=str(doc.get("parent_cluster_id") or ""),
            transport=str(doc.get("transport") or ""),
            status=str(doc.get("status") or "pending"),
            registered=bool(doc.get("registered", False)),
            endpoint=str(doc.get("endpoint") or ""),
            evidence=str(doc.get("evidence") or ""),
            baseline=copy.deepcopy(doc.get("baseline") or {}),
            attempts=[copy.deepcopy(x) for x in doc.get("attempts") or []
                      if isinstance(x, dict)],
            last_error=str(doc.get("last_error") or ""),
            created_at=float(doc.get("created_at") or time.time()),
            updated_at=float(doc.get("updated_at") or time.time()),
        )

    def summary(self) -> dict:
        return {
            "cluster_id": self.cluster_id, "probe_id": self.probe_id,
            "parent_id": self.parent_id,
            "parent_cluster_id": self.parent_cluster_id,
            "transport": self.transport, "status": self.status,
            "registered": bool(self.registered), "endpoint": self.endpoint,
            "baseline_ok": bool(self.baseline.get("ok")),
            "baseline_detail": str(self.baseline.get("detail") or ""),
            "last_error": self.last_error,
        }


# --------------------------------------------------------------------------
# Streams / dialers
# --------------------------------------------------------------------------
class SocketStream:
    """Thin socket adapter with the same calls as ``channel.DialStream``."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(65536)
        except socket.timeout as exc:
            raise RelayTimeout("stream read timed out") from exc

    def close_write(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class DirectDialer:
    """Dial the target directly from the controller host (loopback/lab only)."""

    name = "direct"

    def connect(self, host: str, port: int,
                timeout: float | None = None) -> SocketStream:
        try:
            sock = socket.create_connection((host, int(port)),
                                            timeout=float(timeout or 5.0))
        except OSError as exc:
            raise RelayUnreachable(f"direct dial {host}:{port} failed: {exc}") from exc
        return SocketStream(sock)


class ProbeDialer:
    """Use the existing probe ``dial`` op without changing the wire protocol."""

    name = "probe"

    def __init__(self, probe: Any):
        self.probe = probe

    def connect(self, host: str, port: int, timeout: float | None = None):
        try:
            return self.probe.dial(host, int(port),
                                   timeout_ms=int(float(timeout or 5.0) * 1000))
        except Exception as exc:  # probe-specific errors are normalized here
            raise RelayUnreachable(
                f"probe dial {host}:{port} failed: {type(exc).__name__}: {exc}"
            ) from exc


class Socks5Dialer:
    """Minimal SOCKS5 CONNECT client (no-auth and username/password)."""

    name = "socks5"

    def __init__(self, host: str, port: int = 1080, *, username: str = "",
                 password: str = ""):
        self.host = str(host)
        self.port = int(port)
        self.username = str(username or "")
        self.password = str(password or "")

    @classmethod
    def from_url(cls, url: str) -> "Socks5Dialer":
        raw = str(url or "").strip()
        parsed = urlparse(raw if "://" in raw else f"socks5://{raw}")
        if parsed.scheme not in ("socks5", "socks5h"):
            raise RelayError(f"不是 SOCKS5 代理: {url!r}")
        if not parsed.hostname:
            raise RelayError(f"SOCKS5 代理缺少主机: {url!r}")
        return cls(parsed.hostname, parsed.port or 1080,
                   username=unquote(parsed.username or ""),
                   password=unquote(parsed.password or ""))

    def connect(self, host: str, port: int,
                timeout: float | None = None) -> SocketStream:
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=float(timeout or 5.0))
            sock.settimeout(float(timeout or 5.0))
            self._handshake(sock, host, int(port))
            return SocketStream(sock)
        except RelayError:
            if sock is not None:
                sock.close()
            raise
        except OSError as exc:
            if sock is not None:
                sock.close()
            raise RelayUnreachable(
                f"socks5 {self.host}:{self.port} -> {host}:{port} failed: {exc}"
            ) from exc

    def _handshake(self, sock: socket.socket, host: str, port: int) -> None:
        methods = [0x00]
        if self.username or self.password:
            methods.append(0x02)
        sock.sendall(b"\x05" + bytes([len(methods)]) + bytes(methods))
        reply = _read_exact(sock, 2)
        if reply[0] != 0x05:
            raise RelayUnreachable("socks5: bad version")
        method = reply[1]
        if method == 0xFF:
            raise RelayUnreachable("socks5: no acceptable auth method")
        if method == 0x02:
            user = self.username.encode("utf-8")
            password = self.password.encode("utf-8")
            if len(user) > 255 or len(password) > 255:
                raise RelayError("socks5 username/password too long")
            sock.sendall(b"\x01" + bytes([len(user)]) + user +
                         bytes([len(password)]) + password)
            auth = _read_exact(sock, 2)
            if auth[1] != 0x00:
                raise RelayUnreachable("socks5: authentication failed")
        elif method != 0x00:
            raise RelayUnreachable(f"socks5: unsupported auth method {method}")
        target = _socks_addr(host, port)
        sock.sendall(b"\x05\x01\x00" + target)
        head = _read_exact(sock, 4)
        if head[0] != 0x05:
            raise RelayUnreachable("socks5: bad connect reply")
        if head[1] != 0x00:
            raise RelayUnreachable(f"socks5: connect rejected (code {head[1]})")
        atyp = head[3]
        if atyp == 0x01:
            _read_exact(sock, 4)
        elif atyp == 0x03:
            length = _read_exact(sock, 1)[0]
            _read_exact(sock, length)
        elif atyp == 0x04:
            _read_exact(sock, 16)
        else:
            raise RelayUnreachable(f"socks5: bad address type {atyp}")
        _read_exact(sock, 2)


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = int(count)
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RelayUnreachable("socks5: connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socks_addr(host: str, port: int) -> bytes:
    raw = str(host or "")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        encoded = raw.encode("idna") if raw else b""
        if not encoded or len(encoded) > 255:
            raise RelayError(f"非法 SOCKS5 目标主机: {host!r}")
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack(">H", int(port))
    if isinstance(address, ipaddress.IPv4Address):
        return b"\x01" + address.packed + struct.pack(">H", int(port))
    return b"\x04" + address.packed + struct.pack(">H", int(port))


def stream_http_get(stream: Any, host: str, path: str = "/version", *,
                    timeout: float = 5.0, max_bytes: int = 1024 * 1024,
                    close_write: bool = True) -> dict:
    """One-shot HTTP/1.1 GET over a probe DialStream or socket stream."""
    path = str(path or "/")
    if not path.startswith("/"):
        path = "/" + path
    request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Connection: close\r\nUser-Agent: inkblade-relay/1\r\n\r\n")
    try:
        stream.send(request.encode("utf-8"))
        if close_write:
            try:
                stream.close_write()
            except Exception:
                pass
    except Exception as exc:
        raise RelayUnreachable(f"HTTP send failed: {exc}") from exc
    buf = bytearray()
    deadline = time.time() + max(0.1, float(timeout))
    while len(buf) < max_bytes:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            chunk = stream.recv(timeout=min(remaining, 1.0))
        except RelayTimeout:
            if buf:
                break
            raise
        except Exception as exc:
            if buf:
                break
            raise RelayUnreachable(f"HTTP read failed: {exc}") from exc
        if chunk is None:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if b"\r\n\r\n" in buf:
            header, _, body = bytes(buf).partition(b"\r\n\r\n")
            length = _content_length(header)
            if length is not None and len(body) >= length:
                break
    raw = bytes(buf)
    if b"\r\n\r\n" not in raw:
        raise RelayUnreachable("HTTP response has no header terminator")
    header, _, body = raw.partition(b"\r\n\r\n")
    lines = header.decode("iso-8859-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError) as exc:
        raise RelayUnreachable(f"bad HTTP status line: {lines[0]!r}") from exc
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    expected = _content_length(header)
    if expected is not None:
        body = body[:expected]
    return {"status": status, "headers": headers,
            "body": body.decode("utf-8", "replace"),
            "ok": 200 <= status < 400}


def _content_length(header: bytes) -> int | None:
    for line in header.decode("iso-8859-1", "replace").split("\r\n"):
        key, _, value = line.partition(":")
        if key.strip().lower() == "content-length":
            try:
                return max(0, int(value.strip()))
            except ValueError:
                return None
    return None


# --------------------------------------------------------------------------
# Deployment
# --------------------------------------------------------------------------
class KubectlDeployer:
    """Deploy a child probe with kubectl or an existing Pod shell.

    The runner is injectable so tests use a fake kubectl; production uses
    ``subprocess.run`` with an argv list (never a shell) and no host fallback.
    """

    def __init__(self, *, kubectl: str = "kubectl",
                 runner: Callable[[list[str], str | None], dict] | None = None,
                 timeout: float = 60.0, probe_path: str = "/tmp/.inkblade-probe",
                 pod: str = ""):
        self.kubectl = str(kubectl or "kubectl")
        self.runner = runner or self._run
        self.timeout = float(timeout)
        self.probe_path = str(probe_path or "/tmp/.inkblade-probe")
        self.pod = str(pod or "")

    def _run(self, argv: list[str], stdin: str | None = None) -> dict:
        try:
            proc = subprocess.run(argv, input=stdin, text=True,
                                  capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RelayUnreachable(f"kubectl failed to start: {exc}") from exc
        return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": proc.stdout or "", "stderr": proc.stderr or ""}

    def _base(self, target: ClusterTarget, *, token: str = "") -> list[str]:
        argv = [self.kubectl]
        if target.kubeconfig:
            argv += ["--kubeconfig", target.kubeconfig]
        if target.context:
            argv += ["--context", target.context]
        if token:
            argv += ["--token", token]
        return argv

    def deploy(self, target: ClusterTarget, probe_id: str, *, via: str = "kubectl",
               binary: bytes | None = None, token: str = "") -> dict:
        if via == "kubectl":
            return self._deploy_pod(target, probe_id)
        if via == "sa-token":
            return self._deploy_pod(target, probe_id, token=token,
                                    service_account=target.labels.get(
                                        "service_account", "inkblade-probe"))
        if via == "exec":
            return self._deploy_exec(target, probe_id, binary=binary)
        raise RelayError(f"未知投放传输: {via!r}（{TRANSPORTS}）")

    def _deploy_pod(self, target: ClusterTarget, probe_id: str, *,
                    token: str = "", service_account: str = "") -> dict:
        from ..probe.deploy import ProbeDeploySpec, pod_manifest, render_manifest

        name = _dns_name(probe_id)
        spec = ProbeDeploySpec(
            namespace=target.namespace or "default", name=name,
            token_secret=target.labels.get("token_secret", "inkblade-probe-token"),
            read_only=True, session=str(target.labels.get("session") or ""),
            service_account=service_account or None,
            labels={"inkblade.io/cluster": target.cluster_id,
                    "inkblade.io/probe-id": probe_id,
                    "inkblade.io/parent": target.parent_id or ""},
        )
        manifest = render_manifest(pod_manifest(spec))
        argv = self._base(target, token=token) + [
            "-n", spec.namespace, "apply", "-f", "-"]
        result = self.runner(argv, manifest)
        _require_ok(result, f"kubectl apply {target.cluster_id}/{probe_id}")
        return {
            "ok": True, "transport": "sa-token" if service_account else "kubectl",
            "endpoint": target.api_server, "pod": name,
            "namespace": spec.namespace,
            "evidence": _digest(f"{target.cluster_id}|{probe_id}|{name}|"
                                 f"{result.get('stdout', '')}"),
            "command": _redact(argv, token),
        }

    def _deploy_exec(self, target: ClusterTarget, probe_id: str, *,
                     binary: bytes | None = None) -> dict:
        pod = self.pod or str(target.labels.get("pod") or "")
        if not pod:
            raise RelayError("exec 投放需要 Pod（--pod 或 labels.pod）")
        argv = self._base(target) + ["-n", target.namespace or "default",
                                     "exec", "-i", pod, "--"]
        if binary:
            b64 = base64.b64encode(bytes(binary)).decode("ascii")
            script = (f"base64 -d > {self.probe_path} && "
                      f"chmod 0700 {self.probe_path} && "
                      f"test -x {self.probe_path}")
            argv += ["sh", "-c", script]
            result = self.runner(argv, b64)
        else:
            argv += ["test", "-x", self.probe_path]
            result = self.runner(argv, None)
        _require_ok(result, f"kubectl exec {target.cluster_id}/{probe_id}")
        return {
            "ok": True, "transport": "exec", "endpoint": target.api_server,
            "pod": pod, "path": self.probe_path,
            "evidence": _digest(f"{target.cluster_id}|{probe_id}|exec|"
                                 f"{result.get('stdout', '')}"),
            "command": list(argv),
        }


def _redact(argv: list[str], token: str) -> list[str]:
    out = list(argv)
    if token:
        out = [_mask(token) if item == token else item for item in out]
    return out


def _require_ok(result: dict, label: str) -> None:
    if not isinstance(result, dict):
        raise RelayUnreachable(f"{label}: runner 必须返回对象")
    if not result.get("ok"):
        stderr = str(result.get("stderr") or "").strip()[:400]
        raise RelayUnreachable(
            f"{label}: rc={result.get('returncode')} {stderr}".strip())


def _dns_name(value: str) -> str:
    raw = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    raw = "-".join(part for part in raw.split("-") if part)
    raw = raw[:48] or "probe"
    return f"inkblade-probe-{raw}".strip("-")


# --------------------------------------------------------------------------
# Relay manager
# --------------------------------------------------------------------------
class RelayManager:
    """Durable cross-cluster relay registry and deployment coordinator."""

    def __init__(self, store=None, *, state_path: str | Path | None = None,
                 deployer: Any = None, collector: Callable | None = None,
                 dialer: Any = None, coverage: CoverageGraph | None = None,
                 clock: Callable[[], float] = time.time):
        self.store = store
        self._clock = clock
        self.deployer = deployer or KubectlDeployer()
        self.collector = collector
        self.dialer = dialer
        self.coverage = coverage
        self.graph = None
        if state_path is not None:
            self.state_path = Path(state_path)
        elif store is not None:
            self.state_path = Path(store.ws_dir) / RELAY_RELPATH
        else:
            self.state_path = None
        self._clusters: dict[str, ClusterTarget] = {}
        self._probes: dict[tuple[str, str], ProbeRecord] = {}
        self._prevented: list[dict] = []

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls, store=None, *, state_path: str | Path | None = None,
             deployer: Any = None, collector: Callable | None = None,
             dialer: Any = None, coverage: CoverageGraph | None = None,
             clock: Callable[[], float] = time.time) -> "RelayManager":
        path = Path(state_path) if state_path is not None else (
            Path(store.ws_dir) / RELAY_RELPATH if store is not None else None)
        manager = cls(store, state_path=path, deployer=deployer,
                      collector=collector, dialer=dialer, coverage=coverage,
                      clock=clock)
        if path is None or not path.is_file():
            return manager
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise RelayError(f"{path} 非法 JSON: {exc}") from exc
        if not isinstance(doc, dict) or doc.get("schema") != RELAY_SCHEMA:
            raise RelayError(f"{path} 不是 {RELAY_SCHEMA} 文档")
        for row in doc.get("clusters") or []:
            if isinstance(row, dict):
                target = ClusterTarget.from_dict(row)
                manager._clusters[target.cluster_id] = target
        for row in doc.get("probes") or []:
            if isinstance(row, dict):
                record = ProbeRecord.from_dict(row)
                manager._probes[record.key] = record
        manager._prevented = [copy.deepcopy(x) for x in doc.get("prevented") or []
                              if isinstance(x, dict)]
        if coverage is not None:
            manager.attach_coverage(coverage)
        return manager

    def save(self) -> str:
        if self.state_path is None:
            return ""
        doc = {
            "schema": RELAY_SCHEMA, "updated_at": self._clock(),
            "clusters": [c.to_dict() for c in
                         sorted(self._clusters.values(),
                                key=lambda x: x.created_at)],
            "probes": [p.to_dict() for p in
                       sorted(self._probes.values(), key=lambda x: x.created_at)],
            "prevented": copy.deepcopy(self._prevented[-_MAX_ATTEMPTS:]),
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(_json_safe(doc), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(self.state_path)
        return str(self.state_path)

    # ------------------------------------------------------------ clusters
    def add_cluster(self, cluster_id: str, *, kubeconfig: str = "",
                    context: str = "", api_server: str = "",
                    namespace: str = "default", parent_id: str = "",
                    roe_level: str = DEFAULT_ROE, transport: str = "kubectl",
                    fallback: Iterable[str] | None = None,
                    budget: Any = None, proxies: Iterable[str] | None = None,
                    labels: dict | None = None, insecure_tls: bool = False,
                    force: bool = False) -> dict:
        cid = _cluster_id(cluster_id)
        existing = self._clusters.get(cid)
        if existing is not None and not force:
            self._prevent("duplicate-cluster", cid,
                          "同 cluster_id 已注册，拒绝重复中继")
            return {**existing.summary(), "duplicate": True}
        if parent_id:
            pid = _cluster_id(parent_id)
            if pid == cid:
                self._prevent("cluster-cycle", cid, "cluster 不能以自身为父")
                raise RelayLoopError(f"cluster {cid} 不能以自身为父")
            if pid not in self._clusters:
                raise RelayError(f"父 cluster 不存在: {pid}")
            chain = self._cluster_chain(pid)
            if cid in chain:
                self._prevent("cluster-cycle", cid,
                              f"父链成环: {' -> '.join(chain + [cid])}")
                raise RelayLoopError(
                    f"cluster 父链成环: {' -> '.join(chain + [cid])}")
        self._check_roe(roe_level)
        if transport not in TRANSPORTS:
            raise RelayError(f"未知 transport: {transport!r}（{TRANSPORTS}）")
        fallbacks = [str(x) for x in (fallback if fallback is not None else
                                      [t for t in TRANSPORTS if t != transport])]
        for item in fallbacks:
            if item not in TRANSPORTS:
                raise RelayError(f"未知 fallback transport: {item!r}")
        target = existing or ClusterTarget(cluster_id=cid)
        target.kubeconfig = str(kubeconfig)
        target.context = str(context)
        target.api_server = str(api_server)
        target.namespace = str(namespace or "default")
        target.parent_id = str(parent_id)
        target.roe_level = str(roe_level)
        target.transport = str(transport)
        target.fallback = fallbacks
        target.proxies = [str(x) for x in (proxies if proxies is not None else [])]
        target.labels = {str(k): str(v) for k, v in (labels or {}).items()}
        target.insecure_tls = bool(insecure_tls)
        target.updated_at = self._clock()
        if budget is not None:
            target.budget = _as_budget(budget)
        self._clusters[cid] = target
        if self.coverage is not None:
            self.coverage.add_asset(
                f"cluster:{cid}", cluster_id=cid, kind="api-server",
                name=cid, address=target.api_server, reachable=True,
                attrs={"namespace": target.namespace,
                       "roe_level": target.roe_level,
                       "parent_id": target.parent_id})
        self.save()
        return {**target.summary(), "duplicate": False}

    def list_clusters(self) -> list[dict]:
        return [c.summary() for c in sorted(self._clusters.values(),
                                            key=lambda x: x.created_at)]

    def cluster(self, cluster_id: str) -> ClusterTarget:
        cid = str(cluster_id or "")
        target = self._clusters.get(cid)
        if target is None:
            raise RelayError(f"未知 cluster: {cluster_id!r}")
        return target

    def _cluster_chain(self, cluster_id: str) -> list[str]:
        chain: list[str] = []
        current = str(cluster_id or "")
        while current:
            if current in chain:
                raise RelayLoopError(f"cluster 父链已存在环: {current}")
            chain.append(current)
            target = self._clusters.get(current)
            if target is None:
                break
            current = target.parent_id
        return chain

    def _check_roe(self, roe_level: str) -> None:
        level = str(roe_level or DEFAULT_ROE)
        if level not in LEVELS:
            raise RelayRefused(f"未知 RoE 级别: {level!r}（{LEVELS}）")
        if self.store is None:
            return
        status = roe_status(self.store)
        if status != "complete":
            raise RelayRefused(
                f"工作区 RoE 未签署/已失效（{status}），拒绝跨集群中继")
        consent = self.store.consent() or {}
        fields = consent.get("fields") or {}
        workspace_level = str(fields.get("level") or "")
        if workspace_level and workspace_level in LEVELS:
            if not allowed(level, workspace_level):
                raise RelayRefused(
                    f"cluster RoE {level} 超出工作区 {workspace_level}")

    def bind_graph(self, graph) -> None:
        """Bind a planner graph so relay status can include frontier gaps."""
        self.graph = graph

    def attach_coverage(self, coverage: CoverageGraph) -> None:
        self.coverage = coverage
        for target in self._clusters.values():
            coverage.add_asset(
                f"cluster:{target.cluster_id}", cluster_id=target.cluster_id,
                kind="api-server", name=target.cluster_id,
                address=target.api_server, reachable=True,
                attrs={"namespace": target.namespace,
                       "roe_level": target.roe_level})
        records = list(self._probes.values())
        for record in records:
            coverage.register_probe(
                record.probe_id, cluster_id=record.cluster_id,
                transport=record.transport or "probe",
                registered=record.registered)
        for record in records:
            if record.parent_id:
                parent_ref = CoverageGraph.probe_ref(
                    record.parent_cluster_id or record.cluster_id,
                    record.parent_id)
                coverage.register_probe(
                    record.probe_id, cluster_id=record.cluster_id,
                    parent_id=parent_ref,
                    transport=record.transport or "probe",
                    registered=record.registered)
            if record.registered and record.baseline.get("ok"):
                coverage.mark_baseline(
                    CoverageGraph.probe_ref(record.cluster_id, record.probe_id),
                    ok=True,
                    evidence=record.baseline.get("evidence") or
                    _digest(f"{record.cluster_id}|{record.probe_id}|baseline"),
                    detail=str(record.baseline.get("detail") or ""))

    # ------------------------------------------------------------ deploy
    def deploy(self, cluster_id: str, probe_id: str, *, via: str = "",
               parent_id: str = "", parent_cluster_id: str = "",
               binary: bytes | None = None, token: str = "",
               baseline: bool = True, strict: bool = False) -> dict:
        target = self.cluster(cluster_id)
        pid = str(probe_id or "").strip()
        if not pid:
            raise RelayError("probe_id 不能为空")
        key = (target.cluster_id, pid)
        if key in self._probes:
            self._prevent("duplicate-probe", pid,
                          f"cluster {target.cluster_id} 已投放该 probe，拒绝"
                          f"重复中继")
            return {**self._probes[key].summary(), "duplicate": True}
        if target.budget.exhausted():
            raise RelayBudgetExceeded(target.cluster_id, "steps",
                                      target.budget.spent_steps,
                                      target.budget.steps)
        parent_cid = str(parent_cluster_id or target.cluster_id)
        parent_pid = str(parent_id or "")
        parent_ref = ""
        if parent_pid:
            parent_key = self._resolve_probe(parent_pid, parent_cid)
            self._assert_probe_acyclic(key, parent_key)
            parent_cid, parent_pid = parent_key
            parent_ref = CoverageGraph.probe_ref(*parent_key)
        target.budget.consume(target.cluster_id, "steps", 1)
        record = ProbeRecord(cluster_id=target.cluster_id, probe_id=pid,
                             parent_id=parent_pid,
                             parent_cluster_id=parent_cid if parent_pid else "")
        self._probes[key] = record
        if self.coverage is not None:
            self.coverage.register_probe(
                pid, cluster_id=target.cluster_id, parent_id=parent_ref,
                transport=via or target.transport, registered=False)
        transport_list = [via] if via else target.transports()
        for item in target.transports():
            if item not in transport_list:
                transport_list.append(item)
        errors: list[dict] = []
        first = transport_list[0] if transport_list else target.transport
        for index, transport in enumerate(transport_list):
            try:
                target.budget.consume(target.cluster_id, "actions", 1)
            except RelayBudgetExceeded as exc:
                errors.append({"transport": transport, "error": str(exc),
                               "budget": True})
                break
            try:
                result = self.deployer.deploy(
                    target, pid, via=transport, binary=binary, token=token)
            except Exception as exc:  # noqa: BLE001 - record and fallback
                message = f"{type(exc).__name__}: {exc}"
                errors.append({"transport": transport, "error": message})
                record.attempts.append({"transport": transport, "ok": False,
                                        "error": message,
                                        "ts": self._clock()})
                target.attempts.append({"action": "deploy", "probe_id": pid,
                                        "transport": transport, "ok": False,
                                        "error": message,
                                        "ts": self._clock()})
                continue
            record.transport = str(transport)
            record.status = "deployed"
            record.registered = True
            record.endpoint = str((result or {}).get("endpoint") or
                                  target.api_server)
            record.evidence = str((result or {}).get("evidence") or "")
            record.updated_at = self._clock()
            record.attempts.append({"transport": transport, "ok": True,
                                    "ts": self._clock()})
            target.attempts.append({"action": "deploy", "probe_id": pid,
                                    "transport": transport, "ok": True,
                                    "ts": self._clock()})
            target.status = "deployed"
            target.updated_at = self._clock()
            if self.coverage is not None:
                self.coverage.register_probe(
                    pid, cluster_id=target.cluster_id, parent_id=parent_ref,
                    transport=transport, registered=True)
            baseline_result = None
            if baseline:
                try:
                    baseline_result = self.collect(target.cluster_id, pid)
                except RelayBudgetExceeded as exc:
                    record.baseline = {"ok": False, "detail": str(exc),
                                       "ts": self._clock()}
                    record.status = "degraded"
                except Exception as exc:  # baseline failure is a gap, not a crash
                    record.baseline = {
                        "ok": False,
                        "detail": f"{type(exc).__name__}: {exc}",
                        "ts": self._clock()}
                    record.status = "degraded"
            self.save()
            return {
                **record.summary(),
                "ok": True,
                "duplicate": False,
                "requested_transport": first,
                "fallback_from": first if index > 0 else "",
                "errors": errors,
                "baseline": copy.deepcopy(record.baseline),
                "result_baseline": baseline_result,
            }
        record.status = "failed"
        record.last_error = errors[-1]["error"] if errors else "no transport"
        record.updated_at = self._clock()
        target.status = "degraded"
        target.last_error = record.last_error
        target.updated_at = self._clock()
        self.save()
        if strict:
            raise RelayUnreachable(
                f"cluster {target.cluster_id}/{pid} 投放失败: {record.last_error}")
        return {
            **record.summary(), "ok": False, "duplicate": False,
            "requested_transport": first, "fallback_from": "",
            "errors": errors, "baseline": copy.deepcopy(record.baseline),
        }

    def _resolve_probe(self, probe_id: str,
                       default_cluster: str) -> tuple[str, str]:
        raw = str(probe_id or "").strip()
        if not raw:
            raise RelayError("parent probe_id 不能为空")
        if raw.startswith("probe:"):
            rest = raw[len("probe:"):]
            if "/" in rest:
                cluster, pid = rest.split("/", 1)
                key = (cluster, pid)
            else:
                key = (str(default_cluster), rest)
        else:
            key = (str(default_cluster), raw)
        if key in self._probes:
            return key
        hits = [k for k in self._probes if k[1] == raw]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise RelayError(f"父探针未注册: {probe_id!r}")
        raise RelayError(f"父探针 id 有歧义，请使用 cluster/probe: {probe_id!r}")

    def _assert_probe_acyclic(self, new_key: tuple[str, str],
                              parent_key: tuple[str, str]) -> None:
        seen: set[tuple[str, str]] = set()
        current = parent_key
        while current:
            if current == new_key:
                self._prevent("probe-cycle", "/".join(new_key),
                              "probe 父链成环")
                raise RelayLoopError(
                    f"probe 父链成环: {'/'.join(new_key)}")
            if current in seen:
                self._prevent("probe-cycle", "/".join(current),
                              "probe 父链已存在环")
                raise RelayLoopError(
                    f"probe 父链已存在环: {'/'.join(current)}")
            seen.add(current)
            record = self._probes.get(current)
            if record is None or not record.parent_id:
                break
            current = (record.parent_cluster_id or record.cluster_id,
                       record.parent_id)

    # ------------------------------------------------------------ reach/collect
    def reach(self, cluster_id: str, *, path: str = "/version",
              dialer: Any = None, timeout: float = 5.0,
              consume_budget: bool = True, mark_check: bool = True) -> dict:
        target = self.cluster(cluster_id)
        if not target.api_server:
            raise RelayUnreachable(f"cluster {target.cluster_id} 没有 api_server")
        if consume_budget:
            target.budget.consume(target.cluster_id, "actions", 1)
        url = self._api_url(target)
        host = url.hostname or ""
        port = url.port or (443 if url.scheme == "https" else 80)
        candidates: list[tuple[str, Any]] = []
        if dialer is not None:
            candidates.append(("dialer", dialer))
        if self.dialer is not None:
            candidates.append(("dialer", self.dialer))
        for proxy in target.proxies:
            try:
                candidates.append(("socks5", Socks5Dialer.from_url(proxy)))
            except RelayError as exc:
                target.attempts.append({"action": "reach", "ok": False,
                                        "via": "socks5", "error": str(exc),
                                        "ts": self._clock()})
        candidates.append(("direct", DirectDialer()))
        errors: list[dict] = []
        for label, candidate in candidates:
            stream = None
            try:
                stream = candidate.connect(host, port, timeout=timeout)
                if url.scheme == "https":
                    stream = _wrap_tls(stream, host, target.insecure_tls)
                response = stream_http_get(stream, host, path, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 - try the next transport
                message = f"{type(exc).__name__}: {exc}"
                errors.append({"via": label, "error": message})
                target.attempts.append({"action": "reach", "ok": False,
                                        "via": label, "error": message,
                                        "ts": self._clock()})
                continue
            finally:
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
            evidence = _digest(f"{target.cluster_id}|{path}|"
                               f"{response['status']}|{response['body'][:200]}")
            target.status = "reachable"
            target.last_error = ""
            target.updated_at = self._clock()
            target.attempts.append({"action": "reach", "ok": True, "via": label,
                                    "status": response["status"],
                                    "ts": self._clock()})
            if mark_check and self.coverage is not None:
                ref = f"cluster:{target.cluster_id}"
                if self.coverage.has_node(ref):
                    try:
                        self.coverage.mark_check(
                            ref, mode="read-only", ok=bool(response["ok"]),
                            evidence=evidence if response["ok"] else "",
                            module="relay-api", template="api-version",
                            detail=f"GET {path} -> {response['status']} via {label}")
                    except Exception:
                        pass
            self.save()
            return {"ok": bool(response["ok"]), "status": response["status"],
                    "via": label, "cluster_id": target.cluster_id,
                    "endpoint": target.api_server, "path": path,
                    "body": response["body"][:2000],
                    "headers": response["headers"], "evidence": evidence,
                    "attempts": errors}
        message = "; ".join(f"{e['via']}: {e['error']}" for e in errors[-3:])
        target.status = "degraded"
        target.last_error = message or "no dialer"
        target.updated_at = self._clock()
        self.save()
        raise RelayUnreachable(
            f"cluster {target.cluster_id} API 不可达: {message or 'no dialer'}")

    def collect(self, cluster_id: str, probe_id: str, *, path: str = "/version",
                dialer: Any = None, strict: bool = False) -> dict:
        target = self.cluster(cluster_id)
        record = self.probe(cluster_id, probe_id)
        target.budget.consume(target.cluster_id, "actions", 1)
        if self.collector is not None:
            try:
                result = self.collector(target, record.probe_id)
            except Exception as exc:  # noqa: BLE001 - recorded as a baseline gap
                result = {"ok": False,
                          "detail": f"{type(exc).__name__}: {exc}"}
            if not isinstance(result, dict):
                result = {"ok": False, "detail": "collector 必须返回对象"}
            baseline = {
                "ok": bool(result.get("ok")),
                "evidence": str(result.get("evidence") or
                                (_digest(f"{target.cluster_id}|"
                                         f"{record.probe_id}|collect")
                                 if result.get("ok") else "")),
                "detail": str(result.get("detail") or ""),
                "ts": self._clock(),
            }
        else:
            try:
                reached = self.reach(target.cluster_id, path=path,
                                     dialer=dialer, consume_budget=False)
                baseline_ok = bool(reached.get("ok"))
                baseline = {
                    "ok": baseline_ok,
                    "evidence": reached["evidence"] if baseline_ok else "",
                    "detail": f"GET {path} -> {reached['status']} via "
                              f"{reached['via']}",
                    "ts": self._clock(),
                }
            except Exception as exc:  # noqa: BLE001
                baseline = {"ok": False, "evidence": "",
                            "detail": f"{type(exc).__name__}: {exc}",
                            "ts": self._clock()}
        record.baseline = baseline
        record.status = "ready" if baseline["ok"] else "degraded"
        record.updated_at = self._clock()
        target.status = "deployed" if baseline["ok"] else "degraded"
        target.updated_at = self._clock()
        if self.coverage is not None:
            ref = CoverageGraph.probe_ref(record.cluster_id, record.probe_id)
            if not self.coverage.has_node(ref):
                self.coverage.register_probe(
                    record.probe_id, cluster_id=record.cluster_id,
                    parent_id=record.parent_id, transport=record.transport,
                    registered=record.registered)
            try:
                self.coverage.mark_baseline(
                    ref, ok=bool(baseline["ok"]),
                    evidence=baseline.get("evidence") or "",
                    detail=str(baseline.get("detail") or ""),
                    command="collect")
            except Exception:
                pass
        self.save()
        if strict and not baseline["ok"]:
            raise RelayUnreachable(
                f"cluster {target.cluster_id}/{record.probe_id} baseline "
                f"collect 失败: {baseline['detail']}")
        return {**baseline, "cluster_id": target.cluster_id,
                "probe_id": record.probe_id}

    @staticmethod
    def _api_url(target: ClusterTarget):
        raw = str(target.api_server or "").strip()
        if "://" not in raw:
            raw = "http://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise RelayUnreachable(f"不支持的 api_server: {target.api_server!r}")
        if not parsed.hostname:
            raise RelayUnreachable(f"api_server 缺少主机: {target.api_server!r}")
        return parsed

    # ------------------------------------------------------------ queries
    def probe(self, cluster_id: str, probe_id: str) -> ProbeRecord:
        raw = str(probe_id or "").strip()
        cid = str(cluster_id or "")
        if raw.startswith("probe:"):
            rest = raw[len("probe:"):]
            if "/" in rest:
                cid, raw = rest.split("/", 1)
        record = self._probes.get((cid, raw))
        if record is None:
            raise RelayError(f"未知 probe: {cluster_id}/{probe_id}")
        return record

    def probes(self) -> list[dict]:
        return [p.summary() for p in sorted(self._probes.values(),
                                            key=lambda x: x.created_at)]

    def prevented(self) -> list[dict]:
        return copy.deepcopy(self._prevented)

    def _prevent(self, kind: str, ref: str, reason: str) -> None:
        self._prevented.append({"kind": str(kind), "id": str(ref),
                                "reason": str(reason), "ts": self._clock()})
        if len(self._prevented) > _MAX_ATTEMPTS * 4:
            self._prevented = self._prevented[-_MAX_ATTEMPTS * 4:]

    def gaps(self) -> list[dict]:
        items: list[dict] = []
        for target in self._clusters.values():
            if target.status in ("degraded", "failed", "exhausted"):
                items.append({"kind": "cluster", "id": target.cluster_id,
                              "reason": f"cluster-{target.status}",
                              "detail": target.last_error})
            if target.budget.exhausted():
                items.append({"kind": "budget", "id": target.cluster_id,
                              "reason": "budget-exhausted",
                              "detail": str(target.budget.to_dict())})
        for record in self._probes.values():
            if record.status == "failed":
                items.append({"kind": "probe", "id":
                              CoverageGraph.probe_ref(record.cluster_id,
                                                      record.probe_id),
                              "reason": "probe-deploy-failed",
                              "detail": record.last_error})
            elif not record.registered:
                items.append({"kind": "probe", "id":
                              CoverageGraph.probe_ref(record.cluster_id,
                                                      record.probe_id),
                              "reason": "probe-not-registered",
                              "detail": record.last_error})
            elif not record.baseline.get("ok"):
                items.append({"kind": "probe", "id":
                              CoverageGraph.probe_ref(record.cluster_id,
                                                      record.probe_id),
                              "reason": "baseline-collect-missing"
                              if not record.baseline else
                              "baseline-collect-failed",
                              "detail": str(record.baseline.get("detail") or "")})
        if self.coverage is not None:
            cov_gaps = self.coverage.frontier(graph=self.graph,
                                              include_unknown_frontier=True)
            items.extend(cov_gaps)
        dedup: dict[tuple[str, str, str], dict] = {}
        for item in items:
            key = (item.get("kind", ""), item.get("id", ""),
                   item.get("reason", ""))
            dedup[key] = item
        return sorted(dedup.values(),
                      key=lambda i: (i.get("kind", ""), i.get("id", ""),
                                     i.get("reason", "")))

    def status(self, cluster_id: str | None = None) -> dict:
        if cluster_id:
            target = self.cluster(cluster_id)
            clusters = [target.summary()]
        else:
            clusters = self.list_clusters()
        rows = [p.summary() for p in self._probes.values()
                if not cluster_id or p.cluster_id == cluster_id]
        doc = {
            "schema": RELAY_SCHEMA,
            "clusters": clusters,
            "probes": sorted(rows, key=lambda x: (x["cluster_id"], x["probe_id"])),
            "prevented": self.prevented(),
            "gaps": self.gaps(),
            "budget": {c["cluster_id"]: c["budget"] for c in clusters},
            "state_path": str(self.state_path) if self.state_path else "",
        }
        if self.coverage is not None:
            evaluation = self.coverage.evaluate(graph=self.graph)
            doc["coverage"] = evaluation["coverage"]
            doc["coverage_closed"] = evaluation["closed"]
            doc["coverage_criteria"] = evaluation["criteria"]
        return doc

    def proof(self) -> dict:
        edges = []
        for record in self._probes.values():
            if record.parent_id:
                edges.append({
                    "src": CoverageGraph.probe_ref(
                        record.parent_cluster_id or record.cluster_id,
                        record.parent_id),
                    "dst": CoverageGraph.probe_ref(record.cluster_id,
                                                   record.probe_id),
                    "relation": "relay",
                })
        return {
            "schema": RELAY_SCHEMA,
            "clusters": self.list_clusters(),
            "probes": self.probes(),
            "edges": edges,
            "prevented": self.prevented(),
            "gaps": self.gaps(),
            "coverage": (self.coverage.evaluate(graph=self.graph)["coverage"]
                         if self.coverage is not None else None),
        }


def _wrap_tls(stream: Any, host: str, insecure: bool) -> Any:
    import ssl

    if not isinstance(stream, SocketStream):
        raise RelayUnreachable("https over probe dial 需要 TLS 终止，当前不支持")
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        wrapped = context.wrap_socket(stream.sock, server_hostname=host)
    except OSError as exc:
        raise RelayUnreachable(f"TLS handshake failed: {exc}") from exc
    return SocketStream(wrapped)


def _dialer_from_proxy(url: str) -> Socks5Dialer:
    return Socks5Dialer.from_url(url)


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------
def relay_add(store, *, cluster_id: str, kubeconfig: str = "", context: str = "",
              api_server: str = "", namespace: str = "default",
              parent_id: str = "", roe_level: str = DEFAULT_ROE,
              transport: str = "kubectl", fallback: Iterable[str] | None = None,
              proxies: Iterable[str] | None = None, budget_steps: int = 0,
              budget_actions: int = 0, labels: dict | None = None,
              force: bool = False, coverage: CoverageGraph | None = None,
              state_path: str | Path | None = None) -> dict:
    manager = RelayManager.load(store, state_path=state_path, coverage=coverage)
    result = manager.add_cluster(
        cluster_id, kubeconfig=kubeconfig, context=context,
        api_server=api_server, namespace=namespace, parent_id=parent_id,
        roe_level=roe_level, transport=transport, fallback=fallback,
        proxies=proxies, labels=labels, force=force,
        budget=ClusterBudget(steps=int(budget_steps or 0),
                             actions=int(budget_actions or 0)))
    manager.save()
    return result


def relay_list(store, *, state_path: str | Path | None = None,
               coverage: CoverageGraph | None = None) -> dict:
    manager = RelayManager.load(store, state_path=state_path, coverage=coverage)
    return {"schema": RELAY_SCHEMA, "clusters": manager.list_clusters(),
            "count": len(manager.list_clusters())}


def relay_status(store, *, cluster_id: str | None = None,
                 state_path: str | Path | None = None,
                 coverage: CoverageGraph | None = None) -> dict:
    manager = RelayManager.load(store, state_path=state_path, coverage=coverage)
    return manager.status(cluster_id)


__all__ = [
    "RELAY_SCHEMA", "TRANSPORTS", "RelayError", "RelayLoopError", "RelayRefused",
    "RelayBudgetExceeded", "RelayUnreachable", "RelayTimeout", "ClusterBudget",
    "ClusterTarget", "ProbeRecord", "SocketStream", "DirectDialer", "ProbeDialer",
    "Socks5Dialer", "stream_http_get", "KubectlDeployer", "RelayManager",
    "relay_add", "relay_list", "relay_status",
]
