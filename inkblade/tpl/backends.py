# -*- coding: utf-8 -*-
"""Step backends for the reference template runtime.

``LocalBackend`` executes ops with the standard library only.  It is used by the
mock range and CI; the production path is the Rust probe binary, which
implements the same operation contract natively (see
``probe/TEMPLATE-ENGINE.md``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ALLOWED_EXEC = None  # None = no allowlist; the host orchestrator decides policy


class BackendError(RuntimeError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class LocalBackend:
    """Standard-library implementation of every template op."""

    runtime = "reference"

    def __init__(self, *, workdir: str | Path | None = None,
                 k8s: "K8sShim | None" = None, env: dict | None = None):
        self.workdir = Path(workdir or os.getcwd())
        self._k8s = k8s or K8sShim()
        self.env = dict(os.environ if env is None else env)

    # ------------------------------------------------------------------ http
    def http(self, request: dict) -> dict:
        method = request["method"]
        url = request["url"]
        headers = dict(request.get("headers") or {})
        body = request.get("body")
        data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, bytes):
                data = body
            else:
                data = str(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            req.add_header(str(key), str(value))
        context = None
        if url.lower().startswith("https://") and not request.get("tls_verify", False):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        timeout = max(0.001, int(request.get("timeout_ms") or 8000) / 1000.0)
        max_bytes = int(request.get("max_bytes") or 1048576)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                raw = resp.read(max_bytes + 1)
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            raw = exc.read(max_bytes + 1)
            status = exc.code
            resp_headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        except Exception as exc:  # noqa: BLE001 - network failure is evidence
            return {"status": 0, "headers": {}, "text": "", "json": None,
                    "bytes": 0, "sha256": "", "error": f"{type(exc).__name__}: {exc}"}
        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        return {"status": status, "headers": resp_headers, "text": text,
                "json": payload, "body": raw, "bytes": len(raw),
                "sha256": _sha256(raw), "truncated": truncated}

    # ------------------------------------------------------------------- tcp
    def tcp(self, spec: dict) -> dict:
        host, port = spec["host"], int(spec["port"])
        payload = spec.get("send") or ""
        if spec.get("send_b64"):
            payload = base64.b64decode(spec["send_b64"]).decode("utf-8", "replace")
        timeout = max(0.001, int(spec.get("timeout_ms") or 8000) / 1000.0)
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                if payload:
                    sock.sendall(payload.encode("utf-8"))
                sock.settimeout(timeout)
                raw = sock.recv(int(spec.get("read_bytes") or 65536))
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "text": "", "sha256": "",
                    "error": f"{type(exc).__name__}: {exc}"}
        text = raw.decode("utf-8", "replace")
        return {"ok": True, "text": text, "sha256": _sha256(raw), "bytes": len(raw)}

    # ------------------------------------------------------------------ exec
    def exec(self, spec: dict) -> dict:
        argv = [str(x) for x in spec.get("argv") or []]
        if not argv:
            raise BackendError("exec requires argv")
        timeout = max(0.001, int(spec.get("timeout_ms") or 8000) / 1000.0)
        env = {**self.env, **(spec.get("env") or {})}
        try:
            proc = subprocess.run(argv, input=(spec.get("stdin") or "").encode("utf-8"),
                                  capture_output=True, timeout=timeout, env=env, cwd=str(self.workdir))
        except FileNotFoundError as exc:
            return {"rc": 127, "stdout": "", "stderr": str(exc), "bytes": 0, "sha256": ""}
        except subprocess.TimeoutExpired as exc:
            return {"rc": 124, "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
                    "stderr": "timeout", "bytes": 0, "sha256": ""}
        except Exception as exc:  # noqa: BLE001
            return {"rc": 126, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}",
                    "bytes": 0, "sha256": ""}
        out, err = proc.stdout or b"", proc.stderr or b""
        return {"rc": proc.returncode, "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace"), "bytes": len(out),
                "sha256": _sha256(out)}

    def spawn(self, spec: dict) -> dict:
        argv = [str(x) for x in spec.get("argv") or []]
        if not argv:
            raise BackendError("spawn requires argv")
        env = {**self.env, **(spec.get("env") or {})}
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env, cwd=str(self.workdir),
                                    start_new_session=True)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if not spec.get("detach", False):
            timeout = max(0.001, int(spec.get("timeout_ms") or 8000) / 1000.0)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return {"ok": False, "pid": proc.pid, "error": "timeout", "stdout": "", "stderr": ""}
            return {"ok": proc.returncode == 0, "pid": proc.pid,
                    "stdout": (out or b"").decode("utf-8", "replace"),
                    "stderr": (err or b"").decode("utf-8", "replace")}
        time.sleep(0.05)
        return {"ok": True, "pid": proc.pid, "stdout": "", "stderr": ""}

    # -------------------------------------------------------------------- fs
    def fs(self, spec: dict) -> dict:
        action = spec["action"]
        path = Path(str(spec.get("path") or "")).expanduser()
        max_bytes = int(spec.get("max_bytes") or 1048576)
        if action == "list":
            pattern = str(spec.get("glob") or path.name or "*")
            root = path if path.is_dir() else path.parent
            if not root.is_dir():
                return {"ok": False, "exists": False, "path": str(root), "entries": [],
                        "error": "directory not found"}
            entries = []
            for item in sorted(root.glob(pattern))[:1000]:
                try:
                    stat = item.stat()
                except OSError:
                    continue
                entries.append({"name": item.name, "path": str(item),
                                "size": stat.st_size, "mode": oct(stat.st_mode & 0o777),
                                "dir": item.is_dir()})
            return {"ok": True, "exists": True, "path": str(root), "entries": entries,
                    "size": len(entries)}
        if not path.exists():
            return {"ok": False, "exists": False, "path": str(path), "error": "not found"}
        if action == "stat":
            stat = path.stat()
            return {"ok": True, "exists": True, "path": str(path), "size": stat.st_size,
                    "mode": oct(stat.st_mode & 0o777), "dir": path.is_dir()}
        if action == "hash":
            raw = path.read_bytes()[:max_bytes]
            return {"ok": True, "exists": True, "path": str(path), "sha256": _sha256(raw),
                    "size": len(raw)}
        if action == "write":
            content = str(spec.get("content") or "")
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
            raw = content.encode("utf-8")
            return {"ok": True, "exists": True, "path": str(path), "size": len(raw),
                    "sha256": _sha256(raw), "text": content}
        raw = path.read_bytes()[:max_bytes]
        text = raw.decode("utf-8", "replace")
        payload = None
        if spec.get("json"):
            try:
                payload = json.loads(text)
            except ValueError:
                return {"ok": False, "exists": True, "path": str(path), "text": text,
                        "error": "invalid json"}
        return {"ok": True, "exists": True, "path": str(path), "text": text,
                "json": payload, "size": len(raw), "sha256": _sha256(raw)}

    # ------------------------------------------------------------------- k8s
    def k8s(self, spec: dict) -> dict:
        return self._k8s.request(spec)

    # ------------------------------------------------------------------ socks
    def socks(self, spec: dict) -> dict:
        path = str(spec.get("path") or "")
        timeout = max(0.001, int(spec.get("timeout_ms") or 8000) / 1000.0)
        if not Path(path).exists():
            return {"ok": False, "exists": False, "text": "", "sha256": "",
                    "error": "socket not found"}
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(str(spec.get("request") or "").encode("utf-8"))
            raw = sock.recv(int(spec.get("read_bytes") or 65536))
            sock.close()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "exists": True, "text": "", "sha256": "",
                    "error": f"{type(exc).__name__}: {exc}"}
        return {"ok": True, "exists": True, "text": raw.decode("utf-8", "replace"),
                "sha256": _sha256(raw), "bytes": len(raw)}


class K8sShim:
    """kubectl-equivalent, service-account-token based Kubernetes API client.

    This is the exact semantics the Rust probe implements in-pod: no kubectl
    binary, no kubeconfig, no Python.  Only verbs declared by the template are
    issued; write verbs are additionally gated by the host (RoE + backup) and by
    the probe's write-mode flag.
    """

    TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    def __init__(self, *, api: str | None = None, token: str | None = None,
                 namespace: str | None = None, ca: str | None = None,
                 validate: bool = False):
        self.api = (api or os.environ.get("INKBLADE_K8S_API")
                    or self._default_api()).rstrip("/")
        self._token = token or os.environ.get("INKBLADE_K8S_TOKEN") or ""
        self._namespace = namespace or os.environ.get("INKBLADE_K8S_NAMESPACE") or ""
        self.ca = ca or os.environ.get("INKBLADE_K8S_CA") or self.CA_PATH
        self.validate = validate

    @classmethod
    def _default_api(cls) -> str:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT") or "443"
        return f"https://{host}:{port}" if host else ""

    def token(self) -> str:
        if self._token:
            return self._token
        try:
            return Path(self.TOKEN_PATH).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def namespace(self) -> str:
        if self._namespace:
            return self._namespace
        try:
            return Path(self.NS_PATH).read_text(encoding="utf-8").strip()
        except OSError:
            return "default"

    def path_for(self, spec: dict) -> str:
        api_version = str(spec.get("api_version") or "v1")
        resource = str(spec.get("resource") or "").strip("/")
        namespace = str(spec.get("namespace") if spec.get("namespace") is not None
                        else self.namespace())
        name = str(spec.get("name") or "")
        if "/" in api_version:
            prefix = f"/apis/{api_version}"
        else:
            prefix = f"/api/{api_version}"
        base = f"{prefix}/{resource}"
        if namespace and namespace != "*":
            base = f"{prefix}/namespaces/{namespace}/{resource}"
        if name:
            return f"{base}/{urllib.parse.quote(name, safe='')}"
        return base

    def request(self, spec: dict) -> dict:
        verb = str(spec.get("verb") or "get")
        url = self.api + self.path_for(spec)
        query = {}
        if spec.get("label_selector"):
            query["labelSelector"] = spec["label_selector"]
        if verb == "list":
            query.setdefault("limit", "500")
        if query:
            url += "?" + urllib.parse.urlencode(query)
        method = {"get": "GET", "list": "GET", "create": "POST",
                  "patch": "PATCH", "delete": "DELETE", "apply": "POST"}[verb]
        body = spec.get("body")
        data = None
        headers = {"Accept": "application/json"}
        token = self.token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = ("application/merge-patch+json" if verb == "patch"
                                       else "application/json")
        if not self.api:
            return {"ok": False, "status": 0, "text": "", "json": None, "url": url,
                    "error": "no kubernetes API endpoint (missing service account/env)"}
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context(cafile=self.ca if Path(self.ca).exists() else None)
            if not self.validate:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        timeout = max(0.001, int(spec.get("timeout_ms") or 8000) / 1000.0)
        max_bytes = int(spec.get("max_bytes") or 1048576)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                raw, status = resp.read(max_bytes + 1), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(max_bytes + 1), exc.code
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "status": 0, "text": "", "json": None, "url": url,
                    "error": f"{type(exc).__name__}: {exc}"}
        raw = raw[:max_bytes]
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        ok = 200 <= status < 300
        return {"ok": ok, "status": status, "text": text, "json": payload,
                "url": url, "bytes": len(raw), "sha256": _sha256(raw),
                "error": "" if ok else text[:300]}
