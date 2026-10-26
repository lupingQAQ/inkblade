# -*- coding: utf-8 -*-
"""HTTP endpoint probing with version / product fingerprinting.

GET only.  Bodies are capped and secrets in headers are redacted.  TLS
metadata (version, cipher, certificate hash) is captured when available.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_BODY = 64 * 1024
_SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                   "x-auth-token", "proxy-authorization"}

_PRODUCTS = (
    ("vllm", "vllm"), ("sglang", "sglang"), ("litellm", "litellm"),
    ("ray", "ray"), ("mlflow", "mlflow"), ("dify", "dify"),
    ("open-webui", "open-webui"), ("open webui", "open-webui"),
    ("kubernetes", "kubernetes"), ("istio", "istio"), ("envoy", "envoy"),
    ("spire", "spire"), ("hami", "hami"), ("nginx", "nginx"),
    ("prometheus", "prometheus"), ("grafana", "grafana"),
)
_VERSION_RE = re.compile(r"(?:version|v)[\"'\s:=]+v?(\d+\.\d+(?:\.\d+)?)", re.I)
_BARE_VERSION_RE = re.compile(r"\bv?(\d+\.\d+\.\d+)\b")


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for key, value in headers.items():
        out[key] = "<redacted>" if key.lower() in _SECRET_HEADERS else value
    return out


def _fingerprint(url: str, headers: dict[str, str], body: str) -> dict:
    haystack = f"{url}\n{json.dumps(headers, ensure_ascii=False)}\n{body[:8192]}".lower()
    product = ""
    for needle, name in _PRODUCTS:
        if needle in haystack:
            product = name
            break
    version = ""
    m = _VERSION_RE.search(body[:8192]) or _VERSION_RE.search(
        headers.get("Server", "") + " " + headers.get("X-Powered-By", ""))
    if m:
        version = m.group(1)
    else:
        m = _BARE_VERSION_RE.search(headers.get("Server", ""))
        if m:
            version = m.group(1)
    return {"product": product, "version": version}


def _tls_info(url: str, timeout: float, verify: bool) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {}
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    out: dict[str, Any] = {}
    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                out["version"] = tls.version() or ""
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else ""
                out["alpn"] = tls.selected_alpn_protocol() or ""
                cert = tls.getpeercert(binary_form=True)
                if cert:
                    out["cert_sha256"] = hashlib.sha256(cert).hexdigest()
                out["groups"] = []
    except (OSError, ssl.SSLError, ValueError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def probe_one(url: str, timeout: float = 8.0, verify_tls: bool = True,
              headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, method="GET", headers=headers or {
        "User-Agent": "trident-collect/1.0 (authorized read-only probe)",
        "Accept": "*/*",
    })
    status = 0
    body = ""
    resp_headers: dict[str, str] = {}
    error = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context() if verify_tls else
                                    ssl._create_unverified_context()) as resp:  # noqa: SLF001
            status = int(resp.status)
            resp_headers = _redact_headers(dict(resp.headers.items()))
            body = resp.read(MAX_BODY).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        resp_headers = _redact_headers(dict(exc.headers.items())) if exc.headers else {}
        try:
            body = exc.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
    except (urllib.error.URLError, OSError, ValueError, ssl.SSLError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    fp = _fingerprint(url, resp_headers, body)
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return {
        "url": url,
        "path": urllib.parse.urlparse(url).path or "/",
        "status": status,
        "error": error,
        "server": resp_headers.get("Server", ""),
        "title": title,
        "product": fp["product"],
        "version": fp["version"],
        "headers": resp_headers,
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest() if body else "",
        "body_bytes": len(body.encode("utf-8")),
        "tls": _tls_info(url, timeout, verify_tls),
        "source": "collection:http",
    }


def normalize_targets(targets) -> list[str]:
    out: list[str] = []
    for item in targets or []:
        if isinstance(item, str):
            url = item
        elif isinstance(item, dict):
            url = str(item.get("url") or item.get("target") or "")
            if url and not item.get("path"):
                pass
            elif url and item.get("path"):
                url = url.rstrip("/") + "/" + str(item["path"]).lstrip("/")
        else:
            continue
        url = url.strip()
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if url not in out:
            out.append(url)
    return out


def collect(targets, timeout: float = 8.0, verify_tls: bool = True,
            headers: dict[str, str] | None = None) -> dict:
    urls = normalize_targets(targets)
    endpoints = [probe_one(u, timeout=timeout, verify_tls=verify_tls, headers=headers)
                 for u in urls]
    reachable = sum(1 for e in endpoints if e["status"] and not e["error"])
    status = "ok" if urls and reachable == len(urls) else ("partial" if reachable else "unavailable")
    if not urls:
        status = "unavailable"
    return {
        "schema": "trident-http-collection-v1",
        "status": status,
        "targets": urls,
        "endpoints": endpoints,
    }
