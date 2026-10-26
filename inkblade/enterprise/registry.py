# -*- coding: utf-8 -*-
"""私有 registry / 代理 / 镜像引用本地验证（ER-08）。

不依赖 docker；用标准库实现 registry v2 的最小只读客户端：

- OCI/Docker 引用解析（registry/repo:tag@sha256:...），tag-only 视为未钉住；
- `GET /v2/` → 401 Bearer challenge → token → manifest 的认证链；
- `Docker-Content-Digest` 与响应体 sha256 比对；
- HTTP(S)_PROXY / NO_PROXY、自定义 CA bundle、显式 insecure 开关与 host allowlist。

边界：本地 registry mock 验证的是客户端行为与契约，不是客户 Harbor/ACR 联调。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

Transport = Callable[[str, dict], dict]
_REF = re.compile(r"^(?:(?P<registry>[^/]+)/)?(?P<repo>[^:@]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?$")
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class RegistryError(ValueError):
    """引用/认证/策略错误。"""


def parse_reference(reference: str) -> dict:
    text = str(reference or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise RegistryError(f"非法镜像引用: {reference!r}")
    match = _REF.match(text)
    if not match:
        raise RegistryError(f"非法镜像引用: {reference!r}")
    registry = match.group("registry") or "docker.io"
    repo = match.group("repo")
    if registry == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    digest = match.group("digest") or ""
    tag = match.group("tag") or ("latest" if not digest else "")
    return {
        "reference": text,
        "registry": registry,
        "repository": repo,
        "tag": tag,
        "digest": digest,
        "pinned": bool(digest),
        "tag_only": not digest,
        "mutable_tag": tag.lower() == "latest" and not digest,
        "scheme": "https",
    }


def reference_policy(reference: str) -> dict:
    ref = parse_reference(reference)
    risks = []
    if ref["tag_only"]:
        risks.append("tag-only")
    if ref["mutable_tag"]:
        risks.append("latest-tag")
    if ref["registry"].startswith(("127.", "localhost", "10.", "192.168.")):
        risks.append("private-registry")
    return {**ref, "risks": risks, "risk": "high" if risks else "none"}


class ProxyConfig:
    """从环境变量/显式配置解析代理；NO_PROXY 按主机后缀匹配。"""

    def __init__(self, http_proxy: str = "", https_proxy: str = "", no_proxy: str = "",
                 ca_bundle: str | Path | None = None, insecure: bool = False):
        self.http_proxy = http_proxy or ""
        self.https_proxy = https_proxy or ""
        self.no_proxy = [p.strip().lower() for p in str(no_proxy or "").split(",") if p.strip()]
        self.ca_bundle = str(ca_bundle) if ca_bundle else ""
        self.insecure = bool(insecure)

    @classmethod
    def from_env(cls, env: dict | None = None) -> "ProxyConfig":
        env = env or os.environ
        return cls(env.get("HTTP_PROXY") or env.get("http_proxy") or "",
                   env.get("HTTPS_PROXY") or env.get("https_proxy") or "",
                   env.get("NO_PROXY") or env.get("no_proxy") or "",
                   env.get("REQUESTS_CA_BUNDLE") or env.get("SSL_CERT_FILE") or "",
                   insecure=False)

    def bypass(self, host: str) -> bool:
        host = str(host or "").lower().split(":")[0]
        for item in self.no_proxy:
            if item == "*":
                return True
            if host == item or host.endswith("." + item.lstrip(".")):
                return True
        return False

    def proxy_for(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        if self.bypass(parsed.hostname or ""):
            return ""
        return self.https_proxy if parsed.scheme == "https" else self.http_proxy

    def opener(self) -> urllib.request.OpenerDirector:
        proxies = {}
        if self.http_proxy:
            proxies["http"] = self.http_proxy
        if self.https_proxy:
            proxies["https"] = self.https_proxy
        handlers: list[Any] = [urllib.request.ProxyHandler(proxies)]
        if self.ca_bundle or self.insecure:
            context = ssl.create_default_context(cafile=self.ca_bundle or None)
            if self.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        return urllib.request.build_opener(*handlers)


class RegistryClient:
    def __init__(self, base: str, *, username: str = "", password: str = "",
                 token: str = "", allowlist: list[str] | None = None,
                 proxy: ProxyConfig | None = None, timeout: int = 5,
                 transport: Transport | None = None):
        self.base = str(base or "").rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            raise RegistryError("registry base 必须是 http(s)")
        self.host = urllib.parse.urlsplit(self.base).hostname or ""
        self.allowlist = [a.lower() for a in (allowlist or [])]
        if self.allowlist and self.host.lower() not in self.allowlist:
            raise RegistryError(f"registry host {self.host} 不在 allowlist")
        self.username = username
        self.password = password
        self.token = token
        self.proxy = proxy or ProxyConfig()
        self.timeout = timeout
        self.transport = transport

    def _request(self, url: str, headers: dict | None = None) -> dict:
        headers = dict(headers or {})
        if self.transport is not None:
            return self.transport(url, headers)
        req = urllib.request.Request(url, method="GET")
        for key, value in headers.items():
            req.add_header(key, value)
        opener = self.proxy.opener()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                data = resp.read()
                return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()},
                        "body": data}
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "headers": {k.lower(): v for k, v in exc.headers.items()},
                    "body": exc.read()}
        except Exception as exc:  # noqa: BLE001
            return {"status": 0, "headers": {}, "body": b"", "error": f"{type(exc).__name__}: {exc}"}

    def _basic(self) -> str:
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _auth_token(self, challenge: str) -> dict:
        params = dict(_CHALLENGE.findall(challenge or ""))
        realm = params.get("realm") or ""
        if not realm.startswith(("http://", "https://")):
            return {"ok": False, "error": "Bearer challenge 缺少合法 realm"}
        query = {"service": params.get("service", "")}
        if params.get("scope"):
            query["scope"] = params["scope"]
        url = realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query)
        headers = {"Authorization": self._basic()} if self.username else {}
        res = self._request(url, headers)
        if res.get("status") != 200:
            return {"ok": False, "status": res.get("status"), "error": "token 获取失败"}
        try:
            doc = json.loads(res.get("body") or b"{}")
        except ValueError:
            return {"ok": False, "error": "token 响应非 JSON"}
        token = str(doc.get("token") or doc.get("access_token") or "")
        return {"ok": bool(token), "token": token, "expires_in": doc.get("expires_in")}

    def probe(self, reference: str, *, verify_digest: bool = True) -> dict:
        ref = parse_reference(reference)
        url = f"{self.base}/v2/"
        res = self._request(url)
        auth = "none"
        challenge = res.get("headers", {}).get("www-authenticate", "")
        if res.get("status") == 401 and "bearer" in challenge.lower():
            auth = "bearer"
            token = self.token or self._auth_token(challenge).get("token", "")
            if not token:
                return {"ok": False, "stage": "token", "status": res.get("status"),
                        "auth": auth, **ref}
            res = self._request(url, {"Authorization": f"Bearer {token}"})
        elif self.token:
            auth = "token"
            res = self._request(url, {"Authorization": f"Bearer {self.token}"})
        if res.get("status") != 200:
            return {"ok": False, "stage": "ping", "status": res.get("status"),
                    "auth": auth, "error": res.get("error", ""), **ref}
        ref_part = ref["digest"] or ref["tag"]
        manifest_url = f"{self.base}/v2/{ref['repository']}/manifests/{ref_part}"
        headers = {"Accept": "application/vnd.oci.image.manifest.v1+json,"
                             "application/vnd.docker.distribution.manifest.v2+json"}
        if auth in ("bearer", "token"):
            token = self.token or self._auth_token(challenge).get("token", "") if challenge else self.token
            if token:
                headers["Authorization"] = f"Bearer {token}"
        manifest = self._request(manifest_url, headers)
        body = manifest.get("body") or b""
        actual = "sha256:" + hashlib.sha256(body).hexdigest()
        declared = manifest.get("headers", {}).get("docker-content-digest", "")
        digest_match = (not declared) or declared == actual
        ok = manifest.get("status") == 200 and (digest_match or not verify_digest)
        return {
            "ok": ok,
            "stage": "manifest",
            "status": manifest.get("status"),
            "auth": auth,
            "digest": actual,
            "declared_digest": declared,
            "digest_match": digest_match,
            "manifest_bytes": len(body),
            "via_proxy": bool(self.proxy.proxy_for(manifest_url)),
            **ref,
        }


def manifest_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()
