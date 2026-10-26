# -*- coding: utf-8 -*-
"""Bounded external entry proof: reachability + vulnerable version/route.

This is deliberately *not* a scanner.  It performs at most the profile's
fingerprint and version requests, keeps the responses as evidence, and returns
``vulnerable=False`` unless the observed version falls inside the known-bad
range.  Exploitation is impossible until this proof succeeds.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)")
SEMVER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass
class ChainProfile:
    key: str
    label: str
    version_paths: list[str]
    fingerprint_paths: list[str]
    min_version: tuple[int, int, int] | None = None
    max_version: tuple[int, int, int] | None = None
    rce_modules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


PROFILES: dict[str, ChainProfile] = {
    "ray-dashboard-job": ChainProfile(
        key="ray-dashboard-job", label="Ray dashboard job submission",
        version_paths=["/api/version", "/api/ray/version"],
        fingerprint_paths=["/api/jobs/"],
        min_version=(0, 0, 0), max_version=(2, 49, 99),
        rce_modules=["ray-dashboard-job", "ray-control-plane", "ray-job-marker-rce"],
        notes=["dashboard job API without a token is the command-execution callback",
               "a version below 2.50 is treated as in-range for this profile"],
    ),
    "areal-setenv-engine-rce": ChainProfile(
        key="areal-setenv-engine-rce", label="AReaL set_env/create_engine/call",
        version_paths=["/version", "/health"],
        fingerprint_paths=["/set_env", "/create_engine"],
        min_version=None, max_version=None,
        rce_modules=["areal-setenv-engine-rce", "areal-load-pickle"],
        notes=["the three unauthenticated routes are the command-execution callback",
               "a version endpoint is not always present; route evidence is required"],
    ),
    "sglang-manager": ChainProfile(
        key="sglang-manager", label="SGLang manager and profiler surface",
        version_paths=["/version", "/get_server_info"],
        fingerprint_paths=["/pause", "/health"],
        min_version=None, max_version=None,
        rce_modules=["sglang-zmq-pickle-rce", "sglang-omni-profiler-write"],
        notes=["version/manager evidence gates the SGLang template"],
    ),
}


def profile_for(chain: str) -> ChainProfile:
    if chain in PROFILES:
        return PROFILES[chain]
    # Accept a module key as a chain alias, but keep only its profile.
    for profile in PROFILES.values():
        if chain in profile.rce_modules:
            return profile
    raise ValueError(
        f"unknown external chain {chain!r}; choose one of {', '.join(sorted(PROFILES))}"
    )


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(str(text or ""))
    if not match:
        return None
    parts = SEMVER_RE.search(match.group(1))
    if not parts:
        return None
    return (int(parts.group(1)), int(parts.group(2)), int(parts.group(3) or 0))


def _default_fetch(url: str, timeout: float = 4.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "inkblade-entry-proof/1",
        "Accept": "application/json, text/plain, */*",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(512 * 1024).decode("utf-8", "replace")
            return {
                "url": url, "status": response.status,
                "headers": dict(response.headers.items()), "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(256 * 1024).decode("utf-8", "replace")
        return {
            "url": url, "status": exc.code,
            "headers": dict(exc.headers.items()), "body": body,
        }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "status": 0, "headers": {}, "body": "",
                "error": f"{type(exc).__name__}: {exc}"}


def _base(target: str) -> str:
    value = str(target or "").strip().rstrip("/")
    if "://" not in value:
        raise ValueError("external target must include http:// or https://")
    return value


def recon(
    target: str,
    chain: str,
    *,
    fetch: Callable[[str], dict[str, Any]] | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    profile = profile_for(chain)
    base = _base(target)
    fetch = fetch or (lambda url: _default_fetch(url, timeout))
    requests: list[dict[str, Any]] = []
    version = ""
    version_source = ""
    reachable = False
    route_ok: list[str] = []
    for path in profile.version_paths + profile.fingerprint_paths:
        url = base + (path if path.startswith("/") else "/" + path)
        result = fetch(url)
        # Keep only a compact, safe record; headers can contain cookies.
        requests.append({
            "url": url, "status": result.get("status", 0),
            "error": result.get("error", ""),
            "bytes": len(str(result.get("body") or "")),
        })
        status = int(result.get("status") or 0)
        if status and status < 500:
            reachable = True
        body = str(result.get("body") or "")
        if status in (200, 201) and path in profile.fingerprint_paths:
            route_ok.append(path)
        candidate = None
        for key in ("version", "ray_version", "app_version"):
            match = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"', body)
            if match:
                candidate = match.group(1)
                break
        if candidate is None:
            candidate = VERSION_RE.search(body).group(1) if VERSION_RE.search(body) else None
        if candidate and not version:
            version = candidate
            version_source = url
    parsed = _version_tuple(version) if version else None
    vulnerable = False
    reason = ""
    if not reachable:
        reason = "target did not answer any profile request"
    elif profile.min_version is None and profile.max_version is None:
        # Profiles without a reliable version range require a route proof.
        vulnerable = bool(route_ok)
        reason = ("route proof: " + ", ".join(route_ok)) if route_ok else "no vulnerable route proof"
    elif parsed is None:
        reason = "version not observed; refusing to guess vulnerability"
    else:
        low_ok = profile.min_version is None or parsed >= profile.min_version
        high_ok = profile.max_version is None or parsed <= profile.max_version
        vulnerable = bool(low_ok and high_ok)
        reason = f"observed version {version} ({'in' if vulnerable else 'outside'} profile range)"
    evidence = {
        "target": base, "chain": profile.key, "version": version,
        "version_source": version_source, "routes": route_ok,
        "requests": requests, "reason": reason,
    }
    return {
        "reachable": reachable,
        "vulnerable": vulnerable,
        "version": version,
        "chain": profile.key,
        "profile": profile.label,
        "evidence": evidence,
        "reason": reason,
        "not_a_scan": True,
        "requests": len(requests),
        "rce_modules": list(profile.rce_modules),
        "assumptions": list(profile.notes),
    }


def plan(target: str, chain: str) -> dict[str, Any]:
    profile = profile_for(chain)
    base = _base(target)
    return {
        "mode": "external",
        "target": base,
        "chain": profile.key,
        "bounded_requests": len(profile.version_paths) + len(profile.fingerprint_paths),
        "version_paths": list(profile.version_paths),
        "fingerprint_paths": list(profile.fingerprint_paths),
        "rce_modules": list(profile.rce_modules),
        "assumptions": list(profile.notes),
        "rule": "no exploit or full scan until reachability and a vulnerable version/route are proven",
    }


def choose_rce_modules(chain: str) -> list[str]:
    return list(profile_for(chain).rce_modules)
