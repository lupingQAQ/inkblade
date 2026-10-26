# -*- coding: utf-8 -*-
"""Collection chain: Kubernetes, HTTP, files, hardware.

Modules consume real collection output first; fixture mode is explicit and is
stamped into every artifact and report section.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from . import files as files_collect
from . import hardware as hardware_collect
from . import http as http_collect
from . import k8s as k8s_collect

__all__ = [
    "collect_all", "write_collection", "load_collection", "fixture_collection",
    "summarize", "k8s_collect", "http_collect", "files_collect", "hardware_collect",
]


def load_collection(path: str | Path) -> dict:
    from ..core.surface import load_collection as _load

    return _load(path)


def fixture_collection(profile, *, mode: str = "fixture") -> dict:
    from ..core.surface import profile_collection

    doc = profile_collection(profile, mode=mode)
    doc["fixture"] = True
    doc["mode"] = "fixture"
    doc["note"] = "FIXTURE DATA: surface verdicts are for demo/regression only and must not be reported as production exposure."
    return doc


def collect_all(
    *,
    profile=None,
    kubeconfig: str | None = None,
    context: str | None = None,
    kubectl: str = "kubectl",
    collect_k8s: bool = True,
    targets: Iterable[Any] | None = None,
    files_dirs: Iterable[str | Path] | None = None,
    hardware_dirs: Iterable[str | Path] | None = None,
    timeout: int = 45,
    http_timeout: float = 8.0,
    verify_tls: bool = True,
    fixture: bool = False,
) -> dict:
    if fixture:
        if profile is None:
            raise ValueError("fixture collection requires a profile")
        return fixture_collection(profile)

    doc: dict = {
        "schema": "trident-collection-v1",
        "mode": "live",
        "fixture": False,
        "profile": getattr(profile, "get", lambda *_: "")("name") if isinstance(profile, dict) else (profile or ""),
        "sources": {},
        "k8s": {"status": "unavailable", "objects": [], "note": "not requested"},
        "http": {"status": "unavailable", "endpoints": [], "note": "no targets"},
        "files": {"status": "unavailable", "files": [], "note": "no export directory"},
        "hardware": {"status": "unavailable", "bmc": [], "switches": [], "tpm": [],
                     "note": "no hardware export directory"},
    }
    if collect_k8s:
        doc["k8s"] = k8s_collect.collect(
            kubeconfig=kubeconfig, context=context, kubectl=kubectl, timeout=timeout)
        doc["sources"]["k8s"] = "kubectl get (read-only)"
    if targets:
        doc["http"] = http_collect.collect(targets, timeout=http_timeout, verify_tls=verify_tls)
        doc["sources"]["http"] = "GET probe"
    file_docs = []
    for root in files_dirs or []:
        file_docs.append(files_collect.collect(root))
    if file_docs:
        merged = {"schema": "trident-files-collection-v1", "status": "ok",
                  "roots": [d.get("root") for d in file_docs], "files": [],
                  "errors": []}
        for d in file_docs:
            merged["files"].extend(d.get("files") or [])
            merged["errors"].extend(d.get("errors") or [])
            if d.get("status") != "ok":
                merged["status"] = "partial"
        merged["kinds"] = {}
        for item in merged["files"]:
            merged["kinds"][item["kind"]] = merged["kinds"].get(item["kind"], 0) + 1
        doc["files"] = merged
        doc["sources"]["files"] = "config/model export directory"
    hw_docs = []
    for root in hardware_dirs or []:
        hw_docs.append(hardware_collect.collect(root))
    if hw_docs:
        merged = {"schema": "trident-hardware-collection-v1", "status": "ok",
                  "roots": [d.get("root") for d in hw_docs], "bmc": [], "switches": [],
                  "tpm": [], "errors": []}
        for d in hw_docs:
            for key in ("bmc", "switches", "tpm"):
                merged[key].extend(d.get(key) or [])
            merged["errors"].extend(d.get("errors") or [])
            if d.get("status") != "ok":
                merged["status"] = "partial"
        doc["hardware"] = merged
        doc["sources"]["hardware"] = "BMC/switch export import (offline)"
    return doc


def write_collection(doc: dict, out: str | Path) -> Path:
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    (root / "collection.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name in ("k8s", "http", "files", "hardware"):
        section = doc.get(name)
        if isinstance(section, dict):
            (root / f"{name}.json").write_text(
                json.dumps(section, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return root / "collection.json"


def summarize(doc: dict) -> dict:
    k8s = doc.get("k8s") or {}
    http = doc.get("http") or {}
    files = doc.get("files") or {}
    hw = doc.get("hardware") or {}
    return {
        "mode": doc.get("mode", "live"),
        "fixture": bool(doc.get("fixture")),
        "profile": doc.get("profile", ""),
        "k8s": {"status": k8s.get("status"), "objects": len(k8s.get("objects") or [])},
        "http": {"status": http.get("status"), "endpoints": len(http.get("endpoints") or [])},
        "files": {"status": files.get("status"), "files": len(files.get("files") or []),
                  "kinds": files.get("kinds") or {}},
        "hardware": {"status": hw.get("status"),
                     "bmc": len(hw.get("bmc") or []),
                     "switches": len(hw.get("switches") or []),
                     "tpm": len(hw.get("tpm") or [])},
    }
