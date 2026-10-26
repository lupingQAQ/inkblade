# -*- coding: utf-8 -*-
"""probe-bootstrap — the only host-executed action in InkBlade.

It uploads the static Rust probe into the target Pod (first foothold) and
verifies that it runs.  It never uploads Python, never interprets a module, and
is explicitly registered in ``inkblade/probe-bootstrap.json``.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def run(ctx: dict, params: dict) -> dict:
    from inkblade.tpl.probe import ProbeUnavailable, install_probe, probe_artifact

    session = ctx.get("session")
    if session is None:
        raise ProbeUnavailable("probe-bootstrap requires a delivered session")
    artifact = probe_artifact() or {}
    binary = params.get("probe_binary") or artifact.get("source")
    if not binary:
        raise ProbeUnavailable(
            "no probe binary: build probe/ (cargo build --release) or pass probe_binary")
    path = Path(str(binary))
    if not path.is_file():
        raise ProbeUnavailable(f"probe binary not built: {path}")
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    expected = str(params.get("expected_sha256") or artifact.get("sha256") or "")
    if expected and expected != sha:
        raise ProbeUnavailable(f"probe binary sha256 mismatch: {sha} != {expected}")

    receipt = install_probe(session, artifact if not params.get("probe_binary") else
                            {**artifact, "source": str(path), "sha256": sha},
                            binary=path, remote=params.get("remote_path"))
    findings = [{
        "sev": "info",
        "title": f"Rust 探针已投放（{receipt['binary']}，sha256={receipt['sha256'][:12]}…）",
        "detail": ("首次立足动作：仅上传静态 Rust 探针并 chmod；后续所有模块由探针原生执行模板，"
                   "目标 Pod 不落 Python。"),
    }]
    return {"summary": f"probe installed at {receipt['binary']} ({receipt['bytes']} bytes)",
            "findings": findings, "artifacts": [], "bootstrap": receipt}
