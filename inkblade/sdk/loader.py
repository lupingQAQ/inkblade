"""Plugin loading, fingerprinting and execution.

Security posture (read this before shipping a plugin):

* Plugins are **Python code executed in-process**. The SDK cannot sandbox them.
  Integrity controls are therefore *pre-execution*: a strict manifest contract,
  an entrypoint confined to the plugin directory, a deterministic fingerprint
  and an optional trust store pin.
* Every plugin that is not pinned in a trust store is refused unless the caller
  passes ``allow_unsigned=True``. The CLI default is "refuse".
* The SDK never writes outside the workspace directory it creates for a run.

For untrusted third-party code, run the plugin inside a container or a
dedicated, network-isolated VM (see ``docs/PLUGIN-SDK.md``).
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from .manifest import (
    MAX_PLUGIN_BYTES,
    PluginError,
    PluginManifest,
    load_manifest,
)

SKIP_DIRS = frozenset({"__pycache__", ".git", ".mypy_cache", ".pytest_cache"})
SKIP_SUFFIXES = frozenset({".pyc", ".pyo"})
SEVERITIES = ("critical", "high", "medium", "low", "info")


class PluginLoadError(PluginError):
    """Entrypoint missing, unimportable or without a callable ``run``."""


class PluginUntrusted(PluginError):
    """Fingerprint missing from, or mismatching, the trust store."""


class PluginResultError(PluginError):
    """``run()`` returned something that is not a valid result document."""


@dataclass
class Plugin:
    manifest: PluginManifest
    path: Path
    run: Callable[..., Any]
    fingerprint: str
    trusted: bool = False
    trust_source: str = ""
    warnings: list = field(default_factory=list)


def _iter_plugin_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix in SKIP_SUFFIXES:
            continue
        yield path


def plugin_fingerprint(path: str | Path) -> str:
    """Deterministic SHA-256 over every file name and content in the plugin."""
    root = Path(path).resolve()
    digest = hashlib.sha256()
    for file in _iter_plugin_files(root):
        rel = file.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        with file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def read_trust_store(path: str | Path) -> dict:
    """Load a trust store document.

    Shape::

        {"version": 1,
         "plugins": {"<key>": {"fingerprint": "<sha256>", "publisher": "acme",
                               "allow": true}}}
    """
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PluginError(f"trust store unreadable: {path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("plugins", {}), dict):
        raise PluginError("trust store: expected an object with a 'plugins' object")
    return raw


def _check_entrypoint(root: Path, manifest: PluginManifest) -> Path:
    entry = (root / manifest.entrypoint).resolve()
    try:
        entry.relative_to(root.resolve())
    except ValueError as exc:
        raise PluginLoadError(
            f"entrypoint escapes the plugin directory: {manifest.entrypoint}"
        ) from exc
    if not entry.is_file():
        raise PluginLoadError(f"entrypoint missing: {manifest.entrypoint}")
    size = entry.stat().st_size
    if size > MAX_PLUGIN_BYTES:
        raise PluginLoadError(
            f"entrypoint too large: {size} bytes > {MAX_PLUGIN_BYTES}"
        )
    return entry


def _import_entrypoint(entry: Path, key: str):
    module_name = "inkblade_plugin_" + key.replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, entry)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"cannot create an import spec for {entry.name}")
    module = importlib.util.module_from_spec(spec)
    plugin_dir = str(entry.parent)
    added = plugin_dir not in sys.path
    if added:
        sys.path.insert(0, plugin_dir)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - surfaced with plugin context
        raise PluginLoadError(f"{key}: import failed: {exc}") from exc
    finally:
        if added:
            try:
                sys.path.remove(plugin_dir)
            except ValueError:
                pass
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    return module


def _check_run_signature(run: Any, key: str) -> None:
    if not callable(run):
        raise PluginLoadError(f"{key}: entrypoint has no callable 'run'")
    try:
        signature = inspect.signature(run)
    except (TypeError, ValueError):
        return
    positional = [
        p for p in signature.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(p.kind is p.VAR_POSITIONAL for p in signature.parameters.values())
    if not has_varargs and len(positional) < 2:
        raise PluginLoadError(
            f"{key}: run() must accept (ctx, params), found {len(positional)} parameter(s)"
        )


def load_plugin(
    path: str | Path,
    *,
    trust_store: Mapping[str, Any] | str | Path | None = None,
    allow_unsigned: bool = False,
    strict: bool = True,
) -> Plugin:
    """Validate, fingerprint and import a plugin directory."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise PluginLoadError(f"plugin directory not found: {root}")

    manifest = load_manifest(root, strict=strict)
    entry = _check_entrypoint(root, manifest)
    fingerprint = plugin_fingerprint(root)

    trusted = False
    trust_source = ""
    if trust_store is not None:
        store = (read_trust_store(trust_store)
                 if isinstance(trust_store, (str, Path)) else dict(trust_store))
        entry_doc = (store.get("plugins") or {}).get(manifest.key)
        if entry_doc is None:
            if not allow_unsigned:
                raise PluginUntrusted(
                    f"{manifest.key}: not present in the trust store "
                    f"(fingerprint {fingerprint[:16]}...); add it explicitly or "
                    f"pass allow_unsigned=True"
                )
        else:
            if entry_doc.get("allow") is False:
                raise PluginUntrusted(f"{manifest.key}: explicitly blocked by the trust store")
            expected = str(entry_doc.get("fingerprint") or "")
            if expected and expected.lower() != fingerprint:
                raise PluginUntrusted(
                    f"{manifest.key}: fingerprint mismatch "
                    f"(trusted {expected[:16]}..., actual {fingerprint[:16]}...)"
                )
            trusted = True
            trust_source = str(entry_doc.get("publisher") or "trust-store")
    elif not allow_unsigned:
        raise PluginUntrusted(
            f"{manifest.key}: no trust store provided; refusing to execute "
            f"unsigned plugin code (fingerprint {fingerprint[:16]}...)"
        )

    module = _import_entrypoint(entry, manifest.key)
    run = getattr(module, "run", None)
    _check_run_signature(run, manifest.key)

    return Plugin(
        manifest=manifest,
        path=root,
        run=run,
        fingerprint=fingerprint,
        trusted=trusted,
        trust_source=trust_source,
        warnings=list(manifest.warnings),
    )


def _validate_result(result: Any, key: str) -> dict:
    if not isinstance(result, Mapping):
        raise PluginResultError(f"{key}: run() must return an object, got {type(result).__name__}")
    summary = result.get("summary", "")
    if not isinstance(summary, str):
        raise PluginResultError(f"{key}: summary must be a string")

    findings = result.get("findings", [])
    if not isinstance(findings, list):
        raise PluginResultError(f"{key}: findings must be a list")
    checked: list[dict] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise PluginResultError(f"{key}: findings[{index}] must be an object")
        sev = finding.get("sev", finding.get("severity"))
        title = finding.get("title")
        if not isinstance(sev, str) or sev.lower() not in SEVERITIES:
            raise PluginResultError(
                f"{key}: findings[{index}].sev must be one of {', '.join(SEVERITIES)}"
            )
        if not isinstance(title, str) or not title.strip():
            raise PluginResultError(f"{key}: findings[{index}].title must be a non-empty string")
        detail = finding.get("detail", "")
        if detail is not None and not isinstance(detail, str):
            raise PluginResultError(
                f"{key}: findings[{index}].detail must be a JSON string "
                f"(use inkblade.sdk.encode_detail)")
        checked.append({"sev": sev.lower(), "title": title.strip(), "detail": detail or ""})

    artifacts = result.get("artifacts", [])
    if not isinstance(artifacts, list) or any(not isinstance(a, str) for a in artifacts):
        raise PluginResultError(f"{key}: artifacts must be a list of paths")

    out = dict(result)
    out["summary"] = summary
    out["findings"] = checked
    out["artifacts"] = artifacts
    return out


def run_plugin(
    plugin: Plugin,
    params: Mapping[str, Any] | None = None,
    *,
    workspace: str | Path | None = None,
    marker: str = "INKBLADE",
    meta: Mapping[str, Any] | None = None,
) -> dict:
    """Execute a loaded plugin with a minimal run context.

    Returns ``{"summary", "findings", "artifacts", "run_dir", "plugin"}``.
    """
    base = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="inkblade-sdk-"))
    run_dir = base / "runs" / plugin.manifest.key
    (run_dir / "traces").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    ctx = {
        "run": SimpleNamespace(dir=run_dir, key=plugin.manifest.key),
        "meta": dict(meta or {}),
        "marker": marker,
        "plugin": {
            "key": plugin.manifest.key,
            "fingerprint": plugin.fingerprint,
            "trusted": plugin.trusted,
            "trust_source": plugin.trust_source,
        },
    }
    result = _validate_result(plugin.run(ctx, dict(params or {})), plugin.manifest.key)
    result["run_dir"] = str(run_dir)
    result["plugin"] = ctx["plugin"]
    return result


def encode_detail(detail: Any) -> str:
    """Serialise a finding detail the way the built-in modules do."""
    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail
    return json.dumps(detail, ensure_ascii=False, sort_keys=True)
