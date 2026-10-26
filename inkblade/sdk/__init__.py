"""InkBlade plugin SDK.

Public surface:

``manifest``
    Validate ``module.json`` documents against the same contract the built-in
    registry uses, plus plugin-specific guardrails (entrypoint containment,
    write-level floor, API version, strict key allowlist).

``loader``
    Load a plugin directory, fingerprint it and call ``run(ctx, params)`` with a
    validated result shape.

``scaffold``
    Generate a new plugin from the built-in template.

The SDK intentionally has **no** third-party dependencies and never writes
outside the directory you hand it.
"""

from __future__ import annotations

from .loader import (
    Plugin,
    PluginError,
    PluginLoadError,
    PluginResultError,
    PluginUntrusted,
    encode_detail,
    load_plugin,
    plugin_fingerprint,
    read_trust_store,
    run_plugin,
)
from .manifest import (
    LEVEL_ALIASES,
    MAX_MANIFEST_BYTES,
    SERIES_ALIASES,
    SDK_API,
    PluginManifest,
    lint_manifest,
    load_manifest,
    validate_manifest,
)
from .scaffold import scaffold_plugin, trust_entry

__all__ = [
    "LEVEL_ALIASES",
    "MAX_MANIFEST_BYTES",
    "SERIES_ALIASES",
    "SDK_API",
    "Plugin",
    "PluginError",
    "PluginLoadError",
    "PluginManifest",
    "PluginResultError",
    "PluginUntrusted",
    "encode_detail",
    "lint_manifest",
    "load_manifest",
    "load_plugin",
    "plugin_fingerprint",
    "read_trust_store",
    "run_plugin",
    "scaffold_plugin",
    "trust_entry",
    "validate_manifest",
]
