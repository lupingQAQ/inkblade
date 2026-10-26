"""Manifest contract for InkBlade modules and third-party plugins.

A plugin is a directory containing ``module.json`` and an entrypoint (``run.py``
by default).  The manifest fields are exactly the fields the built-in module
registry already consumes (``inkblade.core.registry.load_modules``), so a plugin
that validates here can also be dropped into ``inkblade/modules/``.

Two validation profiles exist:

``strict=False`` (built-ins)
    Only the registry contract. Use this to prove an existing module still
    parses, including legacy quirks.

``strict=True`` (external plugins, the default for :func:`load_plugin`)
    Additionally rejects unknown top-level keys, requires ``sdk.api`` to be
    present and equal to :data:`SDK_API`, enforces that write-capable plugins
    declare at least the exploit-verification level, and requires quarantined
    (``research_only``) plugins to be disabled by default.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..core.registry import LEVELS, SERIES

SDK_API = 1

MAX_MANIFEST_BYTES = 256 * 1024
MAX_PLUGIN_BYTES = 16 * 1024 * 1024

#: ASCII aliases accepted in addition to the canonical Chinese series names.
SERIES_ALIASES: dict[str, str] = {
    "recon": "侦察",
    "lateral": "横向利用",
    "privesc": "权限链",
    "theft": "窃取与数据泄露",
    "code": "核心代码",
    "network": "网络架构",
    "hybrid-cloud": "混合云",
    "intel": "情报",
}

#: ASCII aliases accepted in addition to the canonical Chinese level names.
LEVEL_ALIASES: dict[str, str] = {
    "read-only": "只读侦察",
    "probe": "主动探测",
    "exploit": "利用验证",
    "full-impact": "全影响演示",
}

KEY_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*\.py$")

_WRITE_FLOOR = LEVELS[2]  # 利用验证 (exploit verification)
_READ_ONLY_LEVELS = (LEVELS[0], LEVELS[1])

_KNOWN_KEYS = frozenset({
    "key", "name", "series", "description", "min_level", "writes", "requires",
    "params_schema", "produces", "knowledge", "combo_signature", "private",
    "surfaces", "required_surfaces", "default_enabled", "research_only",
    "default_disabled_reason", "necessity",
    # plugin-only extension block
    "sdk",
})

_EXTENSION_PREFIX = "x-"


class PluginError(ValueError):
    """Malformed manifest or plugin layout."""


@dataclass
class PluginManifest:
    key: str
    name: dict
    series: str
    description: str
    min_level: str
    writes: bool
    requires: list = field(default_factory=list)
    params_schema: dict = field(default_factory=dict)
    produces: str = ""
    knowledge: str = ""
    combo_signature: str = ""
    private: bool = False
    required_surfaces: list = field(default_factory=list)
    default_enabled: bool = True
    research_only: bool = False
    default_disabled_reason: str = ""
    necessity: str = ""
    entrypoint: str = "run.py"
    api: int = SDK_API
    license: str = ""
    homepage: str = ""
    publisher: str = ""
    raw: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list, repr=False)

    @property
    def title(self) -> str:
        return str(self.name.get("en") or self.name.get("zh") or self.key)

    def to_module_json(self) -> dict:
        """Return the compatibility document consumed by the registry loader."""
        doc = dict(self.raw)
        doc["series"] = self.series
        doc["min_level"] = self.min_level
        return doc

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "series": self.series,
            "min_level": self.min_level,
            "writes": self.writes,
            "requires": list(self.requires),
            "entrypoint": self.entrypoint,
            "api": self.api,
            "research_only": self.research_only,
            "default_enabled": self.default_enabled,
            "required_surfaces": list(self.required_surfaces),
            "warnings": list(self.warnings),
        }


def _fail(message: str) -> None:
    raise PluginError(message)


def _require_str(raw: Mapping[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        _fail(f"{key}: expected a string, got {type(value).__name__}")
    if not allow_empty and not value.strip():
        _fail(f"{key}: must not be empty")
    return value


def _normalize_enum(raw: Mapping[str, Any], key: str, canonical: tuple[str, ...],
                    aliases: Mapping[str, str]) -> str:
    value = _require_str(raw, key)
    if value in canonical:
        return value
    lowered = value.strip().lower()
    if lowered in aliases:
        return aliases[lowered]
    allowed = ", ".join(canonical) + " or " + ", ".join(sorted(aliases))
    _fail(f"{key}: {value!r} is not one of {allowed}")


def _normalize_name(raw: Mapping[str, Any]) -> dict:
    name = raw.get("name")
    if not isinstance(name, dict) or not name:
        _fail("name: expected a non-empty object with at least 'en' or 'zh'")
    out: dict[str, str] = {}
    for lang, text in name.items():
        if not isinstance(lang, str) or not re.match(r"^[a-z]{2}(-[A-Z]{2})?$", lang):
            _fail(f"name: {lang!r} is not a language tag like 'en' or 'zh'")
        if not isinstance(text, str) or not text.strip():
            _fail(f"name.{lang}: must be a non-empty string")
        out[lang] = text.strip()
    if "en" not in out:
        _fail("name.en is required for open-source plugins")
    return out


def _normalize_surfaces(raw: Mapping[str, Any]) -> list:
    surfaces = raw.get("surfaces") or raw.get("required_surfaces") or []
    if not isinstance(surfaces, list):
        _fail("surfaces: expected a list")
    out = []
    for index, item in enumerate(surfaces):
        if not isinstance(item, dict):
            _fail(f"surfaces[{index}]: expected an object")
        kind = item.get("type")
        selector = item.get("selector")
        if not isinstance(kind, str) or not kind.strip():
            _fail(f"surfaces[{index}].type: non-empty string required")
        if not isinstance(selector, str) or not selector.strip():
            _fail(f"surfaces[{index}].selector: non-empty string required")
        out.append({"type": kind.strip(), "selector": selector.strip()})
    return out


def _normalize_entrypoint(raw: Mapping[str, Any], sdk: Mapping[str, Any]) -> str:
    entry = sdk.get("entrypoint", "run.py")
    if not isinstance(entry, str) or not ENTRYPOINT_RE.match(entry):
        _fail("sdk.entrypoint: expected a relative path to a .py file")
    if entry.startswith("/") or "\\" in entry:
        _fail("sdk.entrypoint: must be relative and use forward slashes")
    parts = Path(entry).parts
    if any(part in ("..", ".", "") for part in parts):
        _fail("sdk.entrypoint: must not contain '.' or '..' path segments")
    return entry


def validate_manifest(
    raw: Mapping[str, Any],
    *,
    dir_name: str | None = None,
    strict: bool = True,
) -> PluginManifest:
    """Validate a ``module.json`` document and return a typed manifest."""
    if not isinstance(raw, Mapping):
        _fail("manifest: expected a JSON object")

    warnings: list[str] = []

    if strict:
        unknown = sorted(
            key for key in raw
            if key not in _KNOWN_KEYS and not str(key).startswith(_EXTENSION_PREFIX)
        )
        if unknown:
            _fail(f"unknown top-level keys: {', '.join(unknown)} "
                  f"(prefix vendor keys with '{_EXTENSION_PREFIX}')")

    for key in ("key", "name", "series", "description", "min_level", "writes", "requires"):
        if key not in raw:
            _fail(f"missing required key: {key}")

    key = _require_str(raw, "key")
    if not KEY_RE.match(key):
        _fail(f"key: {key!r} must match {KEY_RE.pattern} (lowercase, digits, dashes)")
    if dir_name is not None and key != dir_name:
        _fail(f"key: {key!r} must equal the directory name {dir_name!r}")

    series = _normalize_enum(raw, "series", SERIES, SERIES_ALIASES)
    min_level = _normalize_enum(raw, "min_level", LEVELS, LEVEL_ALIASES)
    name = _normalize_name(raw)

    description = _require_str(raw, "description")
    if len(description) > 4000:
        _fail("description: keep it under 4000 characters")

    writes = raw.get("writes")
    if not isinstance(writes, bool):
        _fail("writes: expected true or false")

    requires = raw.get("requires", [])
    if not isinstance(requires, list):
        _fail("requires: expected a list of module keys")
    for dep in requires:
        if not isinstance(dep, str) or not KEY_RE.match(dep):
            _fail(f"requires: invalid module key {dep!r}")

    params = raw.get("params_schema", {})
    if not isinstance(params, dict):
        _fail("params_schema: expected an object mapping name -> description")
    for pname, pdesc in params.items():
        if not isinstance(pname, str) or not pname:
            _fail("params_schema: parameter names must be non-empty strings")
        if not isinstance(pdesc, str):
            _fail(f"params_schema.{pname}: description must be a string")

    for optional in ("produces", "knowledge", "combo_signature", "default_disabled_reason",
                     "necessity"):
        if optional in raw and not isinstance(raw[optional], str):
            _fail(f"{optional}: expected a string")

    for flag in ("private", "default_enabled", "research_only"):
        if flag in raw and not isinstance(raw[flag], bool):
            _fail(f"{flag}: expected true or false")

    surfaces = _normalize_surfaces(raw)

    sdk_block = raw.get("sdk", {})
    if sdk_block is None:
        sdk_block = {}
    if not isinstance(sdk_block, dict):
        _fail("sdk: expected an object")
    if strict:
        api = sdk_block.get("api")
        if api is None:
            _fail("sdk.api: required for external plugins (expected 1)")
    else:
        api = sdk_block.get("api", SDK_API)
    if api is not None:
        if not isinstance(api, int) or api != SDK_API:
            _fail(f"sdk.api: unsupported API version {api!r} (this build supports {SDK_API})")
    entrypoint = _normalize_entrypoint(raw, sdk_block)
    for meta_key in ("license", "homepage", "publisher"):
        if meta_key in sdk_block and not isinstance(sdk_block[meta_key], str):
            _fail(f"sdk.{meta_key}: expected a string")

    research_only = bool(raw.get("research_only", False))
    default_enabled = bool(raw.get("default_enabled", True))

    if strict and writes and min_level in _READ_ONLY_LEVELS:
        _fail(f"writes=true requires min_level={_WRITE_FLOOR!r} or higher "
              f"(got {min_level!r}); a state-changing plugin cannot be read-only")
    if strict and research_only and default_enabled:
        _fail("research_only=true requires default_enabled=false")
    if strict and writes and not raw.get("required_surfaces") and not raw.get("surfaces"):
        warnings.append("writes=true without declared surfaces: the runner cannot "
                        "skip this plugin when the surface is absent")
    if writes and min_level in _READ_ONLY_LEVELS:
        warnings.append(f"writes=true with min_level={min_level!r}")

    return PluginManifest(
        key=key,
        name=name,
        series=series,
        description=description,
        min_level=min_level,
        writes=writes,
        requires=list(requires),
        params_schema=dict(params),
        produces=str(raw.get("produces") or ""),
        knowledge=str(raw.get("knowledge") or ""),
        combo_signature=str(raw.get("combo_signature") or ""),
        private=bool(raw.get("private", False)),
        required_surfaces=surfaces,
        default_enabled=default_enabled,
        research_only=research_only,
        default_disabled_reason=str(raw.get("default_disabled_reason") or ""),
        necessity=str(raw.get("necessity") or ""),
        entrypoint=entrypoint,
        api=int(api if api is not None else SDK_API),
        license=str(sdk_block.get("license") or ""),
        homepage=str(sdk_block.get("homepage") or ""),
        publisher=str(sdk_block.get("publisher") or ""),
        raw=dict(raw),
        warnings=warnings,
    )


def load_manifest(path: str | Path, *, strict: bool = True) -> PluginManifest:
    """Read and validate ``<path>/module.json``."""
    path = Path(path)
    manifest_path = path / "module.json" if path.is_dir() else path
    try:
        size = manifest_path.stat().st_size
    except OSError as exc:
        raise PluginError(f"manifest not found: {manifest_path}") from exc
    if size > MAX_MANIFEST_BYTES:
        raise PluginError(f"manifest too large: {size} bytes > {MAX_MANIFEST_BYTES}")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PluginError(f"manifest is not valid JSON: {exc}") from exc
    dir_name = manifest_path.parent.name if manifest_path.name == "module.json" else None
    return validate_manifest(raw, dir_name=dir_name, strict=strict)


def lint_manifest(path: str | Path) -> dict:
    """Non-fatal checks used by ``inkblade sdk lint`` and CI."""
    path = Path(path)
    report: dict[str, Any] = {"path": str(path), "errors": [], "warnings": []}
    try:
        manifest = load_manifest(path, strict=True)
    except PluginError as exc:
        report["errors"].append(str(exc))
        return report
    report["key"] = manifest.key
    report["series"] = manifest.series
    report["min_level"] = manifest.min_level
    report["writes"] = manifest.writes
    report["warnings"].extend(manifest.warnings)
    root = path if path.is_dir() else path.parent
    entry = root / manifest.entrypoint
    if not entry.is_file():
        report["errors"].append(f"entrypoint missing: {manifest.entrypoint}")
    elif entry.stat().st_size > MAX_PLUGIN_BYTES:
        report["errors"].append(f"entrypoint too large: {manifest.entrypoint}")
    if not manifest.license:
        report["warnings"].append("sdk.license is not set")
    if not manifest.homepage:
        report["warnings"].append("sdk.homepage is not set")
    return report


def manifest_digest(manifest: PluginManifest) -> str:
    """Stable digest of the normalized manifest (for trust pinning)."""
    payload = json.dumps(manifest.as_dict(), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
