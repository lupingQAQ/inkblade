"""模块注册表：module.json 契约校验（命名规范强制）与依赖拓扑排序。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SERIES = ("侦察", "横向利用", "权限链", "窃取与数据泄露", "核心代码", "网络架构", "混合云", "情报")
LEVELS = ("只读侦察", "主动探测", "利用验证", "全影响演示")
_KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")  # 纯小写单词/连字符；允许端口或版本数字段（kubelet-10250-exec）

_REQUIRED = ("key", "name", "series", "description", "min_level", "writes", "requires")

# Legacy modules declare their deployment surfaces in a central map so that
# adding a module does not require a second schema migration.  A per-module
# ``surfaces`` / ``required_surfaces`` field always wins.
_PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"
_SURFACE_MAP_PATH = _PROFILES_DIR / "surface-map.json"
_QUARANTINE_PATH = _PROFILES_DIR / "quarantine.json"
_SURFACE_MAP: dict[str, list[dict]] | None = None
_QUARANTINE: set[str] | None = None


def _surface_map() -> dict[str, list[dict]]:
    global _SURFACE_MAP
    if _SURFACE_MAP is None:
        try:
            raw = json.loads(_SURFACE_MAP_PATH.read_text(encoding="utf-8"))
            _SURFACE_MAP = {str(k): list(v) for k, v in (raw.get("modules") or {}).items()}
        except (OSError, ValueError, AttributeError):
            _SURFACE_MAP = {}
    return _SURFACE_MAP


def _quarantine() -> set[str]:
    global _QUARANTINE
    if _QUARANTINE is None:
        try:
            raw = json.loads(_QUARANTINE_PATH.read_text(encoding="utf-8"))
            _QUARANTINE = {str(k) for k in (raw.get("modules") or {})}
        except (OSError, ValueError, AttributeError):
            _QUARANTINE = set()
    return _QUARANTINE


@dataclass
class ModuleMeta:
    key: str
    name: dict
    series: str
    description: str
    min_level: str
    writes: bool
    requires: list[str] = field(default_factory=list)
    params_schema: dict = field(default_factory=dict)
    produces: str = ""
    knowledge: str = ""
    combo_signature: str = ""
    private: bool = False
    required_surfaces: list[dict] = field(default_factory=list)
    default_enabled: bool = True
    research_only: bool = False
    default_disabled_reason: str = ""
    necessity: str = ""
    path: Path | None = None


def load_modules(modules_dir: Path | str) -> dict[str, ModuleMeta]:
    root = Path(modules_dir)
    mods: dict[str, ModuleMeta] = {}
    if not root.exists():
        return mods
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        mf = d / "module.json"
        if not mf.exists():
            continue
        raw = json.loads(mf.read_text(encoding="utf-8"))
        for k in _REQUIRED:
            if k not in raw:
                raise ValueError(f"{d.name}/module.json 缺字段 {k}")
        if not _KEY_RE.match(raw["key"]) or raw["key"] != d.name:
            raise ValueError(f"非法机器键（须纯小写单词、与目录同名、禁数字）: {raw['key']}")
        if raw["series"] not in SERIES:
            raise ValueError(f"{d.name}: 未知系列 {raw['series']}")
        if raw["min_level"] not in LEVELS:
            raise ValueError(f"{d.name}: 未知级别 {raw['min_level']}")
        if not (d / "run.py").exists():
            raise ValueError(f"{d.name}: 缺 run.py")
        mods[raw["key"]] = ModuleMeta(
            key=raw["key"], name=raw["name"], series=raw["series"],
            description=raw["description"], min_level=raw["min_level"],
            writes=bool(raw["writes"]), requires=list(raw.get("requires", [])),
            params_schema=raw.get("params_schema", {}), produces=raw.get("produces", ""),
            knowledge=raw.get("knowledge", ""), combo_signature=raw.get("combo_signature", ""),
            private=bool(raw.get("private", False)),
            required_surfaces=list(raw.get("surfaces") or raw.get("required_surfaces")
                                   or _surface_map().get(raw["key"], [])),
            default_enabled=bool(raw.get("default_enabled",
                                         raw["key"] not in _quarantine())),
            research_only=bool(raw.get("research_only", False)),
            default_disabled_reason=str(raw.get("default_disabled_reason") or ""),
            necessity=str(raw.get("necessity") or ""),
            path=d,
        )
    for m in mods.values():
        for dep in m.requires:
            if dep not in mods:
                raise ValueError(f"{m.key}: 依赖不存在 {dep}")
    return mods


def order_dependencies(mods: dict[str, ModuleMeta]) -> list[str]:
    done: list[str] = []
    seen: set[str] = set()

    def visit(key: str, stack: set[str]) -> None:
        if key in seen:
            return
        if key in stack:
            raise ValueError(f"依赖环: {key}")
        stack.add(key)
        for dep in mods[key].requires:
            visit(dep, stack)
        stack.discard(key)
        seen.add(key)
        done.append(key)

    for k in sorted(mods):
        visit(k, set())
    return done
