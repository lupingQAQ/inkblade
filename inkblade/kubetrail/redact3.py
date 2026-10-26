# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""敏感值三态存储：raw / redact / metadata（引用式，raw 隔离落盘）。

- ``raw``：完整值，仅落在受控目录（默认 0600），返回引用 id，不进入 findings；
- ``redact``：``前4****后4``（可配置），用于报告与工单；
- ``metadata``：``{kind, length, sha256, entropy}``，用于关联与去重（不可逆）。

约束：``TriStore`` 的 raw 目录必须由调用方显式指定（默认不落 raw），避免误把明文
写进工作区；``get(ref, "raw")`` 在 raw 不可用时抛 ``RedactError``。
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from pathlib import Path

MODES = ("raw", "redact", "metadata")


class RedactError(ValueError):
    """三态模式/引用非法。"""


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)


def mask(value: str, *, keep: int = 4) -> str:
    text = str(value or "")
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * max(4, len(text) - keep * 2) + text[-keep:]


def metadata(value: str, kind: str = "generic") -> dict:
    text = str(value or "")
    return {
        "kind": kind,
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "entropy": entropy(text),
    }


class TriStore:
    """引用式三态存储；ref 形如 ``secret:<id>``。"""

    def __init__(self, raw_dir: Path | str | None = None):
        self.raw_dir = Path(raw_dir) if raw_dir else None
        self._values: dict[str, dict] = {}
        self._seq = 0
        if self.raw_dir is not None:
            self.raw_dir.mkdir(parents=True, exist_ok=True)

    def put(self, value: str, *, kind: str = "generic") -> str:
        self._seq += 1
        ref = f"secret:{self._seq:04d}"
        record = {"value": str(value), "kind": kind, "ref": ref}
        self._values[ref] = record
        if self.raw_dir is not None:
            path = self.raw_dir / f"{self._seq:04d}.secret"
            path.write_text(str(value), encoding="utf-8")
            try:  # POSIX 0600；Windows 无等价位，保持目录访问控制
                os.chmod(path, 0o600)
            except OSError:
                pass
            record["raw_path"] = str(path)
        return ref

    def get(self, ref: str, mode: str = "redact") -> str | dict:
        if mode not in MODES:
            raise RedactError(f"未知三态模式 {mode!r}（仅 {MODES}）")
        record = self._values.get(ref)
        if record is None:
            raise RedactError(f"未知引用 {ref}")
        value = record["value"]
        if mode == "raw":
            if "raw_path" not in record:
                raise RedactError("该引用未启用 raw（未配置 raw 目录）")
            return value
        if mode == "redact":
            return mask(value)
        return metadata(value, record["kind"])

    def refs(self) -> list[dict]:
        return [{"ref": r["ref"], "kind": r["kind"],
                 "length": len(r["value"]), "has_raw": "raw_path" in r}
                for r in self._values.values()]


_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{16,}")


def tri_state_finding(value: str, *, kind: str, store: TriStore | None = None) -> dict:
    """把敏感值转成 finding 可用的三态载荷（默认 redact + metadata，不落 raw）。"""
    ref = store.put(value, kind=kind) if store is not None else ""
    meta = metadata(value, kind)
    return {
        "kind": kind,
        "ref": ref,
        "redact": mask(value),
        "metadata": meta,
    }
