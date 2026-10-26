# -*- coding: utf-8 -*-
"""环境变量读取（``INKBLADE_*`` 优先，兼容旧 ``TRIDENT_*``）。

0.2.0 起项目由 Trident 更名为 InkBlade，环境变量前缀随之改为
``INKBLADE_``。旧前缀在过渡期内仍会被读取，但会发出
``DeprecationWarning``（同一变量每次进程只提示一次），并计划在 0.3.0
移除。

用法::

    from .core.env import getenv

    debug = getenv("DEBUG") == "1"          # 读取 INKBLADE_DEBUG
    debug = getenv("INKBLADE_DEBUG") == "1"  # 等价写法

    # 变量名由用户/配置给出时（如 --key-env）用 lookup 逐字读取
    token = lookup("INKBLADE_REPORT_KEY", "")
"""

from __future__ import annotations

import os
import warnings
from typing import Optional

PREFIX = "INKBLADE_"
LEGACY_PREFIX = "TRIDENT_"

_warned: set[str] = set()


def _warn(legacy: str, current: str) -> None:
    if legacy in _warned:
        return
    _warned.add(legacy)
    warnings.warn(
        f"{legacy} is deprecated; use {current} instead "
        f"(legacy prefix support will be removed in 0.3.0)",
        DeprecationWarning,
        stacklevel=3,
    )


def lookup(key: str, default: Optional[str] = None) -> Optional[str]:
    """按变量名逐字读取，并在新旧前缀之间做一次兼容回退。

    ``key`` 可以是任意环境变量名；只有当它本身是 ``INKBLADE_*`` 或
    ``TRIDENT_*`` 时才参与别名映射，其他键名保持原样读取。
    """
    if key in os.environ:
        return os.environ[key]
    if key.startswith(PREFIX):
        legacy = LEGACY_PREFIX + key[len(PREFIX):]
        if legacy in os.environ:
            _warn(legacy, key)
            return os.environ[legacy]
    elif key.startswith(LEGACY_PREFIX):
        current = PREFIX + key[len(LEGACY_PREFIX):]
        if current in os.environ:
            return os.environ[current]
    return default


def getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    """读取 ``INKBLADE_<name>``；``name`` 也可直接写完整变量名。

    先查新前缀；缺失时回退到旧的 ``TRIDENT_<name>``（deprecated）。
    """
    key = name if name.startswith(PREFIX) or name.startswith(LEGACY_PREFIX) else PREFIX + name
    return lookup(key, default)


def reset_warnings() -> None:
    """清空已提示集合（仅测试使用）。"""
    _warned.clear()
