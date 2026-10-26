"""最小 YAML 生成器（仅输出，无解析）：dict/list/str/int/float/bool/None。

用于对外交付物（Kyverno/Gatekeeper/Sigma/Falco/Suricata 清单）。
字符串含 YAML 特殊字符时用 JSON 双引号转义（JSON 字符串是合法 YAML 双引号标量）。
"""

from __future__ import annotations

import json
from typing import Any

_SPECIAL = set(":#{}[],&*?|<>=!%@`\"'\\\n\t")


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    if any(ch in _SPECIAL for ch in s) or s != s.strip() or s == "":
        return json.dumps(s, ensure_ascii=False)
    return s


def _emit(value: Any, indent: int) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        if not value:
            lines.append(pad + "{}")
            return lines
        for k, v in value.items():
            key = _scalar(str(k))
            if isinstance(v, (dict, list)):
                if not v:
                    lines.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}")
                else:
                    lines.append(f"{pad}{key}:")
                    lines.extend(_emit(v, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_scalar(v)}")
    elif isinstance(value, list):
        if not value:
            lines.append(pad + "[]")
            return lines
        for item in value:
            if isinstance(item, dict):
                if not item:
                    lines.append(f"{pad}- {{}}")
                    continue
                first = True
                sub = _emit(item, indent + 1)
                for line in sub:
                    if first:
                        lines.append(f"{pad}- {line.lstrip()}")
                        first = False
                    else:
                        lines.append(line)
            elif isinstance(item, list):
                lines.append(f"{pad}-")
                lines.extend(_emit(item, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(pad + _scalar(value))
    return lines


def dump(obj: Any, indent: int = 0) -> str:
    """把 dict/list 树输出为 YAML 文本（两空格缩进）。"""
    return "\n".join(_emit(obj, indent)) + "\n"
