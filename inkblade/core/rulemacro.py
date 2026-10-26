# -*- coding: utf-8 -*-
"""Falco 宏/列表复用规则编写模型（CM-09）：macro/list 组合展开与校验。

模型（标准库实现，不依赖 Falco 二进制）：
- lists：命名集合 → 展开为 ``("a" or "b")``；
- macros：命名条件片段，可引用 lists 与其它 macros；
- 占位符：``${list:name}`` / ``${macro:name}`` / ``${name}``（先查 list 再查 macro）；
- ``expand`` 递归展开并返回 condition + 使用到的 list/macro + 最大深度；
- 循环引用、未定义占位符、非法名称一律 :class:`MacroError`；
- ``to_falco`` 输出 rule 骨架（rule/desc/condition/output/priority/tags），供 rules 生成器消费。

规则模板只做文本展开，不执行 Falco、不读宿主机。
"""

from __future__ import annotations

import json
import re
from typing import Any

_PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_.:-]+)\}")
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


class MacroError(ValueError):
    """宏/列表定义或展开非法。"""


class RuleBuilder:
    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.macros: dict[str, str] = {}

    def add_list(self, name: str, items: list[str]) -> list[str]:
        _check_name(name)
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise MacroError("list items 必须是字符串列表")
        self.lists[name] = list(items)
        return items

    def add_macro(self, name: str, expr: str) -> str:
        _check_name(name)
        if not str(expr).strip():
            raise MacroError("macro 表达式不能为空")
        self.macros[name] = str(expr)
        return self.macros[name]

    def _resolve(self, token: str, stack: tuple[str, ...],
                 used_lists: set[str], used_macros: set[str], depth: int) -> tuple[str, int]:
        kind, _, name = token.partition(":")
        if kind in ("list", "macro"):
            pass
        else:
            name = token
            kind = ""
        if kind in ("", "list") and name in self.lists:
            used_lists.add(name)
            values = self.lists[name]
            if not values:
                return "(false)", depth
            return "(" + " or ".join(json.dumps(v, ensure_ascii=False) for v in values) + ")", depth
        if kind in ("", "macro") and name in self.macros:
            if name in stack:
                raise MacroError(f"macro 循环引用：{' -> '.join(stack + (name,))}")
            used_macros.add(name)
            sub, sub_depth = self._expand(self.macros[name], stack + (name,),
                                          used_lists, used_macros, depth + 1)
            return "(" + sub + ")", sub_depth
        raise MacroError(f"未定义的占位符 {token!r}")

    def _expand(self, text: str, stack: tuple[str, ...], used_lists: set[str],
                used_macros: set[str], depth: int) -> tuple[str, int]:
        if depth > 16:
            raise MacroError("宏展开深度超过 16")
        max_depth = depth
        out = []
        pos = 0
        for m in _PLACEHOLDER.finditer(text):
            out.append(text[pos:m.start()])
            piece, nested = self._resolve(m.group(1), stack, used_lists, used_macros, depth)
            out.append(piece)
            max_depth = max(max_depth, nested)
            pos = m.end()
        out.append(text[pos:])
        return "".join(out), max_depth

    def expand(self, expr: str) -> dict[str, Any]:
        used_lists: set[str] = set()
        used_macros: set[str] = set()
        condition, depth = self._expand(str(expr), (), used_lists, used_macros, 0)
        if "${" in condition:
            raise MacroError(f"展开后仍含未处理占位符：{condition}")
        return {"condition": condition, "lists": sorted(used_lists),
                "macros": sorted(used_macros), "depth": depth}

    def validate(self) -> dict[str, Any]:
        """展开全部 macro；返回每个 macro 的依赖与总深度。"""
        out = {}
        for name in self.macros:
            exp = self.expand("${macro:" + name + "}")
            out[name] = {"lists": exp["lists"], "macros": [m for m in exp["macros"] if m != name],
                         "depth": exp["depth"], "condition": exp["condition"]}
        return out

    def to_falco(self, *, rule: str, expr: str, desc: str = "", output: str = "",
                 priority: str = "WARNING", tags: list[str] | None = None) -> dict:
        if priority not in ("EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING",
                            "NOTICE", "INFORMATIONAL", "DEBUG"):
            raise MacroError(f"未知 Falco priority {priority!r}")
        if not rule.strip():
            raise MacroError("rule 名称不能为空")
        exp = self.expand(expr)
        return {"rule": rule, "desc": desc or rule, "condition": exp["condition"],
                "output": output or f"{rule} (%proc.name %container.id)",
                "priority": priority, "tags": list(tags or ["trident", "ml-cluster"]),
                "meta": {"lists": exp["lists"], "macros": exp["macros"]}}


def _check_name(name: str) -> None:
    if not _NAME.match(name or ""):
        raise MacroError(f"非法名称 {name!r}（小写字母开头，允许数字/下划线）")


def default_builder() -> RuleBuilder:
    """内置示例：shell 派生与敏感挂载的组合宏。"""
    b = RuleBuilder()
    b.add_list("shell_binaries", ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/zsh"])
    b.add_list("sensitive_mounts", ["/var/run/docker.sock", "/run/containerd/containerd.sock",
                                    "/proc", "/sys", "/etc/kubernetes"])
    b.add_macro("spawn_shell", "evt.type=execve and evt.arg.exe in ${list:shell_binaries}")
    b.add_macro("dangerous_mount", "evt.type=mount and evt.arg.target in ${list:sensitive_mounts}")
    b.add_macro("container_escape_signal", "${macro:spawn_shell} or ${macro:dangerous_mount}")
    return b
