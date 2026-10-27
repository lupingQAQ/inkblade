#!/usr/bin/env python3
"""公开树卫生扫描：禁止内部绝对路径与内部工作区/文档引用进入开源仓库。

扫描目标（默认仓库根）：源代码 / json / md / 配置 / 脚本等文本文件；
排除 ``.git``、``.superpowers``、``__pycache__``、虚拟环境与 node_modules。

禁止模式：
- ``windows-abs-path``：盘符绝对路径（盘符 + 反斜杠/正斜杠；URL scheme 不误报）；
- ``workspace-name``：内部工作区名；
- ``internal-doc``：内部漏洞设计基线文件名。

用法::

    python scripts/check-public-tree.py            # 0 命中 → 退出码 0；否则 1 并逐条打印
    python scripts/check-public-tree.py --root .
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".superpowers", "__pycache__", ".pytest_cache", ".mypy_cache", ".cache", ".envs",
    ".venv", "venv", "env", "node_modules", ".idea", ".vscode", ".wip",
    # 本地 VM/QEMU 实验产物（第三方 QEMU 文档含 Windows 示例路径，不属于本仓公开源码）
    "qemu-k3s",
    "defense-lab",
    # 上游只读源码快照（Apache-2.0，零复用）：第三方代码可能含盘符样文本
    # （如 DeepSpeed 文档字符串中的单字母盘符示例），不属于本仓公开源码；
    # 快照来源与许可见该目录 README。
    "mining-fixture",
    # lab/upstream_verify/upstream：按 commit/tag 固定、用于静态根因与动态
    # PoC 的第三方上游源码快照；哈希记录在 cases/*/manifest.json 与
    # upstream/sources.json，不参与本仓源码卫生检查。
    "upstream",
})

# 明确按文本扫描的扩展名/文件名（无扩展名配置文件另行白名单）。
TEXT_SUFFIXES = frozenset({
    ".py", ".pyi", ".md", ".markdown", ".json", ".jsonl", ".toml", ".cfg", ".ini",
    ".txt", ".yaml", ".yml", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".html",
    ".htm", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".css", ".tmpl", ".tpl",
    ".env", ".example", ".gitignore", ".gitattributes", ".dockerignore",
})
TEXT_NAMES = frozenset({
    "LICENSE", "NOTICE", "Dockerfile", "Makefile", "README", "CHANGELOG", "AUTHORS",
    ".gitignore", ".gitattributes", ".dockerignore",
})

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # 盘符绝对路径；负向后行断言排除 http(s):// / file:// 等 URL scheme。
    ("windows-abs-path", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")),
    ("workspace-name", re.compile("llm-" + "audit-2026-10", re.IGNORECASE)),
    ("internal-doc", re.compile("VULNERABILITY" + "-MASTER", re.IGNORECASE)),
)

MAX_TEXT_BYTES = 8 * 1024 * 1024


def _is_text_candidate(path: Path) -> bool:
    name = path.name
    if name in TEXT_NAMES or name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def scan_tree(
    root: Path | str,
    excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS,
) -> list[dict]:
    """扫描 root 下文本文件；返回 [{file, line, rule, excerpt}]（file 为相对 POSIX 路径）。"""
    root = Path(root)
    excluded = set(excluded_dirs)
    hits: list[dict] = []
    if not root.exists():
        return hits
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        # Raw third-party HTTP bodies (OSV/NVD/GHSA/vendor pages) are cached
        # verbatim for offline novelty checks.  They are upstream data, not
        # project artifacts, and can legitimately contain Windows paths or
        # source snippets from other projects.
        if rel.as_posix().startswith("corpus/novelty/cache/"):
            continue
        if any(part in excluded for part in rel.parts):
            continue
        if not _is_text_candidate(path):
            continue
        try:
            if path.stat().st_size > MAX_TEXT_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule, rx in RULES:
                match = rx.search(line)
                if match:
                    hits.append({
                        "file": rel.as_posix(),
                        "line": lineno,
                        "rule": rule,
                        "excerpt": line.strip()[:200],
                    })
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade public tree hygiene scanner")
    parser.add_argument("--root", default=".", help="仓库根（默认当前目录）")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    hits = scan_tree(root)
    if not hits:
        print(f"public-tree: 0 hits @ {root}")
        return 0
    print(f"public-tree: {len(hits)} hits @ {root}", file=sys.stderr)
    for hit in hits:
        print(f"{hit['file']}:{hit['line']}: [{hit['rule']}] {hit['excerpt']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
