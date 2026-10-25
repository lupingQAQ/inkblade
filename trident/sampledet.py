"""样张确定性：把「动态字段」（时间戳/端口/耗时/运行名/tmp 绝对路径）归一化后再比对。

用途：
- 交付样张（``reports/samples``）的两次生成结果应 **diff=空**（modulo 动态字段）；
- 单元测试用 ``normalize_tree`` + ``diff_trees`` 断言「两次生成、归一化后逐字节一致」；
- 动态字段清单同时作为 ``.gitignore``/CI 的忽略口径（B14：lab/bench/out 为可再生输出）。

动态字段（``DYNAMIC_FIELDS``）：generated_at / measured_at / extracted_at / created_at /
ts / elapsed_ms / duration_ms / latency_ms / wall_ms / ms / 端口 / 时间戳 / 带时间戳的 run 名 /
本机绝对路径。**稳定字段（sha256/manifest/判定/计数）不归一化**，否则测试会失去意义。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

DYNAMIC_FIELDS = (
    "generated_at", "measured_at", "extracted_at", "created_at", "ts",
    "elapsed_ms", "duration_ms", "latency_ms", "wall_ms", "ms",
    "port", "timestamp", "run-name-timestamp", "abs-path",
)

TEXT_SUFFIXES = {".json", ".md", ".html", ".js", ".css", ".yaml", ".yml", ".txt", ".log"}

_ABS_PATH = re.compile(r"[A-Za-z]:\\{1,2}[^\s\"',;|()\[\]{}<>：，；（）]+")

_RULES: list[tuple[str, re.Pattern[str], str]] = [
    # 盘符绝对路径（JSON 双反斜杠 / 普通单反斜杠）
    ("abs-path", _ABS_PATH, "<abs-path>"),
    # ISO 时间戳（含毫秒 / Z）
    ("timestamp",
     re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"),
     "<timestamp>"),
    # 带时间戳的运行名（run-/chain-*/e2e-acceptance/effects/qemu/same-target/perf）
    ("run-name-timestamp",
     re.compile(r"\b(run|e2e-acceptance|effects|effects-chain|chain-[a-z0-9-]+|"
                r"qemu-[a-z0-9-]+|same-target[a-z-]*|perf-[a-z]+)"
                r"-\d{8}-\d{6}(?:-[0-9a-f]{6})?\b"),
     r"\1-<run-ts>"),
    # 本机/回环端口（hostfwd/mock 端口每次随机）
    ("port",
     re.compile(r"\b(127\.0\.0\.1|localhost|0\.0\.0\.0):\d{2,5}\b"),
     r"\1:<port>"),
    # 耗时/时间字段（JSON 键值）
    ("elapsed",
     re.compile(r'"(elapsed_ms|duration_ms|latency_ms|wall_ms|ms|measured_at|generated_at|'
                r'extracted_at|created_at|updated_at|started_at|finished_at|enabled_at|'
                r'last_run|ts)"(\s*:\s*)("[^"]*"|[^,}\n]+)'),
     r'"\1"\2"<dynamic>"'),
]

# Markdown 表格中的纯数字耗时（如 e2e 清单 `| ... | 12.3 |`）不在此处理：
# 该列头固定为「耗时(ms)」，由 _normalize_md_elapsed 定向剥离，避免误伤计数列。
_MD_ELAPSED = re.compile(r"(\|\s*)(\d+(?:\.\d+)?)(\s*\|\s*)$")


def normalize_text(text: str) -> str:
    out = text
    for _name, rx, repl in _RULES:
        out = rx.sub(repl, out)
    return out


def normalize_markdown(text: str) -> str:
    """额外归一化 e2e 清单里的耗时列（表头含「耗时(ms)」）。"""
    lines = text.splitlines()
    if not any("耗时(ms)" in ln for ln in lines):
        return text
    fixed = []
    for ln in lines:
        if ln.startswith("|") and ln.count("|") >= 3:
            ln = _MD_ELAPSED.sub(r"\1<elapsed>\3", ln)
        fixed.append(ln)
    return "\n".join(fixed) + ("\n" if text.endswith("\n") else "")


def normalize_tree(root: Path | str, *, suffixes: Iterable[str] | None = None) -> list[str]:
    """就地归一化目录内文本样张；返回被改写的相对路径（posix）。"""
    root = Path(root)
    allowed = set(suffixes or TEXT_SUFFIXES)
    changed: list[str] = []
    if not root.exists():
        return changed
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in allowed:
            continue
        raw = p.read_text(encoding="utf-8")
        new = normalize_text(raw)
        if p.suffix.lower() == ".md":
            new = normalize_markdown(new)
        if new != raw:
            p.write_text(new, encoding="utf-8")
            changed.append(p.relative_to(root).as_posix())
    return changed


def tree_bytes(root: Path | str, *, suffixes: Iterable[str] | None = None) -> dict[str, bytes]:
    """读取目录内文本样张快照（相对路径 → 字节）。"""
    root = Path(root)
    allowed = set(suffixes or TEXT_SUFFIXES)
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in allowed:
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def diff_trees(left: Path | str, right: Path | str) -> list[str]:
    """逐文件字节比对；返回差异描述（空列表 = 一致）。"""
    a, b = tree_bytes(left), tree_bytes(right)
    diffs: list[str] = []
    for rel in sorted(set(a) - set(b)):
        diffs.append(f"only-left: {rel}")
    for rel in sorted(set(b) - set(a)):
        diffs.append(f"only-right: {rel}")
    for rel in sorted(set(a) & set(b)):
        if a[rel] != b[rel]:
            diffs.append(f"content: {rel}")
    return diffs
