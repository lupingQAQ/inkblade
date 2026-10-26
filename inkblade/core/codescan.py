"""核心代码静态审计：regex + ast 双通道 sink 扫描（规则库 data/sink-rules.json）。"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent / "data" / "sink-rules.json"

# 参与扫描的源码后缀（ast 通道仅 .py；.go 为挖掘流水线对 Go 上游的 regex 通道扩展）
SOURCE_SUFFIXES = {".py", ".go", ".yaml", ".yml", ".json", ".toml", ".txt", ".sh", ".cfg", ".ini", ".md"}

_skip_dirs = {"__pycache__", ".git", "node_modules", ".venv", "evidence"}


def load_rules(path: Path | str | None = None) -> dict:
    p = Path(path) if path else RULES_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# ---------- regex 通道 ----------
def scan_text_regex(text: str, rel: str, rules: list[dict]) -> list[dict]:
    hits = []
    for rule in rules:
        pattern = rule.get("regex")
        if not pattern:
            continue
        rx = re.compile(pattern)
        for lineno, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append({
                    "rule": rule["id"], "file": rel, "line": lineno,
                    "channel": "regex", "snippet": line.strip()[:160],
                })
    return hits


# ---------- ast 通道 ----------
def _call_name(node: ast.Call) -> str:
    f = node.func
    parts: list[str] = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def scan_text_ast(text: str, rel: str, rules: list[dict]) -> list[dict]:
    ast_rules = {r["id"]: r for r in rules if r.get("ast")}
    if not ast_rules:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    def emit(rule_id: str, node: ast.AST, how: str) -> dict:
        return {
            "rule": rule_id, "file": rel, "line": getattr(node, "lineno", 0),
            "channel": "ast", "snippet": how,
        }

    hits: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        bare = name.split(".")[-1]
        if bare == "eval" and "eval-call" in ast_rules:
            hits.append(emit("eval-call", node, "eval(<动态表达式>)"))
        if bare == "exec" and "exec-call" in ast_rules:
            hits.append(emit("exec-call", node, "exec(<动态语句>)"))
        if name in ("pickle.load", "pickle.loads") and "pickle-loads" in ast_rules:
            hits.append(emit("pickle-loads", node, f"{name}(<不可信字节流>)"))
        if name == "torch.load" and "torch-load-unsafe" in ast_rules:
            for kw in node.keywords:
                if kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    hits.append(emit("torch-load-unsafe", node, "torch.load(..., weights_only=False)"))
        if bare in ("import_module", "__import__") and "dynamic-import" in ast_rules:
            hits.append(emit("dynamic-import", node, f"{name}(<运行期值>)"))
    return hits


# ---------- 汇总 ----------
def scan_file(path: Path | str, root: Path | str | None = None) -> list[dict]:
    p = Path(path)
    rel = _rel(p, Path(root) if root else p.parent)
    if p.suffix not in SOURCE_SUFFIXES:
        return []
    rules = load_rules()["rules"]
    text = p.read_text(encoding="utf-8", errors="replace")
    hits = scan_text_regex(text, rel, rules)
    if p.suffix == ".py":
        hits += scan_text_ast(text, rel, rules)
    # 去重（同通道同规则同行只保留一条；跨通道保留双证据）
    seen: set[tuple] = set()
    unique: list[dict] = []
    for h in sorted(hits, key=lambda h: (h["file"], h["line"], h["rule"], h["channel"])):
        k = (h["rule"], h["file"], h["line"], h["channel"])
        if k not in seen:
            seen.add(k)
            unique.append(h)
    return unique


def scan_path(root: Path | str) -> list[dict]:
    base = Path(root)
    if base.is_file():
        return scan_file(base, root=base.parent)
    hits: list[dict] = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _skip_dirs for part in p.relative_to(base).parts[:-1]):
            continue
        hits += scan_file(p, root=base)
    return hits


def match_combos(hits: list[dict], combo_defs: list[dict]) -> list[dict]:
    """组合签名：同一文件内全部 required 规则同时命中才算成立。"""
    by_file: dict[str, set[str]] = {}
    for h in hits:
        by_file.setdefault(h["file"], set()).add(h["rule"])
    results: list[dict] = []
    for combo in combo_defs:
        required = set(combo["requires"])
        for fname, rules in sorted(by_file.items()):
            if required <= rules:
                proofs = [f"{h['file']}:{h['line']}" for h in hits
                          if h["file"] == fname and h["rule"] in required]
                results.append({
                    "id": combo["id"], "file": fname,
                    "description": combo.get("description", ""),
                    "detail": combo.get("detail", ""),
                    "evidence": sorted(set(proofs)),
                })
    return results
