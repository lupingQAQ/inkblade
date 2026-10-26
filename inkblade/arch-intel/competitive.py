# -*- coding: utf-8 -*-
"""arch-intel/competitive.py — 竞品对比矩阵（docs/COMPETITIVE-MATRIX.md）结构与来源校验。

解析与校验四类表（按表头识别，不依赖章节编号，便于 fixture 注入测试）：
- 登记表（工具全集）：表头含「工具」「来源」「核验」；每行必须有来源（http(s) URL 或本地克隆
  .slim/clonedeps 路径）与核验日期（YYYY-MM-DD）。不得编造能力 → 矩阵单元只允许五个判定标记。
- 矩阵表（维度×工具，按类分表）：表头首列为「维度」且含「Trident」基准列；单元标记 ∈ MARKS。
  所有矩阵表的工具列并集必须等于登记表工具全集（每个竞品都有自己的列）。
- 启示表（每工具一行）：表头含「工具」与「对我们启示」；行集必须与登记表工具全集一致。
- Backlog 表（补齐项，只登记不实施）：表头含「ID」「工作量」「重叠」；ID 前缀 CM- 且唯一、
  工作量 ∈ {S,M,L}、对应维度必须是矩阵中出现过的维度键（D# 前缀）。

MARKS 口径（官方文档为准，不臆断）：
- ✓  官方文档明证支持
- ◐  部分支持（有边界/有条件/域内近似）
- ○  官方文档明示无 / 静态扫描器无此能力
- —  类别外（防御产品的攻击维度、攻击产品的防御维度等）
- ?  官方文档未提及（未核实，不视为支持）

用法：python trident/arch-intel/competitive.py [docs/COMPETITIVE-MATRIX.md]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

MARKS = frozenset({"✓", "◐", "○", "—", "?"})
EFFORTS = frozenset({"S", "M", "L"})
BACKLOG_ID_RE = re.compile(r"^CM-\d{2,}$")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DIM_RE = re.compile(r"^(D\d+)\s+(\S+.*)$")


def _split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_sep(cells: list[str]) -> bool:
    return bool(cells) and all(set(c) <= set("-: ") for c in cells)


def _tables(text: str) -> list[list[list[str]]]:
    """按空行/非表格行切分出的所有 markdown 表（含表头行）。"""
    tables: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("|"):
            cells = _split_row(line)
            if _is_sep(cells):
                continue
            current.append(cells)
        else:
            if len(current) >= 2:  # 表头 + 至少一行数据
                tables.append(current)
            current = []
    if len(current) >= 2:
        tables.append(current)
    return tables


def _header(table: list[list[str]]) -> list[str]:
    return table[0]


# ---------------------------------------------------------------- 各表解析

def _head_has(head: list[str], needle: str) -> bool:
    return any(needle in h for h in head)


def parse_registry(text: str) -> list[dict[str, str]]:
    """工具全集表 → [{tool, category, form, anchor, source, verified}]。"""
    rows: list[dict[str, str]] = []
    for table in _tables(text):
        head = _header(table)
        if _head_has(head, "工具") and _head_has(head, "来源") and _head_has(head, "核验"):
            idx = {k: head.index(k) for k in ("工具", "类别", "形态与许可", "版本/核验锚点", "来源", "核验日期") if k in head}
            for cells in table[1:]:
                rows.append({k: (cells[i] if i < len(cells) else "") for k, i in idx.items()})
            break  # 只取第一个登记表
    return rows


def parse_matrix(text: str) -> list[dict]:
    """矩阵表（可能多张，按类分表）→ 每张 {dimensions, columns, cells}。"""
    out: list[dict] = []
    for table in _tables(text):
        head = _header(table)
        if head and head[0] == "维度" and "Trident" in head:
            cols = head[1:]
            dims: list[str] = []
            cells: dict[str, dict[str, str]] = {}
            for row in table[1:]:
                key = row[0] if row else ""
                dims.append(key)
                cells[key] = {cols[i]: (row[i + 1] if i + 1 < len(row) else "")
                              for i in range(len(cols))}
            out.append({"dimensions": dims, "columns": cols, "cells": cells})
    return out


def parse_insights(text: str) -> list[dict[str, str]]:
    """启示表（每工具一行）→ [{tool, category, insight}]。"""
    rows: list[dict[str, str]] = []
    for table in _tables(text):
        head = _header(table)
        if _head_has(head, "工具") and _head_has(head, "对我们启示"):
            idx = {k: head.index(k) for k in ("工具", "类别", "对我们启示：补齐项（映射模块/功能键）") if k in head}
            for cells in table[1:]:
                rows.append({k: (cells[i] if i < len(cells) else "") for k, i in idx.items()})
            break
    return rows


def parse_backlog(text: str) -> list[dict[str, str]]:
    """Backlog 表 → [{id, summary, dimension, effort, overlap, from}]。"""
    rows: list[dict[str, str]] = []
    for table in _tables(text):
        head = _header(table)
        if _head_has(head, "ID") and _head_has(head, "工作量") and _head_has(head, "重叠"):
            idx = {k: head.index(k) for k in ("ID", "一句话", "对应维度", "工作量", "重叠标注", "来源工具") if k in head}
            for cells in table[1:]:
                rows.append({k: (cells[i] if i < len(cells) else "") for k, i in idx.items()})
            break
    return rows


# ---------------------------------------------------------------- 校验

def verify(text: str, *, min_tools: int = 23, min_dims: int = 18) -> dict:
    """校验矩阵文档结构/来源/维度覆盖；返回 {ok, errors, stats}。"""
    errors: list[str] = []

    registry = parse_registry(text)
    matrix = parse_matrix(text)
    insights = parse_insights(text)
    backlog = parse_backlog(text)

    # 1) 登记表：来源字段 + 核验日期
    if len(registry) < min_tools:
        errors.append(f"登记表工具数 {len(registry)} < 最低要求 {min_tools}")
    reg_tools = {r.get("工具", "") for r in registry}
    if len(reg_tools) != len(registry):
        errors.append("登记表存在重复工具行")
    for r in registry:
        src = r.get("来源", "")
        if not (src.startswith("http") or ".slim/clonedeps" in src):
            errors.append(f"[{r.get('工具', '?')}] 来源字段缺失或既非 URL 也非本地克隆: {src!r}")
        if not DATE_RE.search(r.get("核验日期", "")):
            errors.append(f"[{r.get('工具', '?')}] 核验日期缺失或格式错误: {r.get('核验日期', '')!r}")

    # 2) 矩阵：维度覆盖 / 标记合法 / Trident 基准列 / 工具列并集
    all_dims: list[str] = []
    matrix_tools: set[str] = set()
    per_table_dims: list[set[str]] = []
    for i, m in enumerate(matrix, 1):
        if "Trident" not in m["columns"]:
            errors.append(f"矩阵表 {i} 缺少 Trident 基准列")
        per_table_dims.append(set(m["dimensions"]))
        all_dims.extend(m["dimensions"])
        for dim, row_cells in m["cells"].items():
            if not DIM_RE.match(dim):
                errors.append(f"矩阵表 {i} 维度键格式错误（应为 'D# 名称'）: {dim!r}")
            for col, mark in row_cells.items():
                if mark not in MARKS:
                    errors.append(f"矩阵表 {i} [{dim}/{col}] 非法判定标记: {mark!r}")
        matrix_tools.update(c for c in m["columns"] if c != "Trident")
    dim_set = set(all_dims)
    if len(dim_set) < min_dims:
        errors.append(f"矩阵维度数 {len(dim_set)} < 最低要求 {min_dims}")
    if per_table_dims and any(d != per_table_dims[0] for d in per_table_dims[1:]):
        errors.append("各矩阵表维度键集合不一致（同一维度应出现在每张分类表）")
    missing_cols = reg_tools - matrix_tools
    if missing_cols:
        errors.append(f"以下登记工具在矩阵中无列: {sorted(missing_cols)}")
    extra_cols = matrix_tools - reg_tools
    if extra_cols:
        errors.append(f"矩阵存在未登记的工具列: {sorted(extra_cols)}")

    # 3) 启示表：与登记表工具集一致，非空
    ins_tools = [r.get("工具", "") for r in insights]
    if set(ins_tools) != reg_tools:
        only_reg = sorted(reg_tools - set(ins_tools))
        only_ins = sorted(set(ins_tools) - reg_tools)
        errors.append(f"启示表与登记表工具集不一致（缺: {only_reg} 多: {only_ins}）")
    for r in insights:
        if not r.get("对我们启示：补齐项（映射模块/功能键）", "").strip():
            errors.append(f"[{r.get('工具', '?')}] 启示列为空")

    # 4) Backlog：ID/工作量/维度映射
    ids = [b.get("ID", "") for b in backlog]
    if len(ids) != len(set(ids)):
        errors.append("Backlog 存在重复 ID")
    dim_keys = {d.split()[0] for d in dim_set if d.split()}
    for b in backlog:
        bid = b.get("ID", "")
        if not BACKLOG_ID_RE.match(bid):
            errors.append(f"Backlog ID 格式错误（应为 CM-NN）: {bid!r}")
        if b.get("工作量", "") not in EFFORTS:
            errors.append(f"[{bid}] 工作量必须为 S/M/L: {b.get('工作量', '')!r}")
        d = b.get("对应维度", "")
        key = d.split("，")[0].split(",")[0].split()[0] if d else ""
        if key not in dim_keys:
            errors.append(f"[{bid}] 对应维度 {d!r} 未出现在矩阵维度中")
        if not b.get("一句话", "").strip():
            errors.append(f"[{bid}] 一句话描述为空")

    effort_counts = {e: sum(1 for b in backlog if b.get("工作量") == e) for e in ("S", "M", "L")}
    overlap = sum(1 for b in backlog if "gen-27" in b.get("重叠标注", ""))
    stats = {
        "tools": len(registry),
        "categories": len(matrix),
        "dimensions": len(dim_set),
        "insights": len(insights),
        "backlog_total": len(backlog),
        "backlog_effort": effort_counts,
        "backlog_overlap_gen27": overlap,
    }
    return {"ok": not errors, "errors": errors, "stats": stats}


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows 控制台 cp1252 兜底
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2] / "docs" / "COMPETITIVE-MATRIX.md"
    result = verify(path.read_text(encoding="utf-8"))
    import json

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        print(f"FAIL: {len(result['errors'])} 处结构/来源错误", file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
