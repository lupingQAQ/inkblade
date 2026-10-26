# -*- coding: utf-8 -*-
"""声明式评估配置（CM-12）：YAML/JSON 驱动模块/链评估矩阵与基线对比。

配置示例（YAML 子集；也可直接写 JSON）::

    name: ml-baseline
    modules:
      - sglang-admin-failopen
      - vllm-plugin-auth-bypass
    chains:
      - flat-network-admin-plane-weight-poison
    thresholds:
      fail_on: high
      fail_on_new_only: false
    baseline: baseline.json

- 自带最小 YAML 解析（映射/标量/列表/内联列表，拒绝复杂锚点），不依赖 PyYAML；
- 评估矩阵：每个模块 pass/warn/fail（按阈值），每条链 covered/fail/not-run；
- 基线：JSON 列表或 ``{findings:[...]}``，比较 key → new/fixed；
- 退出码复用 ``core/cigate.py`` 的 0/1/2/3 契约；纯只读，不执行模块。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import cigate
from .chains import load_chains
from .registry import load_modules

SEVERITIES = cigate.SEVERITIES


class EvalConfigError(ValueError):
    """配置语法/字段非法。"""


def _split_comment(line: str) -> str:
    out = []
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            out.append(ch)
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    t = text.strip()
    if t == "":
        return ""
    if t in ("null", "~"):
        return None
    if t.lower() in ("true", "yes"):
        return True
    if t.lower() in ("false", "no"):
        return False
    if (t.startswith("[") and t.endswith("]")) or (t.startswith("{") and t.endswith("}")):
        try:
            return json.loads(t)
        except ValueError:
            if t.startswith("[") and t.endswith("]"):
                inner = t[1:-1].strip()
                return [] if not inner else [_scalar(x) for x in inner.split(",")]
            raise EvalConfigError(f"无法解析内联值 {t!r}")
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        return t[1:-1]
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def loads(text: str) -> dict:
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise EvalConfigError(f"JSON 非法：{exc}") from exc
        if not isinstance(doc, dict):
            raise EvalConfigError("配置根必须是对象")
        return _validate(doc)
    lines = []
    for no, raw in enumerate(text.splitlines(), 1):
        line = _split_comment(raw)
        if not line.strip() or line.strip() in ("---", "..."):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent]:
            raise EvalConfigError(f"第 {no} 行：缩进禁止 tab")
        lines.append((indent, line.strip(), no))
    if not lines:
        raise EvalConfigError("配置为空")

    def parse_block(idx: int, indent: int):
        if idx >= len(lines):
            raise EvalConfigError("意外的配置结尾")
        is_list = lines[idx][1].startswith("-")
        if is_list:
            out: list[Any] = []
            while idx < len(lines) and lines[idx][0] == indent and lines[idx][1].startswith("-"):
                rest = lines[idx][1][1:].strip()
                idx += 1
                if rest:
                    out.append(_scalar(rest))
                else:
                    if idx < len(lines) and lines[idx][0] > indent:
                        child, idx = parse_block(idx, lines[idx][0])
                        out.append(child)
                    else:
                        out.append(None)
                if idx < len(lines) and lines[idx][0] < indent:
                    break
            return out, idx
        out_d: dict[str, Any] = {}
        while idx < len(lines) and lines[idx][0] == indent:
            content = lines[idx][1]
            if content.startswith("-"):
                raise EvalConfigError(f"第 {lines[idx][2]} 行：映射中出现列表项")
            key, sep, value = content.partition(":")
            if not sep or not key.strip():
                raise EvalConfigError(f"第 {lines[idx][2]} 行：缺少 key:")
            key = key.strip()
            value = value.strip()
            idx += 1
            if value:
                out_d[key] = _scalar(value)
            elif idx < len(lines) and lines[idx][0] > indent:
                out_d[key], idx = parse_block(idx, lines[idx][0])
            else:
                out_d[key] = {}
            if idx < len(lines) and lines[idx][0] < indent:
                break
        if idx < len(lines) and lines[idx][0] > indent:
            raise EvalConfigError(f"第 {lines[idx][2]} 行：缩进不一致")
        return out_d, idx

    doc, consumed = parse_block(0, lines[0][0])
    if consumed != len(lines):
        raise EvalConfigError(f"第 {lines[consumed][2]} 行起无法解析")
    if not isinstance(doc, dict):
        raise EvalConfigError("配置根必须是对象")
    return _validate(doc)


def _validate(doc: dict) -> dict:
    out = dict(doc)
    out["name"] = str(out.get("name") or "config")
    for key in ("modules", "chains"):
        value = out.get(key)
        if value is None:
            out[key] = []
        elif not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise EvalConfigError(f"{key} 必须是字符串列表")
    if not out["modules"] and not out["chains"]:
        raise EvalConfigError("modules 与 chains 不能同时为空")
    thresholds = out.get("thresholds") or {}
    if not isinstance(thresholds, dict):
        raise EvalConfigError("thresholds 必须是对象")
    fail_on = str(thresholds.get("fail_on") or "high").lower()
    if fail_on not in SEVERITIES:
        raise EvalConfigError(f"thresholds.fail_on 非法：{fail_on}")
    out["thresholds"] = {"fail_on": fail_on,
                         "fail_on_new_only": bool(thresholds.get("fail_on_new_only", False)),
                         "allow_novel": bool(thresholds.get("allow_novel", False))}
    baseline = out.get("baseline")
    if baseline is not None and not isinstance(baseline, (str, list, dict)):
        raise EvalConfigError("baseline 必须是路径/列表/对象")
    return out


def load(path: Path | str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise EvalConfigError(f"配置文件不存在：{p}")
    doc = loads(p.read_text(encoding="utf-8"))
    doc["_path"] = str(p)
    return doc


def _baseline_keys(doc: dict, config: dict) -> set[str]:
    raw = config.get("baseline")
    if raw is None:
        return set()
    if isinstance(raw, str):
        base = Path(raw)
        if not base.is_absolute() and config.get("_path"):
            base = Path(config["_path"]).parent / raw
        if not base.is_file():
            raise EvalConfigError(f"基线文件不存在：{base}")
        raw = json.loads(base.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("findings") or raw.get("keys") or []
    if not isinstance(raw, list):
        raise EvalConfigError("baseline 内容必须是列表")
    return {cigate.finding_key(x) if isinstance(x, dict) else str(x) for x in raw}


def evaluate(store, config: dict, *, run: str = "",
             modules_dir: Path | str | None = None,
             chains_dir: Path | str | None = None) -> dict:
    config = _validate(config)
    if not run:
        runs = sorted((p.name for p in Path(store.ws_dir).iterdir()
                       if p.is_dir() and not p.name.startswith("_")
                       and (p / "evidence.db").is_file()),
                      key=lambda n: (Path(store.ws_dir) / n).stat().st_mtime)
        if not runs:
            raise EvalConfigError("工作区无 run 可评估")
        run = runs[-1]
    try:
        r = store.open_run(run)
    except KeyError as exc:
        raise EvalConfigError(f"run 不存在：{run}") from exc
    findings = r.findings
    step_keys = {row[0] for row in r.query("SELECT step_key FROM steps")}
    mods = load_modules(modules_dir or Path(store.root) / "modules") \
        if (modules_dir or (Path(store.root) / "modules").exists()) else {}
    chains = load_chains(chains_dir or Path(__file__).resolve().parent.parent / "chains")
    threshold = config["thresholds"]["fail_on"]
    rank = SEVERITIES.index(threshold)

    def status_of(items: list[dict]) -> tuple[str, int, int]:
        above = [f for f in items
                 if SEVERITIES.index(str(f.get("severity", "info")).lower()) >= rank]
        if above:
            return "fail", len(items), len(above)
        return ("warn" if items else "pass"), len(items), 0

    matrix = {"modules": [], "chains": []}
    for module in config["modules"]:
        items = [f for f in findings if f.get("step_key") == module]
        status, total, above = status_of(items)
        matrix["modules"].append({"module": module, "status": status,
                                  "findings": total, "above_threshold": above,
                                  "ran": module in step_keys,
                                  "min_level": getattr(mods.get(module), "min_level", "")})
    for cid in config["chains"]:
        chain = chains.get(cid)
        if chain is None:
            matrix["chains"].append({"chain": cid, "status": "unknown", "reason": "未知链"})
            continue
        needed = {st.get("module") for st in chain.get("steps", [])}
        covered = needed <= step_keys if needed else False
        items = [f for f in findings if f.get("step_key") in needed]
        status, total, above = status_of(items)
        if not covered:
            status = "not-run"
        matrix["chains"].append({"chain": cid, "status": status, "findings": total,
                                 "above_threshold": above, "covered": covered,
                                 "modules": sorted(needed)})
    baseline = _baseline_keys(store, config)
    policy = {"fail_on": threshold,
              "fail_on_new_only": config["thresholds"]["fail_on_new_only"],
              "allow_novel": config["thresholds"]["allow_novel"]}
    if config.get("baseline") is not None:
        policy["baseline"] = sorted(baseline)
    gate = cigate.evaluate(findings, policy)
    keys = {cigate.finding_key(f) for f in findings}
    return {"config": config["name"], "run": run, "matrix": matrix,
            "thresholds": config["thresholds"], "gate": gate,
            "baseline": {"size": len(baseline),
                         "new": sorted(keys - baseline),
                         "fixed": sorted(baseline - keys)},
            "counts": {"modules": len(matrix["modules"]), "chains": len(matrix["chains"]),
                       "fail": sum(1 for x in matrix["modules"] + matrix["chains"]
                                   if x.get("status") == "fail")}}


def render_md(result: dict) -> str:
    lines = [f"# 评估矩阵：{result.get('config')}", "",
             f"- Run: `{result.get('run')}`",
             f"- Gate: **{result.get('gate', {}).get('summary', {}).get('gate')}** "
             f"(exit {result.get('gate', {}).get('exit_code')})", "",
             "| 类型 | 对象 | 状态 | 发现 | 超阈值 |", "|---|---|---|---|---|"]
    for m in result.get("matrix", {}).get("modules", []):
        lines.append(f"| module | {m['module']} | {m['status']} | {m['findings']} | {m['above_threshold']} |")
    for c in result.get("matrix", {}).get("chains", []):
        lines.append(f"| chain | {c['chain']} | {c['status']} | {c.get('findings', 0)} | "
                     f"{c.get('above_threshold', 0)} |")
    lines += ["", f"基线：新增 {len(result.get('baseline', {}).get('new', []))} / "
                  f"修复 {len(result.get('baseline', {}).get('fixed', []))}"]
    return "\n".join(lines) + "\n"
