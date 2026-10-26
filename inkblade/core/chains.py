"""链引擎：链目录加载校验 + 前置三态判定（自实现安全表达式求值，禁 eval）+ dry-run + 并行执行。

表达式子集（严格白名单文法）：
    findings('<module-key>').count <op> <number>
    findings('<module-key>').reachable.any(<field> <op> <value>)
    findings('<module-key>').any(<field> <op> <value>)
    上述比较可用 and / or / not / 括号 组合；value = 数字 | 单引号字符串 | true | false
field 支持点号路径（如 detail.port）。任何超出子集的表达式一律 PreconditionError。
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .registry import _KEY_RE, load_modules
from .runner import run_module

CATEGORIES = ("经典攻击链", "云侧权重桶链", "网络利用链", "深度链", "AI 网关链")

_CMP_OPS = ("==", "!=", ">=", "<=", ">", "<")


class PreconditionError(ValueError):
    """表达式超出允许子集 / 语法非法。"""


# ---------------------------------------------------------------- 表达式：词法

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<num>\d+(?:\.\d+)?)
    | (?P<str>'[^']*')
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<op>==|!=|>=|<=|>|<)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<dot>\.)
    """,
    re.X,
)


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise PreconditionError(f"位置 {pos} 起无法识别的记号: {text[pos:pos + 12]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        tokens.append((kind, m.group()))
    return tokens


# ---------------------------------------------------------------- 表达式：语法

class _Parser:
    """递归下降：or → and → not → 括号/比较 → 操作数（findings 视图/字面量）。"""

    def __init__(self, tokens: list[tuple[str, str]]):
        self.toks = tokens
        self.i = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise PreconditionError("表达式意外结束")
        self.i += 1
        return tok

    def _expect(self, kind: str) -> tuple[str, str]:
        tok = self._next()
        if tok[0] != kind:
            raise PreconditionError(f"期望 {kind}，得到 {tok[1]!r}")
        return tok

    def _ident_is(self, word: str) -> bool:
        tok = self._peek()
        return tok is not None and tok[0] == "ident" and tok[1] == word

    def _dotted_ident(self) -> str:
        """点号路径字段（如 detail.port）：ident ('.' ident)*。"""
        parts = [self._expect("ident")[1]]
        while True:
            nxt = self._peek()
            if nxt is not None and nxt[0] == "dot" and self.i + 1 < len(self.toks) \
                    and self.toks[self.i + 1][0] == "ident":
                self._next()
                parts.append(self._expect("ident")[1])
            else:
                return ".".join(parts)

    def parse(self) -> tuple:
        node = self._or_expr()
        if self._peek() is not None:
            raise PreconditionError(f"表达式尾部存在多余记号: {self._peek()[1]!r}")
        return node

    def _or_expr(self) -> tuple:
        node = self._and_expr()
        while self._ident_is("or"):
            self._next()
            node = ("or", node, self._and_expr())
        return node

    def _and_expr(self) -> tuple:
        node = self._not_expr()
        while self._ident_is("and"):
            self._next()
            node = ("and", node, self._not_expr())
        return node

    def _not_expr(self) -> tuple:
        if self._ident_is("not"):
            self._next()
            return ("not", self._not_expr())
        tok = self._peek()
        if tok is not None and tok[0] == "lparen":
            self._next()
            node = self._or_expr()
            self._expect("rparen")
            return node
        return self._comparison()

    def _comparison(self) -> tuple:
        left = self._operand()
        tok = self._peek()
        if tok is not None and tok[0] == "op":
            op = self._next()[1]
            right = self._operand()
            return ("cmp", op, left, right)
        if left[0] in ("any", "reachable_any", "bool"):
            return left  # 布尔值可直接参与 and/or/not
        raise PreconditionError("操作数缺少比较运算符（仅允许白名单比较与 any 判定）")

    def _operand(self) -> tuple:
        tok = self._peek()
        if tok is None:
            raise PreconditionError("缺少操作数")
        kind, text = self._next()
        if kind == "num":
            return ("lit", float(text) if "." in text else int(text))
        if kind == "str":
            return ("lit", text[1:-1])
        if kind == "ident" and text in ("true", "false"):
            return ("bool", text == "true")
        if kind == "ident" and text == "findings":
            return self._findings_expr()
        raise PreconditionError(f"不允许的操作数 {text!r}（仅 findings(...)/数字/字符串/布尔）")

    def _findings_expr(self) -> tuple:
        self._expect("lparen")
        key = self._expect("str")[1][1:-1]
        self._expect("rparen")
        self._expect("dot")
        attr = self._expect("ident")[1]
        if attr == "count":
            return ("count", key)
        if attr in ("any", "reachable"):
            scope = "any"
            if attr == "reachable":
                self._expect("dot")
                if self._expect("ident")[1] != "any":
                    raise PreconditionError("reachable 后仅允许 .any(...)")
                scope = "reachable_any"
            field, op, value = self._inner_predicate()
            return (scope, key, field, op, value)
        raise PreconditionError(f"不支持的属性 .{attr}（仅 count / any / reachable.any）")

    def _inner_predicate(self) -> tuple[str, str, Any]:
        self._expect("lparen")
        field = self._dotted_ident()
        op = self._expect("op")[1]
        kind, text = self._next()
        if kind == "num":
            value: Any = float(text) if "." in text else int(text)
        elif kind == "str":
            value = text[1:-1]
        elif kind == "ident" and text in ("true", "false"):
            value = text == "true"
        else:
            raise PreconditionError(f"谓词值非法: {text!r}")
        self._expect("rparen")
        return field, op, value


def _compile(expr: str) -> tuple:
    return _Parser(_tokenize(expr)).parse()


# ---------------------------------------------------------------- 表达式：求值

def _select(findings: list[dict], key: str) -> list[dict]:
    return [f for f in findings if f.get("step_key") == key or f.get("module") == key]


def _get_path(item: Any, dotted: str) -> Any:
    cur = item
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _cmp(left: Any, op: str, right: Any) -> bool:
    try:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if left is None or right is None:
            return False
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
    except TypeError:
        return False
    raise PreconditionError(f"未知比较运算符 {op}")


def _eval(node: tuple, findings: list[dict]) -> Any:
    tag = node[0]
    if tag == "lit":
        return node[1]
    if tag == "bool":
        return node[1]
    if tag == "count":
        return len(_select(findings, node[1]))
    if tag == "any":
        _, key, field, op, value = node
        return any(_cmp(_get_path(f, field), op, value) for f in _select(findings, key))
    if tag == "reachable_any":
        _, key, field, op, value = node
        for f in _select(findings, key):
            entries = f.get("reachable") or []
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and _cmp(_get_path(entry, field), op, value):
                        return True
        return False
    if tag == "cmp":
        _, op, left, right = node
        return _cmp(_eval(left, findings), op, _eval(right, findings))
    if tag == "and":
        return bool(_eval(node[1], findings)) and bool(_eval(node[2], findings))
    if tag == "or":
        return bool(_eval(node[1], findings)) or bool(_eval(node[2], findings))
    if tag == "not":
        return not bool(_eval(node[1], findings))
    raise PreconditionError(f"未知节点 {tag}")


def evaluate_expression(expr: str, findings: list[dict]) -> bool:
    """安全求值：仅白名单文法，任何越界表达式抛 PreconditionError（绝不 eval）。"""
    return bool(_eval(_compile(expr), list(findings or [])))


# ---------------------------------------------------------------- 目录加载

def _validate_chain(chain: dict, filename: str) -> None:
    for k in ("id", "title", "requires", "preconditions", "steps"):
        if k not in chain:
            raise ValueError(f"{filename}: 缺字段 {k}")
    if not _KEY_RE.match(chain["id"]) or filename != f"{chain['id']}.json":
        raise ValueError(f"{filename}: 链机器键须纯小写单词、与文件名一致且禁数字")
    if chain.get("category") not in CATEGORIES:
        raise ValueError(f"{filename}: 未知链类别 {chain.get('category')!r}")
    if not (isinstance(chain["title"], dict) and "zh" in chain["title"] and "en" in chain["title"]):
        raise ValueError(f"{filename}: title 须含 zh/en")
    for req in chain["requires"]:
        if not _KEY_RE.match(req):
            raise ValueError(f"{filename}: 依赖机器键非法 {req!r}")
    if not chain["steps"]:
        raise ValueError(f"{filename}: steps 为空")
    ids: set[str] = set()
    for st in chain["steps"]:
        if not _KEY_RE.match(st.get("module", "")):
            raise ValueError(f"{filename}: 步骤机器键非法 {st.get('module')!r}")
        sid = st.get("id", st["module"])
        if sid in ids:
            raise ValueError(f"{filename}: 步骤 id 重复 {sid}")
        ids.add(sid)
    # 依赖引用 + 环检测
    graph = {st.get("id", st["module"]): list(st.get("depends_on", [])) for st in chain["steps"]}
    state: dict[str, int] = {}

    def visit(node: str) -> None:
        if state.get(node) == 1:
            raise ValueError(f"{filename}: 步骤依赖成环 {node}")
        if state.get(node) == 2:
            return
        state[node] = 1
        for dep in graph[node]:
            if dep not in graph:
                raise ValueError(f"{filename}: depends_on 引用不存在步骤 {dep}")
            visit(dep)
        state[node] = 2

    for sid in graph:
        visit(sid)
    for pre in chain["preconditions"]:
        expr = pre["expr"] if isinstance(pre, dict) else str(pre)
        try:
            _compile(expr)
        except PreconditionError as exc:
            raise ValueError(f"{filename}: 前置表达式非法: {expr}（{exc}）") from exc


def load_chains(chains_dir: Path | str, *, skip_invalid: bool = False) -> dict[str, dict]:
    """加载目录内全部链定义（<id>.json），加载即校验（命名/结构/表达式/依赖图）。

    skip_invalid=True 仅用于实验/效果验证：跳过并行在途或损坏的链文件，
    生产 CLI/规则生成必须保持默认 False（显式失败，不静默降级）。
    """
    root = Path(chains_dir)
    chains: dict[str, dict] = {}
    if not root.exists():
        return chains
    for p in sorted(root.glob("*.json")):
        raw = json.loads(p.read_text(encoding="utf-8"))
        try:
            _validate_chain(raw, p.name)
        except ValueError:
            if skip_invalid:
                continue
            raise
        chains[raw["id"]] = raw
    return chains


# ---------------------------------------------------------------- 前置判定

def evaluate_preconditions(chain: dict, findings: list[dict]) -> tuple[str, list[str]]:
    """三态判定：成立（全部满足/零前置）/ 部分成立（至少一条满足）/ 不成立（全不满足）。

    返回 (verdict, missing)，missing 为未满足前提的原始表达式清单。
    """
    fs = list(findings or [])
    missing: list[str] = []
    satisfied = 0
    total = 0
    for pre in chain.get("preconditions", []):
        expr = pre["expr"] if isinstance(pre, dict) else str(pre)
        total += 1
        if evaluate_expression(expr, fs):
            satisfied += 1
        else:
            missing.append(expr)
    if total == 0 or satisfied == total:
        return "成立", missing
    if satisfied > 0:
        return "部分成立", missing
    return "不成立", missing


def _assess_for_chain(chain: dict, inventory: dict | None,
                      applicability: dict | None,
                      catalog_path: str | Path | None) -> dict | None:
    """链执行前的适用性评估；显式 applicability 优先，其次 inventory。"""
    if applicability is not None:
        return applicability
    if inventory is None:
        return None
    from .applicability import assess_cves

    return assess_cves(inventory, catalog_path=catalog_path)


# ---------------------------------------------------------------- dry-run

def dry_run(chain: dict, findings: list[dict], modules_dir: Path | str | None = None,
            *, inventory: dict | None = None, applicability: dict | None = None,
            catalog_path: str | Path | None = None,
            surface_ctx=None) -> dict:
    """渲染完整执行计划：模块/参数/目标/依赖/备份动作/预计写面 + CVE 适用性依据。

    只对 ``applicable`` 的 CVE 开放对应模块；``blocked/unknown/not-applicable``
    在步骤上标记 status 与缺失条件（dry-run 不执行，故保留计划供审阅）。
    """
    verdict, missing = evaluate_preconditions(chain, findings)
    assessment = _assess_for_chain(chain, inventory, applicability, catalog_path)
    mods = load_modules(modules_dir) if modules_dir else {}
    steps: list[dict] = []
    gates: list[dict] = []
    for st in chain.get("steps", []):
        meta = mods.get(st["module"])
        params = dict(st.get("params", {}))
        targets = list(st.get("backup_targets", params.get("backup_targets", [])))
        # 写面标志以注册表为准；模块族未落地时回退链内声明
        writes = bool(meta.writes) if meta is not None else bool(st.get("writes", False))
        gate = None
        if assessment is not None:
            from .applicability import gate_module

            gate = gate_module(assessment, st["module"])
            gates.append(gate)
        entry: dict[str, Any] = {
            "id": st.get("id", st["module"]),
            "module": st["module"],
            "params": params,
            "target": st.get("target") or params.get("target") or "",
            "depends_on": list(st.get("depends_on", [])),
            "writes": writes,
            "status": "ready",
        }
        if gate is not None:
            entry["applicability"] = gate
            if gate.get("gated") and not gate.get("allow"):
                entry["status"] = "blocked"
                entry["blocked_reason"] = (
                    f"CVE 适用性闸门：{gate.get('state')}；"
                    + "；".join(gate.get("basis") or [])[:500]
                )
        if surface_ctx is not None and meta is not None:
            from .surface import gate as surface_gate

            sgate = surface_gate(meta, surface_ctx)
            entry["surface"] = sgate
            if sgate["status"] != "run":
                entry["status"] = "blocked"
                entry["blocked_reason"] = sgate["reason"]
        elif meta is not None and not meta.default_enabled:
            entry["status"] = "blocked"
            entry["blocked_reason"] = (
                "default_enabled=false（真实面隔离模块）；需显式 --profile/--collect 或 --probe")
        if writes:
            entry["backup_targets"] = targets
            entry["backup_actions"] = [{"action": "snapshot", "target": t} for t in targets]
            surface = []
            for t in targets:
                if isinstance(t, dict):
                    surface.append(str(t.get("path") or t.get("url") or t))
                else:
                    surface.append(str(t))
            entry["write_surface"] = surface
            if not targets:
                entry["gate"] = "备份闸门：写类步骤缺少 backup_targets，执行将被拒绝（退出码 91）"
        else:
            entry["backup_targets"] = []
            entry["backup_actions"] = []
            entry["write_surface"] = []
        steps.append(entry)
    from .applicability import gate_chain

    applicability_doc = gate_chain(chain, assessment)
    result: dict[str, Any] = {
        "chain": chain["id"],
        "title": chain.get("title", {}),
        "category": chain.get("category", ""),
        "verdict": verdict,
        "missing": missing,
        "steps": steps,
        "evidence": list(chain.get("evidence", [])),
        "mitre": list(chain.get("mitre", [])),
        "applicability": applicability_doc,
        "applicability_basis": applicability_doc.get("basis") or [],
    }
    if chain.get("objective"):
        obj = chain["objective"] if isinstance(chain["objective"], dict) else {}
        result["objective"] = {
            "highest_privilege": obj.get("highest_privilege") or "",
            "stages": len(obj.get("stages") or []),
            "hardware_gates": obj.get("hardware_gates") or [],
            "applicability": applicability_doc,
        }
    return result


# ---------------------------------------------------------------- 执行

def execute(
    chain: dict,
    store,
    session,
    modules_dir: Path | str,
    findings: list[dict] | None = None,
    workers: int = 4,
    run=None,
    strict: bool = False,
    *,
    inventory: dict | None = None,
    applicability: dict | None = None,
    catalog_path: str | Path | None = None,
    surface_ctx=None,
) -> dict:
    """执行链：无依赖步骤并行（ThreadPoolExecutor），依赖分支串行；依赖失败 → 下游跳过。

    全部步骤共用一个证据 run；单步经 runner（授权闸门 + 备份闸门 + 三层落证）。
    strict=True 时前置判定非「成立」即拒绝执行。
    CVE 适用性闸门：只对 applicable 的 CVE 开放对应模块；blocked/unknown 步骤
    记录 skipped 与缺失条件，不进入 runner。
    """
    verdict, missing = evaluate_preconditions(chain, findings or [])
    if strict and verdict != "成立":
        raise PreconditionError(f"链 {chain['id']} 前置判定 {verdict}，缺失: {missing}")
    assessment = _assess_for_chain(chain, inventory, applicability, catalog_path)
    step_gates: dict[str, dict] = {}
    if assessment is not None:
        from .applicability import gate_module

        for st in chain["steps"]:
            step_gates[st.get("id", st["module"])] = gate_module(assessment, st["module"])
    if run is None:
        run = store.create_run(f"chain-{chain['id']}-{time.strftime('%Y%m%d-%H%M%S')}")
    run.log_action(session.name, "chain", chain["id"],
                   {"verdict": verdict,
                    "applicability": (assessment or {}).get("summary") or {}},
                   verdict)

    steps = {st.get("id", st["module"]): st for st in chain["steps"]}
    deps = {sid: list(st.get("depends_on", [])) for sid, st in steps.items()}
    results: dict[str, dict] = {}
    lock = threading.Lock()

    def _record(sid: str, status: str, **payload) -> None:
        with lock:
            results[sid] = {"status": status, **payload}

    def _run_step(sid: str, st: dict) -> None:
        gate = step_gates.get(sid)
        if gate is not None and gate.get("gated") and not gate.get("allow"):
            reason = (f"CVE 适用性闸门：{gate.get('state')}；"
                      + "；".join(gate.get("basis") or [])[:500])
            _record(sid, "skipped", reason=reason, applicability=gate)
            try:
                run.log_action(session.name, "execute", st["module"],
                               dict(st.get("params", {})), "skipped-cve-applicability")
            except Exception:
                pass
            return
        try:
            res = run_module(store, session, st["module"], dict(st.get("params", {})),
                             modules_dir, run=run, surface_ctx=surface_ctx)
            if res.get("skipped"):
                _record(sid, "skipped", reason=res.get("summary", ""),
                        result=res,
                        **({"applicability": gate} if gate is not None else {}))
                return
            _record(sid, "success", result=res,
                    **({"applicability": gate} if gate is not None else {}))
        except Exception as exc:  # 单步失败不拖垮独立分支
            _record(sid, "failed", error=f"{type(exc).__name__}: {exc}",
                    **({"applicability": gate} if gate is not None else {}))

    pending = set(steps)
    done: set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        while pending:
            ready = [sid for sid in pending
                     if all(results.get(d, {}).get("status") == "success" for d in deps[sid])]
            blocked = [sid for sid in pending if sid not in ready and any(
                d in done and results.get(d, {}).get("status") != "success" for d in deps[sid])]
            for sid in blocked:
                _record(sid, "skipped", reason="依赖步骤未成功")
                done.add(sid)
            pending -= set(blocked)
            if ready:
                futs = {pool.submit(_run_step, sid, steps[sid]): sid for sid in ready}
                for fut in as_completed(futs):
                    fut.result()  # _run_step 已捕获全部异常，这里只等待
                done |= set(ready)
                pending -= set(ready)
            elif pending:
                raise ValueError(f"链 {chain['id']} 步骤依赖存在环: {sorted(pending)}")

    ok = len(results) == len(steps) and all(r["status"] == "success" for r in results.values())
    from .applicability import gate_chain

    return {
        "chain": chain["id"],
        "run": run.name,
        "verdict": verdict,
        "missing": missing,
        "steps": results,
        "ok": ok,
        "applicability": gate_chain(chain, assessment),
    }
