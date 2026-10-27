# -*- coding: utf-8 -*-
"""Deterministic expression language for declarative probe templates.

The same grammar is implemented by the Rust probe (``probe/src/template.rs``).
Standard library only: no eval(), no regex, no third-party parser.

Grammar::

    expr    := or
    or      := and ("or" and)*
    and     := not ("and" not)*
    not     := "not" not | cmp
    cmp     := sum (("==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains"
                     | "startswith" | "endswith" | "matches") sum)?
    sum     := mul (("+" | "-") mul)*
    mul     := unary (("*" | "/" | "%") unary)*
    unary   := "-" unary | postfix
    postfix := primary ( "." NAME | "[" INT "]" | "[" "*" "]" )*
    primary := NUMBER | STRING | "true" | "false" | "null" | NAME | NAME "(" args ")" | "(" expr ")"

Paths flatten: ``a[*].b`` maps over the array and concatenates the results.
Missing values are ``null``; comparisons never raise.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


class ExprError(ValueError):
    """Syntax or evaluation error in a template expression."""


# --------------------------------------------------------------------- lexer

_PUNCT = ("==", "!=", "<=", ">=", "&&", "||", "(", ")", "[", "]", ",", ".",
          "<", ">", "+", "-", "*", "/", "%")
_KEYWORDS = {"and", "or", "not", "in", "contains", "startswith", "endswith",
             "matches", "true", "false", "null"}


@dataclass
class _Tok:
    kind: str   # num str name punct eof
    value: Any
    pos: int


def _lex(text: str) -> list[_Tok]:
    out: list[_Tok] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "0123456789":
            j = i
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            raw = text[i:j]
            try:
                value = float(raw) if "." in raw else int(raw)
            except ValueError as exc:
                raise ExprError(f"bad number at {i}: {raw}") from exc
            out.append(_Tok("num", value, i))
            i = j
            continue
        if ch in "'\"":
            quote = ch
            j = i + 1
            buf = []
            while j < n and text[j] != quote:
                if text[j] == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ExprError(f"unterminated string at {i}")
            out.append(_Tok("str", "".join(buf), i))
            i = j + 1
            continue
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_-"):
                j += 1
            word = text[i:j]
            out.append(_Tok("name", word, i))
            i = j
            continue
        for punct in _PUNCT:
            if text.startswith(punct, i):
                # `-` inside identifiers is handled by the ident branch; a lone
                # dash is subtraction/negation.
                out.append(_Tok("punct", punct, i))
                i += len(punct)
                break
        else:
            raise ExprError(f"unexpected character {ch!r} at {i}")
    out.append(_Tok("eof", None, n))
    return out


# -------------------------------------------------------------------- parser

class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = _lex(text)
        self.i = 0

    def peek(self) -> _Tok:
        return self.toks[self.i]

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def accept(self, kind: str, value: Any = None) -> bool:
        tok = self.peek()
        if tok.kind == kind and (value is None or tok.value == value):
            self.i += 1
            return True
        return False

    def expect(self, kind: str, value: Any = None) -> _Tok:
        tok = self.peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            raise ExprError(f"expected {value or kind} at {tok.pos} in {self.text!r}")
        return self.take()

    def parse(self) -> Any:
        node = self.parse_or()
        if self.peek().kind != "eof":
            raise ExprError(f"trailing token {self.peek().value!r} at {self.peek().pos}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek().kind == "name" and self.peek().value in ("or", "||") or \
                self.peek().kind == "punct" and self.peek().value == "||":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek().kind == "name" and self.peek().value in ("and", "&&") or \
                self.peek().kind == "punct" and self.peek().value == "&&":
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.peek().kind == "name" and self.peek().value == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        node = self.parse_sum()
        tok = self.peek()
        op = None
        if tok.kind == "punct" and tok.value in ("==", "!=", "<", "<=", ">", ">="):
            op = tok.value
        elif tok.kind == "name" and tok.value in ("in", "contains", "startswith",
                                                  "endswith", "matches"):
            op = tok.value
        if op is None:
            return node
        self.take()
        return ("cmp", op, node, self.parse_sum())

    def parse_sum(self):
        node = self.parse_mul()
        while self.peek().kind == "punct" and self.peek().value in ("+", "-"):
            op = self.take().value
            node = ("arith", op, node, self.parse_mul())
        return node

    def parse_mul(self):
        node = self.parse_unary()
        while self.peek().kind == "punct" and self.peek().value in ("*", "/", "%"):
            op = self.take().value
            node = ("arith", op, node, self.parse_unary())
        return node

    def parse_unary(self):
        if self.peek().kind == "punct" and self.peek().value == "-":
            self.take()
            return ("neg", self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self):
        node = self.parse_primary()
        while True:
            if self.accept("punct", "."):
                name = self.expect("name")
                node = ("member", node, name.value)
            elif self.accept("punct", "["):
                if self.accept("punct", "*"):
                    self.expect("punct", "]")
                    node = ("flat", node)
                else:
                    idx = self.expect("num")
                    self.expect("punct", "]")
                    node = ("index", node, int(idx.value))
            else:
                return node

    def parse_primary(self):
        tok = self.peek()
        if tok.kind == "num":
            self.take()
            return ("lit", tok.value)
        if tok.kind == "str":
            self.take()
            return ("lit", tok.value)
        if tok.kind == "punct" and tok.value == "(":
            self.take()
            node = self.parse_or()
            self.expect("punct", ")")
            return node
        if tok.kind == "punct" and tok.value == "[":
            self.take()
            items = []
            if not self.accept("punct", "]"):
                while True:
                    items.append(self.parse_or())
                    if self.accept("punct", ","):
                        continue
                    self.expect("punct", "]")
                    break
            return ("array", items)
        if tok.kind == "name":
            name = tok.value
            if name == "true":
                self.take()
                return ("lit", True)
            if name == "false":
                self.take()
                return ("lit", False)
            if name == "null":
                self.take()
                return ("lit", None)
            self.take()
            if self.accept("punct", "("):
                args = []
                if not self.accept("punct", ")"):
                    while True:
                        args.append(self.parse_or())
                        if self.accept("punct", ","):
                            continue
                        self.expect("punct", ")")
                        break
                return ("call", name, args)
            if name in ("and", "or", "not", "in", "contains", "startswith",
                        "endswith", "matches"):
                raise ExprError(f"operator {name!r} used as a value at {tok.pos}")
            return ("var", name)
        raise ExprError(f"unexpected token {tok.value!r} at {tok.pos}")


def parse(text: str):
    if not isinstance(text, str) or not text.strip():
        raise ExprError("empty expression")
    return _Parser(text).parse()


# ----------------------------------------------------------------- eval core

def _truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (str, list, dict, tuple)):
        return len(value) > 0
    return True


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _jsonify(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


class Evaluator:
    """Evaluates a parsed expression against a scope mapping."""

    def __init__(self, scope: dict[str, Any] | None = None):
        self.scope = scope or {}

    def eval(self, node, bindings: dict[str, Any] | None = None) -> Any:
        bindings = bindings or {}
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "array":
            return [self.eval(item, bindings) for item in node[1]]
        if kind == "var":
            name = node[1]
            if name in bindings:
                return bindings[name]
            return self.scope.get(name)
        if kind == "member":
            base = self.eval(node[1], bindings)
            return self._member(base, node[2])
        if kind == "index":
            base = self.eval(node[1], bindings)
            return self._index(base, node[2])
        if kind == "flat":
            base = self.eval(node[1], bindings)
            if isinstance(base, (list, tuple)):
                return list(base)
            return [] if base is None else [base]
        if kind == "not":
            return not _truthy(self.eval(node[1], bindings))
        if kind == "and":
            return _truthy(self.eval(node[1], bindings)) and _truthy(self.eval(node[2], bindings))
        if kind == "or":
            return _truthy(self.eval(node[1], bindings)) or _truthy(self.eval(node[2], bindings))
        if kind == "neg":
            value = _num(self.eval(node[1], bindings))
            return None if value is None else -value
        if kind == "arith":
            left = self.eval(node[2], bindings)
            right = self.eval(node[3], bindings)
            if node[1] == "+" and (isinstance(left, str) or isinstance(right, str)):
                return f"{_to_text(left)}{_to_text(right)}"
            a, b = _num(left), _num(right)
            if a is None or b is None:
                return None
            return {"+": a + b, "-": a - b, "*": a * b,
                    "/": (a / b if b else None), "%": (a % b if b else None)}[node[1]]
        if kind == "cmp":
            return self._compare(node[1], self.eval(node[2], bindings),
                                 self.eval(node[3], bindings))
        if kind == "call":
            return self._call(node[1], node[2], bindings)
        raise ExprError(f"unknown node {kind}")

    # -- accessors ---------------------------------------------------------
    @staticmethod
    def _member(base: Any, name: str) -> Any:
        if isinstance(base, dict):
            return base.get(name)
        if isinstance(base, list):
            # map over arrays of objects
            return [item.get(name) for item in base if isinstance(item, dict)]
        return None

    @staticmethod
    def _index(base: Any, index: int) -> Any:
        if isinstance(base, (list, tuple)):
            return base[index] if 0 <= index < len(base) else None
        if isinstance(base, str):
            return base[index] if 0 <= index < len(base) else None
        if isinstance(base, dict):
            return base.get(str(index))
        return None

    # -- operators ---------------------------------------------------------
    def _compare(self, op: str, left: Any, right: Any) -> Any:
        return _compare_values(op, left, right)

    def _call(self, name: str, args: list, bindings: dict[str, Any]) -> Any:
        # `any`/`all`/`count_if` bind their element lazily.
        if name in ("any", "all", "count_if", "first", "map", "filter"):
            seq = self.eval(args[0], bindings)
            items = _flatten(seq) if isinstance(seq, (list, tuple)) else []
            if name == "map":
                return [self.eval(args[1], {**bindings, "it": item}) for item in items]
            if name == "filter":
                return [item for item in items
                        if _truthy(self.eval(args[1], {**bindings, "it": item}))]
            if len(args) > 1:
                hits = [item for item in items if _truthy(self.eval(args[1], {**bindings, "it": item}))]
            else:
                hits = [item for item in items if _truthy(item)]
            if name == "any":
                return bool(hits)
            if name == "all":
                return len(hits) == len(items)
            if name == "count_if":
                return len(hits)
            return hits[0] if hits else None
        values = [self.eval(arg, bindings) for arg in args]
        return _call_pure(name, values)


def _compare_values(op: str, left: Any, right: Any) -> Any:
    if op == "==":
        return _equal(left, right)
    if op == "!=":
        return not _equal(left, right)
    if op == "in":
        if isinstance(right, str):
            return isinstance(left, str) and left in right
        if isinstance(right, (list, tuple, dict)):
            return any(_equal(left, item) for item in right)
        return False
    if op == "contains":
        if isinstance(left, str):
            return isinstance(right, str) and right in left
        if isinstance(left, (list, tuple)):
            return any(_equal(right, item) for item in _flatten(left))
        if isinstance(left, dict):
            return right in left
        return False
    if op == "startswith":
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    if op == "endswith":
        return isinstance(left, str) and isinstance(right, str) and left.endswith(right)
    if op == "matches":
        return _glob(str(right or ""), _to_text(left))
    a, b = _num(left), _num(right)
    if a is None or b is None:
        return False
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def _flatten(items) -> list:
    out = []
    for item in items if isinstance(items, (list, tuple)) else [items]:
        if isinstance(item, (list, tuple)):
            out.extend(_flatten(item))
        else:
            out.append(item)
    return out


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, (int, float)) and isinstance(right, (int, float)) \
            and not isinstance(left, bool) and not isinstance(right, bool):
        return float(left) == float(right)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    return left == right


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(_jsonify(value), ensure_ascii=False, sort_keys=True)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _glob(pattern: str, value: str) -> bool:
    """Glob match supporting * and ?. No regex, no backtracking blow-up."""
    p = i = 0
    star = -1
    match = 0
    while i < len(value):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == value[i]):
            p += 1
            i += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            match = i
            p += 1
        elif star != -1:
            p = star + 1
            match += 1
            i = match
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _call_pure(name: str, values: list) -> Any:
    if name == "len":
        value = values[0] if values else None
        if isinstance(value, (str, list, dict, tuple)):
            return len(value)
        return 0 if value is None else len(_to_text(value))
    if name == "count":
        return len(_flatten(values[0])) if values and isinstance(values[0], (list, tuple)) else 0
    if name == "int":
        number = _num(values[0] if values else None)
        return None if number is None else int(number)
    if name == "float":
        return _num(values[0] if values else None)
    if name == "str":
        return _to_text(values[0] if values else None)
    if name == "bool":
        return _truthy(values[0] if values else None)
    if name == "lower":
        return _to_text(values[0] if values else "").lower()
    if name == "upper":
        return _to_text(values[0] if values else "").upper()
    if name == "trim":
        return _to_text(values[0] if values else "").strip()
    if name == "replace":
        return _to_text(values[0]).replace(_to_text(values[1]), _to_text(values[2]))
    if name == "split":
        sep = _to_text(values[1]) if len(values) > 1 else ","
        return _to_text(values[0]).split(sep)
    if name == "join":
        sep = _to_text(values[1]) if len(values) > 1 else ","
        seq = values[0] if values and isinstance(values[0], (list, tuple)) else []
        return sep.join(_to_text(item) for item in seq)
    if name == "concat":
        out = []
        for value in values:
            if isinstance(value, (list, tuple)):
                out.extend(value)
            elif value is not None:
                out.append(value)
        return out
    if name == "keys":
        return sorted(values[0].keys()) if values and isinstance(values[0], dict) else []
    if name == "values":
        return list(values[0].values()) if values and isinstance(values[0], dict) else []
    if name == "exists":
        return bool(values) and values[0] is not None
    if name == "if":
        if len(values) < 3:
            return None
        return values[1] if _truthy(values[0]) else values[2]
    if name in ("contains", "startswith", "endswith"):
        if len(values) < 2:
            return False
        return _compare_values(name, values[0], values[1])
    if name == "matches":
        if len(values) < 2:
            return False
        return _glob(_to_text(values[0]), _to_text(values[1]))
    if name == "default":
        left = values[0] if values else None
        return left if _truthy(left) else (values[1] if len(values) > 1 else None)
    if name == "coalesce":
        for value in values:
            if _truthy(value):
                return value
        return None
    if name == "sha256":
        raw = values[0] if values else ""
        if isinstance(raw, bytes):
            return hashlib.sha256(raw).hexdigest()
        return hashlib.sha256(_to_text(raw).encode("utf-8")).hexdigest()
    if name == "b64encode":
        return base64.b64encode(_to_text(values[0] if values else "").encode("utf-8")).decode("ascii")
    if name == "b64decode":
        try:
            return base64.b64decode(_to_text(values[0] if values else "").encode("ascii")).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - malformed base64 is a null value
            return None
    if name == "json":
        raw = values[0] if values else None
        if isinstance(raw, (dict, list)):
            return raw
        try:
            return json.loads(_to_text(raw))
        except (ValueError, TypeError):
            return None
    if name == "keys_contains":
        return isinstance(values[0], dict) and _to_text(values[1]) in values[0]
    if name == "min":
        nums = [_num(v) for v in _flatten(values)] if len(values) == 1 else [_num(v) for v in values]
        nums = [n for n in nums if n is not None]
        return min(nums) if nums else None
    if name == "max":
        nums = [_num(v) for v in _flatten(values)] if len(values) == 1 else [_num(v) for v in values]
        nums = [n for n in nums if n is not None]
        return max(nums) if nums else None
    if name == "abs":
        number = _num(values[0] if values else None)
        return None if number is None else abs(number)
    if name == "sum":
        nums = [_num(v) for v in _flatten(values[0])] if values else []
        nums = [n for n in nums if n is not None]
        return sum(nums) if nums else 0
    if name == "round":
        number = _num(values[0] if values else None)
        digits = int(_num(values[1]) or 0) if len(values) > 1 else 0
        return None if number is None else round(number, digits)
    if name == "range":
        n = int(_num(values[0]) or 0) if values else 0
        return list(range(max(0, n)))
    if name == "now_ms":
        import time
        return int(time.time() * 1000)
    raise ExprError(f"unknown function {name!r}")


# --------------------------------------------------------------- public API

def evaluate(text: str, scope: dict[str, Any] | None = None,
             bindings: dict[str, Any] | None = None) -> Any:
    return Evaluator(scope).eval(parse(text), bindings)


def truthy(text: str | bool, scope: dict[str, Any] | None = None,
           bindings: dict[str, Any] | None = None) -> bool:
    if isinstance(text, bool):
        return text
    if text is None:
        return True
    return _truthy(evaluate(str(text), scope, bindings))


def render(text: Any, scope: dict[str, Any] | None = None,
           bindings: dict[str, Any] | None = None) -> str:
    """Interpolate ``{{ expr }}`` placeholders in a string."""
    if text is None:
        return ""
    if not isinstance(text, str):
        return _to_text(text)
    if "{{" not in text:
        return text
    out: list[str] = []
    i = 0
    while True:
        start = text.find("{{", i)
        if start < 0:
            out.append(text[i:])
            break
        end = text.find("}}", start + 2)
        if end < 0:
            raise ExprError(f"unterminated placeholder in {text!r}")
        out.append(text[i:start])
        expr = text[start + 2:end].strip()
        out.append(_to_text(evaluate(expr, scope, bindings)))
        i = end + 2
    return "".join(out)


def render_value(value: Any, scope: dict[str, Any] | None = None,
                 bindings: dict[str, Any] | None = None) -> Any:
    """Deep-interpolate strings inside JSON values."""
    if isinstance(value, str):
        if value.startswith("{{") and value.endswith("}}") and value.count("{{") == 1:
            inner = value[2:-2].strip()
            return evaluate(inner, scope, bindings)
        return render(value, scope, bindings)
    if isinstance(value, list):
        return [render_value(item, scope, bindings) for item in value]
    if isinstance(value, dict):
        return {key: render_value(item, scope, bindings) for key, item in value.items()}
    return value


def referenced_vars(text: str) -> set[str]:
    """Static analysis helper: top-level variable roots referenced by an expression."""
    roots: set[str] = set()
    tree = parse(text)

    def walk(node) -> None:
        if not isinstance(node, tuple):
            return
        if node[0] == "var":
            roots.add(node[1])
        elif node[0] == "call":
            for arg in node[2]:
                walk(arg)
        else:
            for child in node[1:]:
                if isinstance(child, tuple):
                    walk(child)
                elif isinstance(child, list):
                    for item in child:
                        walk(item)

    walk(tree)
    return roots


def format_number(value: Any) -> str:
    if isinstance(value, float) and math.isfinite(value):
        return str(int(value)) if value.is_integer() else str(value)
    return _to_text(value)
