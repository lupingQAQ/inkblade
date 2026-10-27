# -*- coding: utf-8 -*-
"""Loader and validator for declarative probe templates.

Templates live next to the module contract at
``inkblade/modules/<key>/template.json``.  Validation is dependency-free so the
same rules can run inside packaging, CI and the release gate.

The authoritative JSON Schema is ``probe/schema/probe-template.schema.json``;
this module enforces the semantic rules the Rust engine depends on (unique step
ids, op-specific fields, expression syntax, write/backup consistency).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .expr import ExprError, parse

SCHEMA_ID = "inkblade-probe-template-v1"
SERIES = ("侦察", "横向利用", "权限链", "窃取与数据泄露", "核心代码", "网络架构", "混合云", "情报")
LEVELS = ("只读侦察", "主动探测", "利用验证", "全影响演示")
SEVERITIES = ("info", "low", "medium", "high", "critical")
OPS = ("http", "tcp", "exec", "fs", "k8s", "socks", "spawn")
K8S_VERBS = ("get", "list", "create", "patch", "delete", "apply")
FS_ACTIONS = ("read", "list", "stat", "write", "hash")
_META_KEYS = ("key", "name", "series", "min_level", "writes", "requires")


class TemplateError(ValueError):
    """A template violates the contract."""


@dataclass
class TemplateMeta:
    key: str
    version: str
    name: dict
    series: str
    min_level: str
    writes: bool
    requires: list[str] = field(default_factory=list)
    surfaces: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    fidelity: str = "equivalent"
    steps: int = 0
    findings: int = 0
    checks: int = 0
    path: Path | None = None

    @property
    def execution(self) -> str:
        return "template"


def template_path(module_dir: Path | str) -> Path:
    return Path(module_dir) / "template.json"


def load_template(module_dir: Path | str, *, module_meta: dict | None = None) -> dict:
    path = template_path(module_dir)
    if not path.is_file():
        raise TemplateError(f"缺少 template.json: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TemplateError(f"{path}: 非法 JSON: {exc}") from exc
    errors = validate(doc, module_dir=Path(module_dir), module_meta=module_meta)
    if errors:
        raise TemplateError("; ".join(errors))
    return doc


def iter_templates(modules_dir: Path | str) -> Iterable[Path]:
    root = Path(modules_dir)
    if not root.exists():
        return []
    return sorted(p / "template.json" for p in root.iterdir()
                  if p.is_dir() and (p / "template.json").is_file())


# --------------------------------------------------------------- validation

def validate(doc: dict, *, module_dir: Path | None = None,
             module_meta: dict | None = None) -> list[str]:
    errors: list[str] = []

    def err(message: str) -> None:
        errors.append(message)

    if not isinstance(doc, dict):
        return ["template must be a JSON object"]
    if doc.get("schema") != SCHEMA_ID:
        err(f"schema 必须为 {SCHEMA_ID}")
    key = doc.get("key")
    if not isinstance(key, str) or not key:
        err("缺 key")
    elif module_dir is not None and module_dir.name != key:
        err(f"key={key} 与目录名 {module_dir.name} 不一致")
    version = doc.get("version")
    if not isinstance(version, str) or len(version.split(".")) != 3 or \
            not all(part.isdigit() for part in version.split(".")):
        err("version 必须是 x.y.z")

    meta = doc.get("meta")
    if not isinstance(meta, dict):
        err("缺 meta")
    else:
        for field_name in ("name", "series", "min_level", "writes"):
            if field_name not in meta:
                err(f"meta 缺 {field_name}")
        if meta.get("series") not in SERIES:
            err(f"meta.series 非法: {meta.get('series')!r}")
        if meta.get("min_level") not in LEVELS:
            err(f"meta.min_level 非法: {meta.get('min_level')!r}")
        name = meta.get("name")
        if not isinstance(name, dict) or not name.get("zh") or not name.get("en"):
            err("meta.name 需要 zh/en")
        if not isinstance(meta.get("writes"), bool):
            err("meta.writes 必须是布尔")
        if meta.get("fidelity", "equivalent") not in ("equivalent", "reduced"):
            err("meta.fidelity 非法")
        if module_meta:
            for field_name in _META_KEYS:
                if field_name in ("name",):
                    continue
                if field_name in module_meta and field_name in meta and \
                        module_meta[field_name] != meta[field_name]:
                    err(f"meta.{field_name} 与 module.json 不一致")
            if isinstance(name, dict):
                declared = module_meta.get("name") or {}
                if declared.get("zh") and declared.get("zh") != name.get("zh"):
                    err("meta.name.zh 与 module.json 不一致")
                if declared.get("en") and declared.get("en") != name.get("en"):
                    err("meta.name.en 与 module.json 不一致")
            if int(bool(module_meta.get("writes"))) != int(bool(meta.get("writes"))):
                err("meta.writes 与 module.json 不一致")

    # expressions -------------------------------------------------------
    def check_expr(where: str, text: Any) -> None:
        if text is None:
            return
        if not isinstance(text, str):
            err(f"{where} 必须是表达式字符串")
            return
        try:
            parse(text)
        except ExprError as exc:
            err(f"{where}: {exc}")

    def check_interp(where: str, value: Any) -> None:
        if isinstance(value, str):
            start = 0
            while True:
                begin = value.find("{{", start)
                if begin < 0:
                    return
                end = value.find("}}", begin + 2)
                if end < 0:
                    err(f"{where}: 未闭合的 {{{{ }}}}")
                    return
                check_expr(where, value[begin + 2:end].strip())
                start = end + 2
        elif isinstance(value, list):
            for item in value:
                check_interp(where, item)
        elif isinstance(value, dict):
            for item in value.values():
                check_interp(where, item)

    inputs = doc.get("inputs") or {}
    if not isinstance(inputs, dict):
        err("inputs 必须是对象")
    else:
        for name, spec in inputs.items():
            if not isinstance(spec, dict) or "from" not in spec:
                err(f"inputs.{name} 需要 from")
                continue
            check_expr(f"inputs.{name}.from", spec["from"])

    vars_map = doc.get("vars") or {}
    if not isinstance(vars_map, dict):
        err("vars 必须是对象")
    else:
        for name, value in vars_map.items():
            check_interp(f"vars.{name}", value)

    computed = doc.get("computed") or {}
    if not isinstance(computed, dict):
        err("computed 必须是对象")
    else:
        for name, text in computed.items():
            check_expr(f"computed.{name}", text)

    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        err("steps 必须是非空数组")
        steps = []
    seen: set[str] = set()
    writes = 0
    for idx, step in enumerate(steps):
        where = f"steps[{idx}]"
        if not isinstance(step, dict):
            err(f"{where} 必须是对象")
            continue
        sid = step.get("id")
        if not isinstance(sid, str) or not sid:
            err(f"{where} 缺 id")
        elif sid in seen:
            err(f"{where} id 重复: {sid}")
        else:
            seen.add(sid)
            where = f"step:{sid}"
        op = step.get("op")
        if op not in OPS:
            err(f"{where} op 非法: {op!r}")
            continue
        check_expr(f"{where}.when", step.get("when")) if step.get("when") else None
        check_interp(f"{where}.url", step.get("url"))
        check_interp(f"{where}.headers", step.get("headers"))
        check_interp(f"{where}.body", step.get("body"))
        check_interp(f"{where}.argv", step.get("argv"))
        check_interp(f"{where}.path", step.get("path"))
        check_interp(f"{where}.host", step.get("host"))
        check_interp(f"{where}.socket_path", step.get("socket_path"))
        check_interp(f"{where}.content", step.get("content"))
        check_interp(f"{where}.request", step.get("request"))
        check_interp(f"{where}.stdin", step.get("stdin"))
        check_interp(f"{where}.env", step.get("env"))
        check_interp(f"{where}.name", step.get("name"))
        check_interp(f"{where}.namespace", step.get("namespace"))
        check_interp(f"{where}.resource", step.get("resource"))
        if step.get("write"):
            writes += 1
            if op not in ("fs", "k8s", "exec", "http", "spawn"):
                err(f"{where}: 写步骤不支持 op={op}")
            if not step.get("save") and op in ("fs", "k8s"):
                err(f"{where}: 写步骤需要 save（回执/读回证据）")
        if op == "http":
            if str(step.get("method") or "").upper() not in (
                    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                err(f"{where}: http method 非法")
            if not step.get("url"):
                err(f"{where}: http 缺 url")
        elif op == "tcp":
            if not step.get("host") or not step.get("port"):
                err(f"{where}: tcp 需要 host/port")
        elif op == "exec":
            argv = step.get("argv")
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
                err(f"{where}: exec 需要 argv 字符串数组")
            if len(argv) == 1 and " " in str(argv[0]):
                err(f"{where}: exec argv 必须是分离参数（禁止 shell 字符串）")
        elif op == "fs":
            if step.get("action") not in FS_ACTIONS:
                err(f"{where}: fs action 非法")
            if step.get("action") != "list" and not step.get("path") and not step.get("glob"):
                err(f"{where}: fs 需要 path/glob")
            if step.get("action") == "write" and not step.get("content"):
                err(f"{where}: fs write 需要 content")
        elif op == "k8s":
            if step.get("verb") not in K8S_VERBS:
                err(f"{where}: k8s verb 非法")
            if not step.get("resource"):
                err(f"{where}: k8s 需要 resource")
            if step.get("verb") in ("get", "patch", "delete", "apply") and not step.get("name"):
                err(f"{where}: k8s {step.get('verb')} 需要 name")
        elif op == "socks":
            if not step.get("socket_path"):
                err(f"{where}: socks 需要 socket_path")
            if not step.get("request"):
                err(f"{where}: socks 需要 request")
        elif op == "spawn":
            argv = step.get("argv")
            if not isinstance(argv, list) or not argv:
                err(f"{where}: spawn 需要 argv")
        if op in ("exec", "spawn", "socks", "fs", "k8s") and not step.get("save") \
                and not step.get("write") and (step.get("op") != "fs" or step.get("action") != "write"):
            err(f"{where}: {op} 需要 save 以便断言/证据")

    checks = doc.get("checks") or []
    if not isinstance(checks, list):
        err("checks 必须是数组")
        checks = []
    seen_checks: set[str] = set()
    for idx, check in enumerate(checks):
        where = f"checks[{idx}]"
        if not isinstance(check, dict):
            err(f"{where} 必须是对象")
            continue
        cid = check.get("id")
        if not isinstance(cid, str) or not cid:
            err(f"{where} 缺 id")
        elif cid in seen_checks:
            err(f"{where} id 重复: {cid}")
        else:
            seen_checks.add(cid)
        if "when" not in check:
            err(f"{where} 缺 when")
        else:
            check_expr(f"{where}.when", check["when"])
        if check.get("severity") not in (None, *SEVERITIES):
            err(f"{where}.severity 非法")

    findings = doc.get("findings") or []
    if not isinstance(findings, list):
        err("findings 必须是数组")
        findings = []
    seen_findings: set[str] = set()
    for idx, finding in enumerate(findings):
        where = f"findings[{idx}]"
        if not isinstance(finding, dict):
            err(f"{where} 必须是对象")
            continue
        fid = finding.get("id")
        if not isinstance(fid, str) or not fid:
            err(f"{where} 缺 id")
        elif fid in seen_findings:
            err(f"{where} id 重复: {fid}")
        else:
            seen_findings.add(fid)
            where = f"finding:{fid}"
        if finding.get("sev") not in SEVERITIES:
            err(f"{where}.sev 非法")
        if not finding.get("title"):
            err(f"{where} 缺 title")
        check_expr(f"{where}.when", finding.get("when", "true"))
        if finding.get("for_each"):
            check_expr(f"{where}.for_each", finding["for_each"])
        for text_key in ("title", "detail", "evidence", "mapping", "fix"):
            check_interp(f"{where}.{text_key}", finding.get(text_key))
        vm = finding.get("version_matrix")
        if vm is not None:
            if not isinstance(vm, dict) or "product" not in vm or "source" not in vm:
                err(f"{where}.version_matrix 需要 product/source")
            else:
                check_expr(f"{where}.version_matrix.source", vm["source"])

    artifacts = doc.get("artifacts") or []
    if not isinstance(artifacts, list):
        err("artifacts 必须是数组")
    else:
        for idx, artifact in enumerate(artifacts):
            where = f"artifacts[{idx}]"
            if not isinstance(artifact, dict) or "name" not in artifact:
                err(f"{where} 需要 name")
                continue
            if artifact.get("fields") is not None:
                if not isinstance(artifact["fields"], dict) or not artifact["fields"]:
                    err(f"{where}.fields 必须是非空对象")
                else:
                    for field_name, text in artifact["fields"].items():
                        check_expr(f"{where}.fields.{field_name}", text)
                continue
            if "from" not in artifact:
                err(f"{where} 需要 from 或 fields")
                continue
            check_expr(f"{where}.from", artifact["from"])

    payloads = doc.get("payloads")
    if payloads is not None and not isinstance(payloads, dict):
        err("payloads 必须是对象")
    elif isinstance(payloads, dict):
        for name, payload in payloads.items():
            if not isinstance(payload, dict):
                err(f"payloads.{name} 必须是对象")
                continue
            check_interp(f"payloads.{name}", payload)

    modes = doc.get("modes") or {}
    if not isinstance(modes, dict):
        err("modes 必须是对象")
    else:
        if writes and not modes.get("backup_write"):
            if not meta or not meta.get("writes"):
                err("含写步骤但 modes.backup_write 未声明（写类模块必须显式声明）")
        if modes.get("backup_write") and not modes.get("requires_backup", True):
            err("backup_write 模式必须 requires_backup=true")

    if not errors:
        referenced = set()
        for step in steps:
            if step.get("save"):
                referenced.add(step["id"])
        # A saved step may legitimately be unused, so only validate that every
        # expression root is a known scope name.
        allowed_roots = {"params", "vars", "steps", "input", "ctx", "env", "it", "loop",
                         "computed", "payload", "payloads", "i"}
        allowed_roots |= {str(s.get("index_var")) for s in (doc.get("steps") or [])
                          if isinstance(s, dict) and s.get("index_var")}
        allowed_roots |= {str(f.get("as")) for f in (doc.get("findings") or [])
                          if isinstance(f, dict) and f.get("as")}
        for text in _iter_expression_texts(doc):
            try:
                tree = parse(text)
            except ExprError:
                continue
            for root in _roots(tree):
                if root not in allowed_roots:
                    err(f"表达式引用未知根 {root!r}: {text!r}")
    return errors


def _iter_expression_texts(doc: dict):
    def interp(value):
        if isinstance(value, str):
            start = 0
            while True:
                begin = value.find("{{", start)
                if begin < 0:
                    return
                end = value.find("}}", begin + 2)
                if end < 0:
                    return
                yield value[begin + 2:end].strip()
                start = end + 2
        elif isinstance(value, list):
            for item in value:
                yield from interp(item)
        elif isinstance(value, dict):
            for item in value.values():
                yield from interp(item)

    for step in doc.get("steps") or []:
        if isinstance(step, dict) and step.get("when"):
            yield step["when"]
        yield from interp(step)
    for text in (doc.get("computed") or {}).values():
        if isinstance(text, str):
            yield text
    for check in doc.get("checks") or []:
        if isinstance(check, dict) and check.get("when"):
            yield check["when"]
    for finding in doc.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for key in ("when", "for_each"):
            if finding.get(key):
                yield finding[key]
        for key in ("title", "detail", "evidence", "mapping", "fix"):
            yield from interp(finding.get(key))
    for artifact in doc.get("artifacts") or []:
        if isinstance(artifact, dict):
            if artifact.get("from"):
                yield artifact["from"]
            for text in (artifact.get("fields") or {}).values():
                yield text
    for spec in (doc.get("inputs") or {}).values():
        if isinstance(spec, dict) and spec.get("from"):
            yield spec["from"]


def _roots(tree) -> set[str]:
    out: set[str] = set()

    def walk(node) -> None:
        if not isinstance(node, tuple):
            return
        if node[0] == "var":
            out.add(node[1])
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
    return out


def describe(doc: dict, module_dir: Path | None = None) -> TemplateMeta:
    meta = doc.get("meta") or {}
    return TemplateMeta(
        key=str(doc.get("key")),
        version=str(doc.get("version")),
        name=dict(meta.get("name") or {}),
        series=str(meta.get("series")),
        min_level=str(meta.get("min_level")),
        writes=bool(meta.get("writes")),
        requires=list(meta.get("requires") or []),
        surfaces=list(meta.get("surfaces") or []),
        cves=list(meta.get("cves") or []),
        fidelity=str(meta.get("fidelity") or "equivalent"),
        steps=len(doc.get("steps") or []),
        findings=len(doc.get("findings") or []),
        checks=len(doc.get("checks") or []),
        path=Path(module_dir) if module_dir else None,
    )
