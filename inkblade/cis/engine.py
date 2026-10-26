# -*- coding: utf-8 -*-
"""CIS 判定引擎（只读、fixture 驱动）。

输入 snapshot（dict 或 JSON 路径，模块层负责装载）::

    {
      "_meta": {"profile": "cis-1.8", "k8s_version": "1.29.4", "distribution": "kubeadm"},
      "components": {
        "apiserver": {"args": ["kube-apiserver", "--anonymous-auth=false", ...]},
        "controller-manager": {"args": [...]},
        "scheduler": {"args": [...]},
        "etcd": {"args": [...]},
        "kube-proxy": {"args": [...]}
      },
      "files": {"/etc/kubernetes/manifests/kube-apiserver.yaml": {"mode": "600",
                "owner": "root", "group": "root"}},
      "nodes": [{"name": "cp-1", "role": "control-plane",
                 "kubelet": {"config": {...kubelet config.yaml...}}}],
      "host": {"sysctl": {...}, "modules": {...}, "packages": {...},
               "auditd": {...}, "sshd": {...}, "accounts": {...},
               "file_modes": {"/etc/passwd": "644"}},
      "k3s": {"secrets_encryption": true, ...},
      "policies": {"audit_policy": "minimal", "encryption": {"provider_configured": true}},
      "ml": {...}   # 由 inkblade.cis.ml 读取
    }

判定口径：
- 组件块缺失 / 文件条目缺失 / evidence 键缺失 → ``manual``（不臆造 pass/fail）；
- 组件参数存在但 flag 缺失 → 按 CIS 默认值判定（check 里的 ``default``）；
- 文件权限按八进制比较，``mode <= max_mode`` 为 pass；
- 人工项（kind=manual）恒为 ``manual``，不计入 score 分母。
"""
from __future__ import annotations

import json
from pathlib import Path

from inkblade.cis.catalog import CATALOG, CATALOG as _CATALOG, severity_of

_COMPONENT_ALIASES = {
    "apiserver": ("apiserver", "api-server", "kube-apiserver"),
    "controller-manager": ("controller-manager", "controllermanager",
                           "controller_manager", "kube-controller-manager"),
    "scheduler": ("scheduler", "kube-scheduler"),
    "etcd": ("etcd",),
    "kube-proxy": ("kube-proxy", "kubeproxy", "proxy"),
    "kubelet": ("kubelet",),
}

_WEAK_CIPHERS = ("TLS_RSA", "3DES", "RC4", "NULL", "CBC", "DES_")


# ---------------------------------------------------------------- 基础工具
def parse_args(args) -> dict:
    """解析命令行参数：``--k=v`` / ``--k v`` / 裸 ``--k`` → ``true``。

    重复 flag 以逗号合并（admission plugins 常见）。
    """
    if isinstance(args, dict):
        return {str(k).lstrip("-"): _text(v) for k, v in args.items()}
    tokens = list(args or [])
    flags: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        token = str(tokens[i])
        if not token.startswith("--"):
            i += 1
            continue
        body = token[2:]
        if "=" in body:
            name, value = body.split("=", 1)
        else:
            name = body
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt is not None and not str(nxt).startswith("--"):
                value = str(nxt)
                i += 1
            else:
                value = "true"
        name = name.strip()
        if name in flags and flags[name] != value:
            flags[name] = f"{flags[name]},{value}"
        else:
            flags[name] = value
        i += 1
    return flags


def _text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value).strip()


def _empty(value) -> bool:
    return value is None or _text(value) == ""


def file_mode_ok(observed, max_mode) -> bool | None:
    """八进制权限比较：observed 必须不大等于 max_mode（更严格则通过）。"""
    try:
        obs = int(str(observed).strip().lstrip("0o"), 8)
        limit = int(str(max_mode).strip().lstrip("0o"), 8)
    except (TypeError, ValueError):
        return None
    return obs <= limit


def _dig(obj, path: str):
    return _dig_parts(obj, str(path).split("."))


def _dig_parts(cur, parts):
    if not parts:
        return cur, True
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if isinstance(cur, dict) and key in cur:
            return _dig_parts(cur[key], parts[i:])
    return None, False


def _resolve(snapshot: dict, check: dict):
    value, found = _dig(snapshot, check.get("key", ""))
    field = check.get("field")
    if found and field:
        if isinstance(value, dict):
            if field in value:
                return value[field], True
            return None, False
        return None, False
    return value, found


def _flags(component: dict) -> dict:
    if not isinstance(component, dict):
        return {}
    if isinstance(component.get("flags"), dict):
        return {str(k).lstrip("-"): _text(v) for k, v in component["flags"].items()}
    return parse_args(component.get("args") or [])


def _component(snapshot: dict, name: str):
    comps = snapshot.get("components") or {}
    if not isinstance(comps, dict):
        return None
    for alias in _COMPONENT_ALIASES.get(name, (name,)):
        comp = comps.get(alias)
        if isinstance(comp, dict) and ("args" in comp or "flags" in comp):
            return comp
    return None


def _nodes(snapshot: dict) -> list[dict]:
    nodes = snapshot.get("nodes") or []
    return [n for n in nodes if isinstance(n, dict)]


def _kubelet_config(node: dict) -> dict | None:
    kubelet = node.get("kubelet")
    if not isinstance(kubelet, dict):
        return None
    config = kubelet.get("config", kubelet)
    return config if isinstance(config, dict) else None


# ---------------------------------------------------------------- 比较
def compare(observed, op: str, expected) -> bool:
    if op == "mode_max":
        return bool(file_mode_ok(observed, expected))
    text = _text(observed)
    lowered = text.lower()
    if op == "eq":
        return lowered == _text(expected).lower()
    if op in ("ne", "not_eq"):
        return lowered != _text(expected).lower()
    if op == "contains":
        return _text(expected).lower() in lowered
    if op == "not_contains":
        return _text(expected).lower() not in lowered
    if op == "set":
        return text != ""
    if op == "unset":
        return text == ""
    if op == "empty":
        return text == ""
    if op == "nonempty":
        return text != ""
    if op == "in":
        return lowered in {_text(v).lower() for v in (expected or [])}
    if op == "not_in":
        return lowered not in {_text(v).lower() for v in (expected or [])}
    if op in ("gte", "lte"):
        try:
            left = float(text)
            right = float(_text(expected))
        except (TypeError, ValueError):
            return False
        return left >= right if op == "gte" else left <= right
    if op == "strong_ciphers":
        if text == "":
            return False
        return not any(marker.lower() in lowered for marker in _WEAK_CIPHERS)
    return False


# ---------------------------------------------------------------- 单项判定
def _manual(check: dict, reason: str, observed="—") -> dict:
    return _result(check, "manual", observed, check.get("expected_text", "人工审计"), reason)


def _result(check, status, observed, expected, detail, evidence="") -> dict:
    return {
        "id": check["id"], "section": check["section"],
        "component": check["component"], "title": check["title"],
        "level": int(check.get("level", 1)), "tier": check.get("tier", "cis-1.8"),
        "scored": bool(check.get("scored", True)), "sev": severity_of(check),
        "status": status, "observed": _text(observed), "expected": _text(expected),
        "detail": detail, "evidence": evidence or f"cis§{check['id']}",
        "source": check.get("source", ""), "remediation": check.get("remediation", ""),
    }


def _expected_text(check: dict) -> str:
    kind = check["kind"]
    if kind == "file":
        return f"mode <= {check.get('max_mode')}"
    if kind == "owner":
        return f"{check.get('owner')}:{check.get('group')}"
    if kind == "pair":
        return f"均非空：{check.get('flags')}"
    if kind == "kubelet_pair":
        return f"均非空：{check.get('keys')}"
    if kind == "plugin":
        return f"插件 {check.get('plugin')} {check.get('mode')}"
    if kind in ("flag", "evidence", "kubelet"):
        op = check.get("op", "")
        value = check.get("value", "")
        if op == "strong_ciphers":
            return "仅强加密套件（无 RSA/CBC/3DES/RC4）"
        if op == "set":
            return "已设置/非空"
        if op == "unset":
            return "未设置"
        if op in ("contains", "not_contains"):
            return f"{op} {value}"
        if isinstance(value, (list, tuple)):
            return f"{op} {list(value)}"
        return f"{op} {value}".strip()
    return "人工审计"


def _check_flag(check, snapshot):
    comp = _component(snapshot, check["component"])
    if comp is None:
        return _manual(check, f"缺少 {check['component']} 组件证据（不臆造 pass/fail）")
    flags = _flags(comp)
    flag = check["flag"]
    if flag in flags:
        observed = flags[flag]
    elif "default" in check:
        observed = check["default"]
    else:
        observed = None
    if check.get("manual_if_empty") and _empty(observed):
        return _manual(check, f"--{flag} 为空，需人工确认强套件清单")
    ok = compare(observed, check["op"], check.get("value", ""))
    return _result(check, "pass" if ok else "fail", observed if observed is not None else "<未设置>",
                   _expected_text(check),
                   f"--{flag}={observed!r}；期望 {_expected_text(check)}",
                   evidence=f"{check['component']} --{flag}={observed!r}")


def _check_pair(check, snapshot):
    comp = _component(snapshot, check["component"])
    if comp is None:
        return _manual(check, f"缺少 {check['component']} 组件证据")
    flags = _flags(comp)
    values = {f: flags.get(f, "") for f in check["flags"]}
    empty = [f for f, v in values.items() if _empty(v)]
    observed = ", ".join(f"{f}={v!r}" for f, v in values.items())
    ok = not empty
    return _result(check, "pass" if ok else "fail", observed,
                   f"均非空：{check['flags']}",
                   "成对参数缺失：" + ",".join(empty) if empty else "成对参数齐全",
                   evidence=observed)


def _check_plugin(check, snapshot):
    comp = _component(snapshot, check["component"])
    if comp is None:
        return _manual(check, f"缺少 {check['component']} 组件证据")
    flags = _flags(comp)
    enable = {p.strip() for p in flags.get("enable-admission-plugins", "").split(",") if p.strip()}
    disable = {p.strip() for p in flags.get("disable-admission-plugins", "").split(",") if p.strip()}
    plugin, mode = check["plugin"], check["mode"]
    if mode == "enabled":
        ok = plugin in enable
    elif mode == "absent":
        ok = plugin not in enable
    else:  # default-enabled
        ok = plugin not in disable
    return _result(check, "pass" if ok else "fail",
                   f"enable={sorted(enable)} disable={sorted(disable)}",
                   f"{plugin} {mode}", f"插件 {plugin} 期望 {mode}",
                   evidence=f"enable-admission-plugins={sorted(enable)}")


def _check_file(check, snapshot):
    files = snapshot.get("files") or {}
    if not isinstance(files, dict):
        return _manual(check, "files 证据格式非法")
    paths = list(check.get("paths") or [check.get("path")])
    optional = bool(check.get("optional"))
    if not files:
        return _manual(check, "缺少 files 证据（不臆造 pass/fail）")
    if optional and not any(p in files for p in paths):
        return _result(check, "pass", "<不存在>", "存在则 <= " + check["max_mode"],
                       "可选文件不存在，视为不适用（pass）")
    missing = [p for p in paths if p not in files]
    if missing:
        return _manual(check, "缺少文件权限证据：" + ", ".join(missing))
    modes: dict[str, str] = {}
    for path in paths:
        entry = files[path] if isinstance(files[path], dict) else {"mode": files[path]}
        modes[path] = _text(entry.get("mode"))
    unknown = [p for p, m in modes.items() if file_mode_ok(m, check["max_mode"]) is None]
    if unknown:
        return _manual(check, "权限值不可解析：" + ", ".join(unknown))
    ok = all(file_mode_ok(m, check["max_mode"]) for m in modes.values())
    observed = ", ".join(f"{p}={m}" for p, m in modes.items())
    return _result(check, "pass" if ok else "fail", observed,
                   f"mode <= {check['max_mode']}", f"文件权限 {observed}",
                   evidence=observed)


def _check_owner(check, snapshot):
    files = snapshot.get("files") or {}
    if not isinstance(files, dict):
        return _manual(check, "files 证据格式非法")
    paths = list(check.get("paths") or [check.get("path")])
    optional = bool(check.get("optional"))
    if not files:
        return _manual(check, "缺少 files 证据（不臆造 pass/fail）")
    if optional and not any(p in files for p in paths):
        return _result(check, "pass", "<不存在>", "存在则 root:root",
                       "可选文件不存在，视为不适用（pass）")
    missing = [p for p in paths if p not in files]
    if missing:
        return _manual(check, "缺少文件属主证据：" + ", ".join(missing))
    entries = []
    for path in paths:
        entry = files[path] if isinstance(files[path], dict) else {}
        entries.append((path, _text(entry.get("owner", "")), _text(entry.get("group", ""))))
    ok = all(o.lower() == check["owner"].lower() and g.lower() == check["group"].lower()
             for _p, o, g in entries)
    observed = ", ".join(f"{p}={o}:{g}" for p, o, g in entries)
    return _result(check, "pass" if ok else "fail", observed,
                   f"{check['owner']}:{check['group']}", f"文件属主 {observed}",
                   evidence=observed)


def _check_evidence(check, snapshot):
    value, found = _resolve(snapshot, check)
    if not found:
        return _manual(check, f"缺少证据 {check.get('key')}（不臆造 pass/fail）")
    field = check.get("field")
    if field:
        value = value if not isinstance(value, dict) else value.get(field)
    ok = compare(value, check["op"], check.get("value", ""))
    return _result(check, "pass" if ok else "fail", value, _expected_text(check),
                   f"{check.get('key')}={value!r}；期望 {_expected_text(check)}",
                   evidence=f"{check.get('key')}={value!r}")


def _kubelet_targets(snapshot):
    targets = []
    for node in _nodes(snapshot):
        config = _kubelet_config(node)
        if config is not None:
            targets.append((node.get("name", "node"), config))
    return targets


def _check_kubelet(check, snapshot):
    targets = _kubelet_targets(snapshot)
    if not targets:
        return _manual(check, "缺少 nodes[].kubelet.config 证据")
    statuses = []
    pairs = []
    for name, config in targets:
        value, found = _dig(config, check["key"])
        if not found and "default" in check:
            value, found = check["default"], True
        if not found:
            statuses.append("manual")
            pairs.append(f"{name}=<缺键>")
            continue
        if check.get("manual_if_empty") and _empty(value):
            statuses.append("manual")
            pairs.append(f"{name}=<空>")
            continue
        ok = compare(value, check["op"], check.get("value", ""))
        statuses.append("pass" if ok else "fail")
        pairs.append(f"{name}={_text(value)}")
    observed = "; ".join(pairs)
    if "fail" in statuses:
        status = "fail"
    elif "manual" in statuses:
        status = "manual"
    else:
        status = "pass"
    return _result(check, status, observed, _expected_text(check),
                   f"kubelet {check['key']} → {observed}", evidence=observed)


def _check_kubelet_pair(check, snapshot):
    targets = _kubelet_targets(snapshot)
    if not targets:
        return _manual(check, "缺少 nodes[].kubelet.config 证据")
    statuses, pairs = [], []
    for name, config in targets:
        values = [_dig(config, key)[0] for key in check["keys"]]
        ok = all(not _empty(v) for v in values)
        statuses.append("pass" if ok else "fail")
        pairs.append(f"{name}=" + ",".join(f"{k}:{_text(v)}" for k, v in zip(check["keys"], values)))
    observed = "; ".join(pairs)
    return _result(check, "pass" if all(s == "pass" for s in statuses) else "fail",
                   observed, f"均非空：{check['keys']}", f"kubelet 成对参数 {observed}",
                   evidence=observed)


def check_result(check: dict, snapshot: dict) -> dict:
    kind = check["kind"]
    if kind == "manual":
        return _manual(check, check.get("manual_reason", "人工审计项"))
    if kind == "flag":
        return _check_flag(check, snapshot)
    if kind == "pair":
        return _check_pair(check, snapshot)
    if kind == "plugin":
        return _check_plugin(check, snapshot)
    if kind == "file":
        return _check_file(check, snapshot)
    if kind == "owner":
        return _check_owner(check, snapshot)
    if kind == "evidence":
        return _check_evidence(check, snapshot)
    if kind == "kubelet":
        return _check_kubelet(check, snapshot)
    if kind == "kubelet_pair":
        return _check_kubelet_pair(check, snapshot)
    return _manual(check, f"未知判定类型 {kind}")


# ---------------------------------------------------------------- 汇总
def _matrix(rows: list[dict]) -> dict:
    matrix: dict[str, dict] = {}
    for row in rows:
        cell = matrix.setdefault(row["section"], {"pass": 0, "fail": 0, "manual": 0,
                                                  "total": 0})
        cell[row["status"]] += 1
        cell["total"] += 1
    return {sec: matrix[sec] for sec in sorted(matrix, key=_section_key)}


def _section_key(section: str):
    head = section.split(".")[0]
    if head.isdigit():
        return (0, [int(x) if x.isdigit() else x for x in section.split(".")])
    order = {"DL": 1, "K3S": 2}
    return (order.get(head, 3), [section])


def summarize(profile: str, meta: dict, rows: list[dict]) -> dict:
    counts = {"pass": 0, "fail": 0, "manual": 0}
    for row in rows:
        counts[row["status"]] += 1
    scored = [r for r in rows if r["scored"]]
    evaluated = [r for r in scored if r["status"] != "manual"]
    score = round(sum(1 for r in evaluated if r["status"] == "pass") / len(evaluated), 3) \
        if evaluated else 0.0
    by_tier: dict[str, dict] = {}
    for row in rows:
        cell = by_tier.setdefault(row["tier"], {"pass": 0, "fail": 0, "manual": 0, "total": 0})
        cell[row["status"]] += 1
        cell["total"] += 1
    return {
        "family": "CIS Kubernetes Benchmark",
        "profile": profile,
        "k8s_version": meta.get("k8s_version", ""),
        "distribution": meta.get("distribution", ""),
        "rules_total": len(rows),
        "total": len(rows),
        "pass": counts["pass"], "fail": counts["fail"], "manual": counts["manual"],
        "scored_total": len(scored), "score": score,
        "failed_ids": [r["id"] for r in rows if r["status"] == "fail"],
        "manual_ids": [r["id"] for r in rows if r["status"] == "manual"],
        "by_tier": by_tier,
    }


def assess(snapshot: dict, checks=CATALOG) -> dict:
    snapshot = snapshot or {}
    meta = snapshot.get("_meta") if isinstance(snapshot.get("_meta"), dict) else {}
    profile = meta.get("profile") or snapshot.get("profile") or "cis-1.8"
    rows = [check_result(check, snapshot) for check in checks]
    return {
        "profile": profile,
        "benchmark": meta.get("benchmark", "CIS Kubernetes Benchmark v1.8.0"),
        "k8s_version": meta.get("k8s_version", ""),
        "checks": rows,
        "matrix": _matrix(rows),
        "summary": summarize(profile, meta, rows),
    }


def findings(report: dict) -> list[dict]:
    out = []
    for row in report.get("checks", []):
        if row["status"] != "fail":
            continue
        out.append({
            "sev": row["sev"],
            "title": f"CIS {row['id']} 未通过：{row['title']}",
            "detail": (f"{row['component']} 观测={row['observed']}；期望={row['expected']}；"
                       f"{row['detail']}。来源：{row['source']}"),
            "evidence": row["evidence"],
            "mapping": f"CIS Benchmark §{row['id']}（{row['tier']}）",
            "fix": row["remediation"],
            "cis_id": row["id"], "section": row["section"],
            "component": row["component"], "status": "fail",
            "level": row["level"], "tier": row["tier"],
            "remediation": row["remediation"],
        })
    return out


def load_snapshot(value) -> dict:
    if isinstance(value, dict):
        return value
    return json.loads(Path(str(value)).read_text(encoding="utf-8"))
