"""紫队验证（defense validation）：规则包 × mock 靶场重放 → 覆盖率矩阵。

流程（trident rules validate）：
1. 读规则包 mapping.json（规则 ↔ 链映射 + 简化匹配器规格 match）；
2. 对 lab mock vulnerable 靶场重放各链第一步探针（含链内其余可 HTTP 重放步骤，urllib 仅标准库）；
3. 由重放结果合成事件（Suricata 流 / Falco 连接与执行 / Sigma 审计），非 HTTP 面以日志 fixture 重放；
4. 内置简化 sigma/falco/suricata 匹配器逐条断言「应触发规则」实际命中；
5. 输出覆盖率矩阵（JSON + MD）：每链每规则 拦截（准入/隔离策略在包内齐备）/ 检测（签名实际命中）/
   漏过 → 漏过项反哺规则库迭代（知识闭环）。

Ruling（探针端口口径）：mock 基座监听端口随机分配，合成事件使用探测规格声明的业务端口
（如 sglang 管理 30000 / Ray 8265 / AReaL 9000 / IMDS 169.254.169.254:80）。
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from .generate import ADVICE_ENGINES, ENFORCEMENT_ENGINES, load_catalog  # noqa: E402

_BLOCKED = "拦截"
_DETECTED = "检测"
_MISSED = "漏过"
_ADVICE = "建议"


# ---------------------------------------------------------------- 简化匹配器

def _get_path(item: Any, dotted: str) -> Any:
    cur = item
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_condition(actual: Any, pattern: Any) -> bool:
    """单条件匹配：标量相等 / 列表成员 / '*' 存在即真 / {'not_in': [...]} / {'re': '...'}。"""
    if isinstance(pattern, dict):
        if "not_in" in pattern:
            return actual not in pattern["not_in"] and actual is not None
        if "re" in pattern:
            return actual is not None and re.search(pattern["re"], str(actual)) is not None
        return False
    if pattern == "*":
        return actual is not None
    if isinstance(pattern, list):
        return actual in pattern
    return actual == pattern


def _match_sigma(spec: dict, event: dict) -> bool:
    if event.get("kind") != "sigma":
        return False
    want_ls = spec.get("logsource") or {}
    have_ls = event.get("logsource") or {}
    for key, value in want_ls.items():
        if have_ls.get(key) != value:
            return False
    return all(_match_condition(_get_path(event, field), pattern)
               for field, pattern in (spec.get("selection") or {}).items())


def _match_falco(spec: dict, event: dict) -> bool:
    if event.get("kind") != "falco":
        return False
    if event.get("event_type") not in (spec.get("event_type") or []):
        return False
    return all(_match_condition(event.get(field), pattern)
               for field, pattern in (spec.get("all") or {}).items())


def _match_suricata(spec: dict, event: dict) -> bool:
    if event.get("kind") != "suricata":
        return False
    for cond in spec.get("any_of") or []:
        if "uri_re" in cond:
            uri = event.get("uri") or ""
            if uri and re.search(cond["uri_re"], str(uri)):
                return True
        if "dest_ip_re" in cond:
            ip = event.get("dest_ip") or ""
            if ip and re.search(cond["dest_ip_re"], str(ip)):
                return True
        if "dest_ports" in cond:
            if event.get("dest_port") in cond["dest_ports"]:
                return True
    return False


def rule_fires(match: dict, events: list[dict]) -> bool:
    """用内置简化匹配器判定规则是否在事件流上命中（至少一条事件）。"""
    engine = match.get("engine")
    if engine == "sigma":
        return any(_match_sigma(match, ev) for ev in events)
    if engine == "falco":
        return any(_match_falco(match, ev) for ev in events)
    if engine == "suricata":
        return any(_match_suricata(match, ev) for ev in events)
    return False


# ---------------------------------------------------------------- 靶场重放

def _http_request(mock_base: str, probe: dict, timeout: int = 15) -> dict:
    url = mock_base.rstrip("/") + probe["path"]
    data = json.dumps(probe["body"]).encode("utf-8") if probe.get("body") is not None else None
    req = urllib.request.Request(url, data=data, method=probe["method"].upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return {"status": 0, "payload": None, "error": f"{type(exc).__name__}: {exc}"}
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return {"status": status, "payload": payload, "error": None}


def _synth_events(probe: dict, outcome: dict) -> list[dict]:
    """由重放结果合成事件：Suricata 流 + Falco 管理面连接 + on_success 行为事件。"""
    events: list[dict] = [{
        "kind": "suricata",
        "src": "10.42.0.21",
        "dest_ip": probe.get("dest_ip", "10.42.0.9"),
        "dest_port": probe.get("dest_port", 80),
        "proto": "tcp",
        "http_method": probe["method"],
        "uri": probe["path"],
    }]
    if probe.get("admin_plane"):
        events.append({
            "kind": "falco",
            "event_type": "connect",
            "dest_port": probe.get("dest_port", 80),
            "uri": probe["path"],
            "source_zone": "tenant-workload",
            "authorized": False,
        })
    ok = outcome.get("status") == 200 and outcome.get("error") is None
    payload = outcome.get("payload") if isinstance(outcome.get("payload"), dict) else {}
    hook = probe.get("on_success")
    if not ok:
        return events
    if hook == "weight-write-marker":
        marker = payload.get("marker") or ""
        if marker:
            events.append({
                "kind": "falco", "event_type": "open_write",
                "path": marker, "proc": "slime-pull-worker", "training_process": False,
            })
    elif hook == "ray-job":
        events.append({
            "kind": "sigma",
            "logsource": {"product": "ray", "service": "dashboard"},
            "verb": "create", "objectRef": {"resource": "job"},
            "entrypoint": (probe.get("body") or {}).get("entrypoint", ""),
        })
    elif hook == "sandbox-exec":
        events.append({
            "kind": "falco", "event_type": "exec",
            "host_class": "agent-sandbox", "proc": "sh", "parent": "http-job-runner",
            "cmdline": str((probe.get("body") or {}).get("script", "")),
        })
    elif hook == "tenant-binding":
        events.append({
            "kind": "sigma",
            "logsource": {"category": "agent-platform"},
            "action": "create", "object_class": "tenant-binding",
            "cross_tenant": True, "subject": "session-anon",
        })
    return events


# ---------------------------------------------------------------- 主流程

def validate(pack_dir: Path | str, mock_base: str | None = None) -> dict:
    """对 mock vulnerable 靶场重放攻击链探针，断言规则命中 → 覆盖率矩阵（dict，含 JSON/MD 落盘）。"""
    root = Path(pack_dir)
    mapping = json.loads((root / "mapping.json").read_text(encoding="utf-8"))
    probes_catalog = load_catalog()["probes"]["chains"]
    rules_by_id = {rule["id"]: rule for rule in mapping["rules"]}

    own_server = None
    if mock_base is None:
        from lab.mock_targets import start_all  # 延迟导入（仅自起靶场时需要）

        own_server = start_all(mode="vulnerable")
        mock_base = own_server.url("/")

    chain_rows: dict[str, dict] = {}
    all_events: dict[str, list[dict]] = {}
    for cid, plan in probes_catalog.items():
        chain_meta = mapping["chains"].get(cid)
        if chain_meta is None:
            continue  # 靶场探针目录与链目录解耦：链目录裁剪后跳过多余计划
        events: list[dict] = []
        probe_rows: list[dict] = []
        for probe in plan.get("replay", []):
            outcome = _http_request(mock_base, probe)
            events.extend(_synth_events(probe, outcome))
            blocked = outcome["status"] in (401, 403, 404)
            probe_rows.append({
                "kind": "http", "module": probe["module"], "method": probe["method"],
                "path": probe["path"], "status": outcome["status"],
                "outcome": "blocked-by-hardening" if blocked else
                           ("reproduced" if outcome["status"] == 200 else "unexpected"),
            })
        fixtures = list(plan.get("fixtures", []))
        events.extend(fixtures)
        if fixtures:
            probe_rows.append({"kind": "fixture", "count": len(fixtures)})
        all_events[cid] = events

        cells: list[dict] = []
        for rid in chain_meta["rules"]:
            rule = rules_by_id[rid]
            engines = set(rule["engines"])
            if engines & set(ENFORCEMENT_ENGINES):
                present = all((root / rel).is_file() for rel in rule["files"])
                cells.append({"rule": rid, "engines": rule["engines"],
                              "status": _BLOCKED if present else _MISSED,
                              "evidence": "策略文件在包内齐备（默认 monitor，Enforce 后即拦截）" if present else "策略文件缺失"})
            elif engines & set(ADVICE_ENGINES):
                present = all((root / rel).is_file() for rel in rule["files"])
                cells.append({"rule": rid, "engines": rule["engines"],
                              "status": _ADVICE if present else _MISSED,
                              "evidence": "缓解建议文件在包内" if present else "建议文件缺失"})
            else:
                fired = bool(rule.get("match")) and rule_fires(rule["match"], events)
                hit = next((ev for ev in events if _single_hit(rule.get("match") or {}, ev)), None)
                cells.append({
                    "rule": rid, "engines": rule["engines"],
                    "status": _DETECTED if fired else _MISSED,
                    "evidence": ("事件命中: " + _event_brief(hit)) if hit else "重放事件未命中该签名",
                })
        states = {cell["status"] for cell in cells}
        parts = [s for s in (_BLOCKED, _DETECTED) if s in states]
        if not parts:
            state = _MISSED
        else:
            state = "+".join(parts)
        chain_rows[cid] = {
            "title": chain_meta.get("title", {}),
            "category": chain_meta.get("category", ""),
            "probe": probe_rows,
            "rules": cells,
            "state": state,
        }

    if own_server is not None:
        own_server.shutdown()

    total_cells = sum(len(row["rules"]) for row in chain_rows.values())
    blocked_cells = sum(1 for row in chain_rows.values() for c in row["rules"] if c["status"] == _BLOCKED)
    detected_cells = sum(1 for row in chain_rows.values() for c in row["rules"] if c["status"] == _DETECTED)
    missed_cells = sum(1 for row in chain_rows.values() for c in row["rules"] if c["status"] == _MISSED)
    covered = sum(1 for row in chain_rows.values() if row["state"] != _MISSED)
    matrix = {
        "mock_base": mock_base,
        "mock_mode": "vulnerable",
        "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "chains": chain_rows,
        "summary": {
            "chains": len(chain_rows),
            "covered": covered,
            "missed": len(chain_rows) - covered,
            "rules_evaluated": total_cells,
            "rules_blocked": blocked_cells,
            "rules_detected": detected_cells,
            "rules_missed": missed_cells,
        },
        "ok": covered == len(chain_rows) and missed_cells == 0,
        "ruling": {
            "port_basis": "合成事件使用探测规格声明的业务端口（mock 基座端口随机分配）",
            "matcher": "内置简化 sigma/falco/suricata 匹配器（selection/event_type/any_of 语义子集）",
            "loopback": "漏过项 → 规则缺口 → 反哺规则库迭代",
        },
    }

    _write_matrix(root, matrix)
    return matrix


def _single_hit(match: dict, event: dict) -> bool:
    engine = match.get("engine")
    if engine == "sigma":
        return _match_sigma(match, event)
    if engine == "falco":
        return _match_falco(match, event)
    if engine == "suricata":
        return _match_suricata(match, event)
    return False


def _event_brief(event: dict | None) -> str:
    if not event:
        return ""
    kind = event.get("kind")
    if kind == "suricata":
        return f"suricata {event.get('dest_ip')}:{event.get('dest_port')} uri={event.get('uri') or '-'}"
    if kind == "falco":
        return f"falco {event.get('event_type')} port={event.get('dest_port', '-')} parent={event.get('parent', '-')}"
    return f"sigma {event.get('verb') or event.get('action')} {(event.get('objectRef') or {}).get('resource', event.get('object_class', ''))}"


def _probe_brief(row: dict) -> str:
    if row["kind"] == "fixture":
        return f"fixture×{row['count']}"
    arrow = "→"
    outcome = {"reproduced": "200 复现", "blocked-by-hardening": "加固拦截",
               "unexpected": f"异常({row['status']})"}.get(row["outcome"], str(row["status"]))
    return f"{row['method']} {row['path']} {arrow} {outcome}"


def _write_matrix(root: Path, matrix: dict) -> None:
    (root / "coverage-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# Trident 紫队验证覆盖率矩阵（defense validation）",
        "",
        f"- 时间：{matrix['validated_at']}；靶场：{matrix['mock_base']}（mode={matrix['mock_mode']}，仅 127.0.0.1）",
        f"- 摘要：链 {matrix['summary']['chains']} 条，覆盖 {matrix['summary']['covered']}，漏过 {matrix['summary']['missed']}；"
        f"规则评估 {matrix['summary']['rules_evaluated']} 项（拦截 {matrix['summary']['rules_blocked']} / "
        f"检测 {matrix['summary']['rules_detected']} / 漏过 {matrix['summary']['rules_missed']}）",
        f"- 判定口径：{matrix['ruling']['port_basis']}；匹配器：{matrix['ruling']['matcher']}",
        "",
        "| 链 | 类别 | 探针重放 | 状态 |",
        "|---|---|---|---|",
    ]
    for cid, row in matrix["chains"].items():
        probes = "；".join(_probe_brief(p) for p in row["probe"]) or "（无重放）"
        lines.append(f"| {cid} | {row['category']} | {probes} | {row['state']} |")
    lines += ["", "## 规则命中明细", ""]
    for cid, row in matrix["chains"].items():
        lines.append(f"### {cid}（{row['state']}）")
        for cell in row["rules"]:
            lines.append(f"- [{cell['status']}] {cell['rule']}（{'/'.join(cell['engines'])}）— {cell['evidence']}")
        lines.append("")
    lines += [
        "## 知识闭环",
        "",
        "- 漏过项 → 规则缺口 → 反哺规则库迭代；",
        "- 拦截态 = 准入/隔离策略已在包内（默认 monitor，Enforce 后即拦截）；检测态 = 简化匹配器在重放事件上实际命中。",
        "",
    ]
    (root / "coverage-matrix.md").write_text("\n".join(lines), encoding="utf-8")
