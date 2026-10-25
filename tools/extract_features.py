#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Source-level feature enumeration: ARTEX (RuoJi6 fork) & KubeTrail (ekkoo-z).

Every feature row is EXTRACTED from the cloned sources under
``.slim/clonedeps/repos/`` by the functions in this script — no enumeration
from memory. Human work is limited to the CLASSIFICATION tables below
(Trident status / anchor / action / backlog reference), which are keyed by
the extracted feature ids.

Re-runnable::

    python tools/extract_features.py           # regenerate docs/feature-matrix.json + both MD docs
    python tools/extract_features.py --check   # exit 0 iff generated artifacts match regeneration

Outputs
-------
- docs/feature-matrix.json           machine-readable matrix + source_counts
- docs/FEATURE-BY-FEATURE-ARTEX.md   one row per extracted ARTEX feature
- docs/FEATURE-BY-FEATURE-KUBETRAIL.md  one row per extracted KubeTrail feature

Row contract (one row = one feature):
    id | 来源锚点 (file:line) | 工具行为 | Trident 状态
    (we-have(anchor)|partial(缺什么)|missing|N/A) | 行动项 S/M/L/- | 备注

Completeness proof: matrix rows are generated from the same extraction lists
that produce ``source_counts``; any feature that cannot be mapped to a Trident
module is still emitted with status ``N/A`` (deliberate or unmapped), never
dropped. ``tests/test_feature_matrix.py`` re-parses the markdown and asserts
extraction counts == json counts == doc row counts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
REPOS = PROJECT.parent.parent / ".slim" / "clonedeps" / "repos"
ARTEX = REPOS / "RuoJi6__ARTEX"
KT = REPOS / "ekkoo-z__KubeTrail"

JSON_OUT = PROJECT / "docs" / "feature-matrix.json"
MD_ARTEX = PROJECT / "docs" / "FEATURE-BY-FEATURE-ARTEX.md"
MD_KT = PROJECT / "docs" / "FEATURE-BY-FEATURE-KUBETRAIL.md"

STATUS_WE_HAVE = "we-have"
STATUS_PARTIAL = "partial"
STATUS_MISSING = "missing"
STATUS_NA = "N/A"


# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


# ---------------------------------------------------------------------------
# ARTEX extraction
# ---------------------------------------------------------------------------

def artex_routes() -> list[dict[str, Any]]:
    """All HTTP routes: literal HandleFunc registrations + the two
    programmatic registrations (side-question loop, finding-traffic base)."""
    routes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(method: str, path: str, anchor: str, handler: str):
        if (method, path) in seen:
            return
        seen.add((method, path))
        routes.append({"id": f"{method} {path}", "method": method, "path": path,
                       "anchor": anchor, "behavior": handler or "-"})

    rx = re.compile(r'mux\.HandleFunc\(\s*"([A-Z]+)\s+([^"]+)"\s*,\s*'
                    r'(s\.\w+|func\([^)]*\)[^,]*|[\w.]+)')
    for go in sorted((ARTEX / "server").glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        text = _read(go)
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            add(m.group(1), m.group(2), f"server/{go.name}:{line}", m.group(3))

    # finding_traffic.go: base := "/api/..." then HandleFunc("VERB"+base[+suffix])
    ft = ARTEX / "server" / "finding_traffic.go"
    ft_text = _read(ft)
    base_m = re.search(r'base\s*:=\s*"(/api/[^"]+)"', ft_text)
    if base_m:
        base = base_m.group(1)
        base_line = ft_text.count("\n", 0, base_m.start()) + 1
        rx2 = re.compile(r'mux\.HandleFunc\(\s*"([A-Z]+)\s*"\s*\+\s*base(?:\s*\+\s*"([^"]*)")?')
        for m in rx2.finditer(ft_text):
            line = ft_text.count("\n", 0, m.start()) + 1
            add(m.group(1), base + (m.group(2) or ""), f"server/finding_traffic.go:{line}",
                "s.editFindingTraffic/getFindingTraffic*")

    # side_questions.go: loop over {path,kind} × {GET,POST,DELETE} + 2 literals
    sq = ARTEX / "server" / "side_questions.go"
    sq_text = _read(sq)
    reg_m = re.search(r"func \(s \*Server\) registerSideRoutes\(", sq_text)
    reg_text = sq_text[reg_m.start():] if reg_m else sq_text
    paths = re.findall(r'\{"(/api/[^"]+)",\s*"(\w+)"\}', reg_text)
    meth_m = re.search(r'range \[\]string\{("([A-Z]+)"(?:,\s*"[A-Z]+")+)\}', reg_text)
    meth_list = re.findall(r'"([A-Z]+)"', meth_m.group(1)) if meth_m else ["GET", "POST", "DELETE"]
    for path, _kind in paths:
        for meth in meth_list:
            add(meth, f"{path}/side-questions", "server/side_questions.go:348-358(循环展开)",
                "s.handleSideQuestions")
    for m in re.finditer(r'mux\.HandleFunc\(\s*"([A-Z]+)\s+([^"]+)"\s*,\s*(s\.\w+)', sq_text):
        line = sq_text.count("\n", 0, m.start()) + 1
        add(m.group(1), m.group(2), f"server/side_questions.go:{line}", m.group(3))
    return routes


def artex_tables() -> list[dict[str, Any]]:
    schema = _read(ARTEX / "db" / "schema.sql")
    out = []
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\(", schema):
        line = schema.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(1), "anchor": f"db/schema.sql:{line}",
                    "behavior": f"表 {m.group(1)}"})
    return out


def artex_agent_components() -> list[dict[str, Any]]:
    out = []
    for go in sorted((ARTEX / "agent").glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        types = sorted(set(re.findall(r"^type (\w+) struct", _read(go), re.M)))
        out.append({"id": go.name, "anchor": f"agent/{go.name}:1",
                    "behavior": f"组件文件（types: {', '.join(types) if types else '-'}）"})
    return out


def artex_pages() -> list[dict[str, Any]]:
    out = []
    for page in sorted((ARTEX / "web" / "src" / "app").rglob("page.tsx")):
        rel = _rel(page, ARTEX / "web" / "src" / "app").replace("page.tsx", "").replace("\\", "/")
        out.append({"id": f"/{rel.strip('/')}" if rel.strip("/") else "/", "anchor": f"web/src/app/{rel}page.tsx",
                    "behavior": "Next.js 页面"})
    return out


def artex_components() -> list[dict[str, Any]]:
    out = []
    for tsx in sorted((ARTEX / "web" / "src" / "components").rglob("*.tsx")):
        rel = _rel(tsx, ARTEX / "web" / "src")
        out.append({"id": rel, "anchor": f"web/src/{rel}", "behavior": "UI 组件"})
    for tsx in sorted((ARTEX / "web" / "src" / "app" / "(main)" / "_components").rglob("*.tsx")):
        rel = _rel(tsx, ARTEX / "web" / "src")
        out.append({"id": rel, "anchor": f"web/src/{rel}", "behavior": "主布局组件"})
    return out


def artex_config_keys() -> list[dict[str, Any]]:
    cfg = json.loads(_read(ARTEX / "config.example.json"))
    out: list[dict[str, Any]] = []

    def walk(node: Any, prefix: str = ""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.startswith("_"):  # _comment* / _example_* are docs, not config keys
                    continue
                walk(v, f"{prefix}{k}" if not prefix else f"{prefix}.{k}")
        else:
            out.append({"id": prefix, "anchor": "config.example.json", "behavior": f"配置键 = {node!r}"})

    walk(cfg)
    return out


def artex_skills() -> list[dict[str, Any]]:
    out = []
    for d in sorted((ARTEX / "skills").iterdir()):
        if d.is_dir():
            out.append({"id": d.name, "anchor": f"skills/{d.name}/", "behavior": "内置 skill 目录"})
    return out


# ---------------------------------------------------------------------------
# KubeTrail extraction
# ---------------------------------------------------------------------------

def kt_collectors() -> list[dict[str, Any]]:
    out = []
    for go in sorted((KT / "internal" / "collectors").glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        text = _read(go)
        for m in re.finditer(
                r'simpleCollector\{id: "(\w+)", mode: model\.(\w+)'
                r'(?:, sideEffects: \[\]string\{([^}]*)\})?', text):
            line = text.count("\n", 0, m.start()) + 1
            se = re.findall(r'"([^"]+)"', m.group(3) or "")
            out.append({"id": m.group(1),
                        "anchor": f"internal/collectors/types.go:{line}",
                        "behavior": f"采集器 mode={m.group(2).replace('Mode', '').lower()}"
                                    + (f" 副作用={','.join(se)}" if se else "")})
    return out


def kt_sa_token_audit() -> list[dict[str, Any]]:
    p = KT / "internal" / "collectors" / "serviceaccount_token_audit.go"
    text = _read(p)
    m = re.search(r"func CollectServiceAccountTokenAudit\(", text)
    line = text.count("\n", 0, m.start()) + 1 if m else 1
    return [{"id": "sa_token_audit", "anchor": f"internal/collectors/serviceaccount_token_audit.go:{line}",
             "behavior": "--secretoutput 独立审计文档 kubetrail.sa-token-audit/v1（token 明文+JWT claims+逐 token SSRR/SSAR）"}]


def kt_finding_evaluators() -> list[dict[str, Any]]:
    out = []
    for go in sorted((KT / "internal" / "findings").glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        text = _read(go)
        for m in re.finditer(r"^func ((?:Evaluate|evaluate)\w+)\(", text, re.M):
            line = text.count("\n", 0, m.start()) + 1
            out.append({"id": m.group(1), "anchor": f"internal/findings/{go.name}:{line}",
                        "behavior": "findings 引擎规则函数"})
    return out


def kt_finding_titles() -> list[dict[str, Any]]:
    """Every heuristic the findings engine can emit (kernel/userland LPE, escape,
    RBAC) — one row per distinct title/format literal, anchored to its file."""
    out = []
    seen: set[tuple[str, str]] = set()
    for go in sorted((KT / "internal" / "findings").glob("*.go")):
        if go.name.endswith("_test.go"):
            continue
        text = _read(go)
        for m in re.finditer(r'Title:\s*(?:fmt\.Sprintf\(\s*)?"([^"]+)"', text):
            title = m.group(1)
            if (go.name, title) in seen:
                continue
            seen.add((go.name, title))
            line = text.count("\n", 0, m.start()) + 1
            cat = "lpe" if go.name == "lpe.go" else ("rbac" if "cluster-admin" in title or "allowed" in title else "escape")
            out.append({"id": title, "anchor": f"internal/findings/{go.name}:{line}",
                        "behavior": f"{cat} 启发式 finding 标题"})
    return out


def kt_sensitivity_modes() -> list[dict[str, Any]]:
    text = _read(KT / "internal" / "sensitivity" / "sensitivity.go")
    out = []
    for m in re.finditer(r"Sensitive(\w+)\s+SensitiveMode = \"(\w+)\"", text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(2), "anchor": f"internal/sensitivity/sensitivity.go:{line}",
                    "behavior": "敏感值处理模式（sensitive=true 的 fact 值变换）"})
    return out


def kt_model_schema() -> list[dict[str, Any]]:
    text = _read(KT / "internal" / "model" / "model.go")
    out = []
    for m in re.finditer(r'const (SchemaVersion\w*) = "([^"]+)"', text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(2), "anchor": f"internal/model/model.go:{line}",
                    "behavior": "dbus.json 导出 schema 常量"})
    for struct in ("Document", "SATokenAuditDocument"):
        sm = re.search(rf"type {struct} struct \{{(.*?)\n\}}", text, re.S)
        if not sm:
            continue
        body = sm.group(1)
        struct_line = text.count("\n", 0, sm.start()) + 1
        for fm in re.finditer(r"(\w+)\s+\w+\s+`json:\"(\w+)\"", body):
            line = struct_line + body.count("\n", 0, fm.start())
            out.append({"id": f"{struct}.{fm.group(2)}",
                        "anchor": f"internal/model/model.go:{line}",
                        "behavior": f"dbus.json 字段（{struct}）"})
    return out


def kt_cli_flags() -> list[dict[str, Any]]:
    text = _read(KT / "internal" / "command" / "command.go")
    out = []
    seen = set()
    for m in re.finditer(r'fs\.\w+Var\(&\w+,\s*"(\w+)",[^,]+,\s*"([^"]*)"', text):
        name = m.group(1)
        if len(name) <= 1 or name in seen:  # skip shorthands
            continue
        seen.add(name)
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": f"--{name}", "anchor": f"internal/command/command.go:{line}",
                    "behavior": m.group(2)})
    return out


def kt_desktop_methods() -> list[dict[str, Any]]:
    """All Wails-bound App methods, grouped by the ==== Section ==== comments."""
    p = KT / "apps" / "desktop" / "app.go"
    text = _read(p)
    sections: list[tuple[int, str]] = [(0, "app")]
    for m in re.finditer(r"// =+ (.+?) =+", text):
        sections.append((text.count("\n", 0, m.start()) + 1, m.group(1).strip()))
    out = []
    for m in re.finditer(r"^func \(a \*App\) (\w+)\(", text, re.M):
        name = m.group(1)
        if not name[0].isupper():
            continue
        line = text.count("\n", 0, m.start()) + 1
        sec = "app"
        for sline, sname in sections:
            if sline <= line:
                sec = sname
        out.append({"id": name, "anchor": f"apps/desktop/app.go:{line}",
                    "behavior": f"Wails 绑定方法（{sec}）", "section": sec})
    return out


def kt_persistence_techniques() -> list[dict[str, Any]]:
    text = _read(KT / "apps" / "desktop" / "kube" / "persistence.go")
    out = []
    for m in re.finditer(r"Technique(\w+)\s+PersistenceTechnique = \"([\w-]+)\"", text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(2), "anchor": f"apps/desktop/kube/persistence.go:{line}",
                    "behavior": f"权限维持模板 {m.group(1)}"})
    return out


def kt_mcp_tools() -> list[dict[str, Any]]:
    text = _read(KT / "apps" / "agent" / "src" / "tools" / "kubetrail.ts")
    out = []
    for m in re.finditer(r'name:\s*"(kubetrail_[a-z_]+)"', text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(1), "anchor": f"apps/agent/src/tools/kubetrail.ts:{line}",
                    "behavior": "agent MCP 工具"})
    return out


def kt_exp_templates() -> list[dict[str, Any]]:
    text = _read(KT / "apps" / "agent" / "src" / "exp" / "catalog.ts")
    out = []
    for m in re.finditer(r'templateId:\s*"([\w-]+)",[\s\S]*?mode:\s*"(\w+)"', text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"id": m.group(1), "anchor": f"apps/agent/src/exp/catalog.ts:{line}",
                    "behavior": f"EXP 模板 mode={m.group(2)}"})
    return out


def kt_agent_skills() -> list[dict[str, Any]]:
    out = []
    base = KT / "apps" / "agent" / ".claude" / "skills"
    for d in sorted(base.iterdir()):
        if d.is_dir():
            out.append({"id": d.name, "anchor": f"apps/agent/.claude/skills/{d.name}/SKILL.md:1",
                        "behavior": "agent 攻击面技能（边界见 apps/agent/AGENTS.md）"})
    return out


def kt_views() -> list[dict[str, Any]]:
    out = []
    for vue in sorted((KT / "apps" / "desktop" / "frontend" / "src" / "views").glob("*.vue")):
        out.append({"id": vue.stem, "anchor": f"apps/desktop/frontend/src/views/{vue.name}:1",
                    "behavior": "桌面端 Vue 视图"})
    return out


def kt_components() -> list[dict[str, Any]]:
    out = []
    for vue in sorted((KT / "apps" / "desktop" / "frontend" / "src" / "components").glob("*.vue")):
        out.append({"id": vue.stem, "anchor": f"apps/desktop/frontend/src/components/{vue.name}:1",
                    "behavior": "桌面端 Vue 组件"})
    return out


# ---------------------------------------------------------------------------
# classification (human layer) — rules keyed by feature id / prefix.
# status: we-have(anchor) | partial(缺什么) | missing | N/A
# action: S | M | L | -(刻意不做/无需)
# ---------------------------------------------------------------------------

Cls = tuple[str, str, str, str, str]  # status, trident_anchor, action, note, backlog


def _rule_based(keys: list[str], rules: list[tuple[re.Pattern, Cls]],
                default: Cls) -> dict[str, Cls]:
    out: dict[str, Cls] = {}
    for key in keys:
        hit = None
        for rx, cls in rules:
            if rx.fullmatch(key) or rx.match(key) if rx.pattern else False:
                hit = cls
                break
        out[key] = hit or default
    return out


ARTEX_ROUTE_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"POST /api/auth/init"), (STATUS_PARTIAL, "core/users.py", "S", "首启初始化向导缺独立端点（users.py 已有种子角色）", "")),
    (re.compile(r"(GET|POST) /api/auth/(status|login)"), (STATUS_WE_HAVE, "core/users.py + webui/server.py /api/login", "-", "JWT/会话登录等价", "")),
    (re.compile(r"POST /api/auth/change-password"), (STATUS_PARTIAL, "core/users.py", "S", "缺自助改密端点", "")),
    (re.compile(r"GET /api/basic-auth/check|(GET|PUT) /api/settings/basic-auth"), (STATUS_MISSING, "-", "-", "HTTP Basic Auth 外层门：部署层反代可等价，刻意不做", "")),
    (re.compile(r"GET /api/health"), (STATUS_PARTIAL, "webui/server.py", "S", "缺 /health 探针端点", "")),
    (re.compile(r"GET /api/stats"), (STATUS_PARTIAL, "webui/server.py /api/runs + reports/", "S", "缺全局 stats 聚合端点", "")),
    (re.compile(r"(GET|POST) /api/logs.*"), (STATUS_PARTIAL, "core/evidence.py JSONL artifacts", "S", "日志查询/历史/SSE 流缺端点（过程检索→CM-02）", "CM-02")),
    (re.compile(r"(GET|PUT|POST) /api/update/.*"), (STATUS_MISSING, "-", "-", "一键自更新/回滚：包管理部署形态，刻意不做", "")),
    (re.compile(r"GET /api/schedules|POST /api/schedules|.* /api/schedules/.*"), (STATUS_WE_HAVE, "core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)", "-", "cron 调度等价；缺 remark/metadata 字段", "")),
    (re.compile(r"(GET|POST|PATCH|DELETE) /api/task-categories.*"), (STATUS_MISSING, "-", "M", "任务分类实体（任务模型=runs，无分类维度）", "")),
    (re.compile(r"POST /api/tasks/category/batch"), (STATUS_MISSING, "-", "M", "批量改分类（同上）", "")),
    (re.compile(r"(GET|POST|PATCH|DELETE) /api/task-templates.*"), (STATUS_PARTIAL, "lab/ 配置 + chains/*.json 模板", "S", "任务模板实体与 CRUD 缺（链模板已有）", "")),
    (re.compile(r"GET /api/tasks|POST /api/tasks"), (STATUS_PARTIAL, "core/runner.py runs + webui /api/runs", "L", "任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源", "CM-31")),
    (re.compile(r".* /api/tasks/\{id\}(/category)?$"), (STATUS_PARTIAL, "core/runner.py + webui /api/runs", "L", "任务详情/改元数据：runs 有详情，缺可编辑元数据", "CM-31")),
    (re.compile(r"DELETE /api/tasks/\{id\}"), (STATUS_MISSING, "-", "L", "任务删除（runs 为不可变证据，刻意保留）", "")),
    (re.compile(r".* /api/tasks/\{id\}/intercept-rules.*"), (STATUS_WE_HAVE, "core/roe.py 目标范围/禁打规则", "S", "任务级拦截规则 CRUD 端点缺（ROE 内已有等价约束）", "")),
    (re.compile(r"POST /api/tasks/control/batch"), (STATUS_MISSING, "-", "M", "批量任务控制（单 run 模型外）", "CM-31")),
    (re.compile(r"(GET|POST) /api/task-archives.*|POST /api/tasks/\{id\}/archive|POST /api/tasks/archive/batch"), (STATUS_MISSING, "-", "L", "冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置）", "")),
    (re.compile(r"GET /api/tasks/\{id\}/coverage(-graph)?$"), (STATUS_PARTIAL, "core/graph.py 维度图", "M", "任务级覆盖度/血缘图端点缺（血缘边→CM-16）", "CM-16")),
    (re.compile(r"(GET|POST|DELETE) /api/tasks/\{id\}/(asset-refs|assets|intent-assets)(/.*)?$"), (STATUS_PARTIAL, "core/discovery.py AssetInventory + webui /api/v1/assets", "S", "任务↔资产绑定关系缺", "")),
    (re.compile(r"(GET|POST|DELETE) /api/workspace/.*"), (STATUS_MISSING, "-", "M", "run 工作区文件管理器（离线 artifacts 模型，刻意不做 UI）", "")),
    (re.compile(r".* /api/tasks/\{id\}/scope.*"), (STATUS_WE_HAVE, "core/roe.py 目标范围", "S", "任务级动态 scope CRUD 端点缺", "")),
    (re.compile(r".* /api/tasks/\{id\}/goals.*"), (STATUS_PARTIAL, "agent_planner.py 推荐+审批", "M", "goal 实体 CRUD 缺（planner 输出即目标集）", "CM-16")),
    (re.compile(r".* /api/tasks/\{id\}/constraints.*"), (STATUS_WE_HAVE, "core/roe.py 约束", "S", "运行中动态增删约束端点缺", "")),
    (re.compile(r"POST /api/tasks/\{id\}/control"), (STATUS_WE_HAVE, "webui /api/execute + /api/abort", "-", "暂停/恢复/停止等价（abort）", "")),
    (re.compile(r"POST /api/active"), (STATUS_MISSING, "-", "L", "全局活动任务切换（单活动 run 模型）", "")),
    (re.compile(r".* /api/tasks/\{id\}/intents/.*"), (STATUS_PARTIAL, "core/explorer.py 审批队列 + webui /api/v1/explorer", "M", "意图级控制/消息/重跑缺", "")),
    (re.compile(r"(GET|PUT|POST) /api/llm.*"), (STATUS_MISSING, "-", "-", "LLM 多 profile/池/轮询/重试：刻意不做（REFLECTION-ARTEX-KUBETRAIL §2，0-token 原则）", "")),
    (re.compile(r"(GET|POST|DELETE) /api/assets.*"), (STATUS_PARTIAL, "core/discovery.py + webui /api/v1/assets", "S", "资产插入/删除端点缺（发现+导入已有）", "")),
    (re.compile(r".* /api/companies.*"), (STATUS_MISSING, "-", "M", "公司/归属/重归属实体（多租户工作区另有 users.py 四角色）", "")),
    (re.compile(r"GET /api/exploration/frontier"), (STATUS_PARTIAL, "agent_planner.py 推荐排序", "-", "frontier 视图缺独立端点", "")),
    (re.compile(r"GET /api/exploration/findings/groups"), (STATUS_PARTIAL, "core/combo.py 组合签名", "M", "finding 分组视图缺", "")),
    (re.compile(r".* /api/exploration/finding-cases.*"), (STATUS_MISSING, "-", "M", "同根因案例归并/评审工作流", "CM-17")),
    (re.compile(r"(GET|POST) /api/exploration/finding-case-suggestions.*"), (STATUS_MISSING, "-", "M", "案例归并建议/裁决", "CM-17")),
    (re.compile(r"GET /api/exploration/finding-case-review|POST /api/exploration/finding-case-review"), (STATUS_MISSING, "-", "M", "案例评审 run", "CM-17")),
    (re.compile(r"GET /api/exploration/findings/asset-tree"), (STATUS_PARTIAL, "core/discovery.py + core/graph.py", "S", "资产树端点缺", "")),
    (re.compile(r"GET /api/exploration/findings/stats"), (STATUS_PARTIAL, "reports/render.py 统计", "S", "finding stats 端点缺", "")),
    (re.compile(r"GET /api/exploration/findings/export"), (STATUS_WE_HAVE, "export.py SARIF/OCSF/VEX", "-", "导出等价", "")),
    (re.compile(r".* /api/exploration/findings/\{id\}/traffic.*"), (STATUS_PARTIAL, "core/traffic.py 录制/回放", "M", "finding↔流量证据绑定关系缺", "CM-18")),
    (re.compile(r"GET /api/exploration/findings/\{id\}/lineage|POST /api/exploration/findings/\{id\}/deepen"), (STATUS_PARTIAL, "core/graph.py", "M", "finding 血缘/深挖工作流缺", "CM-16")),
    (re.compile(r"(GET|POST) /api/exploration/findings(/\{id\})?/retests.*|GET /api/exploration/findings/retests/active"), (STATUS_PARTIAL, "webui /api/v1/poc/reverify + verify-effects.py", "M", "finding 级 retest 实体/活跃 run 列表缺", "CM-14")),
    (re.compile(r"(GET|PATCH|DELETE) /api/exploration/findings(/\{id\})?"), (STATUS_PARTIAL, "core/evidence.py findings + webui /api/runs", "S", "单 finding 读取/批注/删除端点缺", "")),
    (re.compile(r"GET /api/exploration/(graph|nodes|intents)"), (STATUS_PARTIAL, "core/graph.py", "M", "探索图/节点/意图查询端点缺", "CM-16")),
    (re.compile(r"GET /api/exploration/activity.*"), (STATUS_PARTIAL, "core/evidence.py 事件流", "S", "活动流/历史/SSE 端点缺", "")),
    (re.compile(r"(GET|POST) /api/exploration/main-session.*"), (STATUS_MISSING, "-", "-", "主 agent 会话（自主执行循环刻意不做，Ruling 规划≠执行）", "")),
    (re.compile(r"GET /api/exploration/tokens|GET /api/tokens/.*"), (STATUS_MISSING, "-", "-", "token 用量统计（0-token 原则，刻意不做）", "")),
    (re.compile(r"GET /api/audit"), (STATUS_PARTIAL, "core/evidence.py manifest 篡改检测", "S", "独立审计查询端点缺", "")),
    (re.compile(r"POST /api/gc"), (STATUS_PARTIAL, "core/backup.py", "S", "显式 GC 端点缺", "")),
    (re.compile(r"(GET|DELETE) /api/traffic.*"), (STATUS_PARTIAL, "core/traffic.py ingest/replay + webui /api/v1/traffic", "S", "按主机/正文浏览与批量删除端点缺", "")),
    (re.compile(r"GET /api/commands.*"), (STATUS_PARTIAL, "core/evidence.py 命令记录", "S", "命令审计/按工具聚合视图缺", "")),
    (re.compile(r"GET /api/llm/records.*|DELETE /api/llm/records"), (STATUS_MISSING, "-", "-", "LLM 调用留档（0-token 原则）", "")),
    (re.compile(r"(GET|PATCH|POST) /api/tasks/\{id\}/intelligence.*|GET /api/assets/\{id\}/intelligence.*"), (STATUS_MISSING, "-", "S", "任务情报登记（凭据/线索集中 registry）", "CM-01")),
    (re.compile(r"(GET|PUT) /api/settings$"), (STATUS_PARTIAL, "lab/ 实验配置 + CLI 参数", "S", "集中设置端点缺", "")),
    (re.compile(r"POST /api/settings/web-search/test"), (STATUS_MISSING, "-", "-", "内置 web 搜索（外部检索由 librarian/websearch 会话承担）", "")),
    (re.compile(r"POST /api/settings/python/detect"), (STATUS_MISSING, "-", "S", "自定义脚本工具解释器检测", "")),
    (re.compile(r"(GET|POST|PATCH|DELETE) /api/notify.*"), (STATUS_MISSING, "-", "S", "IM 推送渠道/投递/重试（输出多路分发同族）", "CM-10")),
    (re.compile(r"GET /api/report"), (STATUS_WE_HAVE, "reports/render.py + compliance", "-", "报告等价", "")),
    (re.compile(r"(GET|POST) /api/chat.*|POST /api/chat$"), (STATUS_MISSING, "-", "-", "对话式主 agent/上传/mentions（自主执行循环刻意不做）", "")),
    (re.compile(r"(GET|POST) /api/tasks/\{id\}/chat.*"), (STATUS_MISSING, "-", "-", "任务对话（同上）", "")),
    (re.compile(r".* /api/conversations.*"), (STATUS_MISSING, "-", "-", "多会话管理（对话式平台刻意不做）", "")),
    (re.compile(r".* /api/agents/.*|GET /api/agents$|POST /api/agents$"), (STATUS_MISSING, "-", "-", "多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台刻意不做，REFLECTION §2）", "")),
    (re.compile(r"(GET|POST|PATCH|DELETE) /api/(agents/\{key\}/triggers|triggers/.*).*"), (STATUS_MISSING, "-", "S", "事件/间隔触发器（调度器族）", "CM-04")),
    (re.compile(r"(GET|PUT|POST|DELETE) /api/tools.*"), (STATUS_PARTIAL, "core/registry.py 模块动态加载", "S", "内置工具目录改描述/默认值缺（模块即工具）", "")),
    (re.compile(r"POST /api/tools/custom.*|PUT /api/tools/custom/.*|DELETE /api/tools/custom/.*"), (STATUS_MISSING, "-", "S", "自定义脚本工具（python 检测联动）", "")),
    (re.compile(r"(GET|POST|DELETE) /api/mcp.*|GET /api/mcp/\{id\}/tools|POST /api/mcp/\{id\}/refresh"), (STATUS_PARTIAL, "mcp_server.py（服务端 10 只读工具）", "M", "作为 client 挂载外部 MCP 的 CRUD 缺", "")),
    (re.compile(r"(GET|POST) /api/sync/scopesentry.*"), (STATUS_MISSING, "-", "S", "ScopeSentry 资产同步（外部输入适配器族）", "CM-13")),
    (re.compile(r"(GET|POST|PUT|DELETE) /api/skills.*"), (STATUS_PARTIAL, "lab/ 脚本 + rules/templates/", "M", "skill 实体 CRUD/上传/使用统计缺", "")),
    (re.compile(r"(GET|POST) /api/visibility.*"), (STATUS_MISSING, "-", "-", "按 agent 的资源可见性（多 agent 模型外）", "")),
    (re.compile(r"(GET|POST|PUT|DELETE) /api/intercept/rules.*"), (STATUS_PARTIAL, "core/roe.py + core/explorer.py 审批", "S", "拦截规则持久化 CRUD 缺（ROE 内置规则）", "")),
    (re.compile(r".* /api/asset-intercept/.*"), (STATUS_WE_HAVE, "core/roe.py 禁打范围", "S", "全局资产黑名单 CRUD 端点缺", "")),
    (re.compile(r"GET /api/intercept/pending.*|POST /api/intercept/pending/.*"), (STATUS_WE_HAVE, "core/explorer.py propose/approve + webui /approve //reject", "-", "待审/裁决等价", "")),
    (re.compile(r"GET /api/intercept/history.*"), (STATUS_PARTIAL, "core/evidence.py 审批留档", "S", "拦截历史/执行细节端点缺", "")),
    (re.compile(r"GET /api/intercept/task/.*"), (STATUS_PARTIAL, "core/evidence.py run 事件", "S", "按任务拦截项列表缺", "")),
    (re.compile(r"(GET|PUT) /api/intercept/tool-config"), (STATUS_PARTIAL, "core/roe.py 工具边界", "S", "按工具拦截配置端点缺", "")),
    (re.compile(r"(GET|PUT) /api/intercept/judge.*"), (STATUS_MISSING, "-", "M", "LLM 兜底审批（模型判定未命中规则的命令）", "")),
    (re.compile(r".* /api/side-questions.*"), (STATUS_MISSING, "-", "M", "agent 侧问/澄清队列（人在环单向审批已对齐，反向提问缺）", "")),
]

ARTEX_TABLE_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"(companies|assets|company_scope)"), (STATUS_PARTIAL, "core/discovery.py AssetInventory", "M", "资产/公司实体持久化缺（发现结果入 evidence）", "")),
    (re.compile(r"explorations?|exploration_.*"), (STATUS_PARTIAL, "core/graph.py + core/explorer.py", "M", "探索图持久化表缺（内存图+runs）", "CM-16")),
    (re.compile(r"task_constraints|task_scope"), (STATUS_WE_HAVE, "core/roe.py", "S", "约束/范围持久化表缺（ROE YAML 内）", "")),
    (re.compile(r"(activity|main_sessions|server_logs)"), (STATUS_PARTIAL, "core/evidence.py JSONL", "S", "活动/日志独立表缺（事件入证据库）", "")),
    (re.compile(r"settings"), (STATUS_PARTIAL, "lab/ 配置", "S", "集中设置表缺", "")),
    (re.compile(r"llm_profile.*"), (STATUS_MISSING, "-", "-", "多模型池（刻意不做，REFLECTION §2）", "")),
    (re.compile(r"task_categories|tasks|task_archives|task_templates|task_relations|task_asset_links|task_llm_profiles|scheduler_state|task_schedules|task_schedule_tasks|task_schedule_history"), (STATUS_PARTIAL, "core/scheduler.py + core/runner.py runs", "M", "任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺", "CM-31")),
    (re.compile(r"agent.*"), (STATUS_MISSING, "-", "-", "多 agent 实体族（刻意不做）", "")),
    (re.compile(r"mcp_servers|mcp_tools_cache"), (STATUS_PARTIAL, "mcp_server.py", "M", "外部 MCP 挂载表缺（服务端已有）", "")),
    (re.compile(r"(skill_usage|tool_usage|tools)"), (STATUS_PARTIAL, "core/registry.py", "S", "工具/技能使用统计缺", "")),
    (re.compile(r"conversations.*"), (STATUS_MISSING, "-", "-", "会话持久化（对话式平台刻意不做）", "")),
    (re.compile(r"agent_triggers"), (STATUS_MISSING, "-", "S", "触发器（调度器族）", "CM-04")),
    (re.compile(r"intercept_rules|intercept_pending"), (STATUS_WE_HAVE, "core/explorer.py 审批队列", "S", "拦截规则/待审持久化表缺（内存队列+ROE）", "")),
    (re.compile(r"findings"), (STATUS_WE_HAVE, "core/evidence.py findings", "S", "独立 findings 表缺（入 run 证据库）", "")),
    (re.compile(r"finding_retests"), (STATUS_PARTIAL, "webui /api/v1/poc/reverify", "M", "retest 实体表缺", "CM-14")),
    (re.compile(r"traffic_evidence_snapshots|finding_traffic_bindings"), (STATUS_PARTIAL, "core/traffic.py", "M", "流量快照/绑定表缺", "CM-18")),
    (re.compile(r"side_question_.*"), (STATUS_MISSING, "-", "M", "侧问会话/请求", "")),
    (re.compile(r"(asset|task)_intercept_rules"), (STATUS_WE_HAVE, "core/roe.py", "S", "规则表缺（ROE 表达）", "")),
    (re.compile(r"notification_.*"), (STATUS_MISSING, "-", "S", "通知渠道/事件/投递表", "CM-10")),
    (re.compile(r"finding_case.*"), (STATUS_MISSING, "-", "M", "案例归并族表", "CM-17")),
    (re.compile(r"task_intelligence"), (STATUS_MISSING, "-", "S", "任务情报表", "CM-01")),
]

ARTEX_AGENT_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"(planner|worker|mainagent|chat)\.go"), (STATUS_PARTIAL, "agent_planner.py + core/explorer.py", "-", "规划/探索循环：推荐+lead 审批等价；自主多轮执行刻意不做", "")),
    (re.compile(r"goals\.go"), (STATUS_PARTIAL, "agent_planner.py", "M", "goal 实体/复活任务缺", "CM-16")),
    (re.compile(r"(intelligence|credentials)\.go"), (STATUS_MISSING, "-", "S", "情报/凭据登记", "CM-01")),
    (re.compile(r"(compaction|noa)\.go"), (STATUS_MISSING, "-", "-", "上下文压缩（无多轮对话运行时，刻意不做）", "")),
    (re.compile(r"finding_(recorder|workflow|cases)\.go"), (STATUS_PARTIAL, "core/evidence.py + core/combo.py", "M", "finding 工作流/案例缺", "CM-17")),
    (re.compile(r"retester\.go"), (STATUS_PARTIAL, "poc reverify + verify-effects.py", "M", "自动复测 worker 缺", "CM-14")),
    (re.compile(r"coldgraph\.go"), (STATUS_PARTIAL, "core/graph.py", "M", "冷启动图重建缺", "CM-16")),
    (re.compile(r"wrapup\.go"), (STATUS_MISSING, "-", "-", "收尾 prompt（对话式运行时外）", "")),
    (re.compile(r"(prompt|promptcatalog|toolcatalog|tools)\.go|tools_.*\.go"), (STATUS_PARTIAL, "core/registry.py + rules/templates/", "S", "提示词/工具目录机制差异（模块即工具）", "")),
    (re.compile(r"side_questions\.go"), (STATUS_MISSING, "-", "M", "侧问", "")),
    (re.compile(r"(taskclock|runinfo|terminalreason|cancelcause)\.go"), (STATUS_PARTIAL, "core/runner.py abort/timeout", "S", "任务钟/终止原因留档细节缺", "")),
    (re.compile(r"(deferred|constraints)\.go"), (STATUS_WE_HAVE, "core/roe.py", "S", "延迟动作/约束执行缺端点", "")),
    (re.compile(r"(provider|request_limiter)\.go|provider_.*\.go"), (STATUS_MISSING, "-", "-", "多模型 provider/限流（刻意不做）", "")),
    (re.compile(r"(assembly|capture)\.go"), (STATUS_PARTIAL, "core/chains.py + core/evidence.py", "S", "工具装配/捕获留档差异", "")),
]

ARTEX_PAGE_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"/dashboard"), (STATUS_WE_HAVE, "webui SPA 总览视图", "-", "", "")),
    (re.compile(r"/function/tasks(/detail)?"), (STATUS_PARTIAL, "webui runs 视图", "M", "任务详情/控制 UI 部分对齐（缺任务元数据编辑）", "CM-31")),
    (re.compile(r"/function/findings/case"), (STATUS_MISSING, "-", "M", "案例归并页", "CM-17")),
    (re.compile(r"/function/findings(/detail)?"), (STATUS_PARTIAL, "webui findings 视图", "S", "finding 详情/批注缺", "")),
    (re.compile(r"/function/llm-records"), (STATUS_MISSING, "-", "-", "LLM 调用记录（0-token）", "")),
    (re.compile(r"/function/schedules"), (STATUS_WE_HAVE, "webui 调度视图", "-", "", "")),
    (re.compile(r"/function/sync"), (STATUS_MISSING, "-", "S", "ScopeSentry 同步页", "CM-13")),
    (re.compile(r"/function/assets"), (STATUS_WE_HAVE, "webui assets 视图", "-", "", "")),
    (re.compile(r"/function/commands"), (STATUS_PARTIAL, "webui + evidence 命令记录", "S", "命令审计页缺", "")),
    (re.compile(r"/function/traffic"), (STATUS_PARTIAL, "webui traffic 回放视图", "S", "流量浏览/删除 UI 缺", "")),
    (re.compile(r"/function/workspace"), (STATUS_MISSING, "-", "M", "工作区文件管理页", "")),
    (re.compile(r"/chat"), (STATUS_MISSING, "-", "-", "对话页（刻意不做）", "")),
    (re.compile(r"/system/agents.*"), (STATUS_MISSING, "-", "-", "多 agent 管理页（刻意不做）", "")),
    (re.compile(r"/system/intercept/approvals"), (STATUS_WE_HAVE, "webui /approve //reject 审批页", "-", "", "")),
    (re.compile(r"/system/intercept(/assets)?"), (STATUS_PARTIAL, "webui 审批 + core/roe.py", "S", "拦截规则/资产黑名单管理页缺", "")),
    (re.compile(r"/system/llm"), (STATUS_MISSING, "-", "-", "LLM 配置页（刻意不做）", "")),
    (re.compile(r"/system/logs"), (STATUS_PARTIAL, "evidence JSONL + webui", "S", "日志流页缺", "CM-02")),
    (re.compile(r"/system/mcp"), (STATUS_PARTIAL, "mcp_server.py", "M", "外部 MCP 挂载页缺", "")),
    (re.compile(r"/system/notify"), (STATUS_MISSING, "-", "S", "通知渠道页", "CM-10")),
    (re.compile(r"/system/settings"), (STATUS_PARTIAL, "lab/ 配置 + CLI", "S", "设置页缺", "")),
    (re.compile(r"/system/skills"), (STATUS_PARTIAL, "lab/ + rules/templates/", "M", "skill 管理页缺", "")),
    (re.compile(r"/system/tools"), (STATUS_PARTIAL, "core/registry.py", "S", "工具目录页缺", "")),
    (re.compile(r"/auth/.*"), (STATUS_PARTIAL, "webui 登录 + core/users.py", "S", "setup 向导页缺", "")),
    (re.compile(r"/.*"), (STATUS_NA, "-", "-", "外部落地页/类别外", "")),
]

ARTEX_COMPONENT_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"components/ui/.*"), (STATUS_NA, "-", "-", "shadcn/ui 基础件（非功能特性）", "")),
    (re.compile(r"components/calendar/.*"), (STATUS_PARTIAL, "core/scheduler.py", "S", "日历式调度视图缺", "")),
    (re.compile(r"_components/.*(sidebar|nav|search|account|theme|update|layout).*"), (STATUS_PARTIAL, "webui SPA 导航", "S", "侧栏/账号切换/主题切换/全局搜索 UI 细节缺", "")),
]

ARTEX_CONFIG_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"database\..*"), (STATUS_MISSING, "-", "-", "PG 依赖（单机零依赖 evidence store，部署形态刻意差异）", "")),
    (re.compile(r"skill_dir"), (STATUS_PARTIAL, "lab/ 脚本目录约定", "S", "可配置 skill 根目录缺", "")),
]

ARTEX_SKILL_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"api-recon"), (STATUS_PARTIAL, "modules/recon 族（exposure-mapping 等）", "-", "API 面侦察细分模块", "")),
    (re.compile(r"playwright-cli"), (STATUS_MISSING, "-", "M", "浏览器自动化 skill（Web UI 攻击面）", "")),
    (re.compile(r"scopesentry"), (STATUS_MISSING, "-", "S", "ScopeSentry 对接 skill", "CM-13")),
]

KT_COLLECTOR_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"identity"), (STATUS_PARTIAL, "core/roe.py + core/discovery.py", "M", "in-pod 身份视角缺（控制面侧等价）", "CM-22")),
    (re.compile(r"environment"), (STATUS_PARTIAL, "modules/metadata-egress 等环境面", "M", "in-pod 环境变量面缺", "CM-22")),
    (re.compile(r"serviceaccount$"), (STATUS_PARTIAL, "modules/rbac-mapping + overprivileged-sa-escalation", "M", "挂载 SA token 本地视角缺", "CM-22")),
    (re.compile(r"proc$|proc_sys_escape"), (STATUS_MISSING, "-", "M", "in-pod /proc /sys 突破面矩阵", "CM-22")),
    (re.compile(r"filesystem"), (STATUS_PARTIAL, "modules/escape-primitives", "M", "in-pod 文件系统挂载面缺", "CM-22")),
    (re.compile(r"node_local"), (STATUS_PARTIAL, "modules/escape-primitives + gpu-network-operator-posture", "M", "节点本地文件/凭据面缺", "CM-22")),
    (re.compile(r"runtime_local"), (STATUS_WE_HAVE, "modules/runtime-socket-escape", "M", "runtime socket 逃逸已覆盖；in-pod 本地探测视角缺", "CM-22")),
    (re.compile(r"lpe_local"), (STATUS_MISSING, "-", "-", "内核 LPE 采集（内核 LPE CVE 库维持不补，REFLECTION Ruling）", "")),
    (re.compile(r"k8s_context|k8s_profile|k8s_objects"), (STATUS_PARTIAL, "core/discovery.py + modules/rbac-mapping", "M", "in-cluster pod 视角缺", "CM-22")),
    (re.compile(r"k8s_permissions"), (STATUS_WE_HAVE, "modules/rbac-mapping + core/auditlog.py 检测器", "M", "SSRR/SSAR 权限审查已覆盖；逐 token 审计缺", "CM-05")),
    (re.compile(r"credential_sweep"), (STATUS_PARTIAL, "modules/supply-chain-credential-theft + cloud-integration-fingerprint", "M", "in-pod 凭据文件清扫缺", "CM-22")),
    (re.compile(r"admission_dryrun"), (STATUS_MISSING, "-", "M", "admission dry-run 反推准入边界", "CM-24")),
    (re.compile(r"dns_services"), (STATUS_PARTIAL, "modules/dns-service-discovery", "-", "SRV 探测细分缺", "")),
    (re.compile(r"cloud_metadata"), (STATUS_WE_HAVE, "modules/metadata-egress + multi-cloud-imds-credentials + ssrf-imds-credential + cloud-sg-imds-exposure", "-", "13 家云元数据端点探测等价（full.go:69-93 枚举）", "")),
    (re.compile(r"syscalls"), (STATUS_MISSING, "-", "M", "in-pod syscall 矩阵（sysprobe.RunMatrix）", "CM-22")),
    (re.compile(r"sa_token_audit"), (STATUS_MISSING, "-", "S", "legacy SA token 逐 token SSRR/SSAR + JWT claims", "CM-05")),
]

KT_EVALUATOR_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"EvaluateLPE|evaluateLPE.*|lpeNoHitsSummary"), (STATUS_MISSING, "-", "-", "内核 LPE 规则族（维持不补 Ruling）", "")),
    (re.compile(r"EvaluateEscape"), (STATUS_PARTIAL, "modules/escape-primitives", "M", "逃逸规则族入口（部分原语已覆盖）", "")),
    (re.compile(r"EvaluateRBAC"), (STATUS_WE_HAVE, "modules/rbac-mapping + core/auditlog.py", "S", "RBAC 规则族入口", "")),
    (re.compile(r"evaluateCaps"), (STATUS_PARTIAL, "modules/escape-primitives", "S", "cap 位检查细分缺（SYS_ADMIN/SYS_PTRACE/NET_ADMIN/DAC_READ_SEARCH/SYS_RAWIO/SYS_MODULE 6 位）", "")),
    (re.compile(r"evaluateSeccomp|evaluateNoNewPrivs|evaluateNamespaceSharing"), (STATUS_PARTIAL, "modules/escape-primitives + privileged-workloads", "S", "seccomp/NNP/命名空间共享信号细分缺", "")),
    (re.compile(r"evaluateCgroup.*"), (STATUS_PARTIAL, "modules/escape-primitives", "S", "cgroup release_agent/设备写面细分缺", "")),
    (re.compile(r"evaluateProcSysBreakoutSurfaces|evaluateKernelHelperPaths|evaluateSensitiveExposures|evaluateSecurityProfiles|evaluateUserNamespaceMapping|evaluateHostVisibility"), (STATUS_PARTIAL, "modules/escape-primitives", "M", "proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility）", "")),
    (re.compile(r"evaluateRuntimeSockets|mergeRuntimeSocketFacts"), (STATUS_WE_HAVE, "modules/runtime-socket-escape", "-", "runtime socket 可写=逃逸原语等价", "")),
    (re.compile(r"evaluateRuntimeVersions"), (STATUS_MISSING, "-", "-", "docker/runc/containerd/alpine 版本比对 CVE（版本启发式库不内置；镜像 CVE→CM-13 适配器承接）", "CM-13")),
    (re.compile(r"evaluateVolumeHints|evaluatePodSpec"), (STATUS_WE_HAVE, "modules/privileged-workloads + privileged-gpu-pod-escape", "S", "hostPath/privileged/hostPID/hostNetwork 检查等价", "")),
    (re.compile(r"evaluateWritableBindMountsWithoutNosuid"), (STATUS_PARTIAL, "modules/escape-primitives", "S", "rw+无 nosuid 挂载细分缺", "")),
    (re.compile(r"evaluateExpandedWildcards"), (STATUS_WE_HAVE, "modules/rbac-mapping + auditlog _detect_rbac_clusteradmin_binding", "-", "cluster-admin 等价", "")),
    (re.compile(r"evaluateHighValueAccess"), (STATUS_WE_HAVE, "modules/overprivileged-sa-escalation + rbac-mapping + auditlog 检测器", "S", "11 条高价值权限规则族", "")),
    (re.compile(r"combineEscapeSignals|collectEscapeSignalSet"), (STATUS_WE_HAVE, "core/chains.py 组合链", "S", "多信号组合升级=链编排思想等价", "")),
]

KT_TITLE_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r".*(CVE-2021-3156|CVE-2025-32463|CVE-2021-4034|PwnKit|CVE-2017-5618|CVE-2026-41651|Dirty Pipe|CVE-2022-0847|CVE-2017-16995|CVE-2021-3490|CVE-2024-1086|CVE-2026-31431|CVE-2026-43284|CVE-2026-43500|CVE-2023-0386|CVE-2022-0185|CVE-2021-3493|Dirty COW|No LPE candidates).*", re.I), (STATUS_MISSING, "-", "-", "内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling）", "")),
    (re.compile(r".*setuid screen.*|PwnKit exposure signal.*", re.I), (STATUS_MISSING, "-", "-", "setuid 工具启发式（同上 Ruling）", "")),
    (re.compile(r".*(CVE-2019-5736|CVE-2019-13139|CVE-2021-41091|CVE-2020-15257|CVE-2019-5021).*"), (STATUS_MISSING, "-", "-", "runtime 版本比对 CVE（版本启发式不内置，镜像 CVE→CM-13）", "CM-13")),
    (re.compile(r".*Runtime socket.*"), (STATUS_WE_HAVE, "modules/runtime-socket-escape", "-", "", "")),
    (re.compile(r".*[Pp]rivileged [Cc]ontainer.*"), (STATUS_WE_HAVE, "modules/privileged-workloads + privileged-gpu-pod-escape", "-", "", "")),
    (re.compile(r".*hostPath.*|.*hostPID.*|.*host network.*|.*Host network.*|.*Host PID.*|.*Host mount.*|.*hostIPC.*|.*host network namespace.*"), (STATUS_WE_HAVE, "modules/privileged-workloads + escape-primitives", "S", "hostPath/hostPID/hostNetwork/hostIPC 信号等价", "")),
    (re.compile(r".*CAP_SYS_ADMIN.*|.*CAP_.*"), (STATUS_PARTIAL, "modules/escape-primitives", "S", "危险 cap 位细分（6 位枚举）缺", "")),
    (re.compile(r".*Cluster-admin equivalent.*"), (STATUS_WE_HAVE, "core/auditlog.py _detect_rbac_clusteradmin_binding", "-", "", "")),
    (re.compile(r".*pods/exec.*|.*Secrets readable.*"), (STATUS_WE_HAVE, "core/auditlog.py _detect_pods_exec/_detect_secret_abnormal_read", "-", "", "")),
    (re.compile(r".*(nodes/proxy|escalate|Impersonation|kube-system secrets|SA token creation|RoleBinding create|MutatingWebhook|Pod creation|DaemonSet creation).*"), (STATUS_PARTIAL, "modules/rbac-mapping + overprivileged-sa-escalation", "S", "高价值 RBAC 规则细分缺逐条", "")),
    (re.compile(r".*(release_agent|cgroup|kernel path|sensitive surface|host memory|proc surface|AppArmor|SELinux|User namespace|Host processes|Host-like|Seccomp disabled|NoNewPrivs|Writable.*mount).*", re.I), (STATUS_PARTIAL, "modules/escape-primitives", "M", "逃逸原语逐路径细分缺（部分已覆盖）", "")),
    (re.compile(r".*(escape:|Confirmed escape|Probable escape).*"), (STATUS_WE_HAVE, "core/chains.py 组合升级链", "S", "组合判定等价", "")),
]

KT_SENSITIVITY_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"raw"), (STATUS_WE_HAVE, "core/redact.py 可关（原始留档）", "-", "", "")),
    (re.compile(r"redact"), (STATUS_WE_HAVE, "core/redact.py cred/pii", "-", "", "")),
    (re.compile(r"metadata"), (STATUS_MISSING, "-", "S", "metadata-by-reference 三态（present/bytes/sha256）", "CM-06")),
]

KT_MODEL_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"kubetrail\..*"), (STATUS_WE_HAVE, "core/auditlog.py adapt_kubetrail（dbus.json→findings 消费端）", "-", "schema 契约已适配", "")),
    (re.compile(r"Document\.(schemaVersion|run|target|mode|collectors|facts|findings)"), (STATUS_WE_HAVE, "core/auditlog.py adapt_kubetrail", "-", "", "")),
    (re.compile(r"Document\.errors"), (STATUS_PARTIAL, "core/auditlog.py adapt_kubetrail", "S", "errors 字段消费细节", "")),
    (re.compile(r"SATokenAuditDocument\..*|SATokenAudit.*"), (STATUS_MISSING, "-", "S", "SA token 审计文档字段消费", "CM-05")),
]

KT_CLI_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"--mode"), (STATUS_WE_HAVE, "core/runner.py dry-run/live 键", "-", "safe/full 分级=ROE 预演/实测", "")),
    (re.compile(r"--output|--pretty"), (STATUS_WE_HAVE, "export.py + core/evidence.py", "-", "", "")),
    (re.compile(r"--secretoutput|--secret"), (STATUS_MISSING, "-", "S", "SA token 审计独立产物", "CM-05")),
    (re.compile(r"--timeout"), (STATUS_WE_HAVE, "core/runner.py 超时", "-", "", "")),
    (re.compile(r"--sensitive"), (STATUS_PARTIAL, "core/redact.py", "S", "三态缺 metadata", "CM-06")),
    (re.compile(r"--rbac-mode"), (STATUS_PARTIAL, "modules/rbac-mapping", "S", "focused/full 模式键", "")),
    (re.compile(r"--kubeconfig"), (STATUS_NA, "-", "-", "目标内运行形态差异（Trident 控制台侧）", "")),
    (re.compile(r"--max-items"), (STATUS_PARTIAL, "core/roe.py 速率约束", "S", "list 限流参数", "")),
    (re.compile(r"--credential-sweep"), (STATUS_PARTIAL, "modules/supply-chain-credential-theft", "M", "凭据清扫开关", "CM-22")),
    (re.compile(r"--scan"), (STATUS_WE_HAVE, "core/runner.py 模块选择", "-", "lpe/escape/rbac 分类=模块族选择", "")),
]

KT_DESKTOP_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"(ListClusters|SaveCluster|DeleteCluster|TestConnection|ConnectCluster|DisconnectCluster|ListClusterExtensions|ClusterExtensionProxyPath)"), (STATUS_PARTIAL, "webui/server.py 多 run + core/discovery.py", "L", "多集群连接管理（Trident 单控制台多 run 模型）", "")),
    (re.compile(r"(OpenKubeconfigDialog|PickSaveFile|PickOpenFile|PickDirectory|OpenExternalURL|OpenDirectoryPath)"), (STATUS_NA, "-", "-", "Wails 桌面对话框（形态差异）", "")),
    (re.compile(r"(ListNamespaces|ListPods|ListNodes|DescribePod)"), (STATUS_PARTIAL, "core/discovery.py + webui /api/v1/assets", "S", "ns/pod/node 浏览端点缺", "")),
    (re.compile(r"(StartTerminal|WriteTerminal|ResizeTerminal|StopTerminal|StartLogs|StopLogs)"), (STATUS_MISSING, "-", "-", "交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做）", "")),
    (re.compile(r"(List|Read|Download|Upload|Delete)(Pod|Node)Files?"), (STATUS_MISSING, "-", "-", "pod/节点文件管理（执行面，刻意不做）", "")),
    (re.compile(r"(CheckNodeShellAccess|StartNodeTerminal|DeleteNodeShellPod)"), (STATUS_MISSING, "-", "-", "节点 shell 落地（执行面刻意不做；节点面侦察已有 escape-primitives/gpu-network-operator-posture）", "")),
    (re.compile(r"(ReconCatalog|ReconRead)"), (STATUS_PARTIAL, "modules/recon 族 + agent_planner.py 推荐排序", "S", "节点面侦察手册目录化缺", "")),
    (re.compile(r"(StartPortForward|StopPortForward|ListPortForwards)"), (STATUS_MISSING, "-", "-", "端口转发 C2 面（刻意不做）", "")),
    (re.compile(r"(ImportScanResult(Path)?|StartClusterScan|GetScanResult|ListScanResults|ExportScanResult|DeleteScanResult)"), (STATUS_WE_HAVE, "core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py", "S", "KubeTrail 导入已适配；通用扫描器导入缺", "CM-13")),
    (re.compile(r"(ConfigureAgent|GetAgentStatus|GetAgentDisplayConfig|GetAgentRuntimeInfo|CheckAgentRuntime|StopAgent|RestartAgent|AgentLogs|SaveAgentConfigOnly|TestAgentConnection|EnsureAgentRunning)"), (STATUS_MISSING, "-", "-", "AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有）", "")),
    (re.compile(r"(ListAgentSkills|GetAgentSkill|SaveAgentSkill|DeleteAgentSkill)"), (STATUS_PARTIAL, "lab/ 脚本 + rules/templates/", "M", "技能 CRUD 缺", "")),
    (re.compile(r"(StartAgentChat|StopAgentChat)"), (STATUS_MISSING, "-", "-", "agent 对话（刻意不做）", "")),
    (re.compile(r"GetAttackGraph"), (STATUS_PARTIAL, "core/graph.py + core/reachability.py", "M", "攻击图端点缺（自动路径计算→CM-23）", "CM-23")),
    (re.compile(r"MaterializeSensitive"), (STATUS_MISSING, "-", "S", "敏感材料受控物化", "CM-06")),
    (re.compile(r"ExportAnalysisReport"), (STATUS_WE_HAVE, "reports/render.py + export.py", "-", "", "")),
    (re.compile(r"(ListExpTemplates|GenerateExp)"), (STATUS_PARTIAL, "core/poc.py + core/payloads.py", "M", "safe/full 分级 EXP 模板库缺", "CM-35")),
    (re.compile(r"(PersistenceCatalog|CreatePersistence(SA|CronJob|Deployment|DaemonSet)|GenerateShadowKubeconfig|RequestSAToken|InjectPullSecret|ListPersistenceResources|DeletePersistenceResource|GetSAKubeconfig|SaveKubeconfigFile)"), (STATUS_MISSING, "-", "-", "权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod）", "")),
]

KT_PERSISTENCE_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"serviceaccount"), (STATUS_MISSING, "-", "-", "SA+CRB 植入（执行面刻意不做；检测=auditlog cluster-admin binding 检测器）", "")),
    (re.compile(r"cronjob|deployment|daemonset"), (STATUS_MISSING, "-", "-", "工作负载持久化植入（同上；检测=auditlog 异常 pod/CRB）", "")),
    (re.compile(r"shadow-kubeconfig"), (STATUS_MISSING, "-", "-", "影子 kubeconfig 生成（执行面刻意不做）", "")),
    (re.compile(r"token-request"), (STATUS_MISSING, "-", "-", "TokenRequest 铸币（执行面刻意不做；面分析=rbac-mapping）", "")),
    (re.compile(r"pull-secret"), (STATUS_MISSING, "-", "-", "pull secret 注入 default SA（执行面刻意不做；供应链面=supply-chain-*）", "")),
]

KT_MCP_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"kubetrail_(load_result|summary)"), (STATUS_WE_HAVE, "core/auditlog.py adapt_kubetrail + mcp_server.py get_findings", "-", "", "")),
    (re.compile(r"kubetrail_(list_facts|get_fact)"), (STATUS_PARTIAL, "mcp_server.py 只读工具 + core/evidence.py", "S", "跨 run 过程/事实检索", "CM-02")),
    (re.compile(r"kubetrail_(list_sensitive_refs|materialize_sensitive)"), (STATUS_MISSING, "-", "S", "敏感引用与受控物化", "CM-06")),
    (re.compile(r"kubetrail_list_exp_templates|kubetrail_generate_exp_plan"), (STATUS_PARTIAL, "core/poc.py + mcp_server.py get_chain_plan", "M", "EXP 模板规划工具", "CM-35")),
]

KT_SKILL_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"k8s-rbac-analysis"), (STATUS_WE_HAVE, "modules/rbac-mapping + overprivileged-sa-escalation + vllm-operator-rbac-escalation", "-", "", "")),
    (re.compile(r"serviceaccount-secret-material"), (STATUS_PARTIAL, "modules/lws-secrets-lateral + supply-chain-credential-theft", "S", "SA/Secret 材料面细分", "")),
    (re.compile(r"pod-escape-surface"), (STATUS_WE_HAVE, "modules/escape-primitives + runtime-socket-escape + privileged-gpu-pod-escape", "-", "", "")),
    (re.compile(r"kubelet-runtime-etcd-bypass"), (STATUS_PARTIAL, "modules/escape-primitives（runtime socket）", "M", "kubelet 10250/etcd 面缺", "CM-08")),
    (re.compile(r"exposed-management-interfaces"), (STATUS_WE_HAVE, "modules/ray-dashboard-job + model-registry-exposure + observability-exposure + open-webui* + dify* + sglang* + vllm* + djev-open-proxy", "-", "ML 平台管理面覆盖更广", "")),
    (re.compile(r"public-workload-rce-surface"), (STATUS_WE_HAVE, "modules/areal-* + trl-serve-dev-mode + djev-open-proxy", "-", "", "")),
    (re.compile(r"cloud-metadata-analysis"), (STATUS_WE_HAVE, "modules/metadata-egress + multi-cloud-imds-credentials + ssrf-imds-credential + cloud-sg-imds-exposure", "-", "", "")),
    (re.compile(r"image-registry-supply-chain"), (STATUS_WE_HAVE, "modules/supply-chain-* + shared-volume-weight-copy", "-", "", "")),
    (re.compile(r"workload-controller-persistence"), (STATUS_PARTIAL, "core/auditlog.py 检测器（ray job pod/CRB）", "S", "持久化植入面=检测侧覆盖", "")),
    (re.compile(r"network-lateral-movement"), (STATUS_WE_HAVE, "modules/cni-aware-reachability-graph + vpc-cni-dual-control-plane-lateral + lws-secrets-lateral + hybrid-cloud-egress-pivot", "-", "", "")),
    (re.compile(r"service-ingress-exposure"), (STATUS_WE_HAVE, "modules/exposure-mapping + network-policy-coverage + dns-service-discovery", "-", "", "")),
    (re.compile(r"admission-policy-governance"), (STATUS_PARTIAL, "modules/defense-bypass-admission", "M", "准入治理面（dry-run 探测→CM-24）", "CM-24")),
    (re.compile(r"operator-crd-controller-abuse"), (STATUS_WE_HAVE, "modules/kuberay-operator-escalation + vllm-operator-rbac-escalation + gpu-network-operator-posture", "-", "", "")),
    (re.compile(r"observability-defense-evasion"), (STATUS_WE_HAVE, "modules/defense-bypass-*（11 族）", "-", "", "")),
    (re.compile(r"resource-hijack-dos"), (STATUS_WE_HAVE, "modules/kv-oom-bomb + gang-scheduler-abuse + nccl-port-exhaustion + gpu-pool-scheduler-unauth", "-", "", "")),
    (re.compile(r"windows-container-surface"), (STATUS_MISSING, "-", "M", "Windows 容器/节点面（无任何模块覆盖）", "CM-34")),
    (re.compile(r"exp-generation"), (STATUS_PARTIAL, "core/poc.py + core/payloads.py", "M", "EXP 规划技能（模板库→CM-35）", "CM-35")),
]

KT_EXP_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"cloud-metadata-verify|cloud-identity-verify"), (STATUS_WE_HAVE, "modules/metadata-egress + multi-cloud-imds-credentials", "-", "", "")),
    (re.compile(r"serviceaccount-token-api-verify"), (STATUS_MISSING, "-", "S", "TokenRequest 铸币验证", "CM-05")),
    (re.compile(r"secret-list-get-verify"), (STATUS_PARTIAL, "modules/rbac-mapping", "S", "Secret 读权限验证模板", "")),
    (re.compile(r"runtime-socket-verify"), (STATUS_WE_HAVE, "modules/runtime-socket-escape", "-", "", "")),
    (re.compile(r"nodes-proxy-verify"), (STATUS_PARTIAL, "modules/escape-primitives + rbac-mapping", "S", "nodes/proxy 验证模板", "")),
    (re.compile(r"kubelet-api-verify"), (STATUS_MISSING, "-", "S", "kubelet API 直连验证", "CM-08")),
    (re.compile(r"etcd-access-verify"), (STATUS_PARTIAL, "modules/escape-primitives", "M", "etcd 端点可达验证", "")),
    (re.compile(r"pod-create-job|pod-hostpath|pod-privileged|pod-hostpid|pod-hostnetwork|ephemeralcontainers-patch|pods-exec-verify|impersonate-verify|rbac-bind-escalate-verify"), (STATUS_MISSING, "-", "-", "full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖）", "")),
    (re.compile(r".*persistence.*|csr-client-cert-persistence|workload-patch-sidecar-persistence|pull-secret-injection|admission-persistence-review|static-pod-node-persistence-review"), (STATUS_MISSING, "-", "-", "持久化 EXP（执行面刻意不做；检测=auditlog）", "")),
    (re.compile(r"registry-auth-verify"), (STATUS_PARTIAL, "modules/supply-chain-credential-theft", "S", "registry 凭据验证", "")),
    (re.compile(r"cve-.*|external-cve-poc"), (STATUS_MISSING, "-", "-", "预置 CVE PoC 二进制（版本/PoC 库不内置，CM-13 适配器承接）", "CM-13")),
]

KT_VIEW_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"(About|Welcome)"), (STATUS_NA, "-", "-", "桌面壳页面", "")),
    (re.compile(r"Cluster"), (STATUS_PARTIAL, "webui SPA 资产/总览视图", "S", "集群浏览视图部分对齐", "")),
    (re.compile(r"Analysis"), (STATUS_PARTIAL, "webui SPA 六视图", "M", "finding 分析/证据下钻缺", "")),
    (re.compile(r"Cheatsheet"), (STATUS_WE_HAVE, "docs/RUNBOOK.md + docs/kb", "-", "速查手册已有", "")),
    (re.compile(r"Settings"), (STATUS_PARTIAL, "lab/ 配置 + CLI", "S", "设置页缺", "")),
]

KT_COMPONENT_RULES: list[tuple[re.Pattern, Cls]] = [
    (re.compile(r"(NodeTerminal|PodTerminal|PortForwardPanel|PersistencePanel|Redteam|ExpForgePanel|NodeFiles|PodFiles)"), (STATUS_MISSING, "-", "-", "交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台）", "")),
    (re.compile(r"AgentPanel"), (STATUS_MISSING, "-", "-", "对话式 agent 面板（刻意不做；mcp_server/agent_planner 已有）", "")),
    (re.compile(r"(ScanPanel|ClusterSidebar|ConnectionForm)"), (STATUS_PARTIAL, "webui SPA", "S", "扫描/连接 UI 部分对齐", "")),
    (re.compile(r"(PodList|NodeList|PodDrawer|NodeDrawer|PodLogs)"), (STATUS_PARTIAL, "webui 资产视图 + discovery", "S", "pod/node 浏览组件缺", "")),
]


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------

def _classify(items: list[dict[str, Any]], rules: list[tuple[re.Pattern, Cls]],
              default: Cls) -> list[dict[str, Any]]:
    rows = []
    for it in items:
        status, anchor, action, note, backlog = default
        for rx, cls in rules:
            if rx.search(it["id"]):
                status, anchor, action, note, backlog = cls
                break
        rows.append({**it, "trident_status": status, "trident_anchor": anchor,
                     "action": action, "backlog": backlog, "note": note})
    return rows


SECTIONS_ARTEX = [
    ("A1", "HTTP 路由（server/*.go，含循环注册展开）", artex_routes, ARTEX_ROUTE_RULES,
     (STATUS_MISSING, "-", "M", "未归类路由：待人工归类（完备性要求下不得长期存在）", "")),
    ("A2", "数据库表（db/schema.sql）", artex_tables, ARTEX_TABLE_RULES,
     (STATUS_MISSING, "-", "M", "未归类表：待人工归类", "")),
    ("A3", "Agent 组件（agent/*.go）", artex_agent_components, ARTEX_AGENT_RULES,
     (STATUS_MISSING, "-", "M", "未归类组件：待人工归类", "")),
    ("A4", "Web 页面（web/src/app/**/page.tsx）", artex_pages, ARTEX_PAGE_RULES,
     (STATUS_NA, "-", "-", "未归类页面", "")),
    ("A5", "Web 组件（components + (main)/_components）", artex_components, ARTEX_COMPONENT_RULES,
     (STATUS_NA, "-", "-", "未归类组件", "")),
    ("A6", "配置键（config.example.json）", artex_config_keys, ARTEX_CONFIG_RULES,
     (STATUS_MISSING, "-", "S", "未归类配置键", "")),
    ("A7", "内置 skills（skills/）", artex_skills, ARTEX_SKILL_RULES,
     (STATUS_MISSING, "-", "S", "未归类 skill", "")),
]

SECTIONS_KT = [
    ("K1", "采集器/检查器（collectors 注册表 + SA token 审计）", lambda: kt_collectors() + kt_sa_token_audit(),
     KT_COLLECTOR_RULES, (STATUS_MISSING, "-", "M", "未归类采集器", "")),
    ("K2", "findings 引擎规则函数（internal/findings）", kt_finding_evaluators, KT_EVALUATOR_RULES,
     (STATUS_MISSING, "-", "M", "未归类规则函数", "")),
    ("K3", "findings 启发式标题（LPE/escape/RBAC 逐条）", kt_finding_titles, KT_TITLE_RULES,
     (STATUS_PARTIAL, "-", "S", "未归类启发式", "")),
    ("K4", "敏感值三态（raw/redact/metadata）", kt_sensitivity_modes, KT_SENSITIVITY_RULES,
     (STATUS_MISSING, "-", "S", "未归类模式", "")),
    ("K5", "dbus.json 导出 schema（model.go）", kt_model_schema, KT_MODEL_RULES,
     (STATUS_PARTIAL, "-", "S", "未归类 schema 字段", "")),
    ("K6", "CLI 参数（kubetrail-server）", kt_cli_flags, KT_CLI_RULES,
     (STATUS_PARTIAL, "-", "S", "未归类参数", "")),
    ("K7", "Wails 桌面绑定方法（apps/desktop/app.go）", kt_desktop_methods, KT_DESKTOP_RULES,
     (STATUS_MISSING, "-", "M", "未归类桌面方法", "")),
    ("K8", "权限维持模板（kube/persistence.go）", kt_persistence_techniques, KT_PERSISTENCE_RULES,
     (STATUS_MISSING, "-", "-", "未归类模板", "")),
    ("K9", "agent MCP 工具（apps/agent）", kt_mcp_tools, KT_MCP_RULES,
     (STATUS_PARTIAL, "-", "S", "未归类工具", "")),
    ("K10", "agent 攻击面技能（.claude/skills + AGENTS.md 边界）", kt_agent_skills, KT_SKILL_RULES,
     (STATUS_MISSING, "-", "M", "未归类技能", "")),
    ("K11", "EXP 模板（exp/catalog.ts，safe/full 分级）", kt_exp_templates, KT_EXP_RULES,
     (STATUS_MISSING, "-", "M", "未归类模板", "")),
    ("K12", "桌面视图（Vue views）", kt_views, KT_VIEW_RULES,
     (STATUS_NA, "-", "-", "未归类视图", "")),
    ("K13", "桌面组件（Vue components）", kt_components, KT_COMPONENT_RULES,
     (STATUS_PARTIAL, "-", "S", "未归类组件", "")),
]


def build() -> dict[str, Any]:
    artex_doc = {"tool": "ARTEX (RuoJi6 fork, v0.3.23 @620ca5d)",
                 "repo": ".slim/clonedeps/repos/RuoJi6__ARTEX", "sections": []}
    kt_doc = {"tool": "KubeTrail (ekkoo-z, main @ba8c3cf)",
              "repo": ".slim/clonedeps/repos/ekkoo-z__KubeTrail", "sections": []}

    for sid, title, extract, rules, default in SECTIONS_ARTEX:
        rows = _classify(extract(), rules, default)
        artex_doc["sections"].append({"id": sid, "title": title, "rows": rows})
    for sid, title, extract, rules, default in SECTIONS_KT:
        rows = _classify(extract(), rules, default)
        kt_doc["sections"].append({"id": sid, "title": title, "rows": rows})

    def count(doc, sid):
        return len(next(s for s in doc["sections"] if s["id"] == sid)["rows"])

    def rows_of(doc):
        return [r for s in doc["sections"] for r in s["rows"]]

    lpe_titles = [r for r in rows_of(kt_doc)
                  if r["id"] in {"Potential CVE-2021-3156 sudo Baron Samedit",
                                 "Potential CVE-2025-32463 sudo chroot LPE",
                                 "Potential CVE-2021-4034 PwnKit pkexec",
                                 "PwnKit exposure signal: setuid pkexec present",
                                 "Potential CVE-2017-5618 setuid screen LPE",
                                 "Potential CVE-2026-41651 PackageKit TOCTOU LPE",
                                 "Potential CVE-2022-0847 Dirty Pipe kernel range",
                                 "Potential CVE-2017-16995 eBPF verifier LPE",
                                 "Potential CVE-2021-3490 eBPF ALU32 LPE",
                                 "Potential CVE-2024-1086 nf_tables LPE",
                                 "CVE-2024-1086 kernel range with nf_tables present",
                                 "Potential CVE-2026-31431 Copy Fail AF_ALG LPE",
                                 "Potential CVE-2026-43284 Dirty Frag xfrm-ESP LPE",
                                 "Potential CVE-2026-43500 Dirty Frag RxRPC LPE",
                                 "Potential CVE-2023-0386 OverlayFS LPE",
                                 "CVE-2023-0386 OverlayFS kernel range",
                                 "Potential CVE-2022-0185 fs_context LPE range",
                                 "Potential CVE-2021-3493 Ubuntu OverlayFS LPE",
                                 "Legacy Dirty COW kernel range",
                                 "No LPE candidates matched"}]

    matrix = {
        "generated_by": "tools/extract_features.py",
        "baseline": "2026-10-25",
        "source_counts": {
            "artex_routes": count(artex_doc, "A1"),
            "artex_tables": count(artex_doc, "A2"),
            "artex_components_agent": count(artex_doc, "A3"),
            "artex_views": count(artex_doc, "A4"),
            "artex_components_web": count(artex_doc, "A5"),
            "artex_config_keys": count(artex_doc, "A6"),
            "artex_skills": count(artex_doc, "A7"),
            "kubetrail_collectors": count(kt_doc, "K1"),
            "kubetrail_finding_rules": count(kt_doc, "K2"),
            "kubetrail_heuristic_titles": count(kt_doc, "K3"),
            "kubetrail_lpe_heuristics": len(lpe_titles),
            "kubetrail_sensitivity_modes": count(kt_doc, "K4"),
            "kubetrail_schema_fields": count(kt_doc, "K5"),
            "kubetrail_cli_flags": count(kt_doc, "K6"),
            "kubetrail_desktop_methods": count(kt_doc, "K7"),
            "kubetrail_persistence_techniques": count(kt_doc, "K8"),
            "kubetrail_mcp_tools": count(kt_doc, "K9"),
            "kubetrail_agent_skills": count(kt_doc, "K10"),
            "kubetrail_exp_templates": count(kt_doc, "K11"),
            "kubetrail_views": count(kt_doc, "K12"),
            "kubetrail_components": count(kt_doc, "K13"),
        },
        "matrix_rows": {"artex": len(rows_of(artex_doc)), "kubetrail": len(rows_of(kt_doc)),
                        "total": len(rows_of(artex_doc)) + len(rows_of(kt_doc))},
        "status_counts": {
            "artex": _status_counts(rows_of(artex_doc)),
            "kubetrail": _status_counts(rows_of(kt_doc)),
        },
        "artex": artex_doc,
        "kubetrail": kt_doc,
    }
    return matrix


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {STATUS_WE_HAVE: 0, STATUS_PARTIAL: 0, STATUS_MISSING: 0, STATUS_NA: 0}
    for r in rows:
        out[r["trident_status"]] = out.get(r["trident_status"], 0) + 1
    return out


STATUS_LABEL = {
    STATUS_WE_HAVE: "we-have",
    STATUS_PARTIAL: "partial",
    STATUS_MISSING: "missing",
    STATUS_NA: "N/A",
}


def _md_for(doc: dict[str, Any], heading: str, intro: str) -> str:
    lines = [f"# {heading}", "", intro, ""]
    for sec in doc["sections"]:
        lines.append(f"## {sec['id']}. {sec['title']}（{len(sec['rows'])} 项）")
        lines.append("")
        lines.append("| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |")
        lines.append("|---|---|---|---|---|---|")
        for r in sec["rows"]:
            status = STATUS_LABEL[r["trident_status"]]
            if r["trident_anchor"] and r["trident_anchor"] != "-":
                status += f"（{r['trident_anchor']}）"
            note = r["note"]
            if r["backlog"]:
                note = (note + " " if note else "") + f"[{r['backlog']}]"
            lines.append(f"| `{r['id']}` | {r['anchor']} | {r['behavior']} | {status} | "
                         f"{r['action']} | {note} |")
        lines.append("")
    return "\n".join(lines)


def render(matrix: dict[str, Any]) -> dict[str, str]:
    sc = matrix["source_counts"]
    st_a = matrix["status_counts"]["artex"]
    st_k = matrix["status_counts"]["kubetrail"]
    intro_a = (
        f"> 生成自 `tools/extract_features.py`（源码枚举，基线 {matrix['baseline']}）。"
        f"克隆：`{matrix['artex']['repo']}`。\n>\n> 行数 = 提取计数："
        f"路由 {sc['artex_routes']}｜表 {sc['artex_tables']}｜agent 组件 {sc['artex_components_agent']}｜"
        f"页面 {sc['artex_views']}｜Web 组件 {sc['artex_components_web']}｜配置键 {sc['artex_config_keys']}｜"
        f"skills {sc['artex_skills']}｜合计 {matrix['matrix_rows']['artex']} 行。\n>\n"
        f"> 状态分布：we-have {st_a['we-have']} / partial {st_a['partial']} / "
        f"missing {st_a['missing']} / N/A {st_a['N/A']}。`missing + 行动项 -` = 刻意不做"
        f"（锚点见 REFLECTION-ARTEX-KUBETRAIL.md）；`N/A` = 类别外（UI 基础件/桌面形态等）。"
    )
    intro_k = (
        f"> 生成自 `tools/extract_features.py`（源码枚举，基线 {matrix['baseline']}）。"
        f"克隆：`{matrix['kubetrail']['repo']}`。\n>\n> 行数 = 提取计数："
        f"采集器(含 SA token 审计) {sc['kubetrail_collectors']}｜findings 规则函数 {sc['kubetrail_finding_rules']}｜"
        f"启发式标题 {sc['kubetrail_heuristic_titles']}（其中 LPE {sc['kubetrail_lpe_heuristics']} 条）｜"
        f"敏感三态 {sc['kubetrail_sensitivity_modes']}｜schema 字段 {sc['kubetrail_schema_fields']}｜"
        f"CLI 参数 {sc['kubetrail_cli_flags']}｜桌面方法 {sc['kubetrail_desktop_methods']}｜"
        f"维持模板 {sc['kubetrail_persistence_techniques']}｜MCP 工具 {sc['kubetrail_mcp_tools']}｜"
        f"agent 技能 {sc['kubetrail_agent_skills']}｜EXP 模板 {sc['kubetrail_exp_templates']}｜"
        f"视图 {sc['kubetrail_views']}｜组件 {sc['kubetrail_components']}｜"
        f"合计 {matrix['matrix_rows']['kubetrail']} 行。\n>\n"
        f"> 状态分布：we-have {st_k['we-have']} / partial {st_k['partial']} / "
        f"missing {st_k['missing']} / N/A {st_k['N/A']}。`missing + 行动项 -` = 刻意不做"
        f"（内核 LPE CVE 库/执行面植入，锚点见 REFLECTION-ARTEX-KUBETRAIL.md 与 docs/COMPETITIVE-MATRIX.md §5）。"
    )
    return {
        str(MD_ARTEX): _md_for(matrix["artex"], "ARTEX 逐功能穷举对比（FEATURE-BY-FEATURE-ARTEX）", intro_a),
        str(MD_KT): _md_for(matrix["kubetrail"], "KubeTrail 逐功能穷举对比（FEATURE-BY-FEATURE-KUBETRAIL）", intro_k),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify generated artifacts match a fresh regeneration")
    args = ap.parse_args()

    matrix = build()
    outputs = {str(JSON_OUT): json.dumps(matrix, ensure_ascii=False, indent=1) + "\n"}
    outputs.update(render(matrix))

    if args.check:
        ok = True
        for path, content in outputs.items():
            current = Path(path).read_text(encoding="utf-8")
            if current != content:
                print(f"DRIFT: {path} 不匹配再生成结果（请运行 tools/extract_features.py）")
                ok = False
        print("check:", "OK" if ok else "DRIFT")
        return 0 if ok else 1

    for path, content in outputs.items():
        Path(path).write_text(content, encoding="utf-8")
        print(f"wrote {path}")
    print(json.dumps({"source_counts": matrix["source_counts"],
                      "matrix_rows": matrix["matrix_rows"],
                      "status_counts": matrix["status_counts"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
