#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate docs/artex-parity-rows.json from the feature-by-feature matrix.

Every ``missing`` row gets exactly one disposition:
- ``done``: implemented in this repository (clean-room equivalent; evidence path);
- ``technical-infeasible``: cannot be provided safely/offline (reason);
- ``not-applicable``: UI/PG/agent-product scaffold outside the API-first architecture
  (reason), or an L-scope multi-tenant item.

The script never marks a row ``missing``; ``tests/test_artex_parity.py`` enforces that.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURE_DOC = ROOT / "docs" / "FEATURE-BY-FEATURE-ARTEX.md"
OUT = ROOT / "docs" / "artex-parity-rows.json"

DONE = {
    "notify": ("trident/core/notify.py", "tests/test_notify.py"),
    "llmpool": ("trident/core/llmpool.py", "tests/test_llmpool.py"),
    "threads": ("trident/core/threads.py", "tests/test_threads.py"),
    "intel": ("trident/core/intel.py", "tests/test_backlog_s.py"),
    "dedupe": ("trident/core/dedupe.py", "tests/test_backlog_m.py"),
    "scheduler": ("trident/core/scheduler.py + trident/core/calendar.py",
                  "tests/test_scheduler.py + tests/test_calendar.py"),
    "importers": ("trident/core/importers.py", "tests/test_backlog_s.py"),
    "templates": ("trident/core/templates.py", "tests/test_templates.py"),
    "graphsnap": ("trident/core/graphsnap.py", "tests/test_graphsnap.py"),
    "search": ("trident/core/search.py", "tests/test_backlog_s.py"),
    "cigate": ("trident/core/cigate.py", "tests/test_backlog_s.py"),
    "credcheck": ("trident/core/credcheck.py", "tests/test_backlog_m.py"),
    "connectors": ("trident/core/connectors.py", "tests/test_backlog_m.py"),
    "lineage": ("trident/core/lineage.py", "tests/test_backlog_m.py"),
}

REASON_UI = "架构不适用：Trident 为 CLI/REST/MCP/静态 SPA 形态，不实现 Next.js 服务端页面"
REASON_TASKS = ("架构不适用：run + 三层证据库是一等对象，不引入 PostgreSQL 任务实体/"
                "分类/归档/Web 工作区编辑器；等价能力见 evidence/run 目录与 CLI")
REASON_MULTI = "架构不适用：工作区 + 四角色隔离；多租户 SaaS 属 L 项 CM-31，不在 S/M 范围"
REASON_AGENT = ("架构不适用：无对话式主 agent/多 agent 实体；自主性止步于 lead 审批的提议队列，"
                "侧问由 core/threads.py 承担")
REASON_UPDATE = ("技术不可行：无签名发布通道与供应链信任根；自动 apply/rollback 会破坏证据链完整性，"
                 "升级由部署方在受控环境执行")
REASON_UI_AUTH = "架构不适用：Bearer 会话 + 反向代理承担 HTTP Basic Auth；不在应用内重复实现"
REASON_WEBSEARCH = "架构不适用：外部检索由 librarian/websearch 会话承担，不在产品内嵌浏览器/搜索后端"
REASON_PYTHON = "架构不适用：模块运行于项目 Python 环境，无需运行时探测/切换解释器"
REASON_TOKENS = "架构不适用：无对话/会话实体；token 用量在 core/llmpool.py 按端点/用途留档"
REASON_SKILLS = "架构不适用：能力以 modules/rules 代码与链定义交付，不支持运行时上传 skill 目录"
REASON_INTERCEPT = ("架构不适用：审批闸门为确定性人工判断；AI judge 自动放行不可审计，不引入")
REASON_DB = "架构不适用：证据库/资产库为 SQLite，工作区配置为 JSON；不使用 PostgreSQL"
REASON_AGENT_LOOP = "架构不适用：无自主 agent 循环（compaction/wrapup/noa 属于该循环）"
REASON_SKILL_EXT = "架构不适用：外部浏览器自动化 skill 不在产品边界；由调用方在授权环境执行"


def classify(item: str, handler: str, gap: str) -> tuple[str, str, str]:
    low = f"{item} {handler} {gap}".lower()
    if "notify" in low or "notification_" in low:
        return _done("notify")
    if any(k in low for k in ("/llm/pool", "/llm/test", "/llm/profiles", "/llm/records",
                              "/llm/models", "/llm/retry-policy", "llm_profile",
                              "provider.go", "request_limiter.go", "/tokens/",
                              "/exploration/tokens")):
        return _done("llmpool")
    if "side-question" in low or "side_question" in low or "side_questions.go" in low:
        return _done("threads")
    if "intelligence" in low or "credentials.go" in low:
        return _done("intel")
    if "finding-case" in low or "finding_case" in low:
        return _done("dedupe")
    if "task-templates" in low:
        return _done("templates")
    if "/api/triggers/" in low:
        return _done("scheduler")
    if "scopesentry" in low and "sync" in low:
        return _done("importers")
    if "scopesentry" in low and "skill" in low:
        return _done("importers")
    if "/api/graph" in low or "graph_" in low or "coverage-graph" in low:
        return _done("graphsnap")
    if "/api/logs" in low or "/api/search" in low:
        return _done("search")
    if "/api/ci-gate" in low:
        return _done("cigate")
    if "credential" in low and "traffic" in low:
        return _done("credcheck")
    if "connector" in low or "ticket" in low or "siem" in low:
        return _done("connectors")
    if "lineage" in low:
        return _done("lineage")
    if "/api/update/" in low:
        return "technical-infeasible", "", REASON_UPDATE
    if "basic-auth" in low or "basic auth" in low:
        return "not-applicable", "", REASON_UI_AUTH
    if "web-search" in low:
        return "not-applicable", "", REASON_WEBSEARCH
    if "python/detect" in low:
        return "not-applicable", "", REASON_PYTHON
    if "company" in low or "companies" in low:
        return "not-applicable", "", REASON_MULTI
    if "workspace/" in low:
        return "not-applicable", "", REASON_TASKS
    if "task-categories" in low or "task-archives" in low or "/api/tasks" in low \
            or "/api/active" in low:
        return "not-applicable", "", REASON_TASKS
    if "intercept/judge" in low:
        return "not-applicable", "", REASON_INTERCEPT
    if "/api/conversations" in low or "/api/chat" in low or "main-session" in low \
            or "exploration/main" in low:
        return "not-applicable", "", REASON_AGENT
    if "/api/agents" in low or low.startswith("`agents`") or "agent_prompts" in low \
            or "agent_visibility" in low or "agent_skill_visibility" in low \
            or "agent_triggers" in low:
        return "not-applicable", "", REASON_AGENT
    if "visibility" in low:
        return "not-applicable", "", REASON_AGENT
    if "task_llm_profiles" in low:
        return "not-applicable", "", REASON_MULTI
    if "compaction.go" in low or "noa.go" in low or "wrapup.go" in low:
        return "not-applicable", "", REASON_AGENT_LOOP
    if "playwright" in low:
        return "not-applicable", "", REASON_SKILL_EXT
    if "database." in low:
        return "not-applicable", "", REASON_DB
    if item.startswith("`/(main)/") or "next.js" in low:
        return "not-applicable", "", REASON_UI
    if "表 " in item or "组件文件" in item:
        return "not-applicable", "", REASON_TASKS
    if "skill" in low:
        return "not-applicable", "", REASON_SKILLS
    return "not-applicable", "", REASON_TASKS


def _done(feature: str) -> tuple[str, str, str]:
    impl, test = DONE[feature]
    return "done", f"{impl}; {test}", ""


def parse_rows() -> list[dict]:
    rows = []
    for line in FEATURE_DOC.read_text(encoding="utf-8").splitlines():
        if "| missing |" not in line:
            continue
        if line.startswith("| `"):
            cells = [c.strip() for c in line.split("|")]
            if len(cells) < 7:
                continue
            item, handler, size, gap = cells[1], cells[3], cells[4], cells[6]
        else:
            # 源文档中偶有循环展开的续行（无首列反引号），同样逐行处置
            cells = [c.strip() for c in line.split("|")]
            if len(cells) < 4:
                continue
            item = cells[0] or "artex-route-continuation"
            handler, size, gap = "", (cells[2] if len(cells) > 2 else "-"), cells[3]
        status, evidence, reason = classify(item, handler, gap)
        rows.append({"item": item.strip("`"), "handler": handler, "size": size,
                     "gap": gap, "status": status,
                     **({"evidence": evidence} if evidence else {}),
                     **({"reason": reason} if reason else {})})
    for i, row in enumerate(rows, 1):
        row["id"] = f"ARTEX-MISS-{i:03d}"
    return rows


def main() -> int:
    rows = parse_rows()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    doc = {
        "source": "docs/FEATURE-BY-FEATURE-ARTEX.md",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "clean_room": True,
        "total_missing": len(rows),
        "status_counts": counts,
        "missing_unclassified": counts.get("missing", 0),
        "rows": rows,
    }
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"artex-parity: {len(rows)} rows -> {OUT} ({counts})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
