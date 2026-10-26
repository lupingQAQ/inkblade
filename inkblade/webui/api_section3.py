# -*- coding: utf-8 -*-
"""第三节只读视图：自主度目录 / 结构化观察 / 成本预算。

只注册 GET，不新增任何写路由；不触碰 server.py 既有 /api/v1/* 语义。
数据源：
- 自主度与分解策略：``trident.core.agent_policy``（静态目录）；
- 观察：``evidence/<ws>/agent/observations.jsonl``（建议队列的只读镜像）；
- 成本：最近一次提议的 ``cost`` 块 + 默认预算。
"""

from __future__ import annotations

from urllib.parse import parse_qs

from ..core import observation
from ..core import agent_policy as ap
from ..core import cost as cost_mod
from ..core import jsonio


def _q(query: str, key: str, default: str = "") -> str:
    return (parse_qs(query).get(key) or [default])[0]


def route(handler, method: str, path: str, query: str, body: dict | None = None) -> bool:
    path = path.rstrip("/") or path
    if not path.startswith("/api/v1/agent/"):
        return False
    session, store, ws = handler._auth(None)
    if session is None:
        return True
    if method != "GET":
        handler._json(405, {"error": "只读视图：仅支持 GET"})
        return True
    try:
        if path == "/api/v1/agent/policy":
            handler._json(200, {
                "workspace": ws,
                "readonly": True,
                "levels": [ap.AUTONOMY[k] for k in ap.LEVELS],
                "strategies": [{"key": k, "summary": _strategy_summary(k)}
                               for k in ap.STRATEGIES],
                "hard_boundary": "提议不执行；批准后仍逐模块走 runner 三闸门",
            })
            return True
        if path == "/api/v1/agent/observations":
            limit = int(_q(query, "limit", "20") or 20)
            rows = observation.read(observation.observation_path(store),
                                    limit=max(1, min(limit, 200)))
            handler._json(200, {
                "workspace": ws,
                "readonly": True,
                "count": len(rows),
                "coverage": observation.coverage(rows),
                "compressed": observation.compress(rows, max_items=10),
                "observations": rows,
            })
            return True
        if path == "/api/v1/agent/cost":
            queue = jsonio.read_json(store.ws_dir / "explorer" / "queue.json", []) or []
            latest = queue[-1] if isinstance(queue, list) and queue else {}
            budget = cost_mod.Budget()
            handler._json(200, {
                "workspace": ws,
                "readonly": True,
                "budget": {"tokens": budget.tokens, "latency_ms": budget.latency_ms,
                           "approvals": budget.approvals,
                           "interventions": budget.interventions},
                "proposal": {"id": latest.get("id"),
                             "cost": latest.get("cost") or {},
                             "policy": latest.get("policy") or {}},
                "pricing": "确定性估算（4 字符/token）；非真实账单",
            })
            return True
    except (PermissionError, KeyError, ValueError) as exc:
        handler._json(409 if isinstance(exc, ValueError) else 403, {"error": str(exc)})
        return True
    return False


def _strategy_summary(key: str) -> str:
    return {
        "phase": "只读侦察一段 + 受控写验证一段（默认）",
        "dependency": "只读先做，每个写动作独占阶段（最保守）",
        "single": "整批一个阶段（仅用于低风险批次）",
    }.get(key, key)
