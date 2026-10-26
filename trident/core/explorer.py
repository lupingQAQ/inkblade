# -*- coding: utf-8 -*-
"""审批制自主探索器（XBow 对标 ②）：资产图 + 链前置 → 下一步模块序列提议 → lead 批准 → 执行。

双模式：
- ``rules``（默认，零外部依赖可用）：资产产品映射（discovery + version_matrix）∪
  链前置三态判定（chains.evaluate_preconditions）→ 确定性候选排序；
- ``llm``（可选）：OpenAI 兼容端点（env TRIDENT_LLM_BASE_URL/TRIDENT_LLM_API_KEY/
  TRIDENT_LLM_MODEL）对候选集做排序/择由；任何失败（无 env/网络/解析/越界）一律
  降级 rules 并在 proposal.mode 记录降级原因——无 LLM 时规则模式完全可用。

硬边界（与 agent_planner 同源，测试锁定）：
- 提议（propose）不执行任何模块、不建 run、不写 actions；
- 每个动作先给出 dry-run 预览（写面/备份闸门/目标资产）；
- 仅 lead/admin（can("approve")）可 approve/reject；execute 只认 approved 提议；
- 执行仍逐模块走 runner（授权闸门 + 备份闸门 + 三层落证）——自主性止步于批准队列。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from . import agent_policy, cost, jsonio, observation
from .blackboard import Blackboard
from .chains import dry_run as chain_dry_run
from .chains import evaluate_preconditions, load_chains
from .discovery import AssetInventory
from .llmpool import pool_available, rank_candidates
from .registry import load_modules
from .roe import LEVELS, roe_status
from .version_matrix import entries as matrix_entries

QUEUE_RELPATH = "explorer/queue.json"
MAX_ACTIONS_DEFAULT = 5
MAX_WORKERS = 8
_LLM_TIMEOUT = 20
POLICY_ENV = "TRIDENT_AGENT_POLICY"


def policy_enabled(explicit: bool | None = None) -> bool:
    """第三节改进开关：默认 ON；``TRIDENT_AGENT_POLICY=off`` 精确复现 HEAD。"""
    if explicit is not None:
        return bool(explicit)
    return os.environ.get(POLICY_ENV, "on").strip().lower() not in (
        "off", "0", "false", "no")


class ExplorerError(ValueError):
    """提议/状态机非法。"""


class ApprovalDenied(PermissionError):
    """角色不足或状态不允许该操作。"""


def _runs(store) -> list[str]:
    """真实 run 目录 = 含 evidence.db 的目录（排除 explorer/ 等工作区级目录）。"""
    if not store.ws_dir.exists():
        return []
    return sorted(p.name for p in store.ws_dir.iterdir()
                  if p.is_dir() and not p.name.startswith("_")
                  and (p / "evidence.db").is_file())


def _latest_findings(store) -> tuple[str | None, list[dict]]:
    runs = _runs(store)
    if not runs:
        return None, []
    latest = max(runs, key=lambda n: (store.ws_dir / n).stat().st_mtime)
    return latest, store.open_run(latest).findings


# ---------------------------------------------------------------- LLM（可选）
def llm_available() -> bool:
    return bool(os.environ.get("TRIDENT_LLM_BASE_URL"))


def _llm_rank(candidates: list[dict], context: dict) -> list[str]:
    """OpenAI 兼容排序；返回模块键序列。任何异常向上抛（由 propose 降级）。"""
    base = os.environ["TRIDENT_LLM_BASE_URL"].rstrip("/")
    key = os.environ.get("TRIDENT_LLM_API_KEY", "")
    model = os.environ.get("TRIDENT_LLM_MODEL", "gpt-4o-mini")
    prompt = json.dumps({
        "role": "You are an authorized pentest planner. Rank the NEXT module sequence "
                "(max 5) for an ML-cluster pentest from candidates only. "
                "Reply JSON: {\"sequence\": [\"module-key\", ...]}.",
        "candidates": [c["module"] for c in candidates],
        "context": context,
    }, ensure_ascii=False)
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    req = urllib.request.Request(base + "/chat/completions", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    with urllib.request.urlopen(req, timeout=_LLM_TIMEOUT) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"]
    seq = json.loads(content).get("sequence") or []
    if not isinstance(seq, list):
        raise ValueError("LLM sequence 非列表")
    return [str(s) for s in seq]


# ---------------------------------------------------------------- 探索器
class Explorer:
    def __init__(self, store, *, chains_dir: Path | str | None = None,
                 modules_dir: Path | str | None = None):
        self.store = store
        self.queue_path = Path(store.ws_dir) / QUEUE_RELPATH
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        self.chains_dir = Path(chains_dir) if chains_dir else Path(__file__).resolve().parent.parent / "chains"
        self.modules_dir = Path(modules_dir) if modules_dir else store.root / "modules"

    # ---------- 队列持久化 ----------
    def _load_queue(self) -> list[dict]:
        if not self.queue_path.exists():
            return []
        return json.loads(self.queue_path.read_text(encoding="utf-8"))

    def _save_queue(self, queue: list[dict]) -> None:
        tmp = self.queue_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(queue, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.queue_path)

    # ---------- 候选与提议 ----------
    def _candidates(self, *, max_actions: int) -> tuple[list[dict], dict]:
        inv = AssetInventory(self.store)
        assets = inv.list(kind="service")
        products_present = {a["product"] for a in assets if a["product"]}
        mods = load_modules(self.modules_dir) if self.modules_dir.exists() else {}
        by_product: dict[str, list[str]] = {}
        for e in matrix_entries():
            if e["kind"] != "exploit":
                continue
            by_product.setdefault(e["product"], []).append(e["module"])
        roe_level = (self.store.consent() or {}).get("fields", {}).get("level", "只读侦察")
        cands: list[dict] = []
        for product in sorted(products_present):
            for mkey in sorted(by_product.get(product, [])):
                meta = mods.get(mkey)
                if meta is None or meta.min_level not in LEVELS:
                    continue
                if LEVELS.index(meta.min_level) > LEVELS.index(roe_level):
                    continue
                target_asset = inv.resolve_targets(mkey, limit=1)
                cands.append({"module": mkey, "product": product, "writes": meta.writes,
                              "reason": f"资产面命中产品 {product}", "series": meta.series,
                              "asset": target_asset[0]["asset_key"] if target_asset else ""})
        run_name, findings = _latest_findings(self.store)
        chains = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
        chain_hits: list[dict] = []
        for cid, chain in sorted(chains.items()):
            verdict, missing = evaluate_preconditions(chain, findings)
            if verdict == "不成立":
                continue
            plan = chain_dry_run(chain, findings, self.modules_dir if self.modules_dir.exists() else None)
            chain_hits.append({"chain": cid, "verdict": verdict, "missing": missing,
                               "steps": [s["module"] for s in plan["steps"]]})
        context = {"assets": len(assets), "products": sorted(products_present),
                   "latest_run": run_name, "findings": len(findings),
                   "roe_level": roe_level, "chains_eligible": [c["chain"] for c in chain_hits],
                   "blackboard": Blackboard(self.store).context(limit=20)}
        # 排序：只读在前、有资产目标在前、链成立优先
        cands.sort(key=lambda c: (c["writes"], not c["asset"]))
        return cands[: max_actions * 3], context

    def propose(self, session, *, use_llm: bool | None = None,
                max_actions: int = MAX_ACTIONS_DEFAULT,
                policy: bool | None = None) -> dict:
        """生成下一步序列提议（pending_approval）。绝不执行。

        ``policy=False``（或 env ``TRIDENT_AGENT_POLICY=off``）精确复现 HEAD
        的字段与行为，用于 lab/tencent-compare 的前后对照。
        """
        candidates, context = self._candidates(max_actions=max_actions)
        if not candidates:
            raise ExplorerError("无可用候选（先 discover 资产或降低 ROE 级别限制）")
        mode, llm_note = "rules", ""
        pool_on = pool_available(self.store)
        want_llm = (llm_available() or pool_on) if use_llm is None \
            else bool(use_llm and (llm_available() or pool_on))
        if want_llm:
            try:
                if pool_on:
                    try:
                        seq = rank_candidates(self.store, candidates, context)
                    except Exception as pool_exc:
                        if not llm_available():
                            raise
                        llm_note = f"LLM 池降级 env：{type(pool_exc).__name__}: {pool_exc}"
                        seq = _llm_rank(candidates, context)
                else:
                    seq = _llm_rank(candidates, context)
                allowed = {c["module"] for c in candidates}
                picked = [m for m in seq if m in allowed][:max_actions]
                if picked:
                    mode = "llm"
                    candidates = [next(c for c in candidates if c["module"] == m) for m in picked]
                else:
                    llm_note = "LLM 返回空/越界序列，降级 rules"
            except Exception as exc:  # 网络/解析/越界一律降级
                llm_note = f"LLM 降级 rules：{type(exc).__name__}: {exc}"
        chosen = candidates[:max_actions]
        actions = []
        mods = load_modules(self.modules_dir) if self.modules_dir.exists() else {}
        for idx, c in enumerate(chosen, 1):
            meta = mods.get(c["module"])
            action = {"seq": idx, "module": c["module"], "product": c["product"],
                      "writes": bool(c["writes"]), "reason": c["reason"],
                      "asset_key": c.get("asset", ""),
                      "params": {"use_assets": True},
                      "dry_run": self._action_dry_run(meta, c)}
            actions.append(action)
        pid = f"prop-{time.strftime('%Y%m%d-%H%M%S')}-{len(self._load_queue()) + 1:03d}"
        extras: dict = {}
        if policy_enabled(policy):
            extras = self._policy_block(pid, actions, candidates)
            if extras.get("_degraded_actions"):
                actions = extras.pop("_degraded_actions")
        proposal = {"id": pid, "mode": mode, "created_by": session.name,
                    "created_at": time.time(), "status": "pending_approval",
                    "context": context, "actions": actions,
                    "approval": {"required": True, "approver_role": "lead", "status": "pending"},
                    "execution": {"trigger": "human", "performed": False}}
        if extras:
            proposal.update(extras)
            proposal["approval"].update({"mode": extras["policy"]["approval_mode"],
                                         "count": extras["policy"]["approval_count"]})
        if llm_note:
            proposal["llm_note"] = llm_note
        queue = self._load_queue()
        queue.append(proposal)
        self._save_queue(queue)
        return proposal

    def _policy_block(self, pid: str, actions: list[dict], catalog: list[dict]) -> dict:
        """只在提议路径附加策略/观察/成本；不执行、不写 actions/evidence。"""
        budget = cost.Budget()
        graded = cost.apply_budget(actions, budget=budget)
        degraded_actions = None
        if graded["degraded"]:
            degraded_actions = [{**a, "seq": i}
                                for i, a in enumerate(graded["actions"], 1)]
            actions = degraded_actions
        decided = agent_policy.decide(actions)
        decomposition = agent_policy.decompose(actions, strategy="phase")
        planned = {a["module"] for a in actions}
        pool = [c for c in catalog if c.get("module") not in planned]
        observations: list[dict] = []
        for action in actions:
            obs = observation.build(
                action["seq"], action, status="proposed",
                result_summary=f"dry-run：writes={action['writes']}；"
                               f"asset={action.get('asset_key') or '-'}；{action['reason']}",
                evidence=[{"kind": "plan", "ref": f"{pid}#{action['seq']}",
                           "detail": "explorer 提议队列（未执行）"}],
                candidates=observation.next_candidates(pool, observations, limit=2),
                tokens=int(cost.estimate_tokens(action["module"] + action["reason"])))
            observations.append(obs)
            observation.append(self.store, obs)
        estimate = cost.plan_cost(actions)
        block = {
            "policy": {
                "engine": "trident.agent_policy",
                "level": decided["level"],
                "label": decided["label"],
                "approval_mode": decided["approval_mode"],
                "approval_count": decided["approval_count"],
                "requires_human": decided["requires_human"],
                "reason": decided["reason"],
                "hard_boundary": "提议不执行；批准后仍逐模块走 runner 三闸门",
            },
            "decomposition": decomposition,
            "observations": observations,
            "cost": {
                "estimate": estimate,
                "tokens": estimate["tokens"],
                "latency_ms": estimate["latency_ms"],
                "budget": budget.status(),
                "degraded": graded["degraded"],
                "dropped": [d.get("module") for d in graded["dropped"]],
                "reason": graded["reason"],
                "pricing": "确定性估算（4 字符/token）；非真实账单",
            },
        }
        if degraded_actions is not None:
            block["_degraded_actions"] = degraded_actions
        return block

    @staticmethod
    def _action_dry_run(meta, cand: dict) -> dict:
        writes = bool(meta.writes) if meta is not None else False
        preview = {"writes": writes, "backup_targets": [], "write_surface": [],
                   "min_level": meta.min_level if meta else "", "series": meta.series if meta else ""}
        if writes:
            preview["gate"] = "备份闸门：写类步骤缺少 backup_targets，执行将被拒绝（退出码 91）"
        return preview

    # ---------- 审批状态机 ----------
    def _get(self, proposal_id: str) -> tuple[dict, list[dict], int]:
        queue = self._load_queue()
        for i, p in enumerate(queue):
            if p.get("id") == proposal_id:
                return p, queue, i
        raise ExplorerError(f"未知提议 {proposal_id}")

    def approve(self, session, proposal_id: str) -> dict:
        if not session.can("approve"):
            raise ApprovalDenied(f"{session.name}({session.role}) 无 approve 权限")
        p, queue, i = self._get(proposal_id)
        if p["status"] != "pending_approval":
            raise ExplorerError(f"提议 {proposal_id} 状态 {p['status']}，不可批准")
        p["status"] = "approved"
        p["approval"] = {"required": True, "approver_role": "lead", "status": "approved",
                         "approved_by": session.name, "approved_at": time.time()}
        queue[i] = p
        self._save_queue(queue)
        return p

    def approve_preauthorized(self, proposal_id: str, *, grant) -> dict:
        """L3 预授权批准：token 已由 AutonomyGuard 验签；这里做白名单/写权限防御性复核。

        审计主体记为 ``preauth:<grant id>``，与人工 approve 明确区分；状态机不变。
        """
        p, queue, i = self._get(proposal_id)
        if p["status"] != "pending_approval":
            raise ExplorerError(f"提议 {proposal_id} 状态 {p['status']}，不可批准")
        allowlist = set(getattr(grant, "allowlist", []) or [])
        allow_writes = bool(getattr(grant, "allow_writes", False))
        for action in p.get("actions") or []:
            if action.get("module") not in allowlist:
                raise ApprovalDenied(
                    f"动作 {action.get('module')} 不在预授权白名单（L3 拒绝）")
            if action.get("writes") and not allow_writes:
                raise ApprovalDenied(
                    f"动作 {action.get('module')} 为写动作但预授权未允许写（L3 拒绝）")
        p["status"] = "approved"
        p["approval"] = {"required": True, "approver_role": "lead", "status": "approved",
                         "approved_by": f"preauth:{grant.id}", "mode": "preauth",
                         "token_hint": getattr(grant, "token_hint", ""),
                         "approved_at": time.time()}
        queue[i] = p
        self._save_queue(queue)
        jsonio.append_audit(self.store, f"preauth:{grant.id}", "explorer.approve", proposal_id,
                            {"mode": "preauth", "actions": len(p.get("actions") or []),
                             "allowlist": sorted(allowlist)}, "ok")
        return p

    def reject(self, session, proposal_id: str, reason: str = "") -> dict:
        if not session.can("approve"):
            raise ApprovalDenied(f"{session.name}({session.role}) 无 approve 权限")
        p, queue, i = self._get(proposal_id)
        if p["status"] not in ("pending_approval", "approved"):
            raise ExplorerError(f"提议 {proposal_id} 状态 {p['status']}，不可拒绝")
        p["status"] = "rejected"
        p["approval"] = {"required": True, "approver_role": "lead", "status": "rejected",
                         "rejected_by": session.name, "reason": reason}
        queue[i] = p
        self._save_queue(queue)
        return p

    def list_proposals(self) -> list[dict]:
        return self._load_queue()

    # ---------- 执行（仅 approved；逐模块走 runner 全部闸门） ----------
    def execute(self, session, proposal_id: str, *, workers: int = 1) -> dict:
        """执行已批准提议；``workers`` 1–8（默认 1）。每个动作独立 run，审计隔离。"""
        from .discovery import AssetInventory
        from .runner import run_module

        if roe_status(self.store) != "complete":
            from .roe import ExecutionLocked

            raise ExecutionLocked("工作区授权未完成（consent 未签署）")
        if not session.can("execute"):
            raise ApprovalDenied(f"{session.name}({session.role}) 无 execute 权限")
        if not isinstance(workers, int) or isinstance(workers, bool) \
                or not (1 <= workers <= MAX_WORKERS):
            raise ExplorerError(f"workers 须为 1-{MAX_WORKERS} 的整数")
        p, queue, i = self._get(proposal_id)
        if p["status"] != "approved":
            raise ExplorerError(f"提议 {proposal_id} 状态 {p['status']}：须先 lead 批准")
        inv = AssetInventory(self.store)

        def _run_one(action: dict) -> dict:
            params = inv.bind_params(action["module"], dict(action.get("params") or {}))
            try:
                res = run_module(self.store, session, action["module"], params,
                                 self.modules_dir)
                return {"module": action["module"], "status": "success", "result": res,
                        "run": res.get("run", ""), "step": res.get("step", ""),
                        "audit": f"run:{res.get('run', '')}"}
            except Exception as exc:
                return {"module": action["module"], "status": "failed",
                        "error": f"{type(exc).__name__}: {exc}", "run": "",
                        "audit": "workspace:audit.jsonl"}

        if workers == 1:
            results = [_run_one(action) for action in p["actions"]]
        else:
            results = [None] * len(p["actions"])  # type: ignore[list-item]
            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="trident-agent") as pool:
                futures = {pool.submit(_run_one, action): idx
                           for idx, action in enumerate(p["actions"])}
                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        results[idx] = fut.result()
                    except Exception as exc:  # 兜底：单动作异常不外溢
                        results[idx] = {"module": p["actions"][idx]["module"],
                                        "status": "failed",
                                        "error": f"{type(exc).__name__}: {exc}",
                                        "run": "", "audit": "workspace:audit.jsonl"}
        ok = all(r["status"] == "success" for r in results) if results else False
        p["status"] = "executed"
        p["execution"] = {"trigger": "human", "performed": True, "workers": workers,
                          "audit_isolation": "per-action run (evidence.db)",
                          "executed_by": session.name, "executed_at": time.time()}
        p["results"] = results
        queue[i] = p
        self._save_queue(queue)
        jsonio.append_audit(self.store, session.name, "explorer.execute", proposal_id,
                            {"workers": workers, "actions": len(results),
                             "ok": ok}, "ok" if ok else "partial")
        return {"proposal": proposal_id, "results": results, "ok": ok,
                "workers": workers, "parallel": workers > 1}

    def execute_parallel(self, session, proposal_id: str, workers: int = 4) -> dict:
        """并发执行的显式别名（仍走 approval + 三闸门；默认上限 8）。"""
        return self.execute(session, proposal_id, workers=workers)
