# -*- coding: utf-8 -*-
"""RoE / scope / write-surface / kill-switch policy for the agent runtime.

One authorization is consumed at run start: a signed RoE (workspace HMAC) plus a
lead start confirmation (one-time token from ``agent authorize`` or an explicit
``--yes`` by a lead/admin).  After that the scheduler runs autonomously; there
is no per-step approval.  ``--approval manual`` is an optional compatibility
mode that pauses only write intents.

Policy is enforced *before* dispatch, independently of the prompt.  The
deterministic runner still re-checks RoE, scope and the backup gate, so a
compromised planner cannot bypass either layer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core import roe
from ..core.users import Session
from .graph import PlanGraph

AUTHORIZATION_SCHEMA = "inkblade-agent-authorization/1"
START_SCHEMA = "inkblade-agent-start/1"
START_RELPATH = "agent/start.json"

_TARGET_KEYS = {"target", "host", "url", "endpoint", "address", "server", "base_url",
                "target_url", "api", "kube_api"}
_NAMESPACE_KEYS = {"namespace", "target_ns", "ns"}
_SKIP_KEYS = {"backup_targets", "fixture", "snapshot", "path", "demo_target",
              "config", "output", "report", "workdir", "modules_dir"}


class PolicyError(PermissionError):
    """Base class for a runtime policy refusal."""


class AuthorizationRequired(PolicyError):
    """No valid RoE + start confirmation."""


class ScopeViolation(PolicyError):
    """An intent targets an address/namespace outside the RoE."""


class DestructiveRefused(PolicyError):
    """A write action lacks the required authorization/level."""


class BackupRequired(PolicyError):
    """A write action has no usable backup target."""


class ApprovalRequired(PolicyError):
    """Optional manual-approval mode is waiting for a write approval."""


class KillSwitchTripped(PolicyError):
    """Operator stop / workspace abort."""


@dataclass
class AgentAuthorization:
    schema: str
    objective: str
    mode: str
    actor: str
    role: str
    allow_destructive: bool
    budgets: dict
    roe_sha256: str
    roe_level: str
    window: str
    start_mode: str
    token_hint: str
    created_at: float
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "objective": self.objective, "mode": self.mode,
            "actor": self.actor, "role": self.role,
            "allow_destructive": self.allow_destructive, "budgets": dict(self.budgets),
            "roe_sha256": self.roe_sha256, "roe_level": self.roe_level,
            "window": self.window, "start_mode": self.start_mode,
            "token_hint": self.token_hint, "created_at": self.created_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "AgentAuthorization":
        fields = {k: doc.get(k) for k in (
            "schema", "objective", "mode", "actor", "role", "allow_destructive",
            "budgets", "roe_sha256", "roe_level", "window", "start_mode",
            "token_hint", "created_at", "signature")}
        fields["budgets"] = dict(fields.get("budgets") or {})
        fields["created_at"] = float(fields.get("created_at") or 0)
        fields["allow_destructive"] = bool(fields.get("allow_destructive"))
        fields["signature"] = str(fields.get("signature") or "")
        return cls(**fields)


def _sha(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _start_path(store) -> Path:
    return Path(store.ws_dir) / START_RELPATH


def issue_start(store, session, *, objective: str, allow_destructive: bool = False,
                budgets: dict | None = None, ttl_seconds: int = 1800,
                note: str = "") -> tuple[dict, str]:
    """Lead creates a one-time start token for an objective (token shown once)."""
    if not session.can("approve"):
        raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
    if roe.roe_status(store) != "complete":
        raise AuthorizationRequired("RoE 未签署或签名校验失败")
    token = secrets.token_hex(16)
    doc = {
        "schema": START_SCHEMA, "objective": str(objective),
        "allow_destructive": bool(allow_destructive),
        "budgets": dict(budgets or {}), "created_by": session.name,
        "created_at": time.time(), "expires_at": time.time() + max(1, int(ttl_seconds)),
        "note": str(note), "token_sha256": _sha(token),
    }
    doc["hmac"] = roe.signature(doc, roe.workspace_key(store))
    path = _start_path(store)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return {k: v for k, v in doc.items() if k not in ("token_sha256", "hmac")}, token


def load_start(store) -> dict | None:
    path = _start_path(store)
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AuthorizationRequired(f"start.json 非法 JSON: {exc}") from exc
    body = {k: v for k, v in doc.items() if k != "hmac"}
    if not hmac.compare_digest(str(doc.get("hmac") or ""),
                              roe.signature(body, roe.workspace_key(store))):
        raise AuthorizationRequired("start.json 验签失败（可能被篡改）")
    if float(doc.get("expires_at") or 0) <= time.time():
        raise AuthorizationRequired("start token 已过期")
    return doc


def _verify_start_token(store, token: str, objective: str) -> dict:
    doc = load_start(store)
    if doc is None:
        raise AuthorizationRequired("缺少 lead 启动确认（先 `inkblade agent authorize`）")
    if str(doc.get("objective") or "") != str(objective):
        raise AuthorizationRequired(
            f"start token 绑定 objective={doc.get('objective')!r}，不是 {objective!r}")
    if not hmac.compare_digest(str(doc.get("token_sha256") or ""), _sha(token)):
        raise AuthorizationRequired("start token 不匹配")
    return doc


def preflight(store, session, *, objective: str, mode: str,
              allow_destructive: bool = False, budgets: dict | None = None,
              start_token: str = "", confirm: bool = False,
              approval: str = "auto") -> AgentAuthorization:
    """Verify one-time authorization; never requires per-step approval."""
    if roe.roe_status(store) != "complete":
        raise AuthorizationRequired(
            "工作区授权未完成（consent 缺失/签名失败）；先 `inkblade roe init` 并 lead 签署")
    fields = (store.consent() or {}).get("fields") or {}
    ok, window = roe.window_status(fields)
    if not ok:
        raise AuthorizationRequired(f"授权时间窗外：{window}")
    if not isinstance(session, Session) or not session.can("execute"):
        raise AuthorizationRequired(f"{getattr(session, 'name', '?')} 无 execute 权限")
    level = str(fields.get("level") or "只读侦察")
    if allow_destructive and level != "全影响演示":
        raise AuthorizationRequired(
            f"--allow-destructive 需要 RoE level=全影响演示，当前 {level}")
    if approval not in ("auto", "manual"):
        raise PolicyError(f"未知 approval 模式: {approval!r}")

    start_mode = "token"
    if start_token:
        _verify_start_token(store, start_token, objective)
    elif load_start(store) is not None:
        raise AuthorizationRequired("存在 start token 但未提供 --start-token")
    elif confirm and session.role in ("lead", "admin"):
        start_mode = "confirm-by-lead"
    elif session.role in ("lead", "admin"):
        # The lead invoking the run is the start confirmation (CLI example);
        # a tester/auditor can never use the implicit path.
        start_mode = "implicit-lead"
    else:
        raise AuthorizationRequired(
            "缺少 lead 启动确认：使用 `--yes`（lead/admin）或 `--start-token`")

    doc = AgentAuthorization(
        schema=AUTHORIZATION_SCHEMA, objective=str(objective), mode=str(mode),
        actor=session.name, role=session.role, allow_destructive=bool(allow_destructive),
        budgets=dict(budgets or {}), roe_sha256=str((store.consent() or {}).get("sha256") or ""),
        roe_level=level, window=window, start_mode=start_mode,
        token_hint=(_sha(start_token)[:12] if start_token else ""),
        created_at=time.time(),
    )
    body = {k: v for k, v in doc.to_dict().items() if k != "signature"}
    doc.signature = roe.signature(body, roe.workspace_key(store))
    return doc


def verify_authorization(store, doc: dict) -> bool:
    if not isinstance(doc, dict) or doc.get("schema") != AUTHORIZATION_SCHEMA:
        return False
    body = {k: v for k, v in doc.items() if k != "signature"}
    return hmac.compare_digest(str(doc.get("signature") or ""),
                              roe.signature(body, roe.workspace_key(store)))


def _parse_target(value: Any) -> tuple[str, str]:
    """Return (address, namespace) from a param value if it looks target-like."""
    text = str(value or "").strip()
    if not text:
        return "", ""
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        return parsed.hostname or "", ""
    if text.count(":") == 1 and not text.startswith("["):
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host.strip("[]"), ""
    return text.strip("[]"), ""


def scope_violation(store, params: dict) -> str | None:
    """Recursively check target-like params against signed RoE CIDRs/namespaces."""
    if not isinstance(params, dict):
        return None
    for key, value in params.items():
        low = str(key).lower()
        if low in _SKIP_KEYS:
            continue
        if isinstance(value, dict):
            nested = scope_violation(store, value)
            if nested:
                return nested
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    nested = scope_violation(store, item)
                    if nested:
                        return nested
            continue
        if low in _NAMESPACE_KEYS:
            if not roe.in_scope(store, target_ns=str(value), target_addr=None):
                return f"命名空间 {key}={value} 不在授权范围"
        elif low in _TARGET_KEYS:
            addr, _ = _parse_target(value)
            if addr and not roe.in_scope(store, target_ns=None, target_addr=addr):
                return f"目标 {key}={value} 不在授权 CIDR 范围"
    return None


@dataclass
class PolicyDecision:
    allow: bool
    reason: str = ""
    kind: str = ""

    def as_dict(self) -> dict:
        return {"allow": self.allow, "reason": self.reason, "kind": self.kind}


class Guard:
    """Runtime gate used by the scheduler before a worker is dispatched."""

    def __init__(self, store, session, authorization: AgentAuthorization, *,
                 approval: str = "auto", manual_approved: bool = False,
                 modules_dir=None, objective=None):
        self.store = store
        self.session = session
        self.authorization = authorization
        self.approval = approval
        self.manual_approved = bool(manual_approved)
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        self.objective = objective
        self.refusals: list[dict] = []

    def check_kill_switch(self) -> None:
        try:
            from ..core.abort import abort_requested

            if abort_requested(self.store):
                raise KillSwitchTripped("工作区 abort.json 已请求停止")
        except KillSwitchTripped:
            raise
        except Exception:  # noqa: BLE001
            pass

    def _module_meta(self, module: str):
        if module == "agent-report":
            return {"key": module, "writes": False, "min_level": "只读侦察"}
        try:
            from ..core.registry import load_modules

            mods = load_modules(self.modules_dir)
        except Exception:  # noqa: BLE001 - registry issues are surfaced by runner
            return None
        meta = mods.get(module)
        return meta.__dict__ if meta is not None else None

    def check_intent(self, intent: dict, graph: PlanGraph | None = None) -> PolicyDecision:
        try:
            self.check_kill_switch()
            if self.objective is not None and not self.objective.allow_writes \
                    and intent.get("writes"):
                raise DestructiveRefused("read-only objective 不允许写 intent")
            meta = self._module_meta(str(intent.get("module") or ""))
            if meta is None and intent.get("module") != "agent-report":
                raise DestructiveRefused(f"模块未注册或不可用: {intent.get('module')}")
            writes = bool(intent.get("writes") or (meta or {}).get("writes"))
            if writes:
                if not self.authorization.allow_destructive:
                    raise DestructiveRefused(
                        "写动作需要 --allow-destructive（RoE 全影响 + 备份闸门）")
                if self.authorization.roe_level != "全影响演示":
                    raise DestructiveRefused(
                        f"写动作需要 RoE level=全影响演示，当前 {self.authorization.roe_level}")
                if self.approval == "manual" and not self.manual_approved:
                    raise ApprovalRequired(
                        "manual 模式：写动作等待 lead 批准（默认 auto 模式无逐步审批）")
                targets = intent.get("params", {}).get("backup_targets") or []
                if not isinstance(targets, list) or not targets:
                    raise BackupRequired("写动作缺少 backup_targets，备份闸门会拒绝")
                for target in targets:
                    if not isinstance(target, dict):
                        raise BackupRequired("backup_targets 每项必须是对象")
                    kind = str(target.get("kind") or "")
                    if kind == "file":
                        path = Path(str(target.get("path") or ""))
                        if not path.is_file():
                            raise BackupRequired(f"备份文件目标不存在: {path}")
                    elif kind == "kube":
                        if not str(target.get("name") or "").strip():
                            raise BackupRequired("kube 备份目标缺 name")
                        if "manifest" not in target:
                            raise BackupRequired("kube 备份目标缺 manifest")
                    elif kind == "http":
                        if not target.get("url"):
                            raise BackupRequired("http 备份目标缺 url")
                    else:
                        raise BackupRequired(f"未知备份目标 kind={kind!r}")
            if str(intent.get("module") or "") != "agent-report":
                violation = scope_violation(self.store, intent.get("params") or {})
                if violation:
                    raise ScopeViolation(violation)
            return PolicyDecision(True)
        except PolicyError as exc:
            decision = PolicyDecision(False, str(exc), type(exc).__name__)
            self.refusals.append({"intent": intent.get("id"), "reason": str(exc),
                                  "kind": decision.kind})
            return decision

    def require(self, intent: dict, graph: PlanGraph | None = None) -> None:
        decision = self.check_intent(intent, graph)
        if not decision.allow:
            raise PolicyError(decision.reason)

    def redact(self, params: dict) -> dict:
        out = {}
        for key, value in (params or {}).items():
            low = str(key).lower()
            if any(word in low for word in ("token", "password", "secret", "key")):
                out[key] = "***"
            elif isinstance(value, dict):
                out[key] = self.redact(value)
            else:
                out[key] = value
        return out
