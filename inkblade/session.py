# -*- coding: utf-8 -*-
"""Entry → probe → channel session state machine.

Three entry modes are explicit and audited:

``kubeconfig``
    A pre-authorised assessment with an operator kubeconfig.  Kubernetes is
    used only to bootstrap the first probe; after that all target actions go
    through probes.
``external``
    Black-box.  The controller must first prove reachability and a vulnerable
    version/route.  It may not run exploits or full scans before that proof.
``foothold``
    The operator already has an SA token or a Pod shell.  That credential is
    used once to deploy a probe; modules then run through the probe.

The session record lives under the evidence workspace and links to a real
evidence run.  Every state transition writes both a run action and a
workspace-level audit line.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .core import jsonio
from .core.evidence import EvidenceStore
from .core.roe import ExecutionLocked, assert_execution_allowed, roe_status, scope_violation

MODES = ("kubeconfig", "external", "foothold")
STATES = (
    "new", "ready", "recon", "vulnerable", "foothold", "probe_ready",
    "channel_ready", "closed", "failed",
)
ENTRY_VECTORS = (
    "kubeconfig", "external-http", "rce", "sa-token", "pod-shell", "shared-volume",
)
_LEVELS = ["只读侦察", "主动探测", "利用验证", "全影响演示"]
_ID_RE = re.compile(r"^sess-[a-z0-9]{8,32}$")


class SessionError(ValueError):
    pass


class SessionLocked(ExecutionLocked):
    """The requested action is not legal in the current entry/session state."""


@dataclass
class PentestSession:
    id: str
    mode: str
    state: str
    actor: str
    role: str
    target: str = ""
    namespace: str = ""
    pod: str = ""
    container: str = ""
    context: str = ""
    chain: str = ""
    entry_vector: str = ""
    credential_source: str = ""
    credential_fingerprint: str = ""
    probe_ids: list[str] = field(default_factory=list)
    parent_id: str | None = None
    probe_path: str = "/tmp/.inkblade-probe"
    token_file: str = "/tmp/.inkblade-probe-token"
    channel: dict[str, Any] = field(default_factory=dict)
    run: str = ""
    dry_run: bool = False
    assumptions: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    proof: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def has_probe(self) -> bool:
        return bool(self.probe_ids) and self.state in ("probe_ready", "channel_ready")

    @property
    def has_foothold(self) -> bool:
        return self.state in ("foothold", "probe_ready", "channel_ready") or bool(self.proof.get("foothold"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "mode": self.mode, "state": self.state,
            "actor": self.actor, "role": self.role,
            "target": self.target, "namespace": self.namespace,
            "pod": self.pod, "container": self.container, "context": self.context,
            "chain": self.chain, "entry_vector": self.entry_vector,
            "credential_source": self.credential_source,
            "credential_fingerprint": self.credential_fingerprint,
            "probe_ids": list(self.probe_ids), "parent_id": self.parent_id,
            "probe_path": self.probe_path, "token_file": self.token_file,
            "channel": dict(self.channel), "run": self.run, "dry_run": self.dry_run,
            "assumptions": list(self.assumptions),
            "preconditions": list(self.preconditions),
            "proof": dict(self.proof), "history": list(self.history),
            "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PentestSession":
        allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "mode": self.mode, "state": self.state,
            "entry_vector": self.entry_vector, "target": self.target,
            "namespace": self.namespace, "pod": self.pod, "chain": self.chain,
            "probes": list(self.probe_ids), "channel": dict(self.channel),
            "run": self.run, "dry_run": self.dry_run,
            "has_foothold": self.has_foothold,
            "updated_at": self.updated_at,
        }


def _root(store: EvidenceStore) -> Path:
    path = Path(store.ws_dir) / "sessions"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _index_path(store: EvidenceStore) -> Path:
    return Path(store.ws_dir) / "sessions.jsonl"


def _new_id() -> str:
    return f"sess-{secrets.token_hex(6)}"


def fingerprint(value: str | bytes | None) -> str:
    if not value:
        return ""
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()[:32]


def _audit(store: EvidenceStore, actor: str, action: str, session: PentestSession,
           params: dict[str, Any] | None = None, result: str = "ok") -> None:
    jsonio.append_audit(
        store, actor, action,
        target=f"{session.id}:{session.state}",
        params={"mode": session.mode, "entry": session.entry_vector,
                "namespace": session.namespace, "probe_ids": session.probe_ids,
                **(params or {})},
        result=result,
    )


def _run_for(store: EvidenceStore, session: PentestSession):
    if not session.run:
        return None
    try:
        return store.open_run(session.run)
    except KeyError:
        return None


def save(store: EvidenceStore, session: PentestSession) -> Path:
    session.updated_at = time.time()
    path = _root(store) / f"{session.id}.json"
    jsonio.write_json(path, session.to_dict())
    return path


def _append_index(store: EvidenceStore, session: PentestSession) -> None:
    row = session.summary()
    path = _index_path(store)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load(store: EvidenceStore, session_id: str) -> PentestSession:
    path = _root(store) / f"{session_id}.json"
    if not path.is_file():
        raise SessionError(f"session not found: {session_id}")
    return PentestSession.from_dict(json.loads(path.read_text(encoding="utf-8")))


def list_sessions(store: EvidenceStore) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(_root(store).glob("sess-*.json")):
        try:
            session = PentestSession.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            continue
        rows.append(session.summary())
    return sorted(rows, key=lambda row: row.get("updated_at") or 0, reverse=True)


def current(store: EvidenceStore) -> PentestSession | None:
    rows = list_sessions(store)
    if not rows:
        return None
    return load(store, str(rows[0]["id"]))


_ALLOWED: dict[str, dict[str, set[str]]] = {
    "kubeconfig": {
        "new": {"ready"},
        "ready": {"probe_ready", "channel_ready", "closed", "failed"},
        "probe_ready": {"channel_ready", "closed", "failed"},
        "channel_ready": {"closed", "failed"},
    },
    "external": {
        "new": {"recon", "closed"},
        "recon": {"vulnerable", "closed", "failed"},
        "vulnerable": {"foothold", "closed", "failed"},
        "foothold": {"probe_ready", "closed", "failed"},
        "probe_ready": {"channel_ready", "closed", "failed"},
        "channel_ready": {"closed", "failed"},
    },
    "foothold": {
        "new": {"foothold", "closed"},
        "foothold": {"probe_ready", "closed", "failed"},
        "probe_ready": {"channel_ready", "closed", "failed"},
        "channel_ready": {"closed", "failed"},
    },
}


def can_transition(mode: str, current_state: str, next_state: str) -> bool:
    if next_state == "closed":
        return True
    if next_state == current_state:
        return True
    return next_state in _ALLOWED.get(mode, {}).get(current_state, set())


def transition(
    store: EvidenceStore,
    session: PentestSession,
    next_state: str,
    *,
    reason: str = "",
    actor: str | None = None,
    params: dict[str, Any] | None = None,
) -> PentestSession:
    if next_state not in STATES:
        raise SessionError(f"unknown session state {next_state}")
    if not can_transition(session.mode, session.state, next_state):
        raise SessionLocked(
            f"非法会话状态迁移：{session.mode} {session.state} → {next_state}"
        )
    previous = session.state
    session.state = next_state
    session.history.append({
        "ts": time.time(), "from": previous, "to": next_state,
        "reason": str(reason), "actor": actor or session.actor,
    })
    save(store, session)
    run = _run_for(store, session)
    if run is not None:
        run.log_action(actor or session.actor, f"session.{next_state}", session.id,
                       {"from": previous, "reason": reason, **(params or {})}, "ok")
    _audit(store, actor or session.actor, f"session.{next_state}", session,
           {"from": previous, "reason": reason, **(params or {})})
    return session


def _require_consent(store: EvidenceStore, min_level: str) -> None:
    if roe_status(store) != "complete":
        raise SessionLocked("工作区授权未完成（consent 未签署或验签失败）")
    try:
        assert_execution_allowed(store, {"min_level": min_level})
    except ExecutionLocked as exc:
        raise SessionLocked(str(exc)) from exc


def _check_scope(store: EvidenceStore, namespace: str, target: str) -> None:
    violation = scope_violation(store, {
        "target_ns": namespace or None,
        "host": target or None,
    })
    if violation:
        raise SessionLocked(violation)


def open_session(
    store: EvidenceStore,
    mode: str,
    *,
    actor: str = "cli",
    role: str = "tester",
    target: str = "",
    namespace: str = "",
    pod: str = "",
    container: str = "",
    chain: str = "",
    context: str = "",
    kubeconfig: str | None = None,
    credential_source: str = "",
    credential: str | bytes | None = None,
    credential_fingerprint: str = "",
    dry_run: bool = False,
    recon_result: dict[str, Any] | None = None,
    recon_fn: Callable[[str, str], dict[str, Any]] | None = None,
    run: str | None = None,
    proof: dict[str, Any] | None = None,
) -> PentestSession:
    if mode not in MODES:
        raise SessionError(f"unknown entry mode {mode}; choose {', '.join(MODES)}")
    if role not in ("admin", "lead", "tester", "auditor"):
        raise SessionError(f"unknown role {role}")
    if mode in ("external", "foothold") and not target and not namespace:
        raise SessionError(f"{mode} mode needs --target or --namespace")
    _require_consent(store, "只读侦察")
    _check_scope(store, namespace, target)

    session = PentestSession(
        id=_new_id(), mode=mode, state="new", actor=actor, role=role,
        target=target, namespace=namespace, pod=pod, container=container,
        context=context, chain=chain, dry_run=bool(dry_run),
        credential_source=credential_source,
        credential_fingerprint=credential_fingerprint or fingerprint(credential),
        proof=dict(proof or {}),
    )
    session.run = run or f"session-{session.id}"
    if not dry_run:
        try:
            store.open_run(session.run)
        except KeyError:
            store.create_run(session.run)
    session.history.append({
        "ts": time.time(), "from": "new", "to": "new",
        "reason": "session created", "actor": actor,
    })

    if mode == "kubeconfig":
        if not dry_run and not (kubeconfig and Path(kubeconfig).is_file()):
            raise SessionError("kubeconfig mode needs an existing --kubeconfig")
        session.entry_vector = "kubeconfig"
        session.credential_source = f"kubeconfig:{Path(kubeconfig).name}" if kubeconfig else "kubeconfig"
        if kubeconfig:
            try:
                session.credential_fingerprint = fingerprint(Path(kubeconfig).read_bytes())
            except OSError:
                session.credential_fingerprint = ""
        session.assumptions = [
            "operator holds an authorised kubeconfig for this workspace",
            "the first probe is bootstrapped over the Kubernetes API/kubectl",
            "all target actions after bootstrap go through the probe",
        ]
        session.preconditions = ["signed RoE", "namespace/CIDR in scope", "probe image or upload path"]
        session.state = "ready"
        save(store, session)
        _append_index(store, session)
        transition(store, session, "ready", reason="kubeconfig accepted", actor=actor)
        return session

    if mode == "foothold":
        if not credential_source:
            raise SessionError("foothold mode needs --credential-source sa-token|pod-shell|rce")
        session.entry_vector = credential_source
        session.assumptions = [
            "the existing credential gives exec or Pod creation in the target namespace",
            "the credential is used only to deploy the first probe",
            "no module executes on the host after the probe is ready",
        ]
        session.preconditions = ["signed RoE", "credential scope verified", "upload path writable"]
        save(store, session)
        _append_index(store, session)
        transition(store, session, "foothold", reason=f"foothold via {credential_source}", actor=actor)
        return session

    # external: read-only, bounded proof first; never a blind full scan.
    session.entry_vector = "external-http"
    session.assumptions = [
        "target is reachable from the operator for the initial proof only",
        "a vulnerable version/route must be evidenced before any exploit",
        "without a foothold only read-only recon is allowed",
        "the RCE callback is used only to place the probe",
    ]
    session.preconditions = [
        "signed RoE", "target in scope", "chain selected", "proof artifact retained",
    ]
    proof = dict(recon_result or {})
    if not proof:
        if dry_run:
            proof = {"reachable": False, "vulnerable": False, "dry_run": True,
                     "reason": "dry-run: proof not attempted"}
        else:
            if recon_fn is None:
                from .entry.external import recon

                recon_fn = recon
            proof = recon_fn(target, chain)
    session.proof = dict(proof)
    save(store, session)
    _append_index(store, session)
    if proof.get("reachable"):
        transition(store, session, "recon", reason="target reachable (read-only)", actor=actor,
                   params={"proof": proof.get("evidence")})
    else:
        session.state = "recon"
        session.history.append({
            "ts": time.time(), "from": "new", "to": "recon",
            "reason": "target not reachable; no exploit allowed", "actor": actor,
        })
        save(store, session)
        _audit(store, actor, "session.recon.unreachable", session,
               {"proof": proof}, result="unreachable")
        return session
    if proof.get("vulnerable"):
        if not proof.get("evidence"):
            raise SessionLocked("脆弱性结论缺少证据，拒绝进入 vulnerable 状态")
        transition(store, session, "vulnerable", reason="version/route proof", actor=actor,
                   params={"version": proof.get("version"), "evidence": proof.get("evidence")})
    return session


def mark_foothold(
    store: EvidenceStore,
    session: PentestSession,
    *,
    vector: str,
    proof: dict[str, Any],
    actor: str | None = None,
) -> PentestSession:
    if not proof.get("evidence"):
        raise SessionLocked("foothold 结论必须带证据（命令回显/任务结果/SHA256）")
    if vector not in ENTRY_VECTORS:
        raise SessionError(f"unknown foothold vector {vector}")
    session.entry_vector = vector
    session.proof = {**session.proof, "foothold": proof}
    if session.state == "vulnerable":
        return transition(store, session, "foothold", reason=f"foothold via {vector}",
                          actor=actor, params={"proof": proof})
    if session.state == "foothold":
        save(store, session)
        return session
    raise SessionLocked(f"当前状态 {session.state} 不能登记 foothold")


def register_probe(
    store: EvidenceStore,
    session: PentestSession,
    *,
    probe_id: str,
    parent_id: str | None = None,
    caps: list[str] | None = None,
    actor: str | None = None,
    dry_run: bool = False,
) -> PentestSession:
    if not probe_id:
        raise SessionError("probe_id is required")
    if not dry_run and session.state not in ("foothold", "ready", "probe_ready", "channel_ready"):
        raise SessionLocked(f"状态 {session.state} 不能注册探针（需要 foothold 或 bootstrap）")
    if probe_id not in session.probe_ids:
        session.probe_ids.append(probe_id)
    session.parent_id = parent_id
    save(store, session)
    if session.state in ("foothold", "ready"):
        transition(store, session, "probe_ready", reason="probe registered", actor=actor,
                   params={"probe_id": probe_id, "parent_id": parent_id, "caps": caps or []})
    else:
        _audit(store, actor or session.actor, "session.probe.registered", session,
               {"probe_id": probe_id, "parent_id": parent_id, "caps": caps or []})
    return session


def register_channel(
    store: EvidenceStore,
    session: PentestSession,
    *,
    kind: str = "socks",
    listen: str = "127.0.0.1:0",
    pid: int | None = None,
    actor: str | None = None,
) -> PentestSession:
    if not session.has_probe:
        raise SessionLocked("没有探针时不能建通道")
    session.channel = {"kind": kind, "listen": listen, "pid": pid, "started_at": time.time()}
    save(store, session)
    if session.state == "probe_ready":
        transition(store, session, "channel_ready", reason="channel started", actor=actor,
                   params={"kind": kind, "listen": listen})
    else:
        _audit(store, actor or session.actor, "session.channel.registered", session,
               {"kind": kind, "listen": listen})
    return session


def close_session(
    store: EvidenceStore,
    session: PentestSession,
    *,
    reason: str = "operator closed",
    actor: str | None = None,
) -> PentestSession:
    if session.state != "closed":
        transition(store, session, "closed", reason=reason, actor=actor)
    else:
        save(store, session)
    run = _run_for(store, session)
    if run is not None:
        try:
            run.finalize_run()
        except Exception:
            pass
    return session


def require_probe(session: PentestSession) -> None:
    if not session.has_probe:
        raise SessionLocked(
            "当前会话没有探针；非 bootstrap 动作必须先 inkblade probe deploy"
        )


def require_foothold(session: PentestSession) -> None:
    if not session.has_foothold:
        raise SessionLocked("未获得 foothold：external 模式只允许只读侦察")


def _module_read_only(meta) -> bool:
    return not bool(getattr(meta, "writes", False)) and getattr(meta, "min_level", "") == "只读侦察"


def run_module(
    store: EvidenceStore,
    session: PentestSession,
    user_session,
    module_key: str,
    params: dict[str, Any],
    modules_dir: Path | str,
    *,
    controller=None,
    run=None,
):
    """Execute a module through a probe or the one registered bootstrap entry.

    There is no adapter/host fallback: template modules require a probe
    transport.  The only host-executed module is ``probe-bootstrap`` before the
    first probe exists.
    """
    from .core.registry import load_modules

    mods = load_modules(modules_dir)
    if module_key not in mods:
        raise KeyError(f"未知模块: {module_key}")
    meta = mods[module_key]
    execution = str(getattr(meta, "execution", "template") or "template")
    if (session.mode == "external" and not session.has_foothold
            and execution != "bootstrap" and not _module_read_only(meta)):
        raise SessionLocked(
            f"{module_key} 不是只读侦察模块；external 模式在证明脆弱性并取得 foothold 前拒绝执行"
        )
    if execution == "bootstrap":
        if session.has_probe:
            raise SessionLocked("bootstrap 只允许在首个探针投放前执行；探针就绪后拒绝 host 入口")
    else:
        if not session.has_probe:
            raise SessionLocked(
                f"{module_key} 是模板模块，必须通过探针执行；先 inkblade probe deploy"
            )
        if controller is None:
            raise SessionLocked("没有探针控制器；模板模块不能回退到 host")
    from .core.runner import run_module as core_run_module

    probe = None
    if execution != "bootstrap":
        from .tpl.probe import RustProbe

        probe_id = str(params.get("probe_id") or session.probe_ids[-1])
        probe = RustProbe(controller.client(probe_id))
    result = core_run_module(
        store, user_session, module_key, params, modules_dir, run=run, probe=probe
    )
    _audit(store, session.actor, "session.module", session,
           {"module": module_key, "execution": execution,
            "probe_id": (session.probe_ids[-1] if session.has_probe else None)})
    return result


def render_status(session: PentestSession) -> str:
    lines = [
        f"session {session.id}  mode={session.mode}  state={session.state}",
        f"entry={session.entry_vector or '-'}  target={session.target or '-'}  ns={session.namespace or '-'}",
        f"probes={','.join(session.probe_ids) or '-'}  channel={session.channel or '-'}",
        f"run={session.run}  dry_run={session.dry_run}  foothold={session.has_foothold}",
    ]
    if session.assumptions:
        lines.append("assumptions: " + "; ".join(session.assumptions))
    if session.preconditions:
        lines.append("preconditions: " + "; ".join(session.preconditions))
    return "\n".join(lines)
