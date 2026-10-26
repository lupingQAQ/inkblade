# -*- coding: utf-8 -*-
"""CLI for sessions, probes, and the exec/SOCKS channel."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from .. import session as session_mod
from ..channel import (
    ChannelError,
    ChannelServer,
    Forward,
    ProbeConnection,
    kubectl_probe_command,
)
from ..core import jsonio
from ..core.evidence import EvidenceStore
from ..core.probes import ProbeController, ProbeRegistry, ProbeRegistryError
from ..core.roe import ExecutionLocked, assert_execution_allowed
from ..core.users import Session as UserSession
from ..entry.external import plan as external_plan, recon as external_recon
from ..entry.rce import deploy as deploy_rce
from ..entry.sa import SaTokenProbe
from ..probe.deploy import (
    PROBE_IMAGE_DEFAULT,
    ProbeDeployError,
    ProbeDeploySpec,
    manifest as build_manifest,
    render_manifest,
    load_probe_binary,
)

LEVELS = ["只读侦察", "主动探测", "利用验证", "全影响演示"]


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _store(home: Path, workspace: str) -> EvidenceStore:
    return EvidenceStore(home, workspace=workspace)


def _user(workspace: str, actor: str, role: str) -> UserSession:
    return UserSession(None, actor, role, [workspace], "cli-local")


def _level_ok(store: EvidenceStore, need: str) -> None:
    assert_execution_allowed(store, {"min_level": need})


def _load_session(store: EvidenceStore, session_id: str) -> session_mod.PentestSession:
    return session_mod.load(store, session_id)


def _ensure_allow_write(args, store: EvidenceStore) -> None:
    if not getattr(args, "allow_write", False):
        raise ExecutionLocked("写操作需要显式 --allow-write（且授权级别为全影响演示）")
    _level_ok(store, "全影响演示")


def _probe_token(args) -> str:
    token = getattr(args, "probe_token", None) or os.environ.get("INKBLADE_PROBE_TOKEN", "")
    path = getattr(args, "probe_token_file", None)
    if path:
        token = Path(path).read_text(encoding="utf-8").strip()
    if not token:
        raise ChannelError("missing --probe-token/--probe-token-file (probe HMAC secret)")
    return token


def _probe_command(args, session: session_mod.PentestSession | None) -> list[str]:
    custom = getattr(args, "probe_command", None)
    if custom:
        value = json.loads(custom) if custom.lstrip().startswith("[") else custom.split()
        return [str(item) for item in value]
    if session is None:
        raise ChannelError("a session (or --probe-command) is required")
    namespace = getattr(args, "namespace", None) or session.namespace
    pod = getattr(args, "pod", None) or session.pod
    if not (namespace and pod):
        raise ChannelError("session has no Pod; use --namespace/--pod or a manifest channel")
    return kubectl_probe_command(
        getattr(args, "kubectl", "kubectl") or "kubectl",
        namespace=namespace,
        pod=pod,
        probe_path=getattr(args, "probe_path", None) or session.probe_path,
        token_file=getattr(args, "token_file", None) or session.token_file,
        container=session.container or None,
        kubeconfig=getattr(args, "kubeconfig", None),
        context=session.context or None,
        read_only=not getattr(args, "allow_write", False),
        allow_cmds=getattr(args, "allow_cmd", []) or (),
        probe_id=getattr(args, "probe_id", None),
    )


def _connect(args, session=None, *, read_only: bool = True) -> ProbeConnection:
    command = _probe_command(args, session)
    connection = ProbeConnection(
        command, _probe_token(args),
        timeout=float(getattr(args, "timeout", 30) or 30),
        probe_id=getattr(args, "probe_id", None),
        on_audit=lambda event: None,
    )
    connection.start()
    return connection


def _controller(store: EvidenceStore, connection: ProbeConnection, session=None) -> ProbeController:
    controller = ProbeController(store)
    controller.add(
        connection.probe_id or getattr(session, "probe_ids", ["probe"])[-1],
        connection,
        session_id=getattr(session, "id", ""),
        namespace=getattr(session, "namespace", ""),
        pod=getattr(session, "pod", ""),
    )
    return controller


def _state_path(home: Path, workspace: str) -> Path:
    path = Path(home) / "evidence" / workspace / "channel-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _write_state(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def register(sub) -> None:
    sp = sub.add_parser("session", help="入口会话：kubeconfig|external|foothold（证据与审计绑定）")
    ssub = sp.add_subparsers(dest="session_cmd", required=True)
    so = ssub.add_parser("open", help="打开入口会话；external 只做有界证明")
    so.add_argument("--mode", choices=session_mod.MODES, required=True)
    so.add_argument("--workspace", default="local-lab")
    so.add_argument("--actor", default="cli")
    so.add_argument("--role", choices=["admin", "lead", "tester", "auditor"], default="tester")
    so.add_argument("--target", default="")
    so.add_argument("--namespace", default="")
    so.add_argument("--pod", default="")
    so.add_argument("--container", default="")
    so.add_argument("--chain", default="")
    so.add_argument("--context", default="")
    so.add_argument("--kubeconfig", default=None)
    so.add_argument("--credential-source", default="")
    so.add_argument("--token-file", default=None)
    so.add_argument("--proof", default=None, help="JSON or @file proof produced by a read-only check")
    so.add_argument("--dry-run", action="store_true")
    ss = ssub.add_parser("status", help="会话状态（缺省列出全部）")
    ss.add_argument("--id", default=None)
    ss.add_argument("--workspace", default="local-lab")
    ss.add_argument("--json", action="store_true")
    sc = ssub.add_parser("close", help="关闭会话并结束证据 run")
    sc.add_argument("--id", required=True)
    sc.add_argument("--workspace", default="local-lab")
    sc.add_argument("--reason", default="operator closed")
    sc.add_argument("--actor", default="cli")
    sr = ssub.add_parser("run", help="通过会话/探针执行一个模板模块")
    sr.add_argument("--id", required=True)
    sr.add_argument("--module", required=True)
    sr.add_argument("--params", default="{}")
    sr.add_argument("--workspace", default="local-lab")
    sr.add_argument("--actor", default="cli")
    sr.add_argument("--role", choices=["admin", "lead", "tester", "auditor"], default="tester")
    sr.add_argument("--modules-dir", default=None)
    sr.add_argument("--allow-write", action="store_true")
    sr.add_argument("--kubectl", default="kubectl")
    sr.add_argument("--probe-token", default=None)
    sr.add_argument("--probe-token-file", default=None)
    sr.add_argument("--probe-command", default=None)

    pr = sub.add_parser("probe", help="探针注册表与任务：list|deploy|collect|exec|upload|download|spawn|cleanup")
    psub = pr.add_subparsers(dest="probe_cmd", required=True)
    pl = psub.add_parser("list", help="列出探针（SQLite 注册表，按父子树）")
    pl.add_argument("--workspace", default="local-lab")
    pl.add_argument("--session", default=None)
    pl.add_argument("--json", action="store_true")
    pd = psub.add_parser("deploy", help="投放探针（默认干跑；写需 --allow-write）")
    pd.add_argument("--session", required=True)
    pd.add_argument("--workspace", default="local-lab")
    pd.add_argument("--actor", default="cli")
    pd.add_argument("--role", choices=["admin", "lead", "tester", "auditor"], default="tester")
    pd.add_argument("--via", choices=["manifest", "rce", "sa-token", "kubectl"], default="manifest")
    pd.add_argument("--binary", default=None)
    pd.add_argument("--namespace", default=None)
    pd.add_argument("--pod", default=None)
    pd.add_argument("--container", default=None)
    pd.add_argument("--image", default=None)
    pd.add_argument("--create-pod", action="store_true")
    pd.add_argument("--token-file", default=None)
    pd.add_argument("--server", default="")
    pd.add_argument("--ca", default=None)
    pd.add_argument("--kubeconfig", default=None)
    pd.add_argument("--kind", choices=["pod", "job", "ephemeral"], default="pod")
    pd.add_argument("--target-pod", default=None)
    pd.add_argument("--out", default=None)
    pd.add_argument("--apply", action="store_true")
    pd.add_argument("--dry-run", action="store_true")
    pd.add_argument("--allow-write", action="store_true")
    pd.add_argument("--allow-cmd", action="append", default=[])
    pd.add_argument("--probe-token", default=None)
    pd.add_argument("--probe-token-file", default=None)
    pd.add_argument("--probe-command", default=None)
    pd.add_argument("--kubectl", default="kubectl")

    for command in ("collect", "exec", "upload", "download", "spawn", "cleanup", "run"):
        pc = psub.add_parser(command, help=f"probe {command}（经 stdio 通道）")
        pc.add_argument("--session", default=None)
        pc.add_argument("--workspace", default="local-lab")
        pc.add_argument("--actor", default="cli")
        pc.add_argument("--role", choices=["admin", "lead", "tester", "auditor"], default="tester")
        pc.add_argument("--probe-id", default=None)
        pc.add_argument("--namespace", default=None)
        pc.add_argument("--pod", default=None)
        pc.add_argument("--probe-path", default=None)
        pc.add_argument("--token-file", default=None)
        pc.add_argument("--kubectl", default="kubectl")
        pc.add_argument("--probe-token", default=None)
        pc.add_argument("--probe-token-file", default=None)
        pc.add_argument("--probe-command", default=None)
        pc.add_argument("--allow-write", action="store_true")
        pc.add_argument("--allow-cmd", action="append", default=[])
        pc.add_argument("--timeout", type=float, default=30)
        pc.add_argument("--json", action="store_true")
        if command == "exec":
            pc.add_argument("argv", nargs=argparse.REMAINDER)
        if command == "upload":
            pc.add_argument("local")
            pc.add_argument("remote")
            pc.add_argument("--mode", type=lambda value: int(value, 8), default=0o600)
        if command == "download":
            pc.add_argument("remote")
            pc.add_argument("local", nargs="?", default=None)
            pc.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
        if command == "spawn":
            pc.add_argument("binary")
            pc.add_argument("--parent-id", default=None)
            pc.add_argument("--remote-path", default=None)
            pc.add_argument("--via", choices=["direct", "k8s-exec", "shared-volume"], default="direct")
            pc.add_argument("--target-namespace", default=None)
            pc.add_argument("--target-pod", default=None)
        if command == "cleanup":
            pc.add_argument("--path", action="append", default=[])
            pc.add_argument("--no-recursive", action="store_true")

    ch = sub.add_parser("channel", help="exec stdio 通道：本地 SOCKS5/端口转发（仅 127.0.0.1）")
    csub = ch.add_subparsers(dest="channel_cmd", required=True)
    cs = csub.add_parser("start", help="启动 SOCKS5/端口转发（默认后台）")
    cs.add_argument("--session", default=None)
    cs.add_argument("--workspace", default="local-lab")
    cs.add_argument("--actor", default="cli")
    cs.add_argument("--role", choices=["admin", "lead", "tester", "auditor"], default="tester")
    cs.add_argument("--socks-port", type=int, default=1080)
    cs.add_argument("--no-socks", action="store_true")
    cs.add_argument("--forward", action="append", default=[],
                    metavar="LOCAL:HOST:PORT")
    cs.add_argument("--namespace", default=None)
    cs.add_argument("--pod", default=None)
    cs.add_argument("--probe-path", default=None)
    cs.add_argument("--token-file", default=None)
    cs.add_argument("--kubectl", default="kubectl")
    cs.add_argument("--probe-token", default=None)
    cs.add_argument("--probe-token-file", default=None)
    cs.add_argument("--probe-command", default=None)
    cs.add_argument("--allow-write", action="store_true")
    cs.add_argument("--allow-cmd", action="append", default=[])
    cs.add_argument("--foreground", action="store_true")
    cs.add_argument("--timeout", type=float, default=30)
    st = csub.add_parser("status", help="通道状态")
    st.add_argument("--workspace", default="local-lab")
    st.add_argument("--json", action="store_true")
    sp = csub.add_parser("stop", help="停止通道并清理探针")
    sp.add_argument("--workspace", default="local-lab")
    sp.add_argument("--json", action="store_true")
    sv = csub.add_parser("serve", help=argparse.SUPPRESS)
    sv.add_argument("--config", required=True)
    sv.add_argument("--state", required=True)


def dispatch(args, home: Path) -> int:
    if args.cmd == "session":
        return _session_cmd(args, home)
    if args.cmd == "probe":
        return _probe_cmd(args, home)
    if args.cmd == "channel":
        return _channel_cmd(args, home)
    print(f"unknown command {args.cmd}", file=sys.stderr)
    return 2


def _session_cmd(args, home: Path) -> int:
    store = _store(home, args.workspace)
    if args.session_cmd == "open":
        proof = None
        if args.proof:
            raw = Path(args.proof[1:]).read_text(encoding="utf-8") if args.proof.startswith("@") else args.proof
            proof = json.loads(raw)
        credential = None
        if args.token_file:
            credential = Path(args.token_file).read_text(encoding="utf-8").strip()
        try:
            sess = session_mod.open_session(
                store, args.mode, actor=args.actor, role=args.role,
                target=args.target, namespace=args.namespace, pod=args.pod,
                container=args.container, chain=args.chain, context=args.context,
                kubeconfig=args.kubeconfig, credential_source=args.credential_source,
                credential=credential, dry_run=args.dry_run, recon_result=proof,
                recon_fn=None if args.dry_run or proof else external_recon,
            )
        except (ExecutionLocked, session_mod.SessionError, ValueError) as exc:
            print(f"inkblade session: {exc}", file=sys.stderr)
            return 91 if isinstance(exc, ExecutionLocked) else 2
        _print_json(sess.to_dict())
        return 0
    if args.session_cmd == "status":
        if args.id:
            sess = _load_session(store, args.id)
            _print_json(sess.to_dict() if args.json else sess.summary())
            if not args.json:
                print(session_mod.render_status(sess))
        else:
            _print_json(session_mod.list_sessions(store))
        return 0
    if args.session_cmd == "close":
        sess = _load_session(store, args.id)
        state_path = _state_path(home, args.workspace)
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                pid = int(state.get("pid") or 0)
                if _pid_alive(pid):
                    os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        sess = session_mod.close_session(store, sess, reason=args.reason, actor=args.actor)
        _print_json(sess.summary())
        return 0
    if args.session_cmd == "run":
        return _session_run(args, home, store)
    return 2


def _session_run(args, home: Path, store: EvidenceStore) -> int:
    sess = _load_session(store, args.id)
    params = json.loads(Path(args.params[1:]).read_text(encoding="utf-8")
                        if args.params.startswith("@") else args.params or "{}")
    user = _user(args.workspace, args.actor, args.role)
    modules_dir = Path(args.modules_dir) if args.modules_dir else _modules_dir(home)
    controller = None
    connection = None
    if sess.probe_ids and not args.probe_command and not (sess.namespace and sess.pod):
        pass
    try:
        if sess.probe_ids:
            connection = _connect(args, sess, read_only=not args.allow_write)
            controller = _controller(store, connection, sess)
        result = session_mod.run_module(
            store, sess, user, args.module, params, modules_dir,
            controller=controller,
        )
    except (ExecutionLocked, session_mod.SessionError, ChannelError) as exc:
        print(f"inkblade session run: {exc}", file=sys.stderr)
        return 91 if isinstance(exc, ExecutionLocked) else 2
    finally:
        if connection:
            connection.close()
    _print_json(result)
    return 0


def _modules_dir(home: Path) -> Path:
    candidate = Path(home) / "modules"
    if candidate.is_dir():
        return candidate
    return Path(__file__).resolve().parents[1] / "modules"


def _probe_cmd(args, home: Path) -> int:
    action = args.probe_cmd
    store = _store(home, args.workspace)
    if action == "list":
        registry = ProbeRegistry(store)
        rows = registry.list(session_id=args.session)
        if args.json:
            _print_json(rows)
        else:
            for row in rows:
                print(f"{row['probe_id']}\tparent={row.get('parent_id') or '-'}\t"
                      f"status={row['status']}\tns={row.get('namespace') or '-'}\t"
                      f"pod={row.get('pod') or '-'}\tcaps={','.join(row.get('caps') or [])}")
        return 0
    sess = None
    if getattr(args, "session", None):
        sess = _load_session(store, args.session)
    if action == "deploy":
        return _probe_deploy(args, home, store, sess)
    connection = None
    controller = None
    try:
        connection = _connect(args, sess, read_only=not args.allow_write)
        controller = _controller(store, connection, sess)
        if action in ("collect", "run"):
            result = connection.collect()
        elif action == "exec":
            argv = list(args.argv or [])
            if argv and argv[0] == "--":
                argv = argv[1:]
            result = connection.exec(argv, timeout_ms=int(args.timeout * 1000))
        elif action == "upload":
            _ensure_allow_write(args, store)
            local = Path(args.local).read_bytes()
            result = connection.upload(args.remote, local, mode=args.mode)
        elif action == "download":
            data = connection.download(args.remote, max_bytes=args.max_bytes)
            if args.local:
                Path(args.local).write_bytes(data)
                result = {"path": args.local, "bytes": len(data)}
            else:
                import base64
                result = {"bytes": len(data), "data_b64": base64.b64encode(data).decode("ascii")}
        elif action == "spawn":
            _ensure_allow_write(args, store)
            binary = Path(args.binary).read_bytes()
            result = controller.spawn(
                connection.probe_id, binary, remote_path=args.remote_path,
                probe_id=args.parent_id, via=args.via,
                namespace=args.target_namespace or (sess.namespace if sess else ""),
                pod=args.target_pod or (sess.pod if sess else ""),
                session_id=getattr(sess, "id", ""),
            )
        elif action == "cleanup":
            result = controller.cleanup(connection.probe_id, recursive=not args.no_recursive,
                                        paths=args.path)
        else:
            print(f"unknown probe action {action}", file=sys.stderr)
            return 2
    except (ExecutionLocked, ChannelError, ProbeRegistryError, OSError, ValueError) as exc:
        print(f"inkblade probe {action}: {exc}", file=sys.stderr)
        return 91 if isinstance(exc, ExecutionLocked) else 2
    finally:
        if controller:
            controller.close()
        elif connection:
            connection.close()
    if getattr(args, "json", False) or not isinstance(result, dict):
        _print_json(result)
    elif action == "collect":
        _print_json(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


def _probe_deploy(args, home: Path, store: EvidenceStore, sess) -> int:
    if args.via == "manifest":
        try:
            binary, sha, arch = load_probe_binary(args.binary, allow_non_elf=True)
        except ProbeDeployError:
            binary, sha, arch = b"", "", "unknown"
    else:
        try:
            binary, sha, arch = load_probe_binary(args.binary, allow_non_elf=bool(args.dry_run))
        except ProbeDeployError as exc:
            print(f"inkblade probe deploy: {exc}", file=sys.stderr)
            return 2
    dry = bool(args.dry_run or not args.allow_write)
    if not dry:
        try:
            _ensure_allow_write(args, store)
        except ExecutionLocked as exc:
            print(f"inkblade probe deploy: {exc}", file=sys.stderr)
            return 91
    probe_id = f"probe-{sha[:12]}"
    if args.via == "rce":
        target = sess.target
        chain = sess.chain
        token = _probe_token(args)
        try:
            result = deploy_rce(chain, target, binary, remote_path=args.out,
                                dry_run=dry)
        except Exception as exc:
            print(f"inkblade probe deploy (rce): {exc}", file=sys.stderr)
            return 2
        if not dry:
            session_mod.mark_foothold(
                store, sess, vector="rce",
                proof={"evidence": result, "target": target, "sha256": sha},
                actor=args.actor,
            )
            sess.probe_path = result.get("remote_path") or sess.probe_path
            session_mod.save(store, sess)
            session_mod.register_probe(store, sess, probe_id=probe_id,
                                       caps=["collect", "exec", "task"], actor=args.actor)
        _print_json({**result, "probe_id": probe_id, "arch": arch})
        return 0
    if args.via in ("sa-token", "kubectl"):
        token_value = ""
        if args.token_file:
            token_value = Path(args.token_file).read_text(encoding="utf-8").strip()
        entry = SaTokenProbe(
            namespace=args.namespace or sess.namespace,
            pod=args.pod or sess.pod,
            container=args.container or sess.container,
            token=token_value, server=args.server, ca_path=args.ca,
            kubeconfig=args.kubeconfig, create_pod=args.create_pod,
            image=args.image or "busybox:1.36", read_only=not args.allow_write,
            allow_cmds=args.allow_cmd or (), dry_run=dry,
        )
        try:
            foothold = entry.deploy(binary, probe_token=token)
        except Exception as exc:
            print(f"inkblade probe deploy (sa): {exc}", file=sys.stderr)
            return 2
        if not dry:
            session_mod.mark_foothold(
                store, sess, vector="sa-token",
                proof={"evidence": foothold.to_dict(), "sha256": sha},
                actor=args.actor,
            )
            sess.namespace = foothold.namespace
            sess.pod = foothold.pod
            sess.container = foothold.container
            sess.probe_path = foothold.probe_path
            sess.token_file = foothold.token_file
            session_mod.save(store, sess)
            session_mod.register_probe(store, sess, probe_id=probe_id,
                                       caps=["collect", "exec", "task"], actor=args.actor)
        _print_json({"probe_id": probe_id, "arch": arch, "sha256": sha,
                     "foothold": foothold.to_dict(), "dry_run": dry})
        return 0
    # manifest
    spec = ProbeDeploySpec(
        namespace=args.namespace or sess.namespace or "default",
        name=args.pod or f"inkblade-probe-{int(time.time()) % 100000}",
        image=args.image or PROBE_IMAGE_DEFAULT, read_only=not args.allow_write,
        allow_write=args.allow_write, session=sess.id,
        allow_cmds=args.allow_cmd or (),
    )
    document = build_manifest(args.kind, spec, target_pod=args.target_pod or sess.pod)
    text = render_manifest(document)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.apply and not dry:
        command = [args.kubectl or "kubectl", "--kubeconfig", args.kubeconfig] if args.kubeconfig else [args.kubectl or "kubectl"]
        command += ["apply", "-f", "-"]
        proc = subprocess.run(command, input=text.encode("utf-8"), capture_output=True)
        if proc.returncode != 0:
            print(proc.stderr.decode("utf-8", "replace"), file=sys.stderr)
            return 2
    _print_json({"kind": args.kind, "manifest": document, "dry_run": dry,
                 "probe_id": probe_id, "arch": arch, "sha256": sha,
                 "apply": bool(args.apply and not dry)})
    return 0


def _parse_forward(value: str) -> Forward:
    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError("--forward expects LOCAL:HOST:PORT")
    return Forward(int(parts[0]), parts[1], int(parts[2]))


def _channel_cmd(args, home: Path) -> int:
    if args.channel_cmd == "serve":
        return _channel_serve(args)
    store = _store(home, args.workspace)
    state = _state_path(home, args.workspace)
    if args.channel_cmd == "status":
        if not state.is_file():
            _print_json({"running": False, "state": str(state)})
            return 0
        data = json.loads(state.read_text(encoding="utf-8"))
        data["running"] = _pid_alive(int(data.get("pid") or 0))
        _print_json(data)
        return 0
    if args.channel_cmd == "stop":
        if not state.is_file():
            _print_json({"stopped": False, "reason": "no state"})
            return 0
        data = json.loads(state.read_text(encoding="utf-8"))
        pid = int(data.get("pid") or 0)
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        data["status"] = "stopped"
        data["running"] = False
        _write_state(state, data)
        _print_json({"stopped": True, "pid": pid})
        return 0
    # start
    sess = _load_session(store, args.session) if args.session else None
    try:
        _level_ok(store, "主动探测")
    except ExecutionLocked as exc:
        print(f"inkblade channel start: {exc}", file=sys.stderr)
        return 91
    if args.allow_write:
        try:
            _ensure_allow_write(args, store)
        except ExecutionLocked as exc:
            print(f"inkblade channel start: {exc}", file=sys.stderr)
            return 91
    forwards = [_parse_forward(item) for item in args.forward]
    config = {
        "command": _probe_command(args, sess),
        "socks_port": -1 if args.no_socks else args.socks_port,
        "forwards": [[f.local_port, f.host, f.port] for f in forwards],
        "session_id": getattr(sess, "id", ""),
        "workspace": args.workspace,
        "actor": args.actor,
        "allow_write": bool(args.allow_write),
        "timeout": float(args.timeout),
    }
    token = _probe_token(args)
    if args.foreground:
        data = _serve_config(config, state, token)
        _print_json(data)
        return 0
    config_path = Path(state).with_suffix(".config.json")
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    env = {**os.environ, "INKBLADE_CHANNEL_TOKEN": token}
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(
        [sys.executable, "-m", "inkblade", "--home", str(home), "channel", "serve",
         "--config", str(config_path), "--state", str(state)],
        env=env, creationflags=creationflags,
        start_new_session=(os.name != "nt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        if state.is_file():
            data = json.loads(state.read_text(encoding="utf-8"))
            if data.get("status") == "running":
                _print_json(data)
                return 0
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    print("inkblade channel start: child did not become ready", file=sys.stderr)
    return 2


def _serve_config(config: dict[str, Any], state: Path, token: str) -> dict[str, Any]:
    from ..channel import Forward
    forwards = [Forward(int(item[0]), str(item[1]), int(item[2]))
                for item in config.get("forwards") or []]
    connection = ProbeConnection(
        config["command"], token,
        timeout=float(config.get("timeout") or 30),
    )
    connection.start()
    server = ChannelServer(
        connection, socks_port=int(config.get("socks_port") or 0),
        forwards=forwards,
    )
    server.start()
    data = {"pid": os.getpid(), "status": "running", "workspace": config.get("workspace"),
            "session_id": config.get("session_id"), "started_at": time.time(),
            **server.status()}
    _write_state(state, data)
    stop = False

    def _handle(signum, frame):
        nonlocal stop
        stop = True

    try:
        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
    except (ValueError, OSError):
        pass
    try:
        while not stop:
            time.sleep(0.5)
            data.update(server.status())
            data["pid"] = os.getpid()
            data["status"] = "running" if not stop else "stopping"
            _write_state(state, data)
    finally:
        server.stop()
        data.update(server.status())
        data["status"] = "stopped"
        data["running"] = False
        _write_state(state, data)
    return data


def _channel_serve(args) -> int:
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    token = os.environ.get("INKBLADE_CHANNEL_TOKEN", "")
    if not token:
        print("channel serve: missing INKBLADE_CHANNEL_TOKEN", file=sys.stderr)
        return 2
    _serve_config(config, Path(args.state), token)
    return 0
