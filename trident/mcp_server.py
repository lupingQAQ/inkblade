# -*- coding: utf-8 -*-
"""Trident MCP 只读服务器（stdio JSON-RPC 2.0，MCP 2026-07-28 + 旧版兼容）。

暴露工具（全部只读，绝不触发 chains.execute / runner / 写动作）：
- ``list_runs``            证据库 run 清单
- ``get_findings``         逐发现读取（含证据 SHA256）
- ``get_chain_plan``       链前置判定 + dry-run 计划（plan-only，需 lead 审批后由人触发）
- ``get_evidence_manifest`` manifest 校验 + 三层证据清单
- ``validate_rules``       规则包静态校验（文件齐备 / 映射一致）

安全边界：
- 复用工作区授权锁：未签署 consent 时数据类工具返回 JSON-RPC -32002（与 CLI/API 423 同源）；
- 不注册任何写工具；未知名（含 execute / run_chain / delete_run）一律 -32602；
- 只读取证：不创建 run、不写 actions / backups / rollbacks；stdout 仅输出协议帧。

用法：``trident --home <ws> mcp --workspace local-lab``（stdio；日志只走 stderr）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from .core.chains import dry_run, load_chains
from .core.evidence import EvidenceStore
from .core.roe import roe_status
from .core.users import UserStore

PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18")
SERVER_NAME = "trident-mcp"
SERVER_VERSION = "0.1.0"
_VERSION_META = "io.modelcontextprotocol/protocolVersion"

_READ_ONLY_NOTE_ZH = "只读接口：不暴露执行/写入工具；链执行必须由 lead 审批后由人触发。"
_READ_ONLY_NOTE_EN = "Read-only interface: no execution or write tools; chain execution is human-triggered after lead approval."


class AuthLocked(RuntimeError):
    """工作区授权未完成（复用 ROE 锁）。"""


class ToolError(RuntimeError):
    """工具级错误（返回 isError=true，而非协议错误）。"""


TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_runs",
        "description": "List evidence runs in the authorized workspace. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_findings",
        "description": "Read findings for a run (default: latest), including evidence SHA256. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run": {"type": "string"},
                "severity": {"type": "string"},
                "zeroday_only": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_chain_plan",
        "description": "Evaluate chain preconditions and return a dry-run plan (plan-only; human execution after lead approval).",
        "inputSchema": {
            "type": "object",
            "properties": {"chain": {"type": "string"}, "run": {"type": "string"}},
            "required": ["chain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_evidence_manifest",
        "description": "Verify a run manifest and list the three-layer evidence inventory. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {"run": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "validate_rules",
        "description": "Statically validate a generated rule pack (files present, mapping consistent). Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pack_dir": {"type": "string"},
                "strict": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
]
_TOOL_NAMES = {t["name"] for t in TOOLS}


def _json_text(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=False)


def _manifest_map(run) -> dict[str, str]:
    path = run.dir / "manifest.sha256"
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        sha, _, rel = line.partition("  ")
        if rel:
            out[rel.strip()] = sha.strip()
    return out


def _runs(store: EvidenceStore) -> list[str]:
    if not store.ws_dir.exists():
        return []
    return sorted(p.name for p in store.ws_dir.iterdir()
                  if p.is_dir() and not p.name.startswith("_"))


def _latest_run(store: EvidenceStore) -> str | None:
    runs = _runs(store)
    if not runs:
        return None
    return max(runs, key=lambda name: (store.ws_dir / name).stat().st_mtime)


def _load_chains(chains_dir: Path | str | None) -> dict[str, dict]:
    root = Path(chains_dir) if chains_dir else Path(__file__).resolve().parent / "chains"
    return load_chains(root)


class McpContext:
    """MCP 会话上下文：工作区 + 可选登录会话 + 链/模块目录。"""

    def __init__(
        self,
        home: Path | str,
        workspace: str = "local-lab",
        *,
        users_path: Path | str | None = None,
        token: str | None = None,
        actor: str = "mcp-readonly",
        role: str = "auditor",
        chains_dir: Path | str | None = None,
        modules_dir: Path | str | None = None,
    ):
        self.home = Path(home)
        self.workspace = workspace
        self.actor = actor
        self.role = role
        self.chains_dir = chains_dir
        self.modules_dir = modules_dir or (self.home / "modules")
        self.session = None
        if token:
            if users_path is None:
                users_path = self.home / "users.json"
            self.session = UserStore(users_path).session(token)
            if self.session is None:
                raise ValueError("MCP token 无效或已过期")
            if not self.session.can("read"):
                raise ValueError(f"角色 {self.session.role} 无读取权限")

    # ---------- 授权 ----------
    def store(self) -> EvidenceStore:
        if self.session is not None:
            return self.session.open_store(self.home, self.workspace)
        return EvidenceStore(self.home, workspace=self.workspace)

    def authorized_store(self) -> EvidenceStore:
        store = self.store()
        if roe_status(store) != "complete":
            raise AuthLocked("工作区授权未完成（consent 未签署）：数据类 MCP 工具拒绝读取")
        return store

    def _run(self, store: EvidenceStore, name: str | None):
        run_name = name or _latest_run(store)
        if run_name is None:
            raise ToolError("证据库为空：没有可读取的 run（先完成一次授权内的执行）")
        try:
            return store.open_run(run_name)
        except KeyError as exc:
            raise ToolError(str(exc)) from exc

    # ---------- 工具实现 ----------
    def list_runs(self, args: dict) -> dict:
        store = self.authorized_store()
        runs = _runs(store)
        return {"workspace": self.workspace, "runs": runs, "count": len(runs),
                "read_only": True}

    def get_findings(self, args: dict) -> dict:
        store = self.authorized_store()
        run = self._run(store, args.get("run"))
        shas = _manifest_map(run)
        items = []
        for f in run.findings:
            if args.get("severity") and f["severity"] != args["severity"]:
                continue
            if args.get("zeroday_only") and not f.get("is_zeroday"):
                continue
            item = dict(f)
            item["is_zeroday"] = bool(f.get("is_zeroday"))
            item["evidence_sha256"] = shas.get(f.get("evidence_path") or "", "")
            items.append(item)
        return {"workspace": self.workspace, "run": run.name, "count": len(items),
                "findings": items, "read_only": True}

    def get_chain_plan(self, args: dict) -> dict:
        chain_id = str(args.get("chain") or "").strip()
        if not chain_id:
            raise ToolError("缺少参数 chain")
        chains = _load_chains(self.chains_dir)
        chain = chains.get(chain_id)
        if chain is None:
            raise ToolError(f"未知链 {chain_id}（可用: {', '.join(sorted(chains))}）")
        store = self.authorized_store()
        run = self._run(store, args.get("run"))
        plan = dry_run(chain, run.findings, self.modules_dir)
        return {
            "workspace": self.workspace,
            "run": run.name,
            "chain": {"id": chain["id"], "title": chain.get("title", {}),
                      "category": chain.get("category", "")},
            "plan": plan,
            "approval": {
                "required": True,
                "approver_role": "lead",
                "status": "pending",
                "reason_zh": "链执行属写面动作：必须由 lead 审批，审批后由人触发执行。",
                "reason_en": "Chain execution is a write-surface action: lead approval is mandatory and execution is human-triggered.",
            },
            "execution": {
                "trigger": "human",
                "performed": False,
                "note_zh": "本工具仅返回计划；不调用 chains.execute / runner。",
                "note_en": "This tool only returns a plan; it never calls chains.execute or the runner.",
            },
            "read_only": True,
        }

    def get_evidence_manifest(self, args: dict) -> dict:
        store = self.authorized_store()
        run = self._run(store, args.get("run"))
        shas = _manifest_map(run)
        entries = [{"path": rel, "sha256": sha} for rel, sha in sorted(shas.items())]
        archives = sorted(p.name for p in (run.dir / "steps").glob("*") if p.is_file())
        return {
            "workspace": self.workspace,
            "run": run.name,
            "verified": store.verify_manifest(run.name),
            "entries": entries,
            "archives": archives,
            "layers": {
                "context": str((run.dir / "context.jsonl.gz").relative_to(store.root)).replace("\\", "/"),
                "context_present": (run.dir / "context.jsonl.gz").is_file(),
                "sqlite": str((run.dir / "evidence.db").relative_to(store.root)).replace("\\", "/"),
                "sqlite_present": (run.dir / "evidence.db").is_file(),
                "manifest": str((run.dir / "manifest.sha256").relative_to(store.root)).replace("\\", "/"),
            },
            "actions": run.query("SELECT COUNT(*) FROM actions")[0][0],
            "read_only": True,
        }

    def validate_rules(self, args: dict) -> dict:
        raw = str(args.get("pack_dir") or "reports/rules-pack")
        pack = Path(raw)
        if not pack.is_absolute():
            pack = self.home / pack
        pack = pack.resolve()
        home = self.home.resolve()
        if home != pack and home not in pack.parents:
            raise ToolError("pack_dir 必须位于工作区根目录内（只读边界）")
        mapping_path = pack / "mapping.json"
        if not mapping_path.is_file():
            raise ToolError(f"规则包缺少 mapping.json: {pack}")
        try:
            mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ToolError(f"mapping.json 无法解析: {exc}") from exc

        errors: list[str] = []
        warnings: list[str] = []
        missing: list[str] = []
        rules = mapping.get("rules")
        chains = mapping.get("chains")
        if not isinstance(rules, list):
            errors.append("mapping.rules 必须是数组")
            rules = []
        if not isinstance(chains, dict):
            errors.append("mapping.chains 必须是对象")
            chains = {}
        seen: set[str] = set()
        for rule in rules:
            rid = str(rule.get("id") or "")
            if not rid:
                errors.append("存在缺少 id 的规则")
                continue
            if rid in seen:
                errors.append(f"规则 id 重复: {rid}")
            seen.add(rid)
            engines = rule.get("engines")
            if not isinstance(engines, list) or not engines:
                errors.append(f"{rid}: engines 为空")
            files = rule.get("files")
            if not isinstance(files, list) or not files:
                errors.append(f"{rid}: files 为空")
                continue
            for rel in files:
                if not (pack / str(rel)).is_file():
                    missing.append(f"{rid}: {rel}")
            for cid in rule.get("blocks_chains") or []:
                if cid not in chains:
                    errors.append(f"{rid}: blocks_chains 引用未知链 {cid}")
        for cid, meta in chains.items():
            if not isinstance(meta, dict):
                errors.append(f"链 {cid}: 元数据必须为对象")
                continue
            rule_ids = meta.get("rules") or []
            if not rule_ids:
                errors.append(f"链 {cid}: 无规则覆盖")
            for rid in rule_ids:
                if rid not in seen:
                    errors.append(f"链 {cid}: 引用未知规则 {rid}")

        catalog: dict[str, dict] = {}
        try:
            catalog = _load_chains(self.chains_dir)
        except Exception as exc:  # 链目录缺失/非法不阻塞规则包内部校验
            warnings.append(f"链目录无法加载: {type(exc).__name__}: {exc}")
        missing_chains = sorted(set(catalog) - set(chains))
        if missing_chains:
            warnings.append(f"{len(missing_chains)} 条链未在本规则包映射中: {', '.join(missing_chains[:8])}")
        if args.get("strict") and missing_chains:
            errors.append(f"strict: 链目录有 {len(missing_chains)} 条链未被规则包覆盖")

        ok = not errors and not missing and (not args.get("strict") or not missing_chains)
        return {
            "workspace": self.workspace,
            "pack_dir": str(pack),
            "ok": ok,
            "rules": len(seen),
            "chains": len(chains),
            "missing_files": missing,
            "errors": errors,
            "warnings": warnings,
            "catalog_chains": len(catalog),
            "chains_missing_from_pack": missing_chains,
            "read_only": True,
        }

    # ---------- 分发 ----------
    def call(self, name: str, args: dict | None) -> dict:
        if name not in _TOOL_NAMES:
            raise KeyError(name)
        handler = {
            "list_runs": self.list_runs,
            "get_findings": self.get_findings,
            "get_chain_plan": self.get_chain_plan,
            "get_evidence_manifest": self.get_evidence_manifest,
            "validate_rules": self.validate_rules,
        }[name]
        return handler(dict(args or {}))


def _error(msg_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def _result(msg_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def dispatch(ctx: McpContext, msg: dict) -> dict | None:
    """处理单条 JSON-RPC 消息；通知（无 id）返回 None。"""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
    method = msg["method"]
    msg_id = msg.get("id")
    is_notification = "id" not in msg
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    request_version = meta.get(_VERSION_META)
    if request_version and request_version not in SUPPORTED_PROTOCOL_VERSIONS:
        return _error(msg_id, -32000, f"Unsupported protocol version: {request_version}",
                      {"supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS)})

    if method == "initialize":
        params = msg.get("params") or {}
        requested = str(params.get("protocolVersion") or PROTOCOL_VERSION)
        return _result(msg_id, {
            "protocolVersion": requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": f"{_READ_ONLY_NOTE_ZH} / {_READ_ONLY_NOTE_EN}",
        })
    if method == "server/discover":
        return _result(msg_id, {
            "resultType": "complete",
            "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {"tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": {
                "name": SERVER_NAME, "version": SERVER_VERSION}},
            "instructions": f"{_READ_ONLY_NOTE_ZH} / {_READ_ONLY_NOTE_EN}",
            "ttlMs": 3600000,
            "cacheScope": "public",
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in _TOOL_NAMES:
            return _error(msg_id, -32602, f"未知工具 {name!r}：仅支持只读工具 {sorted(_TOOL_NAMES)}")
        if not isinstance(args, dict):
            return _error(msg_id, -32602, "tools/call.arguments 必须是对象")
        try:
            payload = ctx.call(name, args)
        except AuthLocked as exc:
            return _error(msg_id, -32002, str(exc))
        except ToolError as exc:
            return _result(msg_id, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            })
        except Exception as exc:  # 工具异常不拖垮 MCP 会话
            return _result(msg_id, {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            })
        return _result(msg_id, {
            "resultType": "complete",
            "content": [{"type": "text", "text": _json_text(payload)}],
            "structuredContent": payload,
            "isError": False,
        })
    if is_notification:
        return None
    return _error(msg_id, -32601, f"Method not found: {method}")


def serve(ctx: McpContext, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """stdio 主循环：一行一帧 JSON-RPC；stdout 只写协议响应。"""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            stdout.write(_json_text(_error(None, -32700, f"Parse error: {exc}")) + "\n")
            stdout.flush()
            continue
        if isinstance(msg, list):  # JSON-RPC batch：逐条处理，通知不产出
            replies = [r for r in (dispatch(ctx, m) for m in msg) if r is not None]
            if replies:
                stdout.write(_json_text(replies) + "\n")
                stdout.flush()
            continue
        reply = dispatch(ctx, msg)
        if reply is not None:
            stdout.write(_json_text(reply) + "\n")
            stdout.flush()
    return 0


def run_stdio(
    home: Path | str,
    workspace: str = "local-lab",
    *,
    users_path: Path | str | None = None,
    token: str | None = None,
    actor: str = "mcp-readonly",
    role: str = "auditor",
    chains_dir: Path | str | None = None,
    modules_dir: Path | str | None = None,
) -> int:
    ctx = McpContext(home, workspace, users_path=users_path, token=token, actor=actor,
                     role=role, chains_dir=chains_dir, modules_dir=modules_dir)
    return serve(ctx)
