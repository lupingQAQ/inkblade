# -*- coding: utf-8 -*-
"""A2A 服务端（agent card + task 状态机，只读委派）+ MCP 客户端（消费外部只读工具）。

A2A 侧：
- ``agent_card``：schema/version/url/capabilities/skills（每项标注 read_only）；
- 任务状态机：submitted → working → completed / failed；submitted|working → canceled；
  写操作或未知技能 **直接 rejected**（绝不进入 working，更不执行）；
- 内置只读技能：list_runs / get_findings / get_chain_plan / get_agent_card / search_skills。

MCP 客户端侧：
- stdio JSON-RPC（initialize/tools/list/tools/call）；
- 只读判定：``annotations.readOnlyHint == True``，缺省时按名称前缀
  （get_/list_/read_/search_/describe_/show_）兜底；显式 False 或未知工具一律拒绝。
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

AGENT_CARD_SCHEMA = "inkblade-a2a-agent-card-v1"
TASKS_RELPATH = "a2a/tasks.json"
READ_PREFIXES = ("get_", "list_", "read_", "search_", "describe_", "show_")

READ_ONLY_SKILLS = {
    "list_runs": {
        "name": "list_runs", "description": "列出工作区内的 run（名称/步骤/发现计数）",
        "tags": ["read", "evidence"], "read_only": True,
    },
    "get_findings": {
        "name": "get_findings", "description": "读取指定 run 的 findings（参数 run）",
        "tags": ["read", "findings"], "read_only": True,
    },
    "get_chain_plan": {
        "name": "get_chain_plan", "description": "返回链 dry-run 计划（参数 chain）",
        "tags": ["read", "plan"], "read_only": True,
    },
    "get_agent_card": {
        "name": "get_agent_card", "description": "返回 A2A agent card",
        "tags": ["read", "meta"], "read_only": True,
    },
    "search_skills": {
        "name": "search_skills", "description": "检索已批准技能（参数 query）",
        "tags": ["read", "skills"], "read_only": True,
    },
}


class A2AError(ValueError):
    """任务状态机/协议错误。"""


class A2AForbidden(PermissionError):
    """只读边界拒绝（写技能/写工具）。"""


def _skill_card(skill_id: str, spec: dict | None = None) -> dict:
    spec = spec or READ_ONLY_SKILLS[skill_id]
    return {
        "id": skill_id,
        "name": spec.get("name", skill_id),
        "description": spec.get("description", ""),
        "tags": list(spec.get("tags") or []),
        "read_only": bool(spec.get("read_only", True)),
        "examples": spec.get("examples") or [],
    }


def agent_card(*, url: str = "http://127.0.0.1:0/a2a", skills=None) -> dict:
    cards = [_skill_card(key) for key in READ_ONLY_SKILLS]
    if skills is not None:
        try:
            for skill in skills.search(""):
                cards.append({
                    "id": f"skill:{skill['id']}",
                    "name": skill["name"],
                    "description": "已批准技能（仅提案复用，执行仍需逐动作审批）",
                    "tags": ["skill", "approved"],
                    "read_only": True,
                    "examples": [],
                })
        except Exception:
            pass
    return {
        "schema": AGENT_CARD_SCHEMA,
        "name": "inkblade",
        "description": "Authorized ML-cluster pentest control plane (read-only delegation)",
        "version": "2026.10",
        "url": url,
        "protocolVersion": "2026-07-28",
        "capabilities": {"streaming": False, "pushNotifications": False,
                         "stateTransitionHistory": True},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": cards,
    }


class A2AServer:
    def __init__(self, store, *, skills=None, chains_dir: Path | str | None = None,
                 modules_dir: Path | str | None = None):
        self.store = store
        self.skills = skills
        self.chains_dir = Path(chains_dir) if chains_dir else \
            Path(__file__).resolve().parent.parent / "chains"
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        self.path = Path(store.ws_dir) / TASKS_RELPATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- 持久化
    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return list(json.loads(self.path.read_text(encoding="utf-8")))
        except ValueError:
            return []

    def _save(self, items: list[dict]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    # ---------------------------------------------------------------- 提交/查询
    def submit(self, skill: str, params: dict | None = None) -> dict:
        task = {
            "id": f"a2a-{time.strftime('%Y%m%d-%H%M%S')}-{len(self._load()) + 1:03d}",
            "skill": skill,
            "params": dict(params or {}),
            "status": "submitted",
            "error": "",
            "result": None,
            "created_at": time.time(),
            "updated_at": time.time(),
            "history": [{"status": "submitted", "at": time.time()}],
        }
        if skill not in READ_ONLY_SKILLS:
            task["status"] = "rejected"
            task["error"] = f"read-only delegation only: 未知技能 {skill!r}"
            task["history"].append({"status": "rejected", "at": time.time()})
            items = self._load()
            items.append(task)
            self._save(items)
            return _copy(task)
        items = self._load()
        items.append(task)
        self._save(items)
        return _copy(task)

    def get(self, task_id: str) -> dict:
        for task in self._load():
            if task["id"] == task_id:
                return _copy(task)
        raise A2AError(f"未知任务 {task_id}")

    def list_tasks(self) -> list[dict]:
        return [_copy(t) for t in self._load()]

    def cancel(self, task_id: str) -> dict:
        items = self._load()
        task = next((t for t in items if t["id"] == task_id), None)
        if task is None:
            raise A2AError(f"未知任务 {task_id}")
        if task["status"] not in ("submitted", "working"):
            raise A2AError(f"任务 {task_id} 状态 {task['status']}，不可取消")
        task["status"] = "canceled"
        task["updated_at"] = time.time()
        task["history"].append({"status": "canceled", "at": time.time()})
        self._save(items)
        return _copy(task)

    # ---------------------------------------------------------------- 执行（只读）
    def run_task(self, task_id: str) -> dict:
        items = self._load()
        task = next((t for t in items if t["id"] == task_id), None)
        if task is None:
            raise A2AError(f"未知任务 {task_id}")
        if task["status"] != "submitted":
            raise A2AError(f"任务 {task_id} 状态 {task['status']}，仅 submitted 可执行")
        task["status"] = "working"
        task["updated_at"] = time.time()
        task["history"].append({"status": "working", "at": time.time()})
        self._save(items)
        try:
            result = self._dispatch(task["skill"], task.get("params") or {})
        except Exception as exc:  # 只读委派失败 → failed（保留错误，不重试写操作）
            task["status"] = "failed"
            task["error"] = f"{type(exc).__name__}: {exc}"
        else:
            task["status"] = "completed"
            task["result"] = result
        task["updated_at"] = time.time()
        task["history"].append({"status": task["status"], "at": time.time()})
        self._save(items)
        return _copy(task)

    # ---------------------------------------------------------------- handlers
    def _dispatch(self, skill: str, params: dict):
        if skill == "list_runs":
            return {"runs": self._list_runs()}
        if skill == "get_findings":
            run_name = params.get("run")
            if not run_name:
                raise A2AError("get_findings 需要 run 参数")
            run = self.store.open_run(run_name)
            findings = run.findings
            return {"run": run_name, "count": len(findings), "findings": findings}
        if skill == "get_chain_plan":
            chain_id = params.get("chain")
            if not chain_id:
                raise A2AError("get_chain_plan 需要 chain 参数")
            from .chains import dry_run, load_chains

            chains = load_chains(self.chains_dir)
            if chain_id not in chains:
                raise A2AError(f"未知链 {chain_id}")
            findings: list[dict] = []
            for run in self._list_runs():
                if run.get("findings"):
                    try:
                        findings = self.store.open_run(run["name"]).findings
                    except KeyError:
                        findings = []
                    break
            return dry_run(chains[chain_id], findings,
                           self.modules_dir if self.modules_dir.exists() else None)
        if skill == "get_agent_card":
            return agent_card(skills=self.skills)
        if skill == "search_skills":
            if self.skills is None:
                return {"skills": []}
            return {"skills": self.skills.search(str(params.get("query") or ""))}
        raise A2AForbidden(f"read-only delegation only: 未知技能 {skill!r}")

    def _list_runs(self) -> list[dict]:
        from .explorer import _runs

        out = []
        for name in _runs(self.store):
            try:
                run = self.store.open_run(name)
                steps = run.query("SELECT COUNT(*) FROM steps")[0][0]
                findings = len(run.findings)
            except Exception:
                continue
            out.append({"name": name, "steps": int(steps), "findings": findings})
        return out


def _copy(value: dict) -> dict:
    return json.loads(json.dumps(value, ensure_ascii=False))


# ---------------------------------------------------------------- MCP 客户端
class MCPClient:
    """stdio JSON-RPC MCP 客户端（只读工具消费方）。"""

    def __init__(self, command: list[str], *, env: dict | None = None, timeout: float = 10):
        if not command:
            raise A2AError("MCP command 为空")
        self.command = list(command)
        self.timeout = float(timeout)
        self._id = 0
        self._tools: list[dict] | None = None
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
            bufsize=1,
        )

    # ---------- 协议 ----------
    def _request(self, method: str, params: dict | None = None) -> dict:
        if self._proc.poll() is not None:
            raise A2AError("MCP 子进程已退出")
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise A2AError(f"MCP 无响应（{method}）")
        payload = json.loads(line)
        if "error" in payload:
            raise A2AError(f"MCP 错误 {payload['error']}")
        return payload.get("result") or {}

    def initialize(self) -> dict:
        result = self._request("initialize", {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "inkblade", "version": "2026.10"},
        })
        return result

    def list_tools(self) -> list[dict]:
        result = self._request("tools/list", {})
        self._tools = list(result.get("tools") or [])
        return self._tools

    # ---------- 只读边界 ----------
    @staticmethod
    def is_read_only(tool: dict) -> bool:
        annotations = tool.get("annotations") or {}
        if annotations.get("readOnlyHint") is True:
            return True
        if annotations.get("readOnlyHint") is False:
            return False
        name = str(tool.get("name", "")).lower()
        return name.startswith(READ_PREFIXES)

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        if self._tools is None:
            self.list_tools()
        tool = next((t for t in (self._tools or []) if t.get("name") == name), None)
        if tool is None:
            raise A2AForbidden(f"read-only delegation only: 未知工具 {name!r}")
        if not self.is_read_only(tool):
            raise A2AForbidden(f"read-only delegation only: 工具 {name!r} 非只读")
        return self._request("tools/call", {"name": name, "arguments": dict(arguments or {})})

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            try:
                if stream is not None and not stream.closed:
                    stream.close()
            except Exception:
                pass
