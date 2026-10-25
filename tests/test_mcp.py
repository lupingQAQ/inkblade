# -*- coding: utf-8 -*-
"""MCP 只读接口与 agent 规划器测试：工具集 / 授权锁 / 审批闸 / 只读性（零 actions 写行）。"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.agent_planner import plan_workspace, render_plan_md
from trident.core.chains import load_chains
from trident.core.evidence import EvidenceStore

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable
CHAIN_COUNT = len(load_chains(REPO / "trident" / "chains"))
VALID_TOOLS = {
    "list_runs", "get_findings", "get_chain_plan", "get_evidence_manifest", "validate_rules",
    # XBow 对标同步暴露（全部只读）：资产/审批队列/计划/流量/漂移
    "get_assets", "get_explorer_queue", "get_schedules", "get_traffic", "get_drift",
}


def _seed(store: EvidenceStore, name: str = "run-mcp"):
    store.pin_roe({"level": "只读侦察", "namespaces": ["ml-inference"],
                   "cidrs": ["127.0.0.1/32"], "operator": "unit-test"})
    run = store.create_run(name)
    art = store.root / "art.txt"
    art.write_text("mcp-evidence", encoding="utf-8")
    run.add_step("ray-control-plane", "curl http://127.0.0.1:8265", {}, "Ray 8265 无鉴权",
                 artifacts=[art])
    run.add_step("agent-platform-x", "GET /v1/workspaces", {}, "跨租户对象读取", artifacts=[art])
    archive = run.query("SELECT archive FROM steps")[0][0]
    run.add_finding("ray-control-plane", "high", "Ray Dashboard 未授权",
                    "8265 无鉴权可提交作业", evidence_path=archive)
    run.add_finding("agent-platform-x", "critical", "智能体平台跨租户读取",
                    "对象存储越权", evidence_path=archive, is_zeroday=True)
    run.finalize_run()
    return run


def _actions(store: EvidenceStore, run_name: str) -> int:
    run = store.open_run(run_name)
    return run.query("SELECT COUNT(*) FROM actions")[0][0]


class _Mcp:
    def __init__(self, home: Path, workspace: str = "local-lab", *extra: str):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        self.proc = subprocess.Popen(
            [PY, "-m", "trident", "--home", str(home), "mcp", "--workspace", workspace, *extra],
            cwd=str(REPO), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", bufsize=1, env=env,
        )
        self._id = 0

    def send(self, method: str, params: dict | None = None, *, notify: bool = False):
        assert self.proc.stdin is not None
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if not notify:
            self._id += 1
            payload["id"] = self._id
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP server closed stdout: "
                                   + (self.proc.stderr.read() if self.proc.stderr else ""))
            line = line.strip()
            if line:
                return json.loads(line)

    def call(self, name: str, arguments: dict | None = None):
        return self.send("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=15)
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream is not None:
                    stream.close()


class TestMcpServer(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        _seed(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _client(self):
        c = _Mcp(self.root)
        self.addCleanup(c.close)
        init = c.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "unit-test", "version": "1"}})
        self.assertIn("result", init, init)
        c.send("notifications/initialized", notify=True)
        return c

    def test_initialize_and_tool_list_read_only(self):
        c = self._client()
        resp = c.send("tools/list")
        tools = resp["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(names, VALID_TOOLS)
        for tool in tools:
            self.assertIn("description", tool)
            self.assertEqual(tool["inputSchema"]["type"], "object")
        blob = json.dumps(tools, ensure_ascii=False).lower()
        for banned in ("execute", "write", "delete", "rollback", "approve"):
            self.assertNotIn(f'"name": "{banned}', blob)
        self.assertEqual(c.send("ping")["result"], {})

    def test_discover_and_protocol_version_meta(self):
        c = _Mcp(self.root)
        self.addCleanup(c.close)
        disc = c.send("server/discover", {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "unit-test", "version": "1"},
        }})
        result = disc["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertIn("2026-07-28", result["supportedVersions"])
        self.assertIn("2025-06-18", result["supportedVersions"])
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "trident-mcp")

        listed = c.send("tools/list", {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28"}})
        self.assertEqual({t["name"] for t in listed["result"]["tools"]}, VALID_TOOLS)

        bad = c.send("tools/list", {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "1999-01-01"}})
        self.assertEqual(bad["error"]["code"], -32000)
        self.assertIn("2026-07-28", bad["error"]["data"]["supportedVersions"])

    def test_list_runs_and_findings(self):
        c = self._client()
        runs = c.call("list_runs")
        self.assertFalse(runs["result"]["isError"], runs)
        self.assertEqual(runs["result"]["structuredContent"]["runs"], ["run-mcp"])

        got = c.call("get_findings", {"run": "run-mcp"})
        body = got["result"]["structuredContent"]
        self.assertFalse(got["result"]["isError"])
        self.assertEqual(body["run"], "run-mcp")
        self.assertEqual(body["count"], 2)
        titles = {f["title"] for f in body["findings"]}
        self.assertIn("Ray Dashboard 未授权", titles)
        self.assertTrue(any(f["is_zeroday"] for f in body["findings"]))

    def test_evidence_manifest(self):
        c = self._client()
        resp = c.call("get_evidence_manifest", {"run": "run-mcp"})
        body = resp["result"]["structuredContent"]
        self.assertTrue(body["verified"])
        self.assertEqual(len(body["entries"]), 2)
        for entry in body["entries"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(body["layers"]["context"].endswith("context.jsonl.gz"))
        self.assertTrue(body["layers"]["sqlite"].endswith("evidence.db"))

    def test_chain_plan_is_plan_only(self):
        c = self._client()
        resp = c.call("get_chain_plan",
                      {"chain": "agent-platform-zero-precondition-lateral", "run": "run-mcp"})
        body = resp["result"]["structuredContent"]
        self.assertEqual(body["chain"]["id"], "agent-platform-zero-precondition-lateral")
        self.assertEqual(body["plan"]["verdict"], "成立")
        self.assertTrue(body["approval"]["required"])
        self.assertEqual(body["approval"]["approver_role"], "lead")
        self.assertEqual(body["approval"]["status"], "pending")
        self.assertEqual(body["execution"]["trigger"], "human")
        self.assertFalse(body["execution"]["performed"])

    def test_validate_rules_minimal_pack(self):
        pack = self.root / "pack"
        (pack / "sigma").mkdir(parents=True)
        (pack / "sigma" / "x.yaml").write_text("title: x\n", encoding="utf-8")
        mapping = {
            "rules": [{"id": "r1", "engines": ["sigma"], "files": ["sigma/x.yaml"],
                       "blocks_chains": ["c1"]}],
            "chains": {"c1": {"category": "经典攻击链", "rules": ["r1"], "modules": []}},
        }
        (pack / "mapping.json").write_text(json.dumps(mapping), encoding="utf-8")
        c = self._client()
        resp = c.call("validate_rules", {"pack_dir": "pack"})
        body = resp["result"]["structuredContent"]
        self.assertFalse(resp["result"]["isError"], body)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["rules"], 1)
        self.assertEqual(body["chains"], 1)

        (pack / "sigma" / "x.yaml").unlink()
        resp = c.call("validate_rules", {"pack_dir": "pack"})
        body = resp["result"]["structuredContent"]
        self.assertFalse(body["ok"])
        self.assertTrue(body["missing_files"])

    def test_write_tool_not_exposed(self):
        c = self._client()
        for name in ("execute", "run_chain", "write_action", "delete_run"):
            resp = c.call(name)
            self.assertIn("error", resp, resp)
            self.assertEqual(resp["error"]["code"], -32602)

    def test_authorization_lock_reused(self):
        with TemporaryDirectory() as tmp:
            locked = Path(tmp)
            store = EvidenceStore(locked, workspace="local-lab")  # 无 consent
            run = store.create_run("run-locked")
            run.add_step("s", "cmd", {}, "ok")
            run.finalize_run()
            c = _Mcp(locked)
            self.addCleanup(c.close)
            c.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "1"}})
            resp = c.call("list_runs")
            self.assertIn("error", resp, resp)
            self.assertEqual(resp["error"]["code"], -32002)
            self.assertIn("授权", resp["error"]["message"])

    def test_calls_do_not_write_actions(self):
        c = self._client()
        before = _actions(self.store, "run-mcp")
        for name, args in (
            ("list_runs", {}),
            ("get_findings", {"run": "run-mcp"}),
            ("get_evidence_manifest", {"run": "run-mcp"}),
            ("get_chain_plan", {"chain": "ray-dashboard-cluster-takeover", "run": "run-mcp"}),
        ):
            resp = c.call(name, args)
            self.assertIn("result", resp, resp)
        after = _actions(self.store, "run-mcp")
        self.assertEqual(before, after, "MCP 只读调用产生了 actions 写行")


class TestPlanner(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        _seed(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_ranks_and_requires_lead(self):
        before = _actions(self.store, "run-mcp")
        result = plan_workspace(self.store, run="run-mcp")
        after = _actions(self.store, "run-mcp")
        self.assertEqual(before, after, "规划器写入了 actions 行")
        self.assertTrue(result["read_only"])
        self.assertEqual(result["workspace"], "local-lab")
        self.assertEqual(result["run"], "run-mcp")
        self.assertEqual(result["approval"]["required"], True)
        self.assertEqual(result["approval"]["approver_role"], "lead")
        self.assertEqual(result["approval"]["status"], "pending")
        self.assertEqual(result["execution"]["trigger"], "human")
        self.assertFalse(result["execution"]["performed"])
        self.assertEqual(len(result["candidates"]), CHAIN_COUNT)
        self.assertEqual(result["candidates"][0]["chain"],
                         "agent-platform-zero-precondition-lateral")
        self.assertEqual(result["candidates"][0]["verdict"], "成立")
        for cand in result["candidates"]:
            self.assertIn(cand["verdict"], ("成立", "部分成立", "不成立"))
            self.assertTrue(cand["reasons"]["zh"] and cand["reasons"]["en"])
            self.assertNotIn("execute", cand.get("execution", {}))
            self.assertFalse(cand["execution"]["performed"])

    def test_plan_no_new_runs(self):
        runs_before = sorted(p.name for p in self.store.ws_dir.iterdir() if p.is_dir())
        plan_workspace(self.store, run="run-mcp")
        runs_after = sorted(p.name for p in self.store.ws_dir.iterdir() if p.is_dir())
        self.assertEqual(runs_before, runs_after)

    def test_plan_markdown(self):
        result = plan_workspace(self.store, run="run-mcp")
        md = render_plan_md(result)
        self.assertIn("lead", md)
        self.assertIn("agent-platform-zero-precondition-lateral", md)
        self.assertIn("只读", md)

    def test_plan_unknown_run(self):
        with self.assertRaises(KeyError):
            plan_workspace(self.store, run="no-such-run")

    def test_cli_plan_json(self):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [PY, "-m", "trident", "--home", str(self.root), "plan", "--workspace", "local-lab",
             "--run", "run-mcp", "--format", "json"],
            cwd=str(REPO), capture_output=True, timeout=60, env=env,
        )
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        data = json.loads(r.stdout.decode("utf-8"))
        self.assertEqual(data["schema"], "trident-agent-plan-v1")
        self.assertEqual(data["approval"]["approver_role"], "lead")
        self.assertEqual(len(data["candidates"]), CHAIN_COUNT)


if __name__ == "__main__":
    unittest.main()
