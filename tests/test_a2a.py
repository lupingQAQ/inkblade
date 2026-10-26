"""tests/test_a2a.py — A2A 服务端（agent card + task 状态机，只读委派）+ MCP 客户端（只读外部工具）。

断言：
- agent card 结构（schema/version/skills/read_only 标记）；
- 只读技能任务：submitted → working → completed，结果含数据；
- 写操作/未知技能被拒（rejected），绝不进入 working；
- cancel 状态机合法（submitted/working 可取消，completed 不可）；
- MCP 客户端 initialize/tools/list/call；写工具与未知工具拒绝。
"""

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.a2a import (
    AGENT_CARD_SCHEMA,
    A2AError,
    A2AForbidden,
    A2AServer,
    MCPClient,
    agent_card,
)
from inkblade.core.evidence import EvidenceStore
from inkblade.core.skills import SkillLibrary
from inkblade.core.users import Session


class A2AServerTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        run = self.store.create_run("run-a2a")
        run.add_finding("exposure-mapping", "high", "Ray 暴露", "LoadBalancer")
        self.server = A2AServer(self.store)
        self.tester = Session(None, "tester", "tester", ["local-lab"], "t")

    def tearDown(self):
        self.td.cleanup()

    def test_agent_card(self):
        card = agent_card(url="http://127.0.0.1:9000/a2a")
        self.assertEqual(card["schema"], AGENT_CARD_SCHEMA)
        self.assertIn("capabilities", card)
        self.assertTrue(card["skills"])
        for skill in card["skills"]:
            self.assertTrue(skill["id"] and skill["name"])
            self.assertTrue(skill["read_only"])
        self.assertIn("http://127.0.0.1:9000/a2a", json.dumps(card))

    def test_read_only_task_state_machine(self):
        task = self.server.submit("list_runs")
        self.assertEqual(task["status"], "submitted")
        self.assertEqual(self.server.get(task["id"])["status"], "submitted")
        done = self.server.run_task(task["id"])
        self.assertEqual(done["status"], "completed")
        self.assertTrue(done["result"]["runs"])
        self.assertIn("run-a2a", [r["name"] for r in done["result"]["runs"]])
        with self.assertRaises(A2AError):
            self.server.run_task(task["id"])  # 终态不可重跑

    def test_get_findings_task(self):
        task = self.server.submit("get_findings", {"run": "run-a2a"})
        done = self.server.run_task(task["id"])
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["result"]["count"], 1)

    def test_write_skill_rejected(self):
        for skill in ("execute_module", "run_chain", "delete_run", "sudo"):
            task = self.server.submit(skill)
            self.assertEqual(task["status"], "rejected", skill)
            self.assertIn("read-only", task["error"])

    def test_cancel_rules(self):
        task = self.server.submit("list_runs")
        canceled = self.server.cancel(task["id"])
        self.assertEqual(canceled["status"], "canceled")
        with self.assertRaises(A2AError):
            self.server.run_task(task["id"])
        done = self.server.run_task(self.server.submit("list_runs")["id"])
        with self.assertRaises(A2AError):
            self.server.cancel(done["id"])

    def test_agent_card_includes_approved_skills(self):
        lib = SkillLibrary(self.store)
        run = self.store.create_run("run-skill")
        run.add_step("exposure-mapping", "snapshot", {}, "x")
        pending = lib.submit(self.tester, lib.extract(run, name="recon-playbook"))
        lib.approve(Session(None, "lead", "lead", ["local-lab"], "t"), pending["id"])
        card = agent_card(url="http://x/a2a", skills=lib)
        ids = {s["id"] for s in card["skills"]}
        self.assertIn("skill:" + pending["id"], ids)


FAKE_MCP = r'''
import json, sys
TOOLS = [
    {"name": "get_runs", "description": "list runs", "inputSchema": {}, "annotations": {"readOnlyHint": True}},
    {"name": "delete_run", "description": "delete", "inputSchema": {}, "annotations": {"readOnlyHint": False}},
    {"name": "list_findings", "description": "list", "inputSchema": {}},
]
for line in sys.stdin:
    if not line.strip():
        continue
    req = json.loads(line)
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        result = {"protocolVersion": "2026-07-28", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-mcp", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = req.get("params", {}).get("name")
        if name == "get_runs":
            result = {"content": [{"type": "text", "text": "run-a2a"}], "isError": False}
        elif name == "list_findings":
            result = {"content": [{"type": "text", "text": "1 finding"}], "isError": False}
        else:
            result = {"content": [{"type": "text", "text": "denied"}], "isError": True}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": rid,
                          "error": {"code": -32601, "message": "unknown"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)
'''


class MCPClientTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        script = Path(self.td.name) / "fake_mcp.py"
        script.write_text(FAKE_MCP, encoding="utf-8")
        self.client = MCPClient([sys.executable, "-I", str(script)], timeout=10)

    def tearDown(self):
        self.client.close()
        self.td.cleanup()

    def test_initialize_and_list(self):
        info = self.client.initialize()
        self.assertEqual(info["serverInfo"]["name"], "fake-mcp")
        tools = self.client.list_tools()
        self.assertEqual(len(tools), 3)
        self.assertTrue(self.client.is_read_only(tools[0]))
        self.assertFalse(self.client.is_read_only(tools[1]))
        self.assertTrue(self.client.is_read_only(tools[2]))  # list_ 前缀兜底

    def test_call_read_only_tool(self):
        self.client.initialize()
        result = self.client.call_tool("get_runs")
        self.assertIn("run-a2a", json.dumps(result))

    def test_write_and_unknown_tools_denied(self):
        self.client.initialize()
        with self.assertRaises(A2AForbidden):
            self.client.call_tool("delete_run")
        with self.assertRaises(A2AForbidden):
            self.client.call_tool("no_such_tool")


if __name__ == "__main__":
    unittest.main()
