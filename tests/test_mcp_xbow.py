# -*- coding: utf-8 -*-
"""MCP 同步暴露（A⑥）测试：5 个新只读工具 + 授权锁 + 零写断言。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import Explorer
from inkblade.core.roe import init_roe
from inkblade.core.scheduler import Scheduler
from inkblade.core.users import Session
from inkblade.mcp_server import TOOLS, McpContext, dispatch

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"
SEEDS = {"services": [{"name": "sglang-admin", "namespace": "ml", "addr": "127.0.0.1",
                       "port": 30000, "labels": {"app": "sglang"}}]}


def _msg(msg_id, method, params=None):
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}


def _session(role="lead"):
    return Session(None, "mcp-test", role, ["local-lab"], "t")


class TestToolsList(unittest.TestCase):
    def test_ten_tools_registered(self):
        names = {t["name"] for t in TOOLS}
        self.assertEqual(names, {
            "list_runs", "get_findings", "get_chain_plan", "get_evidence_manifest",
            "validate_rules", "get_assets", "get_explorer_queue", "get_schedules",
            "get_traffic", "get_drift",
        })
        for t in TOOLS:
            if t["name"].startswith("get_") and t["name"] not in ("get_findings", "get_chain_plan"):
                self.assertTrue(t["description"].endswith("Read-only."), t["name"])


class TestReadOnlyTools(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"], "cidrs": ["127.0.0.0/8"]})
        AssetInventory(self.store).ingest(SEEDS, source="seed")
        Explorer(self.store, modules_dir=MODULES_DIR).propose(_session())
        Scheduler(self.store, modules_dir=MODULES_DIR).add(
            _session(), interval_seconds=60, chains=["demo"])
        run = self.store.create_run("mcp-run")
        run.record_traffic("m", [{"method": "GET", "url": "http://x/", "headers": {},
                                  "status": 200, "ts": 1.0}])
        (Path(run.dir) / "drift.json").write_text(
            json.dumps({"schedule": "s", "counts": {"new": 1, "fixed": 0, "unchanged": 2}}),
            encoding="utf-8")
        self.ctx = McpContext(self.root, "local-lab", modules_dir=MODULES_DIR)

    def tearDown(self):
        self.tmp.cleanup()

    def test_get_assets(self):
        out = self.ctx.get_assets({})
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["assets"][0]["product"], "sglang")
        filtered = self.ctx.get_assets({"product": "vllm"})
        self.assertEqual(filtered["count"], 0)

    def test_get_explorer_queue(self):
        out = self.ctx.get_explorer_queue({})
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["proposals"][0]["status"], "pending_approval")

    def test_get_schedules(self):
        out = self.ctx.get_schedules({})
        self.assertEqual(len(out["schedules"]), 1)
        self.assertIn("due", out)

    def test_get_traffic(self):
        out = self.ctx.get_traffic({"run": "mcp-run"})
        self.assertEqual(out["count"], 1)
        self.assertTrue(out["entries"][0]["sha256"])
        with self.assertRaises(Exception):
            self.ctx.get_traffic({})
        with self.assertRaises(Exception):
            self.ctx.get_traffic({"run": "no-such"})

    def test_get_drift(self):
        out = self.ctx.get_drift({"run": "mcp-run"})
        self.assertEqual(out["drift"]["counts"]["new"], 1)
        # 无 drift 的 run → ToolError（get_drift 只读，不产生 drift）
        driftless = self.store.create_run("mcp-run-plain")
        with self.assertRaises(Exception):
            self.ctx.get_drift({"run": driftless.name})

    def test_dispatch_wiring(self):
        reply = dispatch(self.ctx, _msg(9, "tools/call", {
            "name": "get_assets", "arguments": {}}))
        payload = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(payload["count"], 1)
        # 未知工具 → -32602
        reply = dispatch(self.ctx, _msg(10, "tools/call", {"name": "execute_chain"}))
        self.assertEqual(reply["error"]["code"], -32602)

    def test_actions_table_stays_write_free(self):
        self.ctx.get_assets({})
        self.ctx.get_explorer_queue({})
        self.ctx.get_schedules({})
        self.ctx.get_traffic({"run": "mcp-run"})
        self.ctx.get_drift({"run": "mcp-run"})
        runs = [p.name for p in self.store.ws_dir.iterdir()
                if p.is_dir() and (p / "evidence.db").is_file()]
        for r in runs:
            rows = self.store.open_run(r).query("SELECT COUNT(*) FROM actions")
            self.assertEqual(rows[0][0], 0, f"MCP 工具写入了 actions（{r}）")


class TestAuthLock(unittest.TestCase):
    def test_locked_workspace_rejects_new_tools(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            EvidenceStore(root, workspace="locked")
            ctx = McpContext(root, "locked", modules_dir=MODULES_DIR)
            for name, args in (("get_assets", {}), ("get_explorer_queue", {}),
                               ("get_schedules", {}), ("get_traffic", {"run": "x"}),
                               ("get_drift", {})):
                reply = dispatch(ctx, _msg(1, "tools/call", {"name": name, "arguments": args}))
                self.assertEqual(reply["error"]["code"], -32002, name)


if __name__ == "__main__":
    unittest.main()
