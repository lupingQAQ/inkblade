# -*- coding: utf-8 -*-
"""MCP Tasks / SEP-2640 / A2A protocol tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.agent.protocols import (A2AAgentCard, A2AClient, A2AServer, A2ASkill,
                                      MCPFederation, MCPTaskStore, MCPTool,
                                      MCPToolRegistry, ProtocolError, SkillPackage,
                                      TaskStateError)


class MCPTaskTest(unittest.TestCase):
    def test_lifecycle_and_invalid_transition(self):
        store = MCPTaskStore()
        task = store.create({"method": "scan"}, ttl_ms=1000)
        self.assertEqual(task["state"], "submitted")
        working = store.update(task["id"], "working", lease="w1")
        self.assertEqual(working["state"], "working")
        done = store.update(task["id"], "completed", result={"ok": True})
        self.assertEqual(done["state"], "completed")
        with self.assertRaises(TaskStateError):
            store.update(task["id"], "working")
        with self.assertRaises(ProtocolError):
            store.get("missing")

    def test_cancel_and_ttl(self):
        store = MCPTaskStore()
        task = store.create({"method": "scan"}, ttl_ms=10)
        canceled = store.cancel(task["id"], reason="operator")
        self.assertEqual(canceled["state"], "canceled")
        task2 = store.create({"method": "scan"}, ttl_ms=10)
        expired = store.expire(now=task2["created_at"] + 60)
        self.assertEqual(expired[0]["state"], "failed")

    def test_tool_registry_read_only_gate(self):
        registry = MCPToolRegistry()
        registry.register(MCPTool("recon", "list_assets", read_only=True))
        registry.register(MCPTool("exploit", "delete_pod", read_only=False))
        self.assertEqual(len(registry.discover(namespace="recon")), 1)
        self.assertEqual(len(registry.discover(read_only=False)), 1)
        with self.assertRaises(PermissionError):
            registry.call("exploit.delete_pod", {})
        self.assertTrue(registry.call("recon.list_assets", {})["ok"])

    def test_federation_discovery(self):
        fed = MCPFederation()
        fed.register_server("soc", tools=[MCPTool("soc", "get_findings", read_only=True)])
        self.assertIn("tools", fed.server_discover("soc")["capabilities"])
        self.assertEqual(len(fed.tool_search("findings", read_only=True)), 1)
        with self.assertRaises(ProtocolError):
            fed.server_discover("missing")


class SkillPackageTest(unittest.TestCase):
    def test_front_matter_and_progressive_disclosure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "references").mkdir()
            (root / "references" / "note.txt").write_text("details", encoding="utf-8")
            text = """---
name: rbac-recon
description: read-only RBAC map
version: 1.2.0
allowed-tools: [probe, report]
---
# Instructions
Run the probe template.
"""
            pkg = SkillPackage.from_text(text, root=root)
            self.assertEqual(pkg.name, "rbac-recon")
            self.assertEqual(pkg.version, "1.2.0")
            self.assertEqual(pkg.allowed_tools, ["probe", "report"])
            self.assertIn("Instructions", pkg.instructions())
            self.assertEqual(pkg.resource("references/note.txt"), b"details")
            self.assertEqual(len(pkg.digest), 64)
            pkg.validate_tools({"probe", "report"})
            with self.assertRaises(ProtocolError):
                pkg.validate_tools({"probe"})
            with self.assertRaises(ProtocolError):
                pkg.resource("../outside")

    def test_invalid_package(self):
        with self.assertRaises(ProtocolError):
            SkillPackage.from_text("---\ndescription: no name\n---\n")
        with self.assertRaises(ProtocolError):
            SkillPackage.from_text("---\nname: x\nversion: 1\n---\n")


class A2ATest(unittest.TestCase):
    def setUp(self):
        self.server = A2AServer(A2AAgentCard(
            name="inkblade-recon", description="read-only recon",
            skills=[A2ASkill("recon", "Recon", read_only=True),
                    A2ASkill("write", "Write", read_only=False)]))
        self.client = A2AClient(self.server)

    def test_card_and_read_only_delegation(self):
        card = self.client.card()
        self.assertEqual(card["name"], "inkblade-recon")
        self.assertEqual(len(card["skills"]), 2)
        task = self.client.send("recon", {"target": "lab"})
        self.assertEqual(task["state"], "completed")
        self.assertTrue(task["result"]["read_only"])

    def test_write_skill_rejected(self):
        task = self.client.server.handle("message/send", {"skill": "write", "input": {}})
        self.assertEqual(task["state"], "failed")
        self.assertIn("write skill", task["error"])
        with self.assertRaises(ProtocolError):
            self.client.send("unknown", {})

    def test_task_cancel_and_get(self):
        task = self.server.handle("message/send", {"skill": "recon", "input": {}})
        # completed tasks cannot be canceled; a fresh submitted task can.
        fresh = self.server.tasks.create({"skill": "recon"})
        canceled = self.server.tasks_cancel(fresh["id"], reason="stop")
        self.assertEqual(canceled["state"], "canceled")
        self.assertEqual(self.server.tasks_get(task["id"])["state"], "completed")
        with self.assertRaises(ProtocolError):
            self.server.handle("unknown/method", {})


if __name__ == "__main__":
    unittest.main()
