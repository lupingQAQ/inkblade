"""tests/test_artex_same_target.py — ARTEX 同靶场扫描对标的证据结构断言。

两个部分：
1. scripted-planner 决策逻辑（lab/qemu-k3s/artex-mock-llm.py 的 scripted_reply）
   —— 用按 ARTEX v0.3.23 源码协议构造的请求体驱动：goals 拆解 → planner
   add_intent/prove_goal → worker 探测/上报/收尾，含 runner 降级。
2. 对标产物结构（reports/samples/artex-bench/same-target.json）
   —— 证据字段齐全、数值关系成立；数据一律从文件读取，不硬编码实测值。
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MOCK_LLM = REPO / "lab" / "qemu-k3s" / "artex-mock-llm.py"
RESULT = REPO / "reports" / "samples" / "artex-bench" / "same-target.json"


def _load_mock():
    spec = importlib.util.spec_from_file_location("artex_mock_llm", MOCK_LLM)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CFG = {"target_url": "http://10.0.2.2:18080"}


def _req(tools, messages):
    return {
        "model": "mock-agent-model",
        "stream": True,
        "tools": [{"type": "function",
                   "function": {"name": t, "parameters": {"type": "object", "properties": {}}}}
                  for t in tools],
        "messages": messages,
    }


GOALS_TOOLS = ["set_goals", "set_constraints", "add_task_scope"]
PLANNER_TOOLS = ["graph_overview", "list_findings", "list_facts", "node_detail", "list_goals",
                 "add_intent", "prove_goal", "kill_work", "Bash", "Read", "Write", "TodoWrite"]
WORKER_TOOLS = ["graph_overview", "record_fact", "report_finding", "insert_assets",
                "Bash", "Read", "Write", "Edit", "LS", "Sleep", "TodoWrite", "WebFetch"]

OVERVIEW_EMPTY = ('{"goals":[{"id":2,"state":"open","text":"Probe the target"}],'
                  '"open_intents":[],"running_intents":[],"frontier_open":0,'
                  '"findings_total":0,"finding_list":[],"recent_facts":[]}')
OVERVIEW_FINDING = ('{"goals":[{"id":2,"state":"open","text":"Probe the target"}],'
                    '"open_intents":[],"running_intents":[],"frontier_open":0,'
                    '"findings_total":1,"finding_list":[{"from_intent":3,"id":9,'
                    '"summary":"Lab target unauthenticated admin plane and weight pull"}],'
                    '"recent_facts":[]}')


class ScriptedPlannerTest(unittest.TestCase):
    """mock LLM 的脚本化决策：按 ARTEX 真实协议返回确定的 tool_calls 序列。"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_mock()

    def test_classify_agent_by_toolset(self):
        f = self.mod.classify_agent
        self.assertEqual(f(GOALS_TOOLS), "goals")
        self.assertEqual(f(PLANNER_TOOLS), "planner")
        self.assertEqual(f(WORKER_TOOLS), "worker")
        self.assertEqual(f(["update_finding_report", "Bash"]), "other")

    def test_goals_agent_creates_real_goal_then_stops(self):
        r0 = self.mod.scripted_reply(_req(GOALS_TOOLS, [
            {"role": "system", "content": "goals decomposer"},
            {"role": "user", "content": "task"}]), CFG)
        self.assertEqual(r0["kind"], "tool")
        self.assertEqual(r0["name"], "set_goals")
        self.assertTrue(r0["args"]["goals"][0]["text"].strip())
        r1 = self.mod.scripted_reply(_req(GOALS_TOOLS, [
            {"role": "system", "content": "s"}, {"role": "user", "content": "u"},
            {"role": "assistant", "tool_calls": [{"id": "1", "function": {"name": "set_goals", "arguments": "{}"}}]},
            {"role": "tool", "content": "goal added: 2"},
            {"role": "user", "content": "continue"}]), CFG)
        self.assertEqual(r1["kind"], "text")

    def test_planner_adds_intent_when_frontier_empty(self):
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, [
            {"role": "system", "content": "planner"},
            {"role": "user", "content": "wake\n" + OVERVIEW_EMPTY}]), CFG)
        self.assertEqual((r["kind"], r["name"]), ("tool", "add_intent"))
        self.assertTrue(r["args"]["intents"])
        self.assertIn(CFG["target_url"], r["args"]["intents"][0]["summary"])

    def test_planner_proves_goal_from_prefetched_finding(self):
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, [
            {"role": "system", "content": "planner"},
            {"role": "user", "content": "wake\n" + OVERVIEW_FINDING}]), CFG)
        self.assertEqual((r["kind"], r["name"]), ("tool", "prove_goal"))
        self.assertEqual(r["args"]["goal_id"], 2)
        self.assertEqual(r["args"]["evidence_id"], 9)

    def test_planner_waits_when_work_in_flight(self):
        overview = OVERVIEW_EMPTY.replace('"running_intents":[]', '"running_intents":[{"id":3}]')
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, [
            {"role": "system", "content": "planner"},
            {"role": "user", "content": "wake\n" + overview}]), CFG)
        self.assertEqual(r["kind"], "text")

    def test_planner_dispatches_only_once_per_conversation(self):
        """ARTEX 只在每次 Plan() 的首条 user 消息注入态势 → 同一会话内派过意图必须停。"""
        msgs = [{"role": "system", "content": "planner"},
                {"role": "user", "content": "wake\n" + OVERVIEW_EMPTY},
                {"role": "assistant", "tool_calls": [{"id": "1", "function": {"name": "add_intent", "arguments": "{}"}}]},
                {"role": "tool", "content": "intent created: 12"}]
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, msgs), CFG)
        self.assertEqual(r["kind"], "text", "派发过一次后必须等待下次唤醒，禁止意图工厂循环")

    def test_planner_proves_only_once_and_caps_turns(self):
        msgs = [{"role": "system", "content": "planner"},
                {"role": "user", "content": "wake\n" + OVERVIEW_FINDING},
                {"role": "assistant", "tool_calls": [{"id": "1", "function": {"name": "prove_goal", "arguments": "{}"}}]},
                {"role": "tool", "content": "goal 2 marked met"}]
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, msgs), CFG)
        self.assertEqual(r["kind"], "text")
        # 会话超过 4 轮 → 无论态势如何都收口（防死循环兜底）
        for i in range(2, 6):
            msgs += [{"role": "assistant", "tool_calls": [{"id": f"{i}", "function": {"name": "graph_overview", "arguments": "{}"}}]},
                     {"role": "tool", "content": "{}"}]
        r = self.mod.scripted_reply(_req(PLANNER_TOOLS, msgs), CFG)
        self.assertEqual(r["kind"], "text")

    def test_worker_probe_sequence_and_finding(self):
        sys_msg = {"role": "system", "content":
                   "worker\n【你领到的意图】：probe\n意图 id: 7（写回 record_fact / report_finding 时传它）"}
        msgs = [sys_msg, {"role": "user", "content": "overview"}]
        # 3 sequential probes: routes manifest → /pause → /pull_weights
        seen_urls = []
        for want in ("/__routes__", "/pause", "/pull_weights"):
            r = self.mod.scripted_reply(_req(WORKER_TOOLS, msgs), CFG)
            self.assertEqual((r["kind"], r["name"]), ("tool", "Bash"), r)
            url = [u for u in (want,) if u in r["args"]["command"]]
            self.assertEqual(url, [want], r["args"]["command"])
            seen_urls.append(want)
            msgs += [{"role": "assistant",
                      "tool_calls": [{"id": f"c{len(seen_urls)}", "function": {"name": "Bash", "arguments": "{}"}}]},
                     {"role": "tool", "content": '{"ok":true}\n[HTTP 200]'}]
        # 4th turn: report_finding quoting the real probe outputs as evidence
        r = self.mod.scripted_reply(_req(WORKER_TOOLS, msgs), CFG)
        self.assertEqual((r["kind"], r["name"]), ("tool", "report_finding"), r)
        self.assertEqual(r["args"]["intent_id"], 7)
        self.assertIn("[HTTP 200]", r["args"]["evidence"])
        # after the finding is recorded, stop with plain text
        msgs += [{"role": "assistant",
                  "tool_calls": [{"id": "cf", "function": {"name": "report_finding", "arguments": "{}"}}]},
                 {"role": "tool", "content": "finding recorded: 9\n{}"}]
        r = self.mod.scripted_reply(_req(WORKER_TOOLS, msgs), CFG)
        self.assertEqual(r["kind"], "text")

    def test_worker_runner_fallback_curl_to_wget(self):
        msgs = [{"role": "system", "content": "意图 id: 7"}, {"role": "user", "content": "ov"},
                {"role": "assistant", "tool_calls": [{"id": "a", "function": {"name": "Bash", "arguments": "{}"}}]},
                {"role": "tool", "content": "curl: not found\nexit code 127"}]
        r = self.mod.scripted_reply(_req(WORKER_TOOLS, msgs), CFG)
        self.assertEqual(r["name"], "Bash")
        self.assertIn("wget", r["args"]["command"])
        self.assertIn("/__routes__", r["args"]["command"])

    def test_unknown_agent_gets_stop_text(self):
        r = self.mod.scripted_reply(_req(["update_finding_report", "Bash"], [
            {"role": "system", "content": "s"}, {"role": "user", "content": "u"}]), CFG)
        self.assertEqual(r["kind"], "text")


class SameTargetResultTest(unittest.TestCase):
    """reports/samples/artex-bench/same-target.json 的证据结构（数据全部读自文件）。"""

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(RESULT.read_text(encoding="utf-8"))

    def test_artex_side_hit_the_target(self):
        artex = self.data["artex"]
        self.assertGreaterEqual(artex["target_hit_count"], 3, "ARTEX worker 未打到靶场 ≥3 次")
        paths = {h["path"] for h in artex["target_hits"]}
        self.assertIn("/pause", paths, "ARTEX 未触碰管理面 fail-open 面")
        self.assertIn("/pull_weights", paths, "ARTEX 未触碰权重拉取面")

    def test_artex_side_produced_finding_and_finished(self):
        artex = self.data["artex"]
        self.assertGreaterEqual(artex["findings_total"], 1, "ARTEX 侧 finding < 1")
        self.assertEqual(artex["task_final_status"], "done",
                         f"ARTEX 任务未到终态 done：{artex['task_final_status']}")

    def test_artex_step_latencies_present(self):
        artex = self.data["artex"]
        self.assertTrue(artex["steps"], "ARTEX 步骤时延缺失")
        for st in artex["steps"]:
            self.assertIn("step", st)
            self.assertIn("ms", st)
            self.assertGreaterEqual(st["ms"], 0)
        self.assertGreater(artex["task_total_ms"], 0)
        self.assertGreaterEqual(artex["llm_calls"], 1)
        self.assertGreaterEqual(artex["tokens_in_est"], 0)
        self.assertGreaterEqual(artex["tokens_out_est"], 0)

    def test_inkblade_side_same_chain_same_target(self):
        inkblade = self.data["inkblade"]
        self.assertEqual(inkblade["chain"], "flat-network-admin-plane-weight-poison")
        self.assertTrue(inkblade["ok"], f"InkBlade 链执行失败: {inkblade.get('steps')}")
        self.assertTrue(inkblade["step_timings"])
        for st in inkblade["step_timings"]:
            self.assertIsNotNone(st["ms"])
        self.assertGreaterEqual(inkblade["target_hit_count"], 1)
        self.assertGreater(inkblade["execute_ms"], 0)

    def test_comparison_table_covers_both_sides(self):
        table = self.data["comparison"]
        allowed = ("total_ms", "requests", "tokens", "rss_mib",
                   "per_step_ms", "cold_start_ms", "findings", "llm_calls")
        for row in table:
            self.assertIn(row["metric"], allowed)
            self.assertIn("artex", row)
            self.assertIn("inkblade", row)
        metrics = {row["metric"] for row in table}
        self.assertLessEqual({"total_ms", "requests", "tokens"}, metrics)

    def test_raw_provenance_attached(self):
        prov = self.data["provenance"]
        for key in ("mock_llm_log", "artex_raw", "inkblade_out", "target_stats",
                    "artex_tasks_json", "collected_at"):
            self.assertIn(key, prov)


if __name__ == "__main__":
    unittest.main()
