# -*- coding: utf-8 -*-
"""core/swarm.py — 角色化 worker（recon/exploit/verify/report）+ 本机多进程队列测试。

断言：
- 角色上限 ≥2（每角色可配 2 个以上 worker），未知角色/越界 worker 数拒绝；
- 未批准动作拒绝入队且零残留（与 Supervisor 同一审批门）；
- 15 任务可跑完：成功/失败/重试/审批计数/角色分布可对账；
- 每角色至少 1 个 worker 时，4 worker 吞吐显著优于 1 worker（warm batch，不含进程启动）；
- 多进程真实执行（结果 pid 数 >1）；结果一次性、无重复。
"""

from __future__ import annotations

import unittest

from inkblade.core.swarm import (ROLE_CAPS, ApprovalRequired, Swarm, SwarmError)


def task(tid: str, role: str, delay_ms: int = 40, **extra) -> dict:
    item = {"id": tid, "role": role, "module": f"{role}-check", "params": {},
            "approval": {"status": "approved", "approved_by": "lead"},
            "simulate": {"delay_ms": delay_ms}}
    item.update(extra)
    return item


def tasks_15() -> list[dict]:
    out = []
    for i in range(5):
        out.append(task(f"recon-{i}", "recon", 60))
    for i in range(4):
        out.append(task(f"exploit-{i}", "exploit", 90))
    for i in range(4):
        out.append(task(f"verify-{i}", "verify", 70))
    for i in range(2):
        out.append(task(f"report-{i}", "report", 40))
    return out


class TestSwarmValidation(unittest.TestCase):
    def test_role_caps_each_at_least_two(self):
        self.assertEqual(set(ROLE_CAPS), {"recon", "exploit", "verify", "report"})
        for role, cap in ROLE_CAPS.items():
            self.assertGreaterEqual(cap, 2, f"{role} 上限须 ≥2")
        with self.assertRaises(SwarmError):
            Swarm(workers=4, role_caps={**ROLE_CAPS, "recon": 1})
        with self.assertRaises(SwarmError):
            Swarm(workers=4, role_caps={**ROLE_CAPS, "unknown": 2})
        for bad in (0, 17):
            with self.assertRaises(SwarmError):
                Swarm(workers=bad)

    def test_unapproved_task_rejected_without_queue_residue(self):
        sw = Swarm(workers=2, executor={"kind": "simulate"})
        with self.assertRaises(ApprovalRequired):
            sw.submit([{"id": "x", "role": "recon", "module": "recon-check"}])
        self.assertEqual(sw.pending(), 0)

    def test_duplicate_task_id_rejected(self):
        sw = Swarm(workers=2, executor={"kind": "simulate"})
        try:
            sw.submit([task("dup", "recon")])
            with self.assertRaises(SwarmError):
                sw.submit([task("dup", "verify")])
        finally:
            sw.close()


class TestSwarmRun(unittest.TestCase):
    def test_runs_all_roles_once_with_retry(self):
        sw = Swarm(workers=4, executor={"kind": "simulate", "approval_ms": 0})
        try:
            result = sw.run(tasks_15())
        finally:
            sw.close()
        self.assertEqual(result["mode"], "swarm")
        self.assertEqual(result["total"], 15)
        self.assertEqual(result["approvals"], 15)
        self.assertEqual(result["success"] + result["failed"], 15)
        self.assertEqual(result["by_role"]["recon"]["total"], 5)
        self.assertEqual(result["by_role"]["exploit"]["total"], 4)
        self.assertEqual(result["by_role"]["verify"]["total"], 4)
        self.assertEqual(result["by_role"]["report"]["total"], 2)
        ids = [r["task_id"] for r in result["results"]]
        self.assertEqual(len(ids), len(set(ids)), "结果不得重复")
        self.assertGreaterEqual(len({r["pid"] for r in result["results"]}), 2,
                                "4 worker 应由多个进程执行")

    def test_failure_and_retry_accounting(self):
        sw = Swarm(workers=4, executor={"kind": "simulate"})
        batch = [task("ok-1", "recon"),
                 task("flaky", "verify", fail_times=1),
                 task("bad", "exploit", fail=True)]
        try:
            result = sw.run(batch)
        finally:
            sw.close()
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["success"], 2)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["retries"], 2, "flaky 与 bad 各重派一次")
        rows = {r["task_id"]: r for r in result["results"]}
        self.assertEqual(rows["flaky"]["attempts"], 2)
        self.assertIn("simulated failure", rows["bad"]["error"])

    def test_four_workers_beat_one_worker(self):
        batch = [task(f"m{i}", ["recon", "exploit", "verify", "report"][i % 4], 150)
                 for i in range(12)]
        warm = [task(f"w{i}", ["recon", "exploit", "verify", "report"][i % 4], 30)
                for i in range(4)]
        slow = Swarm(workers=1, executor={"kind": "simulate"})
        fast = Swarm(workers=4, executor={"kind": "simulate"})
        try:
            slow.run(warm)
            t1 = slow.run(batch)["wall_ms"]
            fast.run(warm)
            t4 = fast.run(batch)["wall_ms"]
        finally:
            slow.close()
            fast.close()
        self.assertGreater(t4, 0)
        self.assertLess(t4, t1 * 0.75,
                        f"4 worker 应显著快于 1 worker（1w={t1}ms, 4w={t4}ms）")
        self.assertEqual(fast.last_result["total"], 12)
        self.assertGreaterEqual(fast.last_result["peak_concurrency"], 2)


class TestSwarmCli(unittest.TestCase):
    def test_roles_lists_caps(self):
        import contextlib
        import io

        from inkblade import cli

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["swarm", "roles"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        for role in ("recon", "exploit", "verify", "report"):
            self.assertIn(role, text)


if __name__ == "__main__":
    unittest.main()
