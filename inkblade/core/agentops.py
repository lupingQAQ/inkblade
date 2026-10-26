# -*- coding: utf-8 -*-
"""Agent 运行门面：把 journal / supervisor / reflexion / skills 串成一条可审计闭环。

流程（写面仍逐动作审批，执行仍走 runner 三闸门）：
1. ``Supervisor.submit`` 校验每个动作的批准状态（未批准 → ``ApprovalRequired``）；
2. ``Supervisor.run`` 有界并发执行 + 失败重派 + journal 事件；
3. 对每个成功任务做 ``reflexion.reflect``（**零执行**，只读 evidence DB）；
4. 可选：把反思 playbook 提交为 pending 技能（入库仍需 lead approve）。

本模块不绕过任何闸门，也不改变 explorer/runner 的默认行为。
"""

from __future__ import annotations

import time
from pathlib import Path

from . import reflexion
from .journal import Journal
from .skills import SkillLibrary
from .supervisor import Supervisor


def run_approved_plan(store, session, actions: list[dict], *, proposal: dict | None = None,
                      workers: int = 2, max_attempts: int = 2,
                      modules_dir: Path | str | None = None, executor=None,
                      propose_skills: bool = False) -> dict:
    """执行已批准动作计划 → 反思 →（可选）技能提案。"""
    started = time.time()
    journal = Journal.for_store(store)
    supervisor = Supervisor(store, session, workers=workers, max_attempts=max_attempts,
                            modules_dir=modules_dir, executor=executor, journal=journal)
    submitted = supervisor.submit(actions, proposal=proposal)
    result = supervisor.run()

    reflections: list[dict] = []
    for task in result["tasks"]:
        run_name = ((task.get("result") or {}).get("run") or "")
        if task["status"] != "success" or not run_name:
            continue
        try:
            reflections.append(reflexion.reflect(store.open_run(run_name)))
        except KeyError:
            continue

    proposals: list[dict] = []
    if propose_skills:
        library = SkillLibrary(store, modules_dir=modules_dir)
        for report in reflections:
            if not report.get("playbook"):
                continue
            try:
                proposals.append(reflexion.propose_skill(report, library, session))
            except ValueError:
                continue

    return {
        "mode": "supervisor-worker",
        "submitted": len(submitted),
        "summary": result["summary"],
        "tasks": result["tasks"],
        "reflections": reflections,
        "proposals": proposals,
        "journal": journal.verify(),
        "duration_ms": int((time.time() - started) * 1000),
    }
