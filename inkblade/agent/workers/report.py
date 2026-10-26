# -*- coding: utf-8 -*-
"""Report worker: reads the graph/evidence only; never calls a probe."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .base import Worker, WorkerResult


class ReportWorker(Worker):
    role = "report"

    def execute(self, intent: dict) -> WorkerResult:
        started = time.time()
        iid = str(intent.get("id") or "")
        if self.graph is None:
            return WorkerResult(False, iid, self.role, str(intent.get("module") or ""),
                                error="report worker 缺 graph")
        evaluation = self.objective.evaluate(self.graph) if self.objective is not None else {}
        facts = self.graph.confirmed_facts()
        evidence = [e for e in self.graph.evidence_ids()]
        lines = [
            f"# Agent report — {getattr(self.runtime, 'run_id', 'run')}",
            "",
            f"- objective: {self.objective.key if self.objective is not None else '-'}",
            f"- success: {evaluation.get('success')}",
            f"- confirmed facts: {len(facts)}",
            f"- evidence anchors: {len(evidence)}",
            "",
            "## 确认事实（仅探针证据）",
        ]
        if facts:
            for fact in facts:
                lines.append(f"- [{fact.get('severity')}] {fact.get('fact_kind')}: "
                             f"{fact.get('claim')} (evidence={', '.join(fact.get('evidence') or [])})")
        else:
            lines.append("- 无")
        lines += ["", "## 意图与结果"]
        for item in self.graph.intents():
            lines.append(f"- {item['id']} {item['role']}/{item['module']} "
                         f"status={item['status']} attempts={item.get('attempts', 0)}")
        lines += ["", "## 检查项"]
        for check in evaluation.get("checks") or []:
            lines.append(f"- {'PASS' if check.get('ok') else 'FAIL'} {check.get('id')}: "
                         f"{check.get('detail', '')}")
        text = "\n".join(lines) + "\n"
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        path = ""
        if self.runtime is not None:
            path = str(Path(self.runtime.dir) / "report.md")
            Path(path).write_text(text, encoding="utf-8")
        return WorkerResult(True, iid, self.role, str(intent.get("module") or "agent-report"),
                            output={"report": path, "sha256": sha,
                                    "facts": len(facts), "evidence": len(evidence),
                                    "success": evaluation.get("success")},
                            tokens=0, probe_calls=0,
                            duration_ms=int((time.time() - started) * 1000))
