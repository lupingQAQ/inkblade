"""5 角色专家启发式走查：记录步骤、错误、耗时，产出指标 JSON + SUS 模板。

重要口径（写进输出与 docs/UX-EVALUATION.md）：

- 这是**专家启发式走查（expert heuristic walkthrough）**，由实现者按角色脚本
  执行，**不是真实用户研究**；
- 5 个角色是 persona，不是 5 位受试者；SUS 只给模板与计分公式，**未施测**，
  因此不产出、也不应引用任何 SUS 分数；
- 所有命令跑在临时目录/本地 mock/离线 snapshot 上，不连接真实集群，不发外网。

用法::

    python scripts/usability-walkthrough.py
    python scripts/usability-walkthrough.py --json-out reports/samples/usability/walkthrough.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

DISCLAIMER = (
    "专家走查（expert heuristic walkthrough）：由实现者按 5 个 persona 脚本执行，"
    "为非真实用户数据（not real-user data），不构成 SUS 分数、统计显著性、"
    "可用性认证或 SLA。SUS 仅提供模板，需由真实受试者独立填写后另行分析。"
)

SUS_QUESTIONS = [
    "我愿意经常使用这个系统。 / I think that I would like to use this system frequently.",
    "我觉得系统 unnecessarily complex。 / I found the system unnecessarily complex.",
    "我认为系统容易使用。 / I thought the system was easy to use.",
    "我需要技术支援才能使用这个系统。 / I think that I would need the support of a technical person to be able to use this system.",
    "我觉得系统各功能整合得很好。 / I found the various functions in this system were well integrated.",
    "我觉得系统有太多不一致。 / I thought there was too much inconsistency in this system.",
    "我认为大多数人能很快学会使用。 / I would imagine that most people would learn to use this system very quickly.",
    "我觉得系统使用起来很笨重。 / I found the system very cumbersome to use.",
    "我对使用系统很有信心。 / I felt very confident using the system.",
    "我需要先学很多东西才能上手。 / I needed to learn a lot of things before I could get going with this system.",
]

SUS_SCORING = {
    "scale": "1=非常不同意 … 5=非常同意",
    "formula": "奇数题得分 = 响应-1；偶数题得分 = 5-响应；总分 = 10 题得分和 × 2.5（0–100）",
    "note": "模板未施测；n<10 时不应报告中位数/均值作为产品结论。",
}

ROLES: list[dict[str, Any]] = [
    {
        "id": "platform-admin",
        "name_zh": "平台管理员",
        "name_en": "Platform admin",
        "goal": "确认环境可用，跑出第一条本地发现",
        "steps": [
            {"name": "doctor", "argv": ["doctor", "--mode", "mock"]},
            {"name": "demo", "argv": ["demo", "--out", "{tmp}/demo-out", "--json"],
             "capture_run": True, "first_result": True},
        ],
    },
    {
        "id": "security-lead",
        "name_zh": "安全负责人",
        "name_en": "Security lead",
        "goal": "确认授权状态，并对真实集群做只读上手预演",
        "steps": [
            {"name": "roe", "argv": ["roe", "--workspace", "demo-lab"]},
            {"name": "onboard-dry-run", "argv": [
                "onboard-cluster", "--snapshot",
                "lab/enterprise-fixtures/clusters/east-prod.json",
                "--dry-run", "--out", "{tmp}/pilot-lead",
            ]},
        ],
        "home": "pilot",
    },
    {
        "id": "pentester",
        "name_zh": "渗透测试员",
        "name_en": "Pentester",
        "goal": "查看模块清单并对攻击链做 dry-run 计划",
        "steps": [
            {"name": "module-list", "argv": ["module", "list", "--modules-dir", "inkblade/modules"]},
            {"name": "chain-dry-run", "argv": [
                "execute", "--chain", "flat-network-admin-plane-weight-poison",
                "--workspace", "demo-lab", "--dry-run",
            ]},
        ],
        "home": "shared",
    },
    {
        "id": "auditor",
        "name_zh": "审计员",
        "name_en": "Auditor",
        "goal": "从同一次 run 复现双语报告与 CTEM 叙事",
        "steps": [
            {"name": "report", "argv": [
                "report", "--run", "{run}", "--workspace", "demo-lab",
                "--kind", "pentest", "--lang", "bi", "--out", "{tmp}/audit/pentest-bi.md",
            ]},
            {"name": "report-ctem", "argv": [
                "report-ctem", "--run", "{run}", "--workspace", "demo-lab",
                "--out", "{tmp}/audit/ctem.md",
            ]},
        ],
        "home": "shared",
    },
    {
        "id": "ml-engineer",
        "name_zh": "ML 平台工程师",
        "name_en": "ML platform engineer",
        "goal": "列混沌实验并实跑延迟/断连/PFC 三条，观察稳态破坏与恢复",
        "steps": [
            {"name": "chaos-list", "argv": ["chaos", "list", "--json"]},
            {"name": "chaos-run", "argv": [
                "chaos", "run",
                "net-latency-step-degradation",
                "net-disconnect-workers",
                "fabric-pfc-storm",
                "--json-out", "{tmp}/chaos/three.json",
            ]},
        ],
        "home": "chaos",
    },
]


def _run(argv: list[str], cwd: Path, timeout: int = 180) -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(cwd)
    started = time.perf_counter()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env, timeout=timeout)
        code, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        code, out, err = 124, "", f"timeout after {timeout}s"
    ms = (time.perf_counter() - started) * 1000
    codes = sorted(set(re.findall(r"\bE\d{3}\b", out + "\n" + err)))
    return {
        "exit_code": code,
        "ok": code == 0,
        "duration_ms": round(ms, 1),
        "errors": codes if code != 0 else [],
        "stdout_full": out,
        "stdout_tail": out[-1200:],
        "stderr_tail": err[-1200:],
    }


_ABS_PATH_RX = re.compile(r"[A-Za-z]:[\\/][^\s\"']*")


def _sanitize_text(text: str, roots: list[tuple[Path, str]]) -> str:
    for root, label in roots:
        text = text.replace(str(root), label)
        try:
            text = text.replace(str(root.resolve()), label)
        except OSError:
            pass
    return _ABS_PATH_RX.sub("<abs-path>", text)


def _sanitize(obj: Any, roots: list[tuple[Path, str]]) -> Any:
    if isinstance(obj, str):
        return _sanitize_text(obj, roots)
    if isinstance(obj, list):
        return [_sanitize(x, roots) for x in obj]
    if isinstance(obj, dict):
        return {k: _sanitize(v, roots) for k, v in obj.items()}
    return obj


def _json_from_output(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    try:
        doc = json.loads(text)
        return doc if isinstance(doc, dict) else None
    except ValueError:
        pass
    start = text.find("{")
    if start < 0:
        return None
    try:
        doc = json.loads(text[start:])
        return doc if isinstance(doc, dict) else None
    except ValueError:
        return None


def summarize(steps: list[dict]) -> dict:
    total = len(steps)
    durations = sorted(float(s.get("duration_ms", 0.0)) for s in steps)
    failed = [s for s in steps if not s.get("ok")]
    errors: list[str] = []
    for s in steps:
        for code in s.get("errors", []) or []:
            if code not in errors:
                errors.append(code)
    def pct(p: float) -> float:
        if not durations:
            return 0.0
        idx = min(len(durations) - 1, max(0, round((len(durations) - 1) * p)))
        return round(durations[idx], 1)
    return {
        "steps": total,
        "failed_steps": len(failed),
        "success_rate": round((total - len(failed)) / total, 4) if total else 0.0,
        "total_duration_s": round(sum(durations) / 1000.0, 3),
        "avg_step_ms": round(sum(durations) / total, 1) if total else 0.0,
        "p50_step_ms": pct(0.5),
        "p95_step_ms": pct(0.95),
        "error_classes": sorted(errors),
        "roles": sorted({s.get("role", "") for s in steps if s.get("role")}),
    }


def build_walkthrough(*, run_id: str | None = None, timeout: int = 180) -> dict:
    py = sys.executable
    tmp_root = Path(tempfile.mkdtemp(prefix="inkblade-usability-"))
    homes = {
        "shared": tmp_root / "home",
        "pilot": tmp_root / "pilot-home",
        "chaos": tmp_root / "chaos-home",
    }
    for home in homes.values():
        home.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    role_summaries: list[dict] = []
    resolved_run = run_id or ""
    resolved_workspace = ""

    for role in ROLES:
        home = homes.get(role.get("home", "shared"), homes["shared"])
        role_rows: list[dict] = []
        for step in role["steps"]:
            argv = [py, "-m", "inkblade", "--home", str(home)]
            for part in step["argv"]:
                argv.append(str(part).format(tmp=tmp_root, run=resolved_run))
            result = _run(argv, REPO, timeout=timeout)
            if step.get("capture_run") and result["ok"]:
                doc = _json_from_output(result["stdout_full"])
                if doc and doc.get("run") and not resolved_run:
                    resolved_run = str(doc["run"])
                if doc and doc.get("workspace"):
                    resolved_workspace = str(doc["workspace"])
                    homes["shared"] = Path(resolved_workspace)
            row = {
                "role": role["id"],
                "role_name": role["name_zh"],
                "name": step["name"],
                "argv": argv,
                "ok": result["ok"],
                "exit_code": result["exit_code"],
                "duration_ms": result["duration_ms"],
                "errors": result["errors"],
                "stderr_tail": result["stderr_tail"] if not result["ok"] else "",
                "first_result": bool(step.get("first_result") and result["ok"]),
            }
            records.append(row)
            role_rows.append(row)
            print(f"[{role['id']}] {step['name']}: "
                  f"{'ok' if result['ok'] else 'FAIL(' + str(result['exit_code']) + ')'} "
                  f"{result['duration_ms']:.0f}ms", flush=True)
        role_summaries.append({
            "id": role["id"],
            "name_zh": role["name_zh"],
            "name_en": role["name_en"],
            "goal": role["goal"],
            "steps": len(role_rows),
            "failed": sum(1 for r in role_rows if not r["ok"]),
            "duration_s": round(sum(r["duration_ms"] for r in role_rows) / 1000, 3),
        })

    overall = summarize(records)
    first_result = next((r for r in records if r.get("first_result")), None)
    overall["first_result_s"] = round(first_result["duration_ms"] / 1000, 3) if first_result else None
    overall["roles_success"] = sum(1 for r in role_summaries if r["failed"] == 0)
    overall["role_count"] = len(role_summaries)
    doc = {
        "schema": "inkblade-usability-walkthrough/1",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "method": "expert heuristic walkthrough（专家走查，非真实用户研究）",
        "disclaimer": DISCLAIMER,
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "repo": str(REPO),
            "tmp_root": str(tmp_root),
            "network": "无外网；真实集群仅离线 snapshot；chaos 仅本地仿真靶场",
        },
        "run_id": resolved_run,
        "roles": role_summaries,
        "steps": records,
        "metrics": overall,
        "sus_template": {
            "status": "template-only（未施测；不得作为 SUS 分数引用）",
            "scale": SUS_SCORING["scale"],
            "questions": SUS_QUESTIONS,
            "responses": [],  # 真实受试者填入 10 个 1–5 整数后另行计分
            "scoring": SUS_SCORING,
            "disclaimer": DISCLAIMER,
        },
    }
    return _sanitize(doc, [(REPO, "<repo>"), (tmp_root, "<tmp>")])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="5 角色专家启发式走查（本地/离线）")
    ap.add_argument("--json-out", default=str(REPO / "reports" / "samples" / "usability" / "walkthrough.json"))
    ap.add_argument("--run", default=None, help="复用已有 demo run（缺省由 demo 步骤捕获）")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args(argv)
    doc = build_walkthrough(run_id=args.run, timeout=args.timeout)
    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "json": str(out),
        "metrics": doc["metrics"],
        "roles": doc["roles"],
        "disclaimer": doc["disclaimer"],
    }, ensure_ascii=False, indent=2))
    return 0 if doc["metrics"]["failed_steps"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
