# -*- coding: utf-8 -*-
"""企业真实感实验室：fixture 车道的误报/漏报评测。

三道噪声场景：
1. ``platform-baseline-noise``：云厂商/监控/安全 DaemonSet 的 privileged/hostPath/
   hostNetwork 噪声 → escape-primitives 的“相对客户基线误报”；
2. ``rbac-intent-noise``：system ClusterRole wildcard、CI pods/exec、系统命名空间无
   NetworkPolicy 等常规运维噪声 + 真实租户越权风险；
3. ``audit-flood-noise``：340 条良性审计事件（CI exec / 扫描器 403 / 监控读 Secret /
   平台调度器挂 PVC）+ 5 条风险事件（2 条当前检测器未覆盖）。

真实集群车道：读取 ``reports/samples/real-cluster/recon-findings.json``（单节点
k3s/QEMU TCG，6/6 模块、16 findings），**无标注 → 明确不计算 FP/FN**。

口径（写入 docs/ENTERPRISE-LAB-RESULTS.md）：
- FP 率 = FP / (TP + FP)，即发现级误报占比；
- FN 率 = FN / (TP + FN)，即标注风险漏报率；
- 实现不得临时改标签；标签在 ``ground-truth.json`` 固化。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from trident.core import auditlog  # noqa: E402
from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.roe import init_roe  # noqa: E402
from trident.core.runner import run_module  # noqa: E402
from trident.core.users import Session  # noqa: E402

FIXTURE_DIR = REPO / "lab" / "enterprise-fixtures"
REPLAY_DIR = REPO / "reports" / "samples" / "enterprise-lab"
MODULES = ("escape-primitives", "rbac-mapping", "network-policy-coverage",
           "exposure-mapping", "observability-exposure")
SEVERITIES = ("critical", "high", "medium", "low")
TUNED_BASELINE = auditlog.DEFAULT_BASELINE_SUBJECTS + (
    "system:serviceaccount:ci:ci-runner",
    "system:serviceaccount:security:scanner",
)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_fixture() -> dict:
    east = json.loads((FIXTURE_DIR / "clusters" / "east-prod.json").read_text(encoding="utf-8"))
    west = json.loads((FIXTURE_DIR / "clusters" / "west-prod.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in
              (FIXTURE_DIR / "audit-noise.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    labels = json.loads((FIXTURE_DIR / "ground-truth.json").read_text(encoding="utf-8"))
    kyverno, falco = [], []
    for cluster in (east, west):
        for p in ((cluster.get("defenses") or {}).get("kyverno") or {}).get("policies") or []:
            kyverno.append({**p, "cluster": cluster["context"]})
        for r in ((cluster.get("defenses") or {}).get("falco") or {}).get("rules") or []:
            falco.append({**r, "cluster": cluster["context"]})
    return {
        "snapshot": east,
        "snapshots": {"east-prod": east, "west-prod": west},
        "clusters": [east, west],
        "audit_events": events,
        "ground_truth": labels,
        "defenses": {"kyverno": {"policies": kyverno}, "falco": {"rules": falco}},
        "source": "fixture",
    }


def _normalize_finding(finding: dict) -> dict:
    title = str(finding.get("title") or "")
    detail = str(finding.get("detail") or "")
    evidence = str(finding.get("evidence") or "")
    subject = str(finding.get("subject") or "")
    resource = str(finding.get("resource") or "")
    return {
        "step_key": str(finding.get("step_key") or finding.get("module") or "auditlog"),
        "detector": str(finding.get("detector") or ""),
        "severity": str(finding.get("severity") or finding.get("sev") or "info").lower(),
        "title": title,
        "detail": detail,
        "subject": subject,
        "resource": resource,
        "evidence": evidence,
        "text": " ".join([title, detail, evidence, subject, resource]),
    }


def _audit_findings(events: list[dict], baseline=TUNED_BASELINE) -> list[dict]:
    raw = auditlog.analyze_events(events, baseline_subjects=baseline)
    out = []
    for f in raw:
        item = _normalize_finding(f)
        item["step_key"] = "auditlog"
        item["detector"] = str(f.get("detector") or "auditlog")
        out.append(item)
    return out


def _recon_findings(snapshot: dict) -> list[dict]:
    context = str(snapshot.get("context") or "")
    with tempfile.TemporaryDirectory(prefix="trident-enterprise-lab-") as tmp:
        store = EvidenceStore(Path(tmp), workspace="enterprise-lab")
        init_roe(store, fields={
            "level": "只读侦察",
            "namespaces": ["*"],
            "cidrs": ["10.0.0.0/8"],
            "client": "fixture",
        })
        session = Session(None, "lab", "tester", ["enterprise-lab"], "fixture-token")
        run = store.create_run("enterprise-lab")
        for module in MODULES:
            try:
                run_module(store, session, module, {"snapshot": snapshot},
                           REPO / "trident" / "modules", run=run)
            except Exception as exc:  # noqa: BLE001 - fixture 评测必须显式失败而非假绿
                raise RuntimeError(f"fixture 模块执行失败 {module}: {exc}") from exc
        findings = [_normalize_finding(f) for f in run.findings]
    out = []
    for f in findings:
        f["context"] = context
        out.append(f)
    return [f for f in out if f["severity"] in SEVERITIES]


def _contains(haystack: str, needle: str) -> bool:
    return bool(needle) and needle.lower() in haystack.lower()


def evaluate_labels(findings: Iterable[dict], labels: Iterable[dict], *, scenario: str) -> dict:
    labels = [l for l in labels if l.get("scenario") == scenario]
    risk_labels = [l for l in labels if l.get("label") == "risk"]
    benign_labels = [l for l in labels if l.get("label") == "benign"]
    findings = [f for f in findings if f.get("severity") in SEVERITIES]
    detected: set[str] = set()
    tp = fp = 0
    benign_hits = 0
    for finding in findings:
        step = str(finding.get("step_key") or finding.get("detector") or "")
        text = " ".join(str(finding.get(k) or "") for k in
                        ("title", "detail", "evidence", "subject", "resource", "text"))
        matched_risk = None
        for label in risk_labels:
            if label.get("module") not in (step, finding.get("detector")):
                continue
            if _contains(text, str(label.get("contains") or "")):
                matched_risk = label
                break
        if matched_risk is not None:
            tp += 1
            detected.add(str(matched_risk["id"]))
            continue
        fp += 1
        for label in benign_labels:
            if label.get("module") not in (step, finding.get("detector")):
                continue
            if _contains(text, str(label.get("contains") or "")):
                benign_hits += 1
                break
    fn = sum(1 for l in risk_labels if str(l["id"]) not in detected)
    total = tp + fp
    return {
        "findings_total": total,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "risk_items": len(risk_labels),
        "benign_items": len(benign_labels),
        "benign_hits": benign_hits,
        "fp_rate": round(fp / total, 4) if total else 0.0,
        "fn_rate": round(fn / len(risk_labels), 4) if risk_labels else 0.0,
    }


def _defense_state(fixture: dict) -> dict:
    policies = fixture["defenses"]["kyverno"]["policies"]
    rules = fixture["defenses"]["falco"]["rules"]
    enforced = sum(1 for p in policies
                   if str(p.get("status") or "").lower() in ("enforced", "enforce"))
    audit = sum(1 for p in policies if str(p.get("status") or "").lower() == "audit")
    missing = len(policies) - enforced - audit
    loaded = sum(1 for r in rules if r.get("loaded"))
    namespaces: set[tuple[str, str]] = set()
    covered: set[tuple[str, str]] = set()
    for cluster in fixture["clusters"]:
        ctx = cluster["context"]
        ns_set = {p.get("namespace", "default") for p in cluster.get("pods", [])}
        ns_set |= set(cluster.get("namespaces") or [])
        for ns in ns_set:
            namespaces.add((ctx, ns))
            if any(p.get("namespace") == ns and not p.get("podSelector") and
                   "Ingress" in (p.get("policyTypes") or ["Ingress"])
                   for p in cluster.get("networkpolicies", [])):
                covered.add((ctx, ns))
    return {
        "kyverno": {
            "total": len(policies), "enforced": enforced, "audit": audit, "missing": missing,
            "enforced_rate": round(enforced / len(policies), 4) if policies else 0.0,
        },
        "falco": {
            "total": len(rules), "loaded": loaded, "missing": len(rules) - loaded,
            "loaded_rate": round(loaded / len(rules), 4) if rules else 0.0,
        },
        "network_policy": {
            "namespaces": len(namespaces), "covered": len(covered),
            "coverage_rate": round(len(covered) / len(namespaces), 4) if namespaces else 0.0,
            "uncovered": sorted(f"{ctx}/{ns}" for ctx, ns in namespaces - covered),
        },
    }


def _real_cluster_lane() -> dict:
    path = REPO / "reports" / "samples" / "real-cluster" / "recon-findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    modules = doc.get("modules") or []
    return {
        "source": "real-cluster-k3s",
        "evidence": "reports/samples/real-cluster/recon-findings.json",
        "modules_ok": sum(1 for m in modules if m.get("ok")),
        "modules_total": len(modules),
        "findings": int(doc.get("finding_count") or len(doc.get("findings") or [])),
        "fp_fn_available": False,
        "note": ("真实集群单节点 k3s（QEMU TCG），只有结构性发现、无客户标注真值，"
                 "故不计算 FP/FN；不得把 fixture 的 FP/FN 外推到该集群或客户环境。"),
    }


def _scenario_findings(fixture: dict) -> dict[str, list[dict]]:
    recon = []
    for cluster in fixture["clusters"]:
        recon.extend(_recon_findings(cluster))
    return {
        "platform-baseline-noise": [f for f in recon
                                    if f["step_key"] == "escape-primitives"
                                    and f.get("context") == "east-prod"],
        "rbac-intent-noise": [f for f in recon
                              if f["step_key"] in ("rbac-mapping", "network-policy-coverage")],
        "audit-flood-noise": _audit_findings(fixture["audit_events"]),
    }


def run_suite(*, write: bool = True) -> dict:
    fixture = load_fixture()
    by_scenario = _scenario_findings(fixture)
    scenarios = []
    titles = {
        "platform-baseline-noise": "场景 1：平台组件基线噪声（privileged/hostPath/hostNetwork DaemonSet）",
        "rbac-intent-noise": "场景 2：RBAC/NetworkPolicy 常规运维噪声（system wildcard / CI exec / 系统 NS）",
        "audit-flood-noise": "场景 3：审计事件洪水（340 良性 + 5 风险，2 未覆盖）",
    }
    for sid, findings in by_scenario.items():
        metrics = evaluate_labels(findings, fixture["ground_truth"], scenario=sid)
        row = {"id": sid, "title": titles[sid], "source": "fixture", **metrics}
        if sid == "audit-flood-noise":
            default_metrics = evaluate_labels(_audit_findings(fixture["audit_events"],
                                                              auditlog.DEFAULT_BASELINE_SUBJECTS),
                                              fixture["ground_truth"], scenario=sid)
            tuned_metrics = evaluate_labels(_audit_findings(fixture["audit_events"], TUNED_BASELINE),
                                            fixture["ground_truth"], scenario=sid)
            row["tuning"] = {
                "default_baseline": default_metrics,
                "tuned_baseline": tuned_metrics,
                "baseline_added": ["system:serviceaccount:ci:ci-runner",
                                   "system:serviceaccount:security:scanner"],
                "fp_before": default_metrics["fp"],
                "fp_after": tuned_metrics["fp"],
                "fp_reduction": round(1 - (tuned_metrics["fp"] / default_metrics["fp"]), 4)
                                if default_metrics["fp"] else 0.0,
            }
            row.update({"fp": tuned_metrics["fp"], "fn": tuned_metrics["fn"],
                        "tp": tuned_metrics["tp"], "findings_total": tuned_metrics["findings_total"],
                        "fp_rate": tuned_metrics["fp_rate"], "fn_rate": tuned_metrics["fn_rate"]})
        scenarios.append(row)
    totals = {"tp": sum(s["tp"] for s in scenarios),
              "fp": sum(s["fp"] for s in scenarios),
              "fn": sum(s["fn"] for s in scenarios),
              "findings_total": sum(s["findings_total"] for s in scenarios),
              "risk_items": sum(s["risk_items"] for s in scenarios)}
    overall = {**totals,
               "fp_rate": round(totals["fp"] / totals["findings_total"], 4)
                          if totals["findings_total"] else 0.0,
               "fn_rate": round(totals["fn"] / totals["risk_items"], 4)
                          if totals["risk_items"] else 0.0}
    results = {
        "schema": "trident-enterprise-lab/1",
        "generated_at": _now(),
        "tool": "trident",
        "source": "fixture",
        "fixture": str(FIXTURE_DIR.relative_to(REPO)).replace("\\", "/"),
        "metric_definition": {
            "fp_rate": "FP / (TP + FP)：发现级误报占比",
            "fn_rate": "FN / (TP + FN)：标注风险漏报率",
            "severity_scope": list(SEVERITIES),
            "labels": "ground-truth.json 固化，实现不临时改标签",
        },
        "scenarios": scenarios,
        "overall": overall,
        "defenses": _defense_state(fixture),
        "real_cluster": _real_cluster_lane(),
        "gaps": [
            "fixture 不等于客户集群：版本/CNI/CRD/准入/遥测差异未覆盖",
            "审计场景只有 345 条事件，不等于客户日均百万级事件流",
            "2 个风险（SA token 铸造、pods/portforward）当前检测器未覆盖 → 如实计 FN",
            "真实集群车道无标注，不计算 FP/FN",
        ],
        "reproduce": "python lab/enterprise_lab.py",
    }
    if write:
        REPLAY_DIR.mkdir(parents=True, exist_ok=True)
        (REPLAY_DIR / "results.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (REPLAY_DIR / "results.md").write_text(render_md(results), encoding="utf-8")
    return results


def render_md(results: dict) -> str:
    d = results["defenses"]
    lines = [
        "# 企业真实感实验室结果（fixture 车道）",
        "",
        f"> 生成时间：`{results['generated_at']}` · 来源：**fixture**（`{results['fixture']}`）",
        ">",
        "> 真实集群证据另列：单节点 k3s（QEMU TCG）只有结构性发现、无标注，"
        "**不计算 FP/FN**；本页数字不得外推到客户环境。",
        "",
        "## 1. 口径",
        "",
        f"- {results['metric_definition']['fp_rate']}",
        f"- {results['metric_definition']['fn_rate']}",
        f"- 只统计 {', '.join(results['metric_definition']['severity_scope'])}；info 不计入。",
        "",
        "## 2. 三场景结果",
        "",
        "| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for s in results["scenarios"]:
        lines.append(f"| {s['id']} | {s['findings_total']} | {s['tp']} | {s['fp']} | "
                     f"{s['fn']} | {s['fp_rate']:.2%} | {s['fn_rate']:.2%} |")
    o = results["overall"]
    lines.append(f"| **合计** | {o['findings_total']} | {o['tp']} | {o['fp']} | {o['fn']} | "
                 f"**{o['fp_rate']:.2%}** | **{o['fn_rate']:.2%}** |")
    lines += ["", "## 3. 逐场景说明", ""]
    for s in results["scenarios"]:
        lines.append(f"### {s['title']}")
        lines.append("")
        lines.append(f"- 发现 {s['findings_total']}（TP {s['tp']} / FP {s['fp']} / FN {s['fn']}）；"
                     f"标注风险 {s['risk_items']} 条。")
        if s.get("tuning"):
            t = s["tuning"]
            lines.append(f"- 调优（审计主体基线）：FP {t['fp_before']} → {t['fp_after']}，"
                         f"降幅 {t['fp_reduction']:.1%}；新增基线 "
                         f"`{', '.join(t['baseline_added'])}`。")
            lines.append(f"- 调优后 TP {t['tuned_baseline']['tp']} / FP {t['tuned_baseline']['fp']} / "
                         f"FN {t['tuned_baseline']['fn']}；漏报风险仍为 "
                         f"{t['tuned_baseline']['fn']} 条（未覆盖检测面）。")
        lines.append("")
    lines += ["## 4. 防御生效状态", "",
              "| 项 | 总数 | 生效/加载/覆盖 | 缺口 | 比率 |",
              "|---|---:|---:|---:|---:|",
              f"| Kyverno 策略 | {d['kyverno']['total']} | Enforce {d['kyverno']['enforced']} | "
              f"Audit {d['kyverno']['audit']} + Missing {d['kyverno']['missing']} | "
              f"{d['kyverno']['enforced_rate']:.1%} |",
              f"| Falco 规则 | {d['falco']['total']} | Loaded {d['falco']['loaded']} | "
              f"Missing {d['falco']['missing']} | {d['falco']['loaded_rate']:.1%} |",
              f"| NetworkPolicy 分区 | {d['network_policy']['namespaces']} NS | "
              f"默认拒绝 {d['network_policy']['covered']} | 未覆盖 "
              f"{len(d['network_policy']['uncovered'])} | {d['network_policy']['coverage_rate']:.1%} |",
              "", "未覆盖命名空间（fixture）：" +
              (", ".join(d["network_policy"]["uncovered"]) or "无"), "",
              "## 5. 真实集群车道（与 fixture 分列）", "",
              f"- 来源：`{results['real_cluster']['evidence']}`",
              f"- 模块：{results['real_cluster']['modules_ok']}/{results['real_cluster']['modules_total']} ok；"
              f"findings：{results['real_cluster']['findings']}",
              f"- FP/FN：**不计算** — {results['real_cluster']['note']}",
              "", "## 6. 未达成与调优建议", ""]
    lines += [f"- {g}" for g in results["gaps"]]
    lines += [
        "- 调优建议 1：把 CI/扫描器/平台调度器纳入审计主体基线（本页已演示 FP 降幅，但需客户审批）。",
        "- 调优建议 2：对云厂商 DaemonSet 建例外清单，按 image digest + namespace + SA 三元组，"
        "而不是按 finding 标题永久静默。",
        "- 调优建议 3：pods/portforward、serviceaccounts/token 铸造、mutable image tag 需补检测器/准入，"
        "不能靠调基线“消灭”。",
        "", "## 7. 复现", "", "```bash", results["reproduce"], "```", "",
        "边界：fixture 非客户生产环境；版本/CNI/CRD/遥测差异、日均百万事件流、"
        "真实告警闭环均需 Pilot 在客户环境重测。", "",
    ]
    return "\n".join(lines)


def main() -> int:
    results = run_suite(write=True)
    print(f"enterprise-lab: {REPLAY_DIR / 'results.json'}")
    print(f"overall: TP {results['overall']['tp']} / FP {results['overall']['fp']} / "
          f"FN {results['overall']['fn']} | FP {results['overall']['fp_rate']:.2%} / "
          f"FN {results['overall']['fn_rate']:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
