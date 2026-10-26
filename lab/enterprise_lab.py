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
from trident.core import baseline as baseline_mod  # noqa: E402
from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.roe import init_roe  # noqa: E402
from trident.core.runner import run_module  # noqa: E402
from trident.core.users import Session  # noqa: E402

FIXTURE_DIR = REPO / "lab" / "enterprise-fixtures"
REPLAY_DIR = REPO / "reports" / "samples" / "enterprise-lab"
MODULES = ("escape-primitives", "rbac-mapping", "network-policy-coverage",
           "exposure-mapping", "observability-exposure")
SEVERITIES = ("critical", "high", "medium", "low")

# 调优前（HEAD 实测，2026-10-26，报告于上一版 results.json）：作为 before 固化对照。
BEFORE = {
    "platform-baseline-noise": {"findings_total": 17, "tp": 1, "fp": 16, "fn": 1,
                                "fp_rate": 0.9412, "fn_rate": 0.5},
    "rbac-intent-noise": {"findings_total": 20, "tp": 7, "fp": 13, "fn": 1,
                          "fp_rate": 0.65, "fn_rate": 0.1429},
    "audit-flood-noise": {"findings_total": 3, "tp": 3, "fp": 0, "fn": 2,
                          "fp_rate": 0.0, "fn_rate": 0.4},
    "overall": {"findings_total": 40, "tp": 11, "fp": 29, "fn": 4,
                "fp_rate": 0.725, "fn_rate": 0.2857},
    "audit_default_baseline": {"findings_total": 183, "tp": 3, "fp": 180, "fn": 2},
}


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


def _audit_findings(events: list[dict], baseline_subjects) -> list[dict]:
    raw = auditlog.analyze_events(events, baseline_subjects=baseline_subjects)
    out = []
    for f in raw:
        item = _normalize_finding(f)
        item["step_key"] = "auditlog"
        item["detector"] = str(f.get("detector") or "auditlog")
        out.append(item)
    return out


def _pods_ctx(clusters: list[dict]) -> dict:
    """快照 Pod → (service_account, image) 映射，供工作负载三元组抑制。"""
    pods: dict[str, dict] = {}
    for cluster in clusters:
        for pod in cluster.get("pods") or []:
            containers = pod.get("containers") or []
            pods[f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"] = {
                "service_account": pod.get("serviceAccountName", ""),
                "image": str((containers[0] or {}).get("image", "")) if containers else "",
            }
    return {"pods": pods}


def _entity_baseline() -> baseline_mod.EntityBaseline:
    """调优基线 = 默认清单（CI/扫描器/控制器/平台工作负载）。"""
    return baseline_mod.EntityBaseline.defaults()


def _learned_subjects(events: list[dict]) -> list[dict]:
    """学习模式：时间切分——用事件流前段（历史）学习主体 allowlist 候选。

    不看标签、不看后段；仅按「主体 × 动作形态」频次 + 仅 2xx 成功动作。
    高危形态（token 铸造/portforward/绑定创建/PVC claim 写）在学习器内被封死。
    """
    history = [e for e in events
               if str(e.get("auditID", "")) < "fixture-0341"]  # 前 340 条（良性噪声）
    return baseline_mod.learn_from_events(history, min_occurrences=50)


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
    base = _entity_baseline()
    ctx = _pods_ctx(fixture["clusters"])
    # 场景 1/2：检测保持纯净，实体基线做 triage 抑制（留痕）
    esc_kept, esc_log = base.suppress_findings(
        [f for f in recon if f["step_key"] == "escape-primitives"], ctx)
    intent_kept, intent_log = base.suppress_findings(
        [f for f in recon if f["step_key"] in ("rbac-mapping", "network-policy-coverage")], ctx)
    audit_kept = _audit_findings(fixture["audit_events"], base.audit_subjects())
    fixture["_suppression"] = {
        "platform-baseline-noise": esc_log.summary(),
        "rbac-intent-noise": intent_log.summary(),
    }
    return {
        "platform-baseline-noise": [f for f in esc_kept if f.get("context") == "east-prod"],
        "rbac-intent-noise": intent_kept,
        "audit-flood-noise": audit_kept,
    }


def run_suite(*, write: bool = True) -> dict:
    fixture = load_fixture()
    by_scenario = _scenario_findings(fixture)
    base = _entity_baseline()
    scenarios = []
    titles = {
        "platform-baseline-noise": "场景 1：平台组件基线噪声（privileged/hostPath/hostNetwork DaemonSet）",
        "rbac-intent-noise": "场景 2：RBAC/NetworkPolicy 常规运维噪声（system wildcard / CI exec / 系统 NS）",
        "audit-flood-noise": "场景 3：审计事件洪水（340 良性 + 5 风险）",
    }
    for sid, findings in by_scenario.items():
        metrics = evaluate_labels(findings, fixture["ground_truth"], scenario=sid)
        row = {"id": sid, "title": titles[sid], "source": "fixture", **metrics}
        row["tuning"] = {"before": BEFORE[sid], "after": {
            k: metrics[k] for k in ("findings_total", "tp", "fp", "fn",
                                    "fp_rate", "fn_rate")}}
        if sid in (fixture.get("_suppression") or {}):
            row["tuning"]["suppression"] = fixture["_suppression"][sid]
        if sid == "audit-flood-noise":
            default_metrics = evaluate_labels(
                _audit_findings(fixture["audit_events"], auditlog.DEFAULT_BASELINE_SUBJECTS),
                fixture["ground_truth"], scenario=sid)
            learned = _learned_subjects(fixture["audit_events"])
            learned_base = baseline_mod.EntityBaseline().merge(
                {"subjects": [e["subject"] for e in learned]})
            learned_metrics = evaluate_labels(
                _audit_findings(fixture["audit_events"], learned_base.audit_subjects()),
                fixture["ground_truth"], scenario=sid)
            row["tuning"] = {
                "before": BEFORE[sid], "after": row["tuning"]["after"],
                "default_baseline_rerun": default_metrics,
                "learned_only": {
                    **{k: learned_metrics[k] for k in ("findings_total", "tp", "fp", "fn",
                                                       "fp_rate", "fn_rate")},
                    "learned_entries": [
                        {"subject": e["subject"], "pattern": e["pattern"],
                         "occurrences": e["occurrences"]} for e in learned],
                    "note": ("仅用前 340 条历史学习（时间切分、不看标签）：CI/监控/调度主体"
                             "被习得；扫描器 403 拒绝尝试不可学习 → 学习-only 仍有 FP，"
                             "必须与审批清单合并使用"),
                },
            }
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
        "schema": "trident-enterprise-lab/2",
        "generated_at": _now(),
        "tool": "trident",
        "source": "fixture",
        "fixture": str(FIXTURE_DIR.relative_to(REPO)).replace("\\", "/"),
        "metric_definition": {
            "fp_rate": "FP / (TP + FP)：发现级误报占比",
            "fn_rate": "FN / (TP + FN)：标注风险漏报率",
            "severity_scope": list(SEVERITIES),
            "labels": "ground-truth.json 固化（本版本把已补检测器的 __not_detected__ 占位锚点落位为证据锚，risk/benign 判定不变）",
        },
        "baseline": {
            "module": "trident/core/baseline.py",
            "classes": ["CI 服务账号", "安全扫描器", "平台控制器/调度器", "系统绑定",
                        "平台命名空间", "平台工作负载三元组(ns,SA,image)"],
            "learning": "时间切分：前 340 条历史事件 → 主体×动作形态频次(≥50)+仅 2xx；高危形态永不学习",
            "suppression_semantics": "能力面发现(can-i)仅 CI/扫描器可抑制；行为面发现全部基线主体可抑制",
        },
        "scenarios": scenarios,
        "overall": overall,
        "overall_tuning": {"before": BEFORE["overall"], "after": overall},
        "defenses": _defense_state(fixture),
        "real_cluster": _real_cluster_lane(),
        "gaps": [
            "fixture 不等于客户集群：版本/CNI/CRD/准入/遥测差异未覆盖",
            "审计场景只有 345 条事件，不等于客户日均百万级事件流",
            "残余 FN：mutable image tag（本夹具无该形态证据，检测器已备、不造证据）；客户环境需以真实快照重测",
            "残余 FP 逐条列出（各场景 tuning.after）：多为真实风险形态但无标注，不静默吞掉",
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
    lines += ["", "## 3. 调优前后（before → after）", "",
              "| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for s in results["scenarios"]:
        t = s["tuning"]
        b, a = t["before"], t["after"]
        lines.append(
            f"| {s['id']} 前 | {b['findings_total']} | {b['tp']} | {b['fp']} | {b['fn']} | "
            f"{b['fp_rate']:.2%} | {b['fn_rate']:.2%} |")
        lines.append(
            f"| {s['id']} 后 | {a['findings_total']} | {a['tp']} | {a['fp']} | {a['fn']} | "
            f"{a['fp_rate']:.2%} | {a['fn_rate']:.2%} |")
    ot = results["overall_tuning"]
    b, a = ot["before"], ot["after"]
    lines.append(
        f"| **合计 前** | {b['findings_total']} | {b['tp']} | {b['fp']} | {b['fn']} | "
        f"**{b['fp_rate']:.2%}** | **{b['fn_rate']:.2%}** |")
    lines.append(
        f"| **合计 后** | {a['findings_total']} | {a['tp']} | {a['fp']} | {a['fn']} | "
        f"**{a['fp_rate']:.2%}** | **{a['fn_rate']:.2%}** |")
    lines += ["",
              "> before = 2026-10-26 调优前实测（无基线抑制、无 token/portforward 检测器），",
              "> after = `core/baseline.py` 实体基线 + 学习模式 + 新检测器后的同一夹具重跑。",
              ""]
    lines += ["## 4. 逐场景说明", ""]
    for s in results["scenarios"]:
        lines.append(f"### {s['title']}")
        lines.append("")
        lines.append(f"- 发现 {s['findings_total']}（TP {s['tp']} / FP {s['fp']} / FN {s['fn']}）；"
                     f"标注风险 {s['risk_items']} 条。")
        t = s["tuning"]
        if t.get("suppression"):
            sup = t["suppression"]
            by = "、".join(f"{k}×{v}" for k, v in sup["by_source"].items()) or "无"
            lines.append(f"- 基线抑制 {sup['suppressed']} 条（{by}），检测器输出不变，"
                         "抑制逐条留痕（provenance 可审计）。")
        if s["id"] == "audit-flood-noise":
            lr = t.get("learned_only") or {}
            dd = t["default_baseline_rerun"]
            lines.append(f"- 默认主体基线复跑（新检测器生效）：TP {dd['tp']} / FP {dd['fp']} / "
                         f"FN {dd['fn']}——FP 仍来自 CI exec + 扫描器 403 洪水。")
            if lr:
                entries = "；".join(f"{e['subject']}（{e['pattern']}×{e['occurrences']}）"
                                   for e in lr["learned_entries"]) or "无"
                lines.append(f"- 学习模式（仅前 340 条历史、不看标签）：习得 {entries}。")
                lines.append(f"- 学习-only 基线：TP {lr['tp']} / FP {lr['fp']} / FN {lr['fn']}"
                             f"——{lr['note']}。")
        lines.append("")
    lines += ["## 5. 防御生效状态", "",
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
              "## 6. 真实集群车道（与 fixture 分列）", "",
              f"- 来源：`{results['real_cluster']['evidence']}`",
              f"- 模块：{results['real_cluster']['modules_ok']}/{results['real_cluster']['modules_total']} ok；"
              f"findings：{results['real_cluster']['findings']}",
              f"- FP/FN：**不计算** — {results['real_cluster']['note']}",
              "", "## 7. 未达成与调优建议", ""]
    lines += [f"- {g}" for g in results["gaps"]]
    lines += [
        "- 调优路径 1（已落地）：CI/扫描器/控制器/系统绑定/平台命名空间/工作负载三元组实体基线"
        "（`trident/core/baseline.py`，抑制留痕可审计，客户环境需重审批）。",
        "- 调优路径 2（已落地）：学习模式从历史事件流/run 生成 allowlist 候选（仅 2xx、"
        "高危形态永不学习、lead 审批后合并）。",
        "- 调优路径 3（已落地）：补齐 serviceaccounts/token 与 pods/portforward 检测器 + "
        "Sigma×2（永不基线化）；mutable image tag 检测器已备（本夹具无证据，如实留 FN）。",
        "- 抑制规则（时间窗/标签/注释）：`core/baseline.py::SuppressionRule`，"
        "客户维护窗与例外清单用，规则必须带 reason/created_by。",
        "", "## 8. 复现", "", "```bash", results["reproduce"], "```", "",
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
