"""LWS 集群级 Secrets 横向：检测集群级 secrets 读权 + 节点 patch，演示=凭据面清单落盘。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "clusterroles.json"


def _grants(rule: dict, resource: str, verb: str) -> bool:
    return ("" in rule.get("apiGroups", []) or "core" in rule.get("apiGroups", [])) and (
        resource in rule.get("resources", [])
        and (verb in rule.get("verbs", []) or "*" in rule.get("verbs", [])))


def _detect(doc: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in doc.get("items", [doc]):
        name = item.get("metadata", {}).get("name", "?")
        rules = item.get("rules", [])
        secrets_read = any(_grants(r, "secrets", "get") or _grants(r, "secrets", "list")
                           for r in rules)
        nodes_patch = any(_grants(r, "nodes", "patch") for r in rules)
        if secrets_read and nodes_patch:
            findings.append({
                "sev": "high",
                "title": f"ClusterRole「{name}」可集群级读 Secrets 并 patch 节点（横向原语）",
                "detail": "secrets:get/list=true，nodes:patch=true → 任意命名空间凭据可取，"
                          "叠加节点 patch 可固化持久化（设计基线第 11 节 LWS 条目）",
            })
        elif secrets_read:
            findings.append({
                "sev": "medium",
                "title": f"ClusterRole「{name}」具备集群级 Secrets 读权",
                "detail": "secrets:get/list=true → 跨命名空间横向读取凭据（设计基线第 11 节 LWS 条目）",
            })
    return findings


def _secrets_target_manifest(marker: str) -> str:
    return (
        "# TRIDENT 凭据面读取演示（真实集群为 kubectl get secret -A 的目标清单）\n"
        f"trident-marker: {marker}\n"
        "targets:\n"
        "  - namespace: train\n"
        "    secret: registry-pull-secret\n"
        "  - namespace: train\n"
        "    secret: hf-token\n"
        "  - namespace: kube-system\n"
        "    secret: cloud-controller-credentials\n"
    )


def _demo(ctx: dict, params: dict) -> list[dict[str, Any]]:
    target = Path(params["demo_target"])
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(
        f"{ctx['meta']['key']}-demo", [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    target.write_text(_secrets_target_manifest(ctx["marker"]), encoding="utf-8")
    return [{
        "sev": "high",
        "title": "集群级 Secrets 读取演示已执行（backup-write + 可回滚）",
        "detail": f"目标凭据清单已落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中将逐一读取（内容脱敏存证），回滚=清理由此产生的证据文件",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：LWS 横向检测命中 {len(findings)} 项"
    if params.get("mode") == "backup-write":
        findings += _demo(ctx, params)
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-detection.json"
    art.write_text(json.dumps({
        "fixture": str(fixture), "findings": findings, "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
