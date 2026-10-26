"""KubeRay Operator 提权：准 cluster-admin 检测 + backup-write 特权 Pod 清单演示。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "clusterroles.json"


def _rule_grants(rule: dict, group: str, resource: str, verb: str) -> bool:
    return (group in rule.get("apiGroups", [])
            and resource in rule.get("resources", [])
            and (verb in rule.get("verbs", []) or "*" in rule.get("verbs", [])))


def _detect(doc: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in doc.get("items", [doc]):
        name = item.get("metadata", {}).get("name", "?")
        rules = item.get("rules", [])
        ray_wildcard = any(
            "ray.io" in r.get("apiGroups", []) and "*" in r.get("verbs", []) for r in rules)
        pod_create = any(_rule_grants(r, "", "pods", "create") for r in rules)
        exec_create = any(_rule_grants(r, "", "pods/exec", "create") for r in rules)
        if ray_wildcard or (pod_create and exec_create):
            findings.append({
                "sev": "high",
                "title": f"ClusterRole「{name}」为准 cluster-admin（{name} → 特权 Pod）",
                "detail": (
                    f"ray.io 全动词={ray_wildcard}，pods:create={pod_create}，"
                    f"pods/exec:create={exec_create} → 可提交特权 RayCluster/Job 工作负载落到任意节点"
                    "（设计基线第 11 节 KubeRay 条目）"
                ),
            })
    return findings


def _raycluster_privileged_manifest(marker: str) -> str:
    return (
        "apiVersion: ray.io/v1\n"
        "kind: RayCluster\n"
        "metadata:\n"
        "  name: trident-escape-demo\n"
        "  annotations:\n"
        f"    trident-marker: {marker}\n"
        "spec:\n"
        "  headGroupSpec:\n"
        "    template:\n"
        "      spec:\n"
        "        containers:\n"
        "          - name: ray-head\n"
        "            securityContext: {privileged: true}\n"
        "            volumeMounts:\n"
        "              - {name: host-root, mountPath: /host}\n"
        "        volumes:\n"
        "          - name: host-root\n"
        "            hostPath: {path: /}\n"
    )


def _demo(ctx: dict, params: dict) -> list[dict[str, Any]]:
    target = Path(params["demo_target"])
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(
        f"{ctx['meta']['key']}-demo", [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    target.write_text(_raycluster_privileged_manifest(ctx["marker"]), encoding="utf-8")
    return [{
        "sev": "high",
        "title": "特权 RayCluster 创建演示已执行（backup-write + 可回滚）",
        "detail": f"特权 Pod 清单已落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中将由 operator 调和出 privileged Pod，回滚=删除该 RayCluster",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：KubeRay 提权检测命中 {len(findings)} 项"
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
