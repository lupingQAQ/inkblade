"""vLLM Operator RBAC 提权：ClusterRole 检测 + backup-write RoleBinding 创建演示。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "clusterroles.json"

_RBAC_GROUP = "rbac.authorization.k8s.io"
_TARGET_RESOURCES = {"roles", "rolebindings"}
_WRITE_VERBS = {"create", "update", "patch", "delete"}


def _detect(doc: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in doc.get("items", [doc]):
        name = item.get("metadata", {}).get("name", "?")
        for rule in item.get("rules", []):
            groups = set(rule.get("apiGroups", []))
            resources = set(rule.get("resources", []))
            verbs = set(rule.get("verbs", []))
            if (_RBAC_GROUP in groups and _TARGET_RESOURCES & resources
                    and _WRITE_VERBS & verbs):
                findings.append({
                    "sev": "high",
                    "title": f"ClusterRole「{name}」具备集群级 RBAC 对象写权（提权原语）",
                    "detail": (
                        f"apiGroups={sorted(groups)} resources={sorted(resources)} "
                        f"verbs={sorted(verbs)} → 可创建 RoleBinding 绑定 cluster-admin 接管集群"
                        "（设计基线第 11 节 vLLM Operator 条目）"
                    ),
                })
    return findings


def _rolebinding_manifest(marker: str) -> str:
    return (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: RoleBinding\n"
        "metadata:\n"
        f"  name: inkblade-rbac-demo\n"
        "  namespace: train\n"
        "  annotations:\n"
        f"    inkblade-marker: {marker}\n"
        "subjects:\n"
        "  - kind: ServiceAccount\n"
        "    name: pipeline-runner\n"
        "    namespace: train\n"
        "roleRef:\n"
        "  kind: ClusterRole\n"
        "  name: cluster-admin\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
    )


def _demo(ctx: dict, params: dict) -> list[dict[str, Any]]:
    target = Path(params["demo_target"])
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(
        f"{ctx['meta']['key']}-demo", [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    target.write_text(_rolebinding_manifest(ctx["marker"]), encoding="utf-8")
    return [{
        "sev": "high",
        "title": "RoleBinding 创建演示已执行（backup-write + 可回滚）",
        "detail": f"已将接管用 RoleBinding 清单落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中将通过 kubectl apply 生效，回滚=删除该 RoleBinding",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：RBAC 提权检测命中 {len(findings)} 项"
    if params.get("mode") == "backup-write":
        findings += _demo(ctx, params)
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-detection.json"
    art.write_text(json.dumps({
        "fixture": str(fixture), "findings": findings,
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
