"""宽 ServiceAccount 提权：can-i 矩阵检测 + backup-write 特权 Pod 清单演示。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "cani-matrix.json"


def _allowed(doc: dict, verb: str, resource: str) -> dict | None:
    for r in doc.get("rules", []):
        if r.get("verb") == verb and r.get("resource") == resource and r.get("allowed"):
            return r
    return None


def _detect(doc: dict) -> list[dict[str, Any]]:
    subject = doc.get("subject", "?")
    grants = []
    for verb, res in (("create", "pods"), ("create", "pods/exec"),
                      ("create", "rolebindings"), ("get", "secrets")):
        if _allowed(doc, verb, res):
            grants.append(f"{verb}:{res}")
    findings: list[dict[str, Any]] = []
    if {"create:pods", "create:pods/exec"} <= set(grants):
        findings.append({
            "sev": "high",
            "title": f"ServiceAccount「{subject}」可创建 Pod 与 exec（提权到节点原语齐备）",
            "detail": f"授权项: {', '.join(grants)} → 提交特权 Pod / exec 进宿主面"
                      "（设计基线第 11 节宽 SA 条目）",
        })
    elif "create:rolebindings" in grants or "create:pods" in grants:
        findings.append({
            "sev": "medium",
            "title": f"ServiceAccount「{subject}」存在越权授权项",
            "detail": f"授权项: {', '.join(grants)}（设计基线第 11 节宽 SA 条目）",
        })
    return findings


def _privileged_pod_manifest(marker: str) -> str:
    return (
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: inkblade-sa-escape-demo\n"
        "  namespace: train\n"
        "  annotations:\n"
        f"    inkblade-marker: {marker}\n"
        "spec:\n"
        "  restartPolicy: Never\n"
        "  containers:\n"
        "    - name: escape\n"
        "      image: busybox\n"
        "      command: [sh, -c, 'echo host-escape-proof > /host/inkblade-proof']\n"
        "      securityContext: {privileged: true}\n"
        "      volumeMounts:\n"
        "        - {name: host-root, mountPath: /host}\n"
        "  volumes:\n"
        "    - name: host-root\n"
        "      hostPath: {path: /}\n"
    )


def _demo(ctx: dict, params: dict) -> list[dict[str, Any]]:
    target = Path(params["demo_target"])
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(
        f"{ctx['meta']['key']}-demo", [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    target.write_text(_privileged_pod_manifest(ctx["marker"]), encoding="utf-8")
    return [{
        "sev": "high",
        "title": "特权 Pod 创建演示已执行（backup-write + 可回滚）",
        "detail": f"特权 Pod 清单已落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中将以该 SA 提交，回滚=删除演示 Pod",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：宽 SA 检测命中 {len(findings)} 项"
    if params.get("mode") == "backup-write":
        findings += _demo(ctx, params)
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-detection.json"
    art.write_text(json.dumps({
        "fixture": str(fixture), "subject": doc.get("subject"),
        "findings": findings, "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
