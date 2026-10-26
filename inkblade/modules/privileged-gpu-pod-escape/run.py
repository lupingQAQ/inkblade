"""特权 GPU Pod 宿主逃逸：特权原语组合检测 + backup-write 宿主 marker 证明。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "privileged-pods.json"


def _pod_primitives(pod: dict) -> list[str]:
    prim: list[str] = []
    spec = pod.get("spec", {})
    if spec.get("hostPID"):
        prim.append("hostPID")
    if spec.get("hostIPC"):
        prim.append("hostIPC")
    if spec.get("hostNetwork"):
        prim.append("hostNetwork")
    for vol in spec.get("volumes", []):
        hp = vol.get("hostPath", {}).get("path", "")
        if hp:
            prim.append(f"hostPath:{hp}")
    for c in spec.get("containers", []):
        sc = c.get("securityContext", {})
        if sc.get("privileged"):
            prim.append("privileged")
        for cap in sc.get("capabilities", {}).get("add", []):
            prim.append(f"cap:{cap}")
        gpus = c.get("resources", {}).get("limits", {}).get("nvidia.com/gpu")
        if gpus:
            prim.append(f"gpu-limit:{gpus}")
    return prim


def _detect(doc: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pod in doc.get("items", []):
        name = pod.get("metadata", {}).get("name", "?")
        prim = _pod_primitives(pod)
        escape_kit = [p for p in prim if p.startswith(("hostPath:/", "hostPath:/var/run",
                                                       "privileged", "hostPID", "hostIPC", "cap:"))]
        if len(escape_kit) >= 2:
            findings.append({
                "sev": "high",
                "title": f"Pod「{name}」特权原语组合可宿主逃逸",
                "detail": f"原语: {', '.join(prim)} → hostPath/或特权+caps 即宿主 root"
                          "（设计基线第 11 节特权部署条目）",
            })
    return findings


def _demo(ctx: dict, params: dict) -> list[dict[str, Any]]:
    target = Path(params["demo_target"])
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(
        f"{ctx['meta']['key']}-demo", [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    payload = (
        f"TRIDENT host-escape proof {ctx['marker']}\n"
        "宿主挂载点写入证明：经由 hostPath:/ + privileged 容器对宿主根的可写性验证\n"
    )
    target.write_text(payload, encoding="utf-8")
    return [{
        "sev": "high",
        "title": "宿主逃逸 marker 证明已写入（backup-write + 可回滚）",
        "detail": f"marker 文件已落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中路径为宿主 hostPath 挂载点，回滚=删除 marker 文件",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：特权逃逸检测命中 {len(findings)} 项"
    if params.get("mode") == "backup-write":
        findings += _demo(ctx, params)
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-detection.json"
    art.write_text(json.dumps({
        "fixture": str(fixture),
        "pods": [{"name": p.get("metadata", {}).get("name"), "primitives": _pod_primitives(p)}
                 for p in doc.get("items", [])],
        "findings": findings, "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
