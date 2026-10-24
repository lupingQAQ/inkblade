"""容器运行时 Socket 逃逸：socket hostPath 检测 + backup-write marker 证明。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO / "lab" / "fixtures" / "perm" / "privileged-pods.json"

_RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "podman", "/run/containerd")


def _socket_mounts(pod: dict) -> list[dict[str, str]]:
    mounts = []
    vol_names = {v.get("name"): v.get("hostPath", {}).get("path", "")
                 for v in pod.get("spec", {}).get("volumes", []) if v.get("hostPath")}
    for name, host_path in vol_names.items():
        if any(s in host_path for s in _RUNTIME_SOCKETS):
            mount = next((m.get("mountPath") for c in pod.get("spec", {}).get("containers", [])
                          for m in c.get("volumeMounts", []) if m.get("name") == name), "?")
            mounts.append({"volume": name, "host_path": host_path, "mount_path": mount})
    return mounts


def _detect(doc: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pod in doc.get("items", []):
        name = pod.get("metadata", {}).get("name", "?")
        mounts = _socket_mounts(pod)
        for m in mounts:
            findings.append({
                "sev": "high",
                "title": f"Pod「{name}」挂载容器运行时 socket（宿主逃逸原语）",
                "detail": f"hostPath {m['host_path']} → 容器内 {m['mount_path']}；"
                          "经运行时 API 可在宿主侧拉起特权容器（总纲第 11 节 socket 逃逸条目）",
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
        f"TRIDENT runtime-socket proof {ctx['marker']}\n"
        "经 containerd.sock 挂载点的可写性/可达性验证证明（对应宿主面特权容器创建能力）\n"
    )
    target.write_text(payload, encoding="utf-8")
    return [{
        "sev": "high",
        "title": "运行时 socket 逃逸 marker 证明已写入（backup-write + 可回滚）",
        "detail": f"marker 文件已落盘 {target}（marker={ctx['marker']}），"
                  "真实集群中为 socket 挂载路径下的证明文件，回滚=删除 marker",
    }]


def run(ctx: dict, params: dict) -> dict:
    fixture = params.get("fixture") or str(_DEFAULT_FIXTURE)
    doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
    findings = _detect(doc)
    summary = f"解析 {fixture}：socket 逃逸检测命中 {len(findings)} 项"
    if params.get("mode") == "backup-write":
        findings += _demo(ctx, params)
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-detection.json"
    art.write_text(json.dumps({
        "fixture": str(fixture),
        "socket_mounts": [{"pod": p.get("metadata", {}).get("name"), **m}
                          for p in doc.get("items", []) for m in _socket_mounts(p)],
        "findings": findings, "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
