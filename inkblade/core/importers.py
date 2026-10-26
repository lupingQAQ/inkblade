# -*- coding: utf-8 -*-
"""外部扫描器输入适配器（CM-13）：Trivy / Syft / grype JSON → findings 归一入证据链。

- ``detect`` 按结构特征识别（不依赖文件名）；
- ``normalize`` 统一为 InkBlade finding（sev/title/detail/evidence），severity 映射
  CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN → critical/high/medium/low/info；
- ``ingest`` 把归一结果写入 run：先落 ``imports/<tool>-<sha8>.json``，再经
  ``run.add_step`` 归档（第三层证据），最后 ``run.add_finding``（evidence_path 指向归档）；
- 幂等：同 run 内相同工具 + 相同内容 SHA 只导入一次；
- ``sync_scopesentry`` 把 ScopeSentry 项目/任务/资产清单归一为工作区资产库（assets.db）。

只读输入、不发网络、不调用扫描器本身。
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from . import jsonio
from .discovery import AssetInventory

SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
           "LOW": "low", "UNKNOWN": "info", "NEGLIGIBLE": "info"}


class ScanImportError(ValueError):
    """导入文档非法。"""


def detect(doc: dict) -> str:
    if not isinstance(doc, dict):
        raise ScanImportError("扫描器输入必须是 JSON 对象")
    if isinstance(doc.get("Results"), list) and any(
            isinstance(r, dict) and "Vulnerabilities" in r for r in doc["Results"]):
        return "trivy"
    if isinstance(doc.get("matches"), list) and any(
            isinstance(m, dict) and "vulnerability" in m for m in doc["matches"]):
        return "grype"
    if isinstance(doc.get("artifacts"), list) and ("descriptor" in doc or "schema" in doc
                                                   or "source" in doc):
        return "syft"
    raise ScanImportError("无法识别的扫描器文档（支持 Trivy / Syft / grype JSON）")


def _sev(value: Any) -> str:
    return SEV_MAP.get(str(value or "").upper(), "info")


def normalize(doc: dict, tool: str = "") -> dict:
    tool = tool or detect(doc)
    findings: list[dict] = []
    if tool == "trivy":
        for result in doc.get("Results") or []:
            target = result.get("Target") or result.get("Class") or ""
            for v in result.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID") or v.get("ID") or "?"
                pkg = v.get("PkgName") or "?"
                version = v.get("InstalledVersion") or "?"
                detail = " | ".join(str(x) for x in (
                    v.get("Title"), v.get("Description"),
                    f"fixed={v.get('FixedVersion')}" if v.get("FixedVersion") else "",
                    v.get("PrimaryURL")) if x)
                findings.append({
                    "sev": _sev(v.get("Severity")),
                    "title": f"{vid} {pkg}@{version}",
                    "detail": detail or f"{vid} in {pkg}@{version}",
                    "evidence": f"{target} {pkg}:{version}",
                })
    elif tool == "grype":
        for m in doc.get("matches") or []:
            v = m.get("vulnerability") or {}
            a = m.get("artifact") or {}
            vid = v.get("id") or "?"
            name = a.get("name") or "?"
            version = a.get("version") or "?"
            findings.append({
                "sev": _sev(v.get("severity")),
                "title": f"{vid} {name}@{version}",
                "detail": " | ".join(str(x) for x in (v.get("description"),
                                                      f"fixed={v.get('fix', {}).get('versions')}"
                                                      if (v.get("fix") or {}).get("versions") else "")
                                     if x),
                "evidence": f"{m.get('artifact', {}).get('type', '')} {name}:{version}",
            })
    elif tool == "syft":
        for a in doc.get("artifacts") or []:
            name = a.get("name") or "?"
            version = a.get("version") or "?"
            findings.append({
                "sev": "info", "title": f"SBOM 组件 {name}@{version}",
                "detail": f"type={a.get('type', '')} language={a.get('language', '')} "
                          f"purl={a.get('purl', '')}",
                "evidence": f"syft artifact {name}:{version}",
            })
    else:
        raise ScanImportError(f"未知工具 {tool!r}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    return {"tool": tool, "findings": findings, "count": len(findings), "counts": counts,
            "source": {"tool": tool, "detected": True, "ts": time.time()}}


def _sha(doc: dict) -> str:
    return hashlib.sha256(json.dumps(doc, ensure_ascii=False, sort_keys=True,
                                     default=str).encode("utf-8")).hexdigest()


def _index(run) -> dict:
    p = Path(run.dir) / "imports" / "index.json"
    doc = jsonio.read_json(p, {})
    return doc if isinstance(doc, dict) else {}


def _save_index(run, doc: dict) -> None:
    jsonio.write_json(Path(run.dir) / "imports" / "index.json", doc)


def ingest(store, run_name: str, doc: dict, *, source: str = "") -> dict:
    """归一 + 归档 + 写 findings（幂等）。"""
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise ScanImportError(f"run 不存在：{run_name}") from exc
    normalized = normalize(doc)
    sha = _sha(doc)
    tool = normalized["tool"]
    idx = _index(run)
    key = f"{tool}:{sha}"
    if key in idx:
        return {"run": run_name, "tool": tool, "sha256": sha, "skipped": True,
                "findings": idx[key].get("findings", 0), "step": idx[key].get("step", "")}
    out_dir = Path(run.dir) / "imports"
    out_dir.mkdir(parents=True, exist_ok=True)
    art = out_dir / f"{tool}-{sha[:8]}.json"
    art.write_text(json.dumps({"tool": tool, "source": source, "normalized": normalized,
                               "raw": doc}, ensure_ascii=False, indent=1), encoding="utf-8")
    step = run.add_step(f"import-{tool}", "external-scan-import",
                        {"tool": tool, "source": source, "sha256": sha},
                        f"导入 {tool} 结果：{normalized['count']} 条",
                        artifacts=[art])
    for f in normalized["findings"]:
        run.add_finding(f"import-{tool}", sev=f["sev"], title=f["title"],
                        detail=f["detail"], evidence_path=step["archive"])
    run.log_action("importer", "import", tool,
                   {"sha256": sha, "findings": normalized["count"], "source": source}, "success")
    idx[key] = {"findings": normalized["count"], "step": step["archive"], "ts": time.time()}
    _save_index(run, idx)
    jsonio.append_audit(store, "importer", "import.scan", tool,
                        {"run": run_name, "sha256": sha, "count": normalized["count"]}, "ok")
    return {"run": run_name, "tool": tool, "sha256": sha, "skipped": False,
            "findings": normalized["count"], "counts": normalized["counts"],
            "step": step["archive"], "artifact": str(art)}


def sync_scopesentry(store, doc: dict, *, source: str = "scopesentry") -> dict:
    """ScopeSentry 项目/任务/资产 → 资产库（只读输入，不执行扫描）。"""
    if not isinstance(doc, dict):
        raise ScanImportError("ScopeSentry 文档必须是对象")
    services, namespaces = [], []
    for ns in doc.get("projects") or []:
        name = ns.get("name") if isinstance(ns, dict) else str(ns)
        if name:
            namespaces.append(str(name))
    for asset in doc.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name") or asset.get("host") or asset.get("addr")
        if not name:
            continue
        services.append({"name": str(name),
                         "namespace": str(asset.get("namespace") or asset.get("project") or "default"),
                         "addr": str(asset.get("addr") or asset.get("host") or ""),
                         "port": asset.get("port"),
                         "labels": dict(asset.get("labels") or {}),
                         "product": str(asset.get("product") or "")})
    for task in doc.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        target = task.get("target") or task.get("host")
        if target:
            services.append({"name": str(task.get("name") or target),
                             "namespace": str(task.get("project") or "default"),
                             "addr": str(target), "port": task.get("port"),
                             "labels": {"source": "scopesentry-task"}})
    if not services and not namespaces:
        raise ScanImportError("ScopeSentry 文档无 assets/projects/tasks")
    seeds = {}
    if services:
        seeds["services"] = services
    if namespaces:
        seeds["namespaces"] = sorted(set(namespaces))
    diff = AssetInventory(store).ingest(seeds, source=source)
    jsonio.append_audit(store, "importer", "sync.scopesentry", "",
                        {"services": len(services), "namespaces": len(namespaces)}, "ok")
    return {"source": source, "diff": diff, "services": len(services),
            "namespaces": len(namespaces)}
