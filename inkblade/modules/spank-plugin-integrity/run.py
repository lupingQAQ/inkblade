# -*- coding: utf-8 -*-
"""SPANK 插件加载完整性审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "spank-plugin-integrity"
_UNTRUSTED = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/srv/images/")


def _parse_plugstack(text: str) -> list[dict]:
    out = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        mode = parts[0].lower()
        if mode not in ("optional", "required"):
            mode, path = "required", parts[0]
        else:
            path = parts[1]
        out.append({"mode": mode, "path": path, "args": parts[2:]})
    return out


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    text_path, text = _C.find_file(snap, "plugstack.conf")
    plugins = _parse_plugstack(text)
    findings: list[dict] = []

    conf_meta = _C.meta(snap, "plugstack.conf")
    if conf_meta and _C.world_writable(conf_meta.get("mode")):
        findings.append(_C.finding(
            "high", "plugstack.conf 全局可写",
            {"path": text_path, "meta": conf_meta},
            evidence=f"plugstack.conf mode={conf_meta.get('mode')}",
            mapping="SPANK 配置完整性",
            fix="plugstack.conf root:root 0644；纳入配置基线",
        ))
    if not plugins:
        findings.append(_C.finding(
            "info", "未发现 SPANK 插件（无插件面或导出不完整）",
            {"path": text_path},
            evidence="plugstack.conf empty or missing",
            mapping="SPANK 面清点",
            fix="若启用 SPANK，补充插件清单与签名校验",
        ))
    for item in plugins:
        path = item["path"]
        meta = _C.meta(snap, Path(path).name, path)
        mode = _C.parse_mode(meta.get("mode"))
        owner = str(meta.get("owner") or "")
        issues = []
        if not path.startswith("/"):
            issues.append("relative-path")
        if path.lower().startswith(_UNTRUSTED):
            issues.append("user-writable-location")
        if mode is not None and mode & 0o022:
            issues.append("group-or-world-writable")
        if owner and owner not in ("root", "slurm"):
            issues.append(f"owner={owner}")
        if meta.get("signed") is False:
            issues.append("unsigned")
        if not meta:
            issues.append("missing-metadata")
        if issues:
            findings.append(_C.finding(
                "high", f"SPANK 插件加载路径不可信：{path}",
                {"plugin": item, "meta": meta, "issues": issues},
                evidence=f"{path} issues={','.join(issues)}",
                mapping="SPANK 插件代码执行 / 供应链",
                fix="插件放 /opt/slurm/plugins，root:root 0755，签名校验；禁止用户目录与 optional 降级",
            ))
    if "optional" in text.lower():
        findings.append(_C.finding(
            "medium", "plugstack.conf 使用 optional 插件（失败静默降级）",
            {"lines": [p for p in plugins if p["mode"] == "optional"]},
            evidence="optional plugin present",
            mapping="插件加载失败可见性",
            fix="安全关键插件改 required；optional 仅用于非安全功能",
        ))
    merged_conf = _C.conf(snap, "slurm.conf")
    if "ld_preload" in (text + " " + _C.get(merged_conf, "SlurmdParameters")).lower():
        findings.append(_C.finding(
            "critical", "插件配置出现 LD_PRELOAD 注入",
            {"plugstack": text[:500]},
            evidence="LD_PRELOAD in plugstack/slurmd parameters",
            mapping="动态链接劫持",
            fix="移除 LD_PRELOAD；用受签名插件机制",
        ))

    extra = {
        "plugins": len(plugins),
        "required": sum(1 for p in plugins if p["mode"] == "required"),
        "optional": sum(1 for p in plugins if p["mode"] == "optional"),
        "untrusted": sum(1 for f in findings if f["sev"] == "high"),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "SPANK 插件加载完整性审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
