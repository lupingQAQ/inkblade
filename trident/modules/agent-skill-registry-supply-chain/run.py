# -*- coding: utf-8 -*-
"""R02 Agent Skill 注册表供应链检查（只读快照）。"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "agent-skill-registry-supply-chain"
_REMOTE_EXEC = re.compile(r"(curl|wget)\s+[^|]+\|\s*(sh|bash|python|node)", re.I)
_INJECTION = re.compile(r"(ignore (all|previous) instructions|do not mention|exfiltrat|"
                        r"send .* to http|base64 -d|eval\()", re.I)


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    registry = _C.section(doc, "skill_registry", default={})
    if isinstance(registry, dict) and "registry" in registry:
        reg = registry.get("registry") or {}
        skills = [s for s in (registry.get("skills") or []) if isinstance(s, dict)]
    else:
        reg = registry if isinstance(registry, dict) else {}
        skills = _C.items(registry, "skills")
    findings: list[dict] = []

    if not _C.as_bool(reg.get("signature_required")):
        findings.append(_C.finding(
            "high", "Skill 注册表未强制签名",
            {"registry": reg},
            evidence="registry.signature_required=false",
            mapping="Agent skill 供应链",
            source="USENIX Security 2026 I08 / OWASP Agentic Skills AST02",
            fix="要求发布者签名（Sigstore/cosign）并在安装前验签",
        ))
    allow = [str(x) for x in (reg.get("publisher_allowlist") or [])]
    if not allow:
        findings.append(_C.finding(
            "medium", "未配置发布者白名单",
            {"registry": reg},
            evidence="publisher_allowlist empty",
            mapping="发布者信任",
            source="OWASP Agentic Skills AST02",
            fix="维护内部发布者 allowlist；未知发布者进入人工评审",
        ))
    for skill in skills:
        name = str(skill.get("name") or "?")
        perms = skill.get("permissions") or {}
        issues = []
        if not str(skill.get("signature") or ""):
            issues.append("unsigned")
        if str(skill.get("publisher") or "").lower() not in [a.lower() for a in allow] and allow:
            issues.append("publisher-not-allowed")
        if _C.wildcard(perms.get("fs")) or _C.wildcard(perms.get("net")) or _C.as_bool(perms.get("exec")):
            issues.append("wildcard-permissions")
        if _C.as_bool(skill.get("hidden_instructions")):
            issues.append("hidden-instructions")
        if _REMOTE_EXEC.search(str(skill.get("install_script") or "")):
            issues.append("remote-install-exec")
        if not _C.as_bool(skill.get("pinned")):
            issues.append("unpinned")
        previous = str(skill.get("previous_sha256") or "")
        current = str(skill.get("sha256") or "")
        if previous and current and previous != current:
            issues.append("hash-changed-rug-pull")
        if issues:
            sev = "critical" if "remote-install-exec" in issues else "high"
            findings.append(_C.finding(
                sev, f"Skill 供应链风险：{name}",
                {"skill": skill, "issues": issues},
                evidence=f"skill={name} issues={','.join(issues)}",
                mapping="Agent skill 安装前静态检查",
                source="USENIX Security 2026 I08 / I35 / OWASP AST02",
                fix="移除未签名/通配权限；固定版本与哈希；安装脚本白名单；人工复核隐藏指令",
            ))
    for skill in skills:
        blob = str(skill.get("description") or "") + " " + str(skill.get("readme") or "")
        if _INJECTION.search(blob):
            findings.append(_C.finding(
                "high", f"Skill 文档包含可疑指令：{skill.get('name')}",
                {"skill": skill.get("name"), "sample": blob[:300]},
                evidence="prompt-injection marker in skill docs",
                mapping="Skill 文档注入",
                source="Black Hat USA 2026 I35",
                fix="把 skill 文档当不可信输入；安装前扫描/隔离",
            ))

    extra = {
        "skills": len(skills),
        "signature_required": _C.as_bool(reg.get("signature_required")),
        "publisher_allowlist": len(allow),
        "risky": sum(1 for f in findings if f["sev"] in ("critical", "high")),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Agent Skill 注册表供应链检查", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
