# -*- coding: utf-8 -*-
"""_surface_common — K8s 攻击面模块族共享库（仅标准库）。

职责：
- snapshot 装载（dict / JSON 路径）；
- finding 构造（与 runner.add_finding / _recon-common 同字段）；
- RBAC 判定：can-i 条目 → ``allows(subject, verb, resource)`` / ``subjects_with``；
- Pod 面提取：特权/能力/hostPath/host 标志/自动挂载 token/seccomp；
- 脱敏：``mask``（前缀 + 末 4 位）、``entropy``（密钥扫描）；
- ``run_surface`` 统一入口：缺 snapshot 抛 ValueError，输出 {summary, findings, artifacts}。

模块全部为纯 Python 快照分析（默认只读），不发起网络请求、不写集群。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from inkblade.kubetrail.redact3 import entropy, mask

SEVS = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVS)}


# ---------------------------------------------------------------- 输入
def load_snapshot(params: dict) -> dict:
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 lab/fixtures/attack-surface/*.json 路径）")
    if isinstance(snap, dict):
        return snap
    return json.loads(Path(str(snap)).read_text(encoding="utf-8"))


def section(snapshot: dict, *names: str) -> list:
    """读取第一个存在的列表节（支持别名）。"""
    for name in names:
        value = snapshot.get(name)
        if isinstance(value, list):
            return value
    return []


def mapping(snapshot: dict, *names: str) -> dict:
    for name in names:
        value = snapshot.get(name)
        if isinstance(value, dict):
            return value
    return {}


# ---------------------------------------------------------------- findings
def finding(sev: str, title: str, detail: str = "", *, evidence: str = "",
            mapping_text: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {"sev": sev, "title": title, "detail": detail}
    if evidence:
        item["evidence"] = evidence
    if mapping_text:
        item["mapping"] = mapping_text
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def summarize(family: str, findings: list[dict], *, extra: dict | None = None,
              source: str = "") -> dict:
    counts = Counter(f.get("sev", "info") for f in findings)
    top = min((f.get("sev", "info") for f in findings),
              key=lambda s: _SEV_RANK.get(s, len(_SEV_RANK)), default="info")
    dist = {sev: counts[sev] for sev in SEVS if counts.get(sev)}
    summary = {
        "family": family,
        "findings": len(findings),
        "severity": dist,
        "top": top if findings else "none",
        "source": source,
    }
    summary.update(extra or {})
    return summary


def run_surface(ctx: dict, params: dict, analyze, *, family: str,
                extra=None) -> dict:
    snapshot = load_snapshot(params)
    findings = list(analyze(snapshot, params) or [])
    src = params.get("snapshot")
    meta = extra(snapshot, findings) if extra else {}
    summary = summarize(family, findings, extra=meta,
                        source=src if isinstance(src, str) else "<inline snapshot>")
    return {"summary": json.dumps(summary, ensure_ascii=False), "findings": findings,
            "artifacts": []}


# ---------------------------------------------------------------- RBAC
def allows(entry: dict, verb: str, resource: str) -> bool:
    """can-i 条目是否允许 verb+resource（支持 * 与 resource/subresource）。"""
    allowed = [str(a).strip().lower() for a in (entry.get("allowed") or [])]
    verb = verb.lower()
    resource = resource.lower()
    for item in allowed:
        if item in ("*", "* *", "*/*"):
            return True
        parts = item.split()
        if len(parts) != 2:
            continue
        v, r = parts
        if v not in ("*", verb):
            continue
        if r in ("*", resource):
            return True
        if r.endswith("/*") and resource.startswith(r[:-1]):
            return True
        if resource == r.split("/")[0] and r.split("/")[-1] == "*":
            return True
    return False


def subjects_with(snapshot: dict, verb: str, resource: str) -> list[str]:
    out = []
    for entry in section(snapshot, "cani"):
        if allows(entry, verb, resource):
            out.append(str(entry.get("subject", "?")))
    return sorted(set(out))


def wildcard_subjects(snapshot: dict) -> list[str]:
    out = []
    for entry in section(snapshot, "cani"):
        allowed = [str(a).strip() for a in (entry.get("allowed") or [])]
        if any(a == "*" or a == "* *" or a.startswith("* ") for a in allowed):
            out.append(str(entry.get("subject", "?")))
    return sorted(set(out))


# ---------------------------------------------------------------- Pod 面
def pods(snapshot: dict) -> list[dict]:
    return [p for p in section(snapshot, "pods") if isinstance(p, dict)]


def pod_id(pod: dict) -> str:
    return f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"


def containers(pod: dict) -> list[dict]:
    return [c for c in (pod.get("containers") or []) if isinstance(c, dict)]


def pod_caps(pod: dict) -> set[str]:
    caps: set[str] = set()
    for container in containers(pod):
        sc = container.get("securityContext") or {}
        caps |= {str(c).upper() for c in ((sc.get("capabilities") or {}).get("add") or [])}
    return caps


def is_privileged(pod: dict) -> bool:
    return any(bool((c.get("securityContext") or {}).get("privileged")) for c in containers(pod))


def seccomp_profile(pod: dict) -> str:
    profiles = []
    for container in containers(pod):
        sc = container.get("securityContext") or {}
        profile = (sc.get("seccompProfile") or {}).get("type") or pod.get("seccompProfile") or ""
        profiles.append(str(profile or "unset"))
    return ",".join(sorted(set(profiles))) or "unset"


def host_paths(pod: dict) -> list[dict]:
    out = []
    for volume in pod.get("volumes") or []:
        hp = (volume.get("hostPath") or {}).get("path")
        if hp:
            out.append({"name": volume.get("name", ""), "path": hp})
    return out


def automount_token(pod: dict) -> bool:
    value = pod.get("automountServiceAccountToken")
    if value is None:
        return True  # 默认挂载
    return bool(value)


def env_pairs(pod: dict) -> list[tuple[str, str]]:
    out = []
    for container in containers(pod):
        for env in container.get("env") or []:
            if isinstance(env, dict) and env.get("name"):
                out.append((str(env["name"]), str(env.get("value", ""))))
    return out


# ---------------------------------------------------------------- 脱敏/熵
# mask/entropy 统一来自 inkblade.kubetrail.redact3（三态脱敏单一实现）

SECRET_PATTERNS = ()  # 规则单一来源：inkblade.kubetrail.manifestscan.SECRET_RULES


def scan_secrets(text: str) -> list[dict]:
    """对文本做规则 + 熵扫描（委托 KubeTrail manifestscan，保持单一规则源）。"""
    from inkblade.kubetrail.manifestscan import scan_text

    return [{"kind": hit["kind"], "match": hit["redact"],
             "entropy": hit["metadata"]["entropy"]} for hit in scan_text(text or "")]


def blob(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def section_names(snapshot: dict) -> list[str]:
    return sorted(k for k in snapshot.keys() if not k.startswith("_"))
