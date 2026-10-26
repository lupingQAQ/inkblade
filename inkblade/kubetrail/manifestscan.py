# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""manifest / configmap 云密钥扫描（trufflehog/gitleaks 面裁剪到 ML 栈常用云凭据）。

- 规则 + 熵双通道；命中值一律 **脱敏**（前4****后4）+ SHA256/长度/熵元数据；
- 支持 K8s manifest 文档（Deployment/Pod/Secret/ConfigMap）与裸文本；
- 可选 ``TriStore``：显式启用时才把 raw 落到受控目录，默认不落明文；
- 返回 findings（sev/title/detail/evidence/secret_kind/redact/metadata/path）。

覆盖类型：AWS AK/SK、GCP service_account JSON、Azure client secret、私钥、kubeconfig、
dockerconfigjson、GitHub/Slack/OpenAI token、高熵通用串。
"""

from __future__ import annotations

import json
import re

from .redact3 import TriStore, entropy, mask, metadata

SECRET_RULES = (
    ("aws-access-key", "critical", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", "critical",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("gcp-service-account", "critical",
     re.compile(r'\\?"type\\?"\s*:\s*\\?"service_account\\?"')),
    ("private-key", "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("azure-client-secret", "critical",
     re.compile(r"(?i)azure[_-]?client[_-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9~._-]{20,})")),
    ("kubeconfig", "high", re.compile(r"(?i)(apiVersion:\s*v1\s*\nkind:\s*Config|client-key-data:)")),
    ("dockerconfig", "medium", re.compile(r'"auths"\s*:\s*\{')),
    ("github-token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-key", "high", re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{20,}\b")),
    ("hf-token", "high", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
)

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def scan_text(text: str) -> list[dict]:
    """规则 + 高熵扫描；返回 [{kind, value, redact, metadata}]（value 仅内存用）。"""
    hits: list[dict] = []
    seen: set[str] = set()
    for kind, _sev, rx in SECRET_RULES:
        for match in rx.finditer(text or ""):
            # 捕获组仅在「组本身就是完整密钥」时优先（AK 前缀、kubeconfig 等用整段匹配）
            group = match.group(1) if match.lastindex else None
            value = group if (group and len(group) >= 16) else match.group(0)
            key = f"{kind}:{value}"
            if key in seen:
                continue
            seen.add(key)
            hits.append({"kind": kind, "value": value, "redact": mask(value),
                         "metadata": metadata(value, kind)})
    for token in re.findall(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9])", text or ""):
        if entropy(token) < 4.2:
            continue
        key = f"high-entropy:{token}"
        if key in seen:
            continue
        seen.add(key)
        hits.append({"kind": "high-entropy", "value": token, "redact": mask(token),
                     "metadata": metadata(token, "high-entropy")})
    return hits


def _severity(kind: str) -> str:
    for rule_kind, sev, _rx in SECRET_RULES:
        if rule_kind == kind:
            return sev
    return "medium"


def _doc_text(manifest: dict) -> str:
    doc = manifest.get("doc", manifest)
    if isinstance(doc, str):
        return doc
    return json.dumps(doc, ensure_ascii=False, sort_keys=True)


def scan_manifests(manifests: list[dict], *, store: TriStore | None = None) -> dict:
    findings: list[dict] = []
    by_kind: dict[str, int] = {}
    for manifest in manifests or []:
        path = str(manifest.get("path", "<inline>"))
        kind = str(manifest.get("kind", ""))
        namespace = str(manifest.get("namespace", ""))
        for hit in scan_text(_doc_text(manifest)):
            by_kind[hit["kind"]] = by_kind.get(hit["kind"], 0) + 1
            finding = {
                "sev": _severity(hit["kind"]),
                "title": f"{path}: {hit['kind']} 明文凭据（{hit['redact']}）",
                "detail": (f"{kind}/{namespace} 文档内含 {hit['kind']} 类型敏感值；"
                           f"长度 {hit['metadata']['length']} / 熵 {hit['metadata']['entropy']} / "
                           f"sha256 {hit['metadata']['sha256'][:16]}…"),
                "evidence": f"path={path} kind={kind} ns={namespace}",
                "secret_kind": hit["kind"],
                "redact": hit["redact"],
                "metadata": hit["metadata"],
                "mapping": "凭据窃取面（manifest/configmap 明文密钥）；CDK Credential Access",
            }
            if store is not None:
                finding["ref"] = store.put(hit["value"], kind=hit["kind"])
            findings.append(finding)
    findings.sort(key=lambda f: (_SEV_RANK.get(f["sev"], 9), f["title"]))
    return {"findings": findings, "by_kind": by_kind, "scanned": len(manifests or [])}


def scan_configmaps(configmaps: list[dict]) -> dict:
    """把 ConfigMap data 映射为 manifest 形态后复用扫描。"""
    manifests = [{"path": f"configmap/{cm.get('namespace', 'default')}/{cm.get('name', '?')}",
                  "kind": "ConfigMap", "namespace": cm.get("namespace", ""),
                  "doc": cm.get("data", {})}
                 for cm in configmaps or []]
    return scan_manifests(manifests)


def scan_env(pairs: list[tuple[str, str]]) -> list[dict]:
    hits = []
    for name, value in pairs or []:
        for hit in scan_text(str(value)):
            hits.append({**hit, "env": name})
    return hits
