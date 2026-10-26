"""secret-scanner — manifest/configmap/env 明文凭据扫描（三态脱敏，raw 不落证据）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, pods, env_pairs = _C.section, _C.pods, _C.env_pairs


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from inkblade.kubetrail.manifestscan import scan_configmaps, scan_env, scan_manifests

    out: list[dict] = []
    manifests = section(snapshot, "manifests")
    report = scan_manifests(manifests)
    out += report["findings"]
    cm_report = scan_configmaps(section(snapshot, "configmaps"))
    for hit in cm_report["findings"]:
        out.append({**hit, "title": "ConfigMap " + hit["title"]})
    for pod in pods(snapshot):
        for hit in scan_env(env_pairs(pod)):
            out.append({
                "sev": "critical" if hit["kind"] in ("aws-access-key", "aws-secret-key",
                                                     "private-key", "gcp-service-account") else "high",
                "title": f"{pod.get('namespace')}/{pod.get('name')} 环境变量明文凭据："
                         f"{hit['kind']}（{hit['redact']}）",
                "detail": f"环境变量 {hit.get('env')} 命中 {hit['kind']}；容器内可读。",
                "evidence": f"pod={pod.get('name')} env={hit.get('env')}",
                "secret_kind": hit["kind"], "redact": hit["redact"],
                "metadata": hit["metadata"],
                "mapping": "trufflehog/gitleaks 规则面（CM-34）；KubeTrail 凭据采集",
                "fix": "使用工作负载身份/外部密钥管理（ESO/Vault），禁 env 注入长期凭据",
            })
    # 去重（同 kind + redact + evidence）
    seen = set()
    unique = []
    for item in out:
        key = (item.get("secret_kind") or item.get("kind"), item.get("redact"), item.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def extra(snapshot: dict, findings: list[dict]) -> dict:
    kinds: dict[str, int] = {}
    for item in findings:
        kind = item.get("secret_kind") or item.get("kind") or "unknown"
        kinds[kind] = kinds.get(kind, 0) + 1
    return {"by_kind": kinds, "scanned_manifests": len(section(snapshot, "manifests")),
            "scanned_configmaps": len(section(snapshot, "configmaps")),
            "scanned_pods": len(pods(snapshot))}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="密钥扫描", extra=extra)
