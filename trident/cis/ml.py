# -*- coding: utf-8 -*-
"""CIS 超出项 — GPU Operator / vLLM / SGLang 部署基线（只读 fixture 判定）。

不属于 CIS Kubernetes Benchmark；作为 ML 集群特有的"部署基线"补充，
独立 catalog / 独立矩阵，避免与 CIS 130 项口径混淆。

来源：NVIDIA GPU Operator 文档（security / DCGM exporter / NFD）、
vLLM OpenAI server 文档（--api-key / --trust-remote-code / metrics）、
SGLang server 文档（api key / metrics / 多租隔离）、K8s Pod Security Standards。
"""
from __future__ import annotations

from trident.cis.engine import _dig, _text, compare, severity_of

_GPU = "gpu-operator"
_VLLM = "vllm"
_SGL = "sglang"
_DEP = "deployment"


def _m(mid, area, title, kind, *, key="", op="eq", value="", field="", scope="",
       scopes=None, remediation="", source="", level=1):
    return {
        "id": mid, "area": area, "title": title, "kind": kind, "key": key,
        "op": op, "value": value, "field": field, "scope": scope,
        "scopes": list(scopes or []), "remediation": remediation,
        "source": source or f"ML 部署基线 {mid}", "level": level,
    }


ML_CHECKS = (
    _m("ML-GPU-01", _GPU, "GPU Operator 版本已固定（非 latest/main）", "evidence",
       key="ml.gpu_operator.version", op="pinned",
       remediation="固定 GPU Operator chart/镜像版本并纳入升级窗口。"),
    _m("ML-GPU-02", _GPU, "GPU Operator 命名空间 PSA 为 baseline/restricted", "evidence",
       key="ml.gpu_operator.namespace_psa", op="in", value=["baseline", "restricted"],
       remediation="为 gpu-operator 命名空间启用 PSA baseline/restricted。"),
    _m("ML-GPU-03", _GPU, "DCGM exporter 未通过 NodePort/LoadBalancer 暴露", "evidence",
       key="ml.gpu_operator.dcgm_exporter_service_type", op="not_in",
       value=["NodePort", "LoadBalancer"],
       remediation="DCGM exporter 仅 ClusterIP，或前置认证代理。"),
    _m("ML-GPU-04", _GPU, "NFD worker 未以 privileged 运行", "evidence",
       key="ml.gpu_operator.nfd_worker_privileged", op="eq", value=False,
       remediation="NFD worker 使用最小权限（hostPath 只读 + drop ALL）。"),
    _m("ML-GPU-05", _GPU, "MIG manager 未以 privileged 运行", "evidence",
       key="ml.gpu_operator.mig_manager_privileged", op="eq", value=False,
       remediation="MIG manager 仅在需要时启用并限制 capabilities。"),
    _m("ML-GPU-06", _GPU, "GPU Operator validator 已启用", "evidence",
       key="ml.gpu_operator.validator_enabled", op="eq", value=True,
       remediation="启用 operator validator，失败即阻断 GPU 工作负载。"),

    _m("ML-VLLM-01", _VLLM, "vLLM OpenAI API 已启用 api-key", "each",
       scope="ml.vllm.deployments", field="api_key_set", op="eq", value=True,
       remediation="vLLM 启动加 --api-key，或前置网关鉴权。"),
    _m("ML-VLLM-02", _VLLM, "vLLM 未启用 --trust-remote-code", "each",
       scope="ml.vllm.deployments", field="args", op="not_contains",
       value="--trust-remote-code",
       remediation="禁止 --trust-remote-code；模型仓库固定 revision + 本地扫描。"),
    _m("ML-VLLM-03", _VLLM, "vLLM metrics 未公开暴露", "each",
       scope="ml.vllm.deployments", field="metrics_public", op="eq", value=False,
       remediation="metrics 绑定 127.0.0.1 或加 network policy/认证。"),
    _m("ML-VLLM-04", _VLLM, "vLLM 容器非 privileged", "each",
       scope="ml.vllm.deployments", field="privileged", op="eq", value=False,
       remediation="移除 privileged，仅挂载必要 GPU device。"),
    _m("ML-VLLM-05", _VLLM, "vLLM 镜像以 digest 固定", "each",
       scope="ml.vllm.deployments", field="image_digest_pinned", op="eq", value=True,
       remediation="镜像使用 @sha256 digest 固定。"),

    _m("ML-SGL-01", _SGL, "SGLang server 已启用 api-key", "each",
       scope="ml.sglang.deployments", field="api_key_set", op="eq", value=True,
       remediation="SGLang 启动加 --api-key，或前置网关鉴权。"),
    _m("ML-SGL-02", _SGL, "SGLang 未启用 --trust-remote-code", "each",
       scope="ml.sglang.deployments", field="args", op="not_contains",
       value="--trust-remote-code",
       remediation="禁止 --trust-remote-code；固定模型 revision。"),
    _m("ML-SGL-03", _SGL, "SGLang metrics 未公开暴露", "each",
       scope="ml.sglang.deployments", field="metrics_public", op="eq", value=False,
       remediation="metrics 绑定 127.0.0.1 或加网络策略。"),
    _m("ML-SGL-04", _SGL, "SGLang 容器未使用 hostNetwork", "each",
       scope="ml.sglang.deployments", field="host_network", op="eq", value=False,
       remediation="移除 hostNetwork，使用 Service/Ingress。"),

    _m("ML-NET-01", _DEP, "推理命名空间已定义 NetworkPolicy（默认拒绝）", "evidence",
       key="ml.inference.network_policy", op="eq", value=True,
       remediation="为推理命名空间添加 default-deny + 显式放行策略。"),
    _m("ML-SEC-01", _DEP, "推理容器 runAsNonRoot", "each",
       scopes=["ml.vllm.deployments", "ml.sglang.deployments"], field="run_as_non_root",
       op="eq", value=True,
       remediation="securityContext.runAsNonRoot=true + 非 root 镜像用户。"),
    _m("ML-SEC-02", _DEP, "推理容器 seccomp=RuntimeDefault", "each",
       scopes=["ml.vllm.deployments", "ml.sglang.deployments"], field="seccomp",
       op="eq", value="RuntimeDefault",
       remediation="securityContext.seccompProfile.type=RuntimeDefault。"),
    _m("ML-SEC-03", _DEP, "推理容器未挂载敏感 hostPath", "each",
       scopes=["ml.vllm.deployments", "ml.sglang.deployments"], field="host_paths",
       op="disjoint", value=["/var/run/docker.sock", "/run/containerd/containerd.sock",
                             "/etc/kubernetes", "/var/lib/kubelet", "/root"],
       remediation="移除敏感 hostPath；模型目录只读挂载专用 PVC。"),
)


def _ok(value, check) -> bool:
    op = check["op"]
    if op == "pinned":
        text = _text(value).lower()
        return text not in ("", "latest", "main", "stable", "edge")
    if op == "disjoint":
        items = value if isinstance(value, list) else [value]
        sensitive = {str(v).lower() for v in check["value"]}
        return not any(str(item).lower() in sensitive for item in items)
    return compare(value, op, check.get("value", ""))


def _manual(check, reason, observed="—") -> dict:
    return _row(check, "manual", observed, reason)


def _row(check, status, observed, detail, evidence="") -> dict:
    return {
        "id": check["id"], "area": check["area"], "title": check["title"],
        "status": status, "observed": _text(observed),
        "expected": f"{check['op']} {check.get('value', '')}".strip(),
        "detail": detail, "sev": "high" if check.get("level", 1) == 1 else "medium",
        "level": int(check.get("level", 1)), "source": check["source"],
        "remediation": check["remediation"],
        "evidence": evidence or f"ml§{check['id']}",
    }


def _ml_path(path: str) -> str:
    return path[3:] if path.startswith("ml.") else path


def _check_one(check, ml: dict) -> dict:
    if check["kind"] == "evidence":
        value, found = _dig(ml, _ml_path(check["key"]))
        if not found:
            return _manual(check, f"缺少证据 {check['key']}")
        field = check.get("field")
        if field:
            value = value.get(field) if isinstance(value, dict) else None
            if value is None:
                return _manual(check, f"缺少证据 {check['key']}.{field}")
        ok = _ok(value, check)
        return _row(check, "pass" if ok else "fail", value,
                    f"{check['key']}={_text(value)}；期望 {check['op']} {check.get('value', '')}",
                    evidence=f"{check['key']}={_text(value)}")
    scopes = check.get("scopes") or ([check["scope"]] if check.get("scope") else [])
    targets = []
    for scope in scopes:
        value, found = _dig(ml, _ml_path(scope))
        if not found or not isinstance(value, list) or not value:
            continue
        for item in value:
            if isinstance(item, dict):
                targets.append((scope, item))
    if not targets:
        return _manual(check, f"未部署/缺少 {', '.join(scopes)}（不臆造 pass/fail）")
    statuses, observed = [], []
    for scope, item in targets:
        name = item.get("name", scope)
        value = item.get(check["field"])
        if value is None:
            statuses.append("manual")
            observed.append(f"{name}=<缺字段>")
            continue
        ok = _ok(value, check)
        statuses.append("pass" if ok else "fail")
        observed.append(f"{name}={_text(value)}")
    text = "; ".join(observed)
    if "fail" in statuses:
        status = "fail"
    elif "manual" in statuses:
        status = "manual"
    else:
        status = "pass"
    return _row(check, status, text, f"{check['field']} → {text}", evidence=text)


def assess_ml(snapshot: dict) -> dict:
    ml = (snapshot or {}).get("ml")
    if not isinstance(ml, dict):
        ml = {}
    rows = [_check_one(check, ml) for check in ML_CHECKS]
    counts = {"pass": 0, "fail": 0, "manual": 0}
    matrix: dict[str, dict] = {}
    for row in rows:
        counts[row["status"]] += 1
        cell = matrix.setdefault(row["area"], {"pass": 0, "fail": 0, "manual": 0, "total": 0})
        cell[row["status"]] += 1
        cell["total"] += 1
    evaluated = [r for r in rows if r["status"] != "manual"]
    score = round(sum(1 for r in evaluated if r["status"] == "pass") / len(evaluated), 3) \
        if evaluated else 0.0
    summary = {
        "family": "ML deployment baseline (beyond CIS)",
        "total": len(rows), "rules_total": len(rows),
        "pass": counts["pass"], "fail": counts["fail"], "manual": counts["manual"],
        "score": score,
        "failed_ids": [r["id"] for r in rows if r["status"] == "fail"],
        "manual_ids": [r["id"] for r in rows if r["status"] == "manual"],
    }
    return {"checks": rows, "matrix": matrix, "summary": summary}


def findings(report: dict) -> list[dict]:
    out = []
    for row in report.get("checks", []):
        if row["status"] != "fail":
            continue
        out.append({
            "sev": row["sev"],
            "title": f"ML 基线 {row['id']} 未通过：{row['title']}",
            "detail": (f"{row['area']} 观测={row['observed']}；期望={row['expected']}；"
                       f"{row['detail']}。来源：{row['source']}"),
            "evidence": row["evidence"],
            "mapping": f"ML 部署基线 §{row['id']}（超出 CIS）",
            "fix": row["remediation"],
            "ml_id": row["id"], "area": row["area"], "status": "fail",
            "remediation": row["remediation"],
        })
    return out
