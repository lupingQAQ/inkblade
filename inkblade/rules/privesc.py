"""提权检测规则包：把 47 条提权向量转成 Sigma/Falco 规则 + Kyverno 准入策略。

- 每个向量至少 1 条 Sigma/Falco 规则（`purple_replay` 用内置简化匹配器重放）；
- 另有 6 条 Kyverno ClusterPolicy（Audit 模式）覆盖高危写入面；
- 产物：sigma/*.yaml、falco/*.yaml、kyverno/*.yaml、coverage.json/md、README.md。

规则口径：Sigma 的 `detection.selection` 使用 K8s audit 字段路径（objectRef.resource 等）；
`custom.inkblade-replay` 记录内置匹配器的扁平规格，便于在无 SIEM 环境复现命中。
Falco 规则为行为化签名（socket/路径/端口/进程），monitor 标签；不包含真实利用 payload。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..core.privesc import load_matrix
from ..core.yamlish import dump as yaml_dump

LEVEL = {"rbac": "high", "workload": "high", "credential": "high",
         "node": "critical", "platform": "high"}


class PrivescCoverageError(ValueError):
    """存在未命中/未覆盖的提权向量。"""


ADMISSION_VECTORS = (
    "workload-hostpath-kubelet",
    "workload-hostpath-runtime-socket",
    "workload-init-container-override",
    "rbac-admission-webhook-write",
    "rbac-apiservice-hijack",
    "rbac-crd-conversion-webhook",
)

ADMISSION_RULE_IDS = (
    "privesc-deny-kubelet-hostpath",
    "privesc-deny-runtime-socket",
    "privesc-deny-init-privileged",
    "privesc-deny-webhook-failopen",
    "privesc-deny-insecure-apiservice",
    "privesc-deny-crd-conversion-no-ca",
)


def _uuid(seed: str) -> str:
    d = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return f"{d[:8]}-{d[8:12]}-{d[12:16]}-{d[16:20]}-{d[20:32]}"


def _sigma_text(v: dict) -> str:
    d = v["detect"]
    tags = ["attack.privilege_escalation", "inkblade", f"inkblade.vector.{v['category']}"]
    tags += [f"attack.{m.lower()}" for m in v.get("mitre", [])]
    doc = {
        "kind": "SigmaRule",
        "title": v["title"]["zh"],
        "id": _uuid(f"inkblade-sigma-privesc-{v['id']}"),
        "status": "stable",
        "description": v["primitive"],
        "references": [s["ref"] for s in v.get("sources", [])],
        "author": "InkBlade privesc matrix",
        "metadata": {
            "author": "InkBlade privesc matrix",
            "annotations": {"inkblade.io/vector": v["id"], "inkblade.io/module": v["module"]},
        },
        "date": "2026/10/26",
        "logsource": d.get("logsource") or {"product": "kubernetes", "service": "audit"},
        "detection": {"selection": d["selection"], "condition": "selection"},
        "falsepositives": ["授权的运维/CI 变更（按主体白名单收敛）"],
        "level": LEVEL.get(v["category"], "high"),
        "tags": tags + ["inkblade-mode-monitor"],
        "custom": {
            "inkblade-mode": "monitor",
            "inkblade-vector": v["id"],
            "inkblade-module": v["module"],
            "inkblade-detection-point": d["point"],
            "inkblade-replay": {"match": {"engine": "sigma", "logsource": d.get("logsource"),
                                          "selection": d["selection"]},
                               "event": d["event"]},
        },
    }
    return yaml_dump(doc)


def _falco_cond(key: str, value: Any) -> str:
    if isinstance(value, dict) and "re" in value:
        return f'{key} ~ "{value["re"]}"'
    if isinstance(value, bool):
        return f"{key}={str(value).lower()}"
    if isinstance(value, list):
        return f"{key} in ({', '.join(json.dumps(v) for v in value)})"
    return f"{key}={json.dumps(value)}"


def _falco_text(v: dict) -> str:
    d = v["detect"]
    filters = " and ".join(_falco_cond(k, val) for k, val in d.get("filter", {}).items())
    rule = {
        "rule": f"InkBlade Privesc {v['id']}",
        "desc": v["title"]["zh"],
        "condition": "evt.type in (open,openat,connect,execve) and " + filters,
        "output": "InkBlade privilege-escalation primitive "
                  f"(vector={v['id']} module={v['module']} proc=%proc.name)",
        "priority": "CRITICAL" if v["category"] == "node" else "WARNING",
        "tags": ["inkblade", "privesc", v["category"], v["id"]],
    }
    return "# inkblade.io/vector: " + v["id"] + "\n# detection-point: " + d["point"] + "\n" + yaml_dump([rule])


def _admission_doc(vec_id: str, rule_id: str) -> dict:
    titles = {
        "workload-hostpath-kubelet": ("拒绝 kubelet/kubernetes 目录 hostPath", "Deny kubelet hostPath"),
        "workload-hostpath-runtime-socket": ("拒绝容器运行时 socket hostPath", "Deny runtime socket hostPath"),
        "workload-init-container-override": ("检查 initContainers 特权/hostPath", "Inspect initContainers"),
        "rbac-admission-webhook-write": ("拒绝 failurePolicy=Ignore 的准入 Webhook", "Deny fail-open webhook"),
        "rbac-apiservice-hijack": ("拒绝 insecureSkipTLSVerify 的 APIService", "Deny insecure APIService"),
        "rbac-crd-conversion-webhook": ("拒绝无 caBundle 的 CRD conversion webhook", "Deny conversion webhook without CA"),
    }
    zh, en = titles[vec_id]
    if vec_id in ("workload-hostpath-kubelet", "workload-hostpath-runtime-socket"):
        cond = {
            "any": [
                {"key": "{{ request.object.spec.volumes[].hostPath.path[] || `[]` }}",
                 "operator": "AnyIn",
                 "value": ["/var/lib/kubelet", "/etc/kubernetes", "/var/run/containerd/containerd.sock",
                           "/var/run/docker.sock", "/run/crio/crio.sock"]},
            ]
        }
        rule = {"name": rule_id, "match": {"anyResources": [{"kinds": ["Pod"]}]},
                "validate": {"message": f"{zh} / {en}", "deny": {"conditions": cond}}}
    elif vec_id == "workload-init-container-override":
        rule = {"name": rule_id, "match": {"anyResources": [{"kinds": ["Pod"]}]},
                "validate": {"message": f"{zh} / {en}", "deny": {"conditions": {
                    "any": [
                        {"key": "{{ request.object.spec.initContainers[].securityContext.privileged[] || `[]` }}",
                         "operator": "AnyIn", "value": [True]},
                        {"key": "{{ request.object.spec.initContainers[].volumeMounts[].mountPath[] || `[]` }}",
                         "operator": "AnyIn", "value": ["/host", "/var/lib/kubelet"]},
                    ]}}}}
    elif vec_id == "rbac-admission-webhook-write":
        rule = {"name": rule_id,
                "match": {"anyResources": [{"kinds": ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"],
                                             "operations": ["CREATE", "UPDATE"]}]},
                "validate": {"message": f"{zh} / {en}", "deny": {"conditions": {
                    "any": [
                        {"key": "{{ request.object.webhooks[].failurePolicy[] || `[]` }}",
                         "operator": "AnyIn", "value": ["Ignore"]},
                        {"key": "{{ request.object.webhooks[].clientConfig.url[] || `[]` }}",
                         "operator": "AnyIn", "value": ["http://*"]},
                    ]}}}}
    elif vec_id == "rbac-apiservice-hijack":
        rule = {"name": rule_id,
                "match": {"anyResources": [{"kinds": ["APIService"], "operations": ["CREATE", "UPDATE"]}]},
                "validate": {"message": f"{zh} / {en}", "deny": {"conditions": {
                    "any": [{"key": "{{ request.object.spec.insecureSkipTLSVerify || `false` }}",
                             "operator": "Equals", "value": True}]}}}}
    else:
        rule = {"name": rule_id,
                "match": {"anyResources": [{"kinds": ["CustomResourceDefinition"],
                                             "operations": ["CREATE", "UPDATE"]}]},
                "validate": {"message": f"{zh} / {en}", "deny": {"conditions": {
                    "all": [
                        {"key": "{{ request.object.spec.conversion.strategy || `` }}", "operator": "Equals", "value": "Webhook"},
                        {"key": "{{ request.object.spec.conversion.webhook.clientConfig.caBundle || `` }}",
                         "operator": "Equals", "value": ""},
                    ]}}}}
    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": f"inkblade-{rule_id}",
            "annotations": {
                "inkblade.io/mode": "monitor",
                "inkblade.io/vector": vec_id,
                "inkblade.io/tuning": "先 Audit 观察基线；确认无合法例外后切 Enforce",
            },
        },
        "spec": {"validationFailureAction": "Audit", "background": True, "rules": [rule]},
    }


def render_rule_pack(matrix: dict | None = None) -> dict:
    m = matrix or load_matrix()
    documents: list[dict] = []
    admission: list[dict] = []
    for v in m["vectors"]:
        engine = v["detect"]["engine"]
        rid = ("sigma-privesc-" if engine == "sigma" else "falco-privesc-") + v["id"]
        text = _sigma_text(v) if engine == "sigma" else _falco_text(v)
        documents.append({"vector": v["id"], "rule_id": rid, "engine": engine,
                          "module": v["module"], "text": text})
    for vec_id, rid in zip(ADMISSION_VECTORS, ADMISSION_RULE_IDS):
        admission.append({"vector": vec_id, "rule_id": rid,
                          "text": yaml_dump(_admission_doc(vec_id, rid))})
    return {"documents": documents, "admission": admission,
            "summary": {"vectors": len(documents), "admission": len(admission)}}


def _match_spec(v: dict) -> tuple[dict, dict]:
    d = v["detect"]
    if d["engine"] == "sigma":
        return ({"engine": "sigma", "logsource": d.get("logsource"),
                 "selection": d["selection"]}, d["event"])
    return ({"engine": "falco", "event_type": d["event_type"], "all": d["filter"]}, d["event"])


def purple_replay(matrix: dict | None = None, strict: bool = True) -> dict:
    """对每向量合成事件 → 内置匹配器重放；默认有任何漏过即抛错。"""
    from .validate import rule_fires

    m = matrix or load_matrix()
    items: list[dict] = []
    missed: list[dict] = []
    for v in m["vectors"]:
        match, event = _match_spec(v)
        try:
            fired = rule_fires(match, [event])
        except Exception as exc:  # 规则规格非法也算漏过，保留诊断
            fired = False
            event = {"error": f"{type(exc).__name__}: {exc}", **event}
        engine = v["detect"]["engine"]
        rid = ("sigma-privesc-" if engine == "sigma" else "falco-privesc-") + v["id"]
        item = {"vector": v["id"], "rule": rid, "engine": engine, "fired": bool(fired),
                "detection_point": v["detect"]["point"]}
        items.append(item)
        if not fired:
            missed.append({"vector": v["id"], "rule": rid, "match": match, "event": event})
    result = {
        "ok": not missed,
        "vectors": len(m["vectors"]),
        "rules": len(m["vectors"]),
        "hit": len(m["vectors"]) - len(missed),
        "missed": missed,
        "items": items,
    }
    if missed and strict:
        raise PrivescCoverageError(
            "提权检测规则未命中: " + ", ".join(x["vector"] for x in missed))
    return result


def _coverage_md(m: dict, result: dict) -> str:
    lines = [
        "# InkBlade 提权检测覆盖（Purple Replay）",
        "",
        f"- 向量：{result['vectors']}；命中：{result['hit']}；漏过：{len(result['missed'])}",
        f"- 判定：{'PASS' if result['ok'] else 'FAIL'}",
        "",
        "| 向量 | 规则 | 引擎 | 紫队重放 | 检测点 |",
        "|---|---|---|---|---|",
    ]
    for item in result["items"]:
        lines.append(f"| `{item['vector']}` | `{item['rule']}` | {item['engine']} | "
                     f"{'命中' if item['fired'] else '漏过'} | {item['detection_point'].replace('|', '\\|')} |")
    lines.append("")
    return "\n".join(lines)


def write_rule_pack(matrix: dict | None = None, out_dir: Path | str = ".") -> dict:
    m = matrix or load_matrix()
    root = Path(out_dir)
    pack = render_rule_pack(m)
    result = purple_replay(m, strict=False)
    files: list[str] = []

    def write(rel: str, text: str) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        files.append(rel.replace("\\", "/"))

    for doc in pack["documents"]:
        sub = "sigma" if doc["engine"] == "sigma" else "falco"
        write(f"{sub}/{doc['rule_id']}.yaml", doc["text"])
    for doc in pack["admission"]:
        write(f"kyverno/{doc['rule_id']}.yaml", doc["text"])
    coverage = {
        "generator": "inkblade.rules.privesc",
        "matrix_schema": m.get("schema", ""),
        "summary": {"vectors": result["vectors"], "rules": result["rules"],
                    "hit": result["hit"], "missed": len(result["missed"]), "ok": result["ok"]},
        "items": result["items"],
        "admission": [{"vector": d["vector"], "rule": d["rule_id"]} for d in pack["admission"]],
    }
    write("coverage.json", json.dumps(coverage, ensure_ascii=False, indent=2))
    write("coverage.md", _coverage_md(m, result))
    readme = [
        "# InkBlade 提权检测规则包",
        "",
        "由 `inkblade privesc detections` 生成。每个提权向量至少 1 条 Sigma/Falco 规则；",
        "另有 6 条 Kyverno ClusterPolicy（Audit 模式）。",
        "",
        f"- 向量 {result['vectors']}；规则 {result['rules']}；紫队命中 {result['hit']}/{result['vectors']}",
        "- Sigma：K8s audit 字段路径；Falco：行为化签名（monitor 标签）",
        "- 先以 monitor/Audit 观察基线，再按主体白名单切 Enforce/Block",
        "",
        "复现：`inkblade privesc detections --out reports/rules-pack`；"
        "`inkblade rules validate --pack reports/rules-pack` 会附带 `privesc` 覆盖结果。",
        "",
    ]
    write("README.md", "\n".join(readme))
    return {"ok": result["ok"], "vectors": result["vectors"], "rules": result["rules"],
            "admission": len(pack["admission"]), "files": files,
            "coverage": "coverage.json"}
