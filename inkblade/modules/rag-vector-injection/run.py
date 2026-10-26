# -*- coding: utf-8 -*-
"""RAG 向量库注入面（主动探测，只读）。

GET /rag/documents：
- 未签名外部注入文档 → high；
- 跨租户共享 collection/embedding namespace 或检索未按租户过滤 → high；
- 未清洗/文档数无上限 → medium。

只读：不写入向量库、不触发检索或模型生成。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "rag-vector-injection"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/rag/documents")
    doc = _C.resp(entry)
    documents = [d for d in _C.as_list(doc.get("documents")) if isinstance(d, dict)]
    retrieval = doc.get("retrieval") or {}
    findings: list[dict] = []

    injected = [d for d in documents
                if bool(d.get("injected_instruction"))
                or (not bool(d.get("trusted")) and not bool(d.get("signed")))]
    tenant = str(doc.get("tenant") or "")
    collection = str(doc.get("collection") or "")
    namespace = str(doc.get("embedding_namespace") or "")
    tenant_filter = bool(retrieval.get("tenant_filter"))
    shared = (not collection.startswith(f"tenant-{tenant}")) or namespace != f"tenant-{tenant}"
    sanitize = bool(retrieval.get("sanitize"))
    max_docs = _C.as_int(retrieval.get("max_docs"), 0)

    if injected:
        findings.append(_C.finding(
            "high", "RAG 知识库存在未签名注入文档",
            {"detected": True,
             "documents": [{"id": d.get("id"), "source": d.get("source"),
                            "trusted": d.get("trusted"), "signed": d.get("signed")}
                           for d in injected]},
            evidence=f"injected_docs={len(injected)}",
            mapping="RAG 检索语料投毒 / 间接提示注入",
            fix="外部文档签名与来源校验；隔离不可信语料，检索结果标注信任级别",
        ))
    if not tenant_filter or shared:
        findings.append(_C.finding(
            "high", "检索未按租户过滤",
            {"detected": True, "tenant": tenant, "collection": collection,
             "embedding_namespace": namespace, "tenant_filter": tenant_filter},
            evidence=f"tenant_filter={tenant_filter} collection={collection} ns={namespace}",
            mapping="多租户 RAG / embedding namespace 隔离",
            fix="collection 与 embedding namespace 按租户隔离；检索强制 tenant filter",
        ))
    if not sanitize or max_docs == 0 or max_docs > 20:
        findings.append(_C.finding(
            "medium", "检索内容未清洗或文档数无上限",
            {"detected": True, "sanitize": sanitize, "max_docs": max_docs},
            evidence=f"sanitize={sanitize} max_docs={max_docs}",
            mapping="RAG 上下文注入面 / 检索预算",
            fix="检索内容清洗并限制条数；对指令型内容做去毒/隔离",
        ))

    extra = {
        "tenant": tenant,
        "collection": collection,
        "embedding_namespace": namespace,
        "documents": len(documents),
        "injected_docs": len(injected),
        "tenant_filter": tenant_filter,
        "sanitize": sanitize,
        "max_docs": max_docs,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("RAG 向量注入面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "rag": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
