# -*- coding: utf-8 -*-
"""漏洞知识库条目（CM-07 等价）：finding → 可引用 KB 键，中英双语条目。

- 内置条目覆盖 Trident 的 ML/K8s 攻击面（RBAC 逃逸、kubelet 10250、推理网关鉴权、
  GPU 租户残留、NCCL 集合通信、间接提示注入、权重供应链、证据链完整性）；
- ``match(text)`` 关键词命中；``cite(finding)`` 返回稳定 KB 键 + 双语标题/修复建议/参考，
  未命中时返回通用条目（不返回 None，保证报告每条 finding 都有引用键）；
- 纯本地数据，不联网、不依赖外部 KB；条目为我方独立编写的控制建议，引用通用标准
  （CWE / OWASP LLM / MITRE ATLAS 编号为公开分类，不复制第三方正文）。
"""

from __future__ import annotations

from typing import Any

KB: dict[str, dict] = {
    "TRIDENT-KB-001": {
        "title": {"zh": "K8s RBAC 权限链逃逸", "en": "Kubernetes RBAC privilege-chain escape"},
        "category": "权限链", "cwe": ["CWE-269"], "owasp": ["A01:2021"],
        "keywords": ["rbac", "rolebinding", "clusterrole", "escalate", "impersonate",
                     "serviceaccount", "sa-token", "overprivileged"],
        "summary": {
            "zh": "工作负载或用户被授予可创建/绑定高权限角色、读取 Secret 或伪造 SA token 的能力，"
                  "可沿 RoleBinding → ClusterRole → 节点/宿主面升级。",
            "en": "A workload or user can create/bind privileged roles, read Secrets, or mint "
                  "service-account tokens, enabling RoleBinding → ClusterRole → node/host escalation.",
        },
        "remediation": {
            "zh": "按最小权限重写 Role/ClusterRole；禁用自动挂载 SA token；对 bind/escalate/impersonate "
                  "加准入阻断与审计告警；定期做 SSRR/SSAR 权限复核。",
            "en": "Rewrite Roles/ClusterRoles to least privilege; disable SA token automount; block "
                  "bind/escalate/impersonate at admission and alert on them; run periodic SSRR/SSAR reviews.",
        },
        "refs": ["CWE-269", "MITRE ATLAS AML.T0051"],
    },
    "TRIDENT-KB-002": {
        "title": {"zh": "kubelet 10250 未授权面", "en": "Unauthenticated kubelet 10250 surface"},
        "category": "资产发现", "cwe": ["CWE-306"], "owasp": ["A07:2021"],
        "keywords": ["kubelet", "10250", "runningpods", "anonymous-auth", "read-only-port"],
        "summary": {
            "zh": "kubelet 读接口（/pods、/runningpods、/logs、/exec）允许匿名或弱鉴权访问，"
                  "可枚举 Pod、读取日志、收割挂载的 SA token，甚至进入容器。",
            "en": "kubelet read endpoints (/pods, /runningpods, /logs, /exec) allow anonymous or weak "
                  "authentication, exposing pods, logs, mounted SA tokens, and container execution.",
        },
        "remediation": {
            "zh": "关闭 --anonymous-auth 与 --read-only-port；启用 Webhook 授权；限制 10250 到控制面/监控网段；"
                  "轮换已暴露的 SA token。",
            "en": "Disable --anonymous-auth and --read-only-port; enable webhook authorization; restrict "
                  "10250 to control-plane/monitoring networks; rotate exposed SA tokens.",
        },
        "refs": ["CWE-306", "CIS Kubernetes Benchmark 4.2"],
    },
    "TRIDENT-KB-003": {
        "title": {"zh": "推理网关管理面鉴权失效", "en": "Inference gateway admin-plane auth bypass"},
        "category": "AI 网关", "cwe": ["CWE-287", "CWE-306"], "owasp": ["LLM01:2026"],
        "keywords": ["sglang", "vllm", "litellm", "higress", "gateway", "admin", "fail-open",
                     "master-key", "auth-bypass"],
        "summary": {
            "zh": "推理/网关管理 API（模型加载、路由、key 管理、配置）缺少鉴权或使用默认主密钥，"
                  "可导致模型替换、上游凭据外泄与跨租户调用。",
            "en": "Inference/gateway admin APIs (model load, routing, key management, config) lack "
                  "authentication or use default master keys, enabling model swap, upstream key theft, "
                  "and cross-tenant calls.",
        },
        "remediation": {
            "zh": "管理面与数据面分离并强制鉴权；删除默认主密钥并轮换；管理端口仅内网可达；"
                  "对配置/模型变更加签名与审计。",
            "en": "Separate admin and data planes with mandatory auth; remove and rotate default master "
                  "keys; restrict admin ports to the internal network; sign and audit config/model changes.",
        },
        "refs": ["CWE-287", "OWASP LLM01:2026"],
    },
    "TRIDENT-KB-004": {
        "title": {"zh": "GPU/租户残留与跨租户复用", "en": "GPU tenant residue and cross-tenant reuse"},
        "category": "GPU 多租户", "cwe": ["CWE-212"], "owasp": ["A01:2021"],
        "keywords": ["gpu", "mig", "mps", "residue", "tenant", "vgpu", "hami", "device"],
        "summary": {
            "zh": "GPU 分配/回收未清理显存、MIG 配置或 MPS 上下文，后一租户可读取前一租户的模型/数据残留。",
            "en": "GPU allocation/release leaves memory, MIG configuration, or MPS contexts uncleared, "
                  "letting the next tenant read the previous tenant's model/data residue.",
        },
        "remediation": {
            "zh": "回收时重置 MIG/MPS 与显存；按租户隔离设备插件与节点池；对 GPU 复用做清零证明与审计。",
            "en": "Reset MIG/MPS and GPU memory on release; isolate device plugins and node pools per "
                  "tenant; require zeroization evidence and audit for GPU reuse.",
        },
        "refs": ["CWE-212", "MITRE ATLAS AML.T0024"],
    },
    "TRIDENT-KB-005": {
        "title": {"zh": "NCCL/集合通信未授权加入", "en": "Unauthenticated NCCL collective join"},
        "category": "Fabric/集合通信", "cwe": ["CWE-306"], "owasp": ["A07:2021"],
        "keywords": ["nccl", "collective", "ib", "rdma", "roce", "sharp", "rendezvous"],
        "summary": {
            "zh": "NCCL/集合通信端点无身份校验，攻击者可加入通信组注入梯度、窃听权重或制造 straggler。",
            "en": "NCCL/collective endpoints lack peer identity checks, allowing an attacker to join the "
                  "group, inject gradients, eavesdrop weights, or induce stragglers.",
        },
        "remediation": {
            "zh": "启用集合通信身份认证/网络策略；隔离 IB/RDMA 分区；对 rendezvous 端口做源校验与流量监测。",
            "en": "Enable collective identity/auth and network policies; isolate IB/RDMA partitions; "
                  "enforce source validation and monitoring on rendezvous ports.",
        },
        "refs": ["CWE-306", "MITRE ATLAS AML.T0043"],
    },
    "TRIDENT-KB-006": {
        "title": {"zh": "LLM 间接提示注入导致工具执行", "en": "Indirect prompt injection leading to tool execution"},
        "category": "AI/LLM", "cwe": ["CWE-1426"], "owasp": ["LLM01:2026"],
        "keywords": ["injection", "prompt", "open-webui", "agent", "tool", "indirect",
                     "rag", "webui"],
        "summary": {
            "zh": "检索内容、文件或工具输出携带指令，模型将其当作用户意图并调用高权限工具，造成数据外泄或命令执行。",
            "en": "Retrieved content, files, or tool output carries instructions that the model treats as "
                  "user intent and executes via privileged tools, causing data exfiltration or command execution.",
        },
        "remediation": {
            "zh": "工具调用最小权限与人工确认；对不可信内容做来源标记/隔离；输出过滤与 canary 监测；"
                  "高风险工具禁自动执行。",
            "en": "Least-privilege tools with human confirmation; label/isolate untrusted content; output "
                  "filtering and canary monitoring; disable auto-execution for high-risk tools.",
        },
        "refs": ["CWE-1426", "OWASP LLM01:2026"],
    },
    "TRIDENT-KB-007": {
        "title": {"zh": "模型权重供应链投毒", "en": "Model weight supply-chain poisoning"},
        "category": "供应链", "cwe": ["CWE-345"], "owasp": ["LLM03:2026"],
        "keywords": ["weight", "checkpoint", "pickle", "lora", "huggingface", "supply",
                     "signature", "cosign", "safetensors"],
        "summary": {
            "zh": "权重/检查点来源未签名或可被替换，加载器使用 pickle 等不安全格式，导致训练污染或加载即 RCE。",
            "en": "Weights/checkpoints are unsigned or replaceable and loaded via unsafe formats such as "
                  "pickle, enabling training poisoning or RCE on load.",
        },
        "remediation": {
            "zh": "权重签名与哈希校验（cosign/OCI）；优先 safetensors；限制写权限与跨租户共享；"
                  "加载前做来源三元组核验。",
            "en": "Verify weight signatures and hashes (cosign/OCI); prefer safetensors; restrict write "
                  "access and cross-tenant sharing; verify the source/version/digest triple before loading.",
        },
        "refs": ["CWE-345", "OWASP LLM03:2026"],
    },
    "TRIDENT-KB-008": {
        "title": {"zh": "证据链完整性与审计缺口", "en": "Evidence-chain integrity and audit gaps"},
        "category": "证据链", "cwe": ["CWE-778"], "owasp": ["A09:2021"],
        "keywords": ["evidence", "manifest", "audit", "log", "tamper", "sha256", "trace"],
        "summary": {
            "zh": "执行动作、请求响应或判定理由未完整留档，或归档缺少哈希/清单校验，导致结论不可复核。",
            "en": "Actions, request/response traces, or decision rationale are not fully recorded, or "
                  "archives lack hash/manifest verification, making conclusions unreviewable.",
        },
        "remediation": {
            "zh": "三层证据全量落库（摘要/SQLite/归档）；manifest SHA256 校验；审批与重试动作追加审计；"
                  "敏感值按 metadata/redact/raw 三态引用。",
            "en": "Persist all three evidence layers (summary/SQLite/archive); verify manifest SHA256; "
                  "append audit for approvals and retries; store sensitive values as metadata/redact/raw refs.",
        },
        "refs": ["CWE-778", "OWASP A09:2021"],
    },
    "TRIDENT-KB-000": {
        "title": {"zh": "未归类的控制缺口", "en": "Unclassified control gap"},
        "category": "通用", "cwe": [], "owasp": [],
        "keywords": [],
        "summary": {
            "zh": "该发现尚未匹配到专用知识库条目；请结合证据锚人工归类并补充修复建议。",
            "en": "This finding has no dedicated KB entry yet; classify it using the evidence anchor and "
                  "add remediation guidance.",
        },
        "remediation": {
            "zh": "回链 run 证据、确认影响面、按最小权限修复并复测。",
            "en": "Link back to run evidence, confirm impact, remediate to least privilege, and retest.",
        },
        "refs": [],
    },
}


class KBError(ValueError):
    """KB 条目参数非法。"""


def entry(key: str) -> dict:
    if key not in KB:
        raise KBError(f"未知 KB 键 {key}")
    return {"key": key, **KB[key]}


def match(text: str, *, limit: int = 5) -> list[dict]:
    hay = str(text or "").lower()
    hits = []
    for key, e in KB.items():
        if key == "TRIDENT-KB-000":
            continue
        if any(str(k).lower() in hay for k in e.get("keywords", [])):
            hits.append(entry(key))
    return hits[:limit]


def cite(finding: dict) -> dict:
    """finding → 引用块（始终有键；未命中回退通用条目）。"""
    text = " ".join(str(finding.get(k, "")) for k in ("step_key", "title", "detail", "mapping"))
    hits = match(text, limit=1)
    kb = hits[0] if hits else entry("TRIDENT-KB-000")
    return {"key": kb["key"], "title": kb["title"], "category": kb["category"],
            "summary": kb["summary"], "remediation": kb["remediation"],
            "refs": kb["refs"], "cwe": kb["cwe"], "owasp": kb["owasp"],
            "matched_keyword": (kb.get("keywords") or [None])[0] if hits else None,
            "bilingual": True}


def render_md(key: str) -> str:
    e = entry(key)
    lines = [f"# {e['key']} — {e['title']['zh']} / {e['title']['en']}", "",
             f"- 分类：{e['category']}",
             f"- CWE：{', '.join(e['cwe']) or '—'}",
             f"- OWASP：{', '.join(e['owasp']) or '—'}", "",
             f"**摘要（中）**：{e['summary']['zh']}", "",
             f"**Summary (EN)**: {e['summary']['en']}", "",
             f"**修复（中）**：{e['remediation']['zh']}", "",
             f"**Remediation (EN)**: {e['remediation']['en']}", ""]
    if e["refs"]:
        lines.append("参考 / References: " + ", ".join(e["refs"]))
    return "\n".join(lines) + "\n"


def stats() -> dict:
    return {"entries": len(KB), "bilingual": True,
            "categories": sorted({e["category"] for e in KB.values()})}
