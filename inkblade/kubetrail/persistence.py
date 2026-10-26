# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""持久化检测（KubeTrail kube/persistence.go 7 类模板的 **检测侧**，不含植入）。

检测对象：
- serviceaccount / cronjob / deployment / daemonset：高权限 SA + 工作负载持久化；
- shadow-kubeconfig：非标准路径 kubeconfig（/tmp、/root/.kube 等）；
- token-request：超长有效期 TokenRequest（>365 天）；
- pull-secret：default SA 被注入 imagePullSecrets（拉取面持久化）。

输入：``persistence`` 快照节（fixture/控制台侧）或 K8s 清单集合。
输出：findings + indicators（不执行任何写操作，不生成植入模板）。
"""

from __future__ import annotations

SUSPICIOUS_ROLES = ("cluster-admin", "admin", "edit", "backdoor", "wildcard")
STANDARD_KUBECONFIG = ("/etc/kubernetes/admin.conf",)
MAX_TOKEN_DAYS = 365


def _finding(sev, title, detail, evidence, fix):
    return {"sev": sev, "title": title, "detail": detail, "evidence": evidence,
            "mapping": "KubeTrail 权限维持检测（K8 7 模板 → 检测侧）", "fix": fix}


def detect(snapshot: dict) -> dict:
    persistence = snapshot.get("persistence") or {}
    findings: list[dict] = []
    indicators: dict = {"bindings": 0, "shadow_kubeconfigs": 0, "workloads": 0,
                        "token_requests": 0, "pull_secret_patches": 0, "webhooks": 0}

    for binding in persistence.get("suspicious_bindings") or []:
        role = str(binding.get("role", "")).lower()
        if not any(s in role for s in SUSPICIOUS_ROLES):
            continue
        indicators["bindings"] += 1
        findings.append(_finding(
            "critical",
            f"可疑高权限绑定：{binding.get('name', '?')} → {binding.get('role')}",
            f"主体 {binding.get('subject', '?')} 通过绑定获得 {'/'.join(SUSPICIOUS_ROLES)} 类权限，"
            "常见于后门账户/权限维持。",
            f"binding={binding.get('name')} subject={binding.get('subject')}",
            "删除非基线绑定；开启 RBAC 漂移告警（auditlog）"))

    # 从集群清单侧补充：cluster-admin 绑定到非系统主体
    for binding in snapshot.get("clusterrolebindings") or []:
        role = str(binding.get("role", "")).lower()
        subjects = [str(s) for s in binding.get("subjects") or []]
        for subject in subjects:
            if role in ("cluster-admin", "admin") and not subject.startswith("system:"):
                indicators["bindings"] += 1
                findings.append(_finding(
                    "critical", f"cluster-admin 绑定到非系统主体：{subject}",
                    f"绑定 {binding.get('name')} 将最高权限授予普通主体（持久化/后门风险）。",
                    f"binding={binding.get('name')} subject={subject}",
                    "收敛 cluster-admin；使用 break-glass + 审计"))

    for path in persistence.get("shadow_kubeconfigs") or []:
        if path in STANDARD_KUBECONFIG:
            continue
        indicators["shadow_kubeconfigs"] += 1
        findings.append(_finding(
            "high", f"影子 kubeconfig：{path}",
            "非标准路径 kubeconfig 常为持久化凭据副本（节点/容器内可读即集群控制面入口）。",
            f"path={path}", "删除并轮换证书；限制 kubeconfig 落盘路径与权限"))

    for workload in persistence.get("workloads") or []:
        kind = str(workload.get("kind", ""))
        if kind not in ("DaemonSet", "CronJob", "Deployment", "StatefulSet", "Job"):
            continue
        risky = bool(workload.get("privileged")) or bool(workload.get("hostPath"))
        if not risky:
            continue
        indicators["workloads"] += 1
        findings.append(_finding(
            "critical" if workload.get("privileged") else "high",
            f"持久化工作负载面：{workload.get('namespace', '')}/{kind} {workload.get('name', '?')}",
            f"镜像 {workload.get('image', '?')}；privileged={bool(workload.get('privileged'))} "
            f"hostPath={workload.get('hostPath') or '-'}；常被用于常驻后门/采集器。",
            f"kind={kind} name={workload.get('name')}",
            "工作负载白名单 + 准入（privileged/hostPath）+ 镜像签名验证"))

    for request in persistence.get("token_requests") or []:
        days = float(request.get("expiration", 0)) / 86400
        if days <= MAX_TOKEN_DAYS:
            continue
        indicators["token_requests"] += 1
        findings.append(_finding(
            "high", f"超长有效期 TokenRequest（{int(days)} 天）",
            f"主体 {request.get('subject', '?')} 申请超长 token，等价长期凭据植入。",
            f"subject={request.get('subject')} expiration_days={int(days)}",
            "强制短有效期（≤1h）+ audience 绑定"))

    for patch in persistence.get("pull_secret_patches") or []:
        indicators["pull_secret_patches"] += 1
        findings.append(_finding(
            "medium",
            f"default SA 被注入 imagePullSecrets：{patch.get('namespace', '')}/"
            f"{patch.get('serviceaccount', '')}",
            f"注入 {patch.get('secret', '?')} 可让该命名空间全部 Pod 使用攻击者镜像仓库凭据"
            "（拉取面持久化）。",
            f"sa={patch.get('serviceaccount')} secret={patch.get('secret')}",
            "default SA 不挂 pull secret；按工作负载显式绑定"))

    for webhook in persistence.get("webhooks") or []:
        url = str(webhook.get("url", ""))
        if not url or webhook.get("failurePolicy") != "Ignore":
            continue
        indicators["webhooks"] += 1
        findings.append(_finding(
            "high", f"准入 webhook 指向外部且 fail-open：{webhook.get('name', '?')}",
            f"URL {url} + failurePolicy=Ignore：控制面不可用时放行，且可篡改 Pod（持久化/后门面）。",
            f"webhook={webhook.get('name')} url={url}",
            "webhook 强制 fail-closed + 域名白名单 + mTLS"))

    return {"findings": findings, "indicators": indicators,
            "checked": sum(indicators.values())}
