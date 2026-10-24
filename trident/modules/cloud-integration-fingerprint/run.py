"""cloud-integration-fingerprint — 云商识别与云集成面：providerID/IRSA/Workload Identity/云存储类/混合互联。"""
from __future__ import annotations

import re
import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

PROVIDER_MATCHERS: list[tuple[str, object]] = [
    ("EKS（AWS）", lambda pid: pid.startswith(("aws://", "aws:"))),
    ("AKS（Azure）", lambda pid: pid.startswith(("azure://", "azure:"))),
    ("GKE（GCP）", lambda pid: pid.startswith(("gce://", "gce:"))),
    ("ACK（阿里云）", lambda pid: bool(re.match(r"^cn-[a-z0-9-]+\.i-", pid)) or pid.startswith("aliyun://")),
    ("TKE（腾讯云）", lambda pid: pid.startswith(("qcloud://", "tencent://"))),
    ("CCE（华为云）", lambda pid: pid.startswith("cce:") or "huawei" in pid),
]
CLOUD_PROVISIONER_HINTS = ("alibabacloud", "aws", "azure", "tencentcloud", "googleapis", "huawei")
SA_ANNOTATION_RULES = (
    ("eks.amazonaws.com/role-arn", "IRSA 角色绑定", "medium"),
    ("azure.workload.identity/use", "Azure Workload Identity", "medium"),
    ("iam.gke.io/gcp-service-account", "GCP Workload Identity 联邦", "medium"),
)


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    nodes = snapshot.get("nodes", [])
    matched: dict[str, list[str]] = {}
    sample_provider_id: dict[str, str] = {}
    for node in nodes:
        pid = str(node.get("providerID") or "")
        for provider, matcher in PROVIDER_MATCHERS:
            if pid and matcher(pid):  # type: ignore[operator]
                matched.setdefault(provider, []).append(str(node.get("name", "?")))
                sample_provider_id.setdefault(provider, pid)
                break
    for provider, names in sorted(matched.items()):
        findings.append(finding(
            "info", f"云商识别：{provider}（{len(names)} 节点）",
            detail="云 K8s 形态决定后续云侧链面：IMDS 端点、云角色绑定方式与 VPC-CNI 安全组双控制面。",
            evidence=f"provider={provider} nodes={names[:5]} sample_providerID={sample_provider_id[provider]}",
            mapping="链「云集成指纹 → 多云元数据凭据面 → 云角色过权」；VPC-CNI 双控制面错配检测",
            fix="按云商收敛：IMDSv2/强认证、最小实例角色、VPC 安全组与 NetworkPolicy 对账",
        ))
    if nodes and not matched:
        findings.append(finding(
            "info", "未识别云商（providerID 缺失）→ 自建/裸金属形态判定",
            detail="无云 providerID：按自建集群路径继续（重点转为 fabric/主机网络层与本地凭据面）。",
            evidence=f"nodes={len(nodes)} providerID=absent",
            mapping="网络分层「物理 Fabric 层」；混合云出网与回旋",
            fix="确认部署形态后套用对应检测面（自建重点：IB/RDMA 隔离与出口治理）",
        ))

    for sa in snapshot.get("serviceaccounts", []):
        annotations = sa.get("annotations") or {}
        for key, label, sev in SA_ANNOTATION_RULES:
            if key in annotations:
                findings.append(finding(
                    sev, f"{label}：{sa.get('namespace', 'default')}/{sa.get('name', '?')} → {annotations[key]}",
                    detail="Pod 级云身份绑定：绑定角色的权限即该命名空间全部工作负载的云权限（角色过权直接放大到租户面）。",
                    evidence=f"sa={sa.get('namespace')}/{sa.get('name')} annotation={key} value={annotations[key]}",
                    mapping="云角色过权（cloud-role-overprivilege）；四条云侧权重桶链",
                    fix="按工作负载最小化角色；条件密钥限定；云侧权限变更纳入审计",
                ))

    for sc in snapshot.get("storageclasses", []):
        provisioner = str(sc.get("provisioner", ""))
        if any(h in provisioner.lower() for h in CLOUD_PROVISIONER_HINTS):
            findings.append(finding(
                "info", f"云存储类：{sc.get('name', '?')}（{provisioner}）",
                detail="云块/对象存储入口：checkpoint 与权重桶的落点线索（云角色链的目标面）。",
                evidence=f"storageclass={sc.get('name')} provisioner={provisioner}",
                mapping="云侧权重桶链（S3/OSS/COS/Blob）",
                fix="存储桶按租户隔离 + KMS 加密 + 版本化防投毒",
            ))

    for ic in snapshot.get("interconnects", []):
        findings.append(finding(
            "medium", f"混合互联形态：{ic.get('kind', '?')} {ic.get('name', '?')}（peer={ic.get('peer', '?')}）",
            detail="专线/云联网把本地与云私网打通：横向平网从集群扩展到混合边界，需双向限流与隔离评估。",
            evidence=f"interconnect={ic}",
            mapping="混合云出网与回旋（hybrid-cloud-egress-pivot）",
            fix="互联边界最小化路由；跨边界流量审计与出口白名单",
        ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="云集成指纹")
