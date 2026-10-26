"""rbac-mapping — RBAC 权限测绘：can-i 矩阵、cluster-admin/通配符、RBAC 扩散权限、Secret 名称盘点。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

RBAC_OBJECTS = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}


def _image_tag_mutable(image: str) -> bool:
    """无 tag / :latest（可变标签）且无 digest 锚定 = 供应链可替换面。"""
    if not image or "@" in image:  # digest 锚定（即使 tag 可变，内容固定）
        return False
    tag = image.rsplit("/", 1)[-1]
    return ":" not in tag or tag.rsplit(":", 1)[1].lower() == "latest"


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []

    # 镜像可变标签盘点（供应链提权面：镜像引用可被仓库侧重放/替换）
    for pod in snapshot.get("pods", []):
        pid = f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"
        for container in pod.get("containers", []):
            image = str(container.get("image", ""))
            if _image_tag_mutable(image):
                findings.append(finding(
                    "medium", f"{pid}：镜像可变标签（{image}）",
                    detail="无 tag/:latest 且无 digest 锚定 = 镜像内容可被仓库侧重放"
                           "（供应链注入→运行时提权面，绕过镜像扫描时点）。",
                    evidence=f"pod={pid} image={image}",
                    mapping="供应链投毒面；权限链「容器运行时 Socket 逃逸」上游",
                    fix="镜像引用统一 digest 锚定（@sha256:…）+ 准入校验注册表白名单",
                ))

    for scope, key in (("ClusterRole", "clusterroles"), ("Role", "roles")):
        for role in snapshot.get(key, []):
            rules = role.get("rules", [])
            wildcard = any(
                "*" in r.get("verbs", []) or "*" in r.get("resources", []) or "*" in r.get("apiGroups", [])
                for r in rules
            )
            if wildcard:
                findings.append(finding(
                    "critical", f"通配符{scope}：{role.get('name', '?')}",
                    detail="verbs/resources/apiGroups 含 *：等价全权限（准 cluster-admin），绑定主体可接管集群。",
                    evidence=f"{scope}={role.get('name')} rules={rules}",
                    mapping="权限链「KubeRay Operator 提权」等 operator 链前置",
                    fix="改写为按资源/动词最小化清单；禁止通配符进入生产角色",
                ))
                continue
            spread = sorted({res for r in rules if "create" in r.get("verbs", []) for res in r.get("resources", [])} & RBAC_OBJECTS)
            if spread:
                findings.append(finding(
                    "high", f"RBAC 扩散权限：{scope} {role.get('name', '?')} 可创建 {'/'.join(spread)}",
                    detail="可创建 roles/rolebindings 即可自铸高权绑定（提权闭环），无需触碰节点。",
                    evidence=f"{scope}={role.get('name')} create={spread}",
                    mapping="权限链「vLLM Operator RBAC 提权」；Sigma 规则「创建指向 cluster-admin 的 RoleBinding」",
                    fix="移除 RBAC 对象创建权限；准入告警/拦截 RoleBinding 扩散",
                ))

    for key in ("clusterrolebindings", "rolebindings"):
        for binding in snapshot.get(key, []):
            if binding.get("role") == "cluster-admin":
                subjects = ", ".join(
                    f"{s.get('kind')}:{s.get('name')}" + (f"@{s.get('namespace')}" if s.get("namespace") else "")
                    for s in binding.get("subjects", [])
                )
                findings.append(finding(
                    "critical", f"cluster-admin 绑定：{binding.get('name', '?')} → {subjects}",
                    detail="cluster-admin 主体一步接管集群（含节点与密钥面）。",
                    evidence=f"binding={binding.get('name')} role=cluster-admin subjects={subjects}",
                    mapping="权限链判定总入口；审计重点主体",
                    fix="清点并最小化 cluster-admin 主体；改细分角色 + break-glass 审批",
                ))

    for entry in snapshot.get("cani", []):
        subject = entry.get("subject", "?")
        allowed = entry.get("allowed", [])
        wildcard = "*" in allowed
        if wildcard or any("pods/exec" in a for a in allowed):
            findings.append(finding(
                "high", f"can-i：{subject} 可 exec Pod（提权/横向支点）",
                detail="pods/exec 允许进入任意（含特权）容器，等价借用其能力与挂载凭据。",
                evidence=f"subject={subject} allowed={allowed}",
                mapping="权限链「宽 ServiceAccount 提权」；链「Ray Dashboard → 集群控制」末段",
                fix="exec 权限收敛到运维.break-glass 角色；会话审计与告警",
            ))
        if wildcard or any("secrets" in a for a in allowed):
            findings.append(finding(
                "medium", f"can-i：{subject} 可读 Secrets",
                detail="Secrets 读取可达 SA token/云凭据/模型仓库凭据（横向与云侧链起点）。",
                evidence=f"subject={subject} allowed={allowed}",
                mapping="链「SSRF / SA Token → 云元数据」；「LWS 集群级 Secrets 横向」",
                fix="按命名空间最小化 secrets 读；敏感 Secret 改外部密钥管理 + 短时效",
            ))

    secrets = snapshot.get("secrets", [])
    if secrets:
        names = [f"{s.get('namespace', 'default')}/{s.get('name', '?')}" for s in secrets]
        shown = ", ".join(names[:20]) + ("…" if len(names) > 20 else "")
        findings.append(finding(
            "info", f"Secret 名称盘点：{len(names)} 项",
            detail="名称清单供凭据面链（supply-chain-credential-theft / 云角色链）定位目标，不含值。",
            evidence=f"secrets={shown}",
            mapping="窃取与数据泄露族目标定位",
            fix="梳理凭据类 Secret 生命周期：轮换、加密静态存储与按需挂载",
        ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="RBAC 权限测绘")
