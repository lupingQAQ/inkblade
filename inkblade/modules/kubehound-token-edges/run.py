"""kubehound-token-edges — TOKEN_STEAL / TOKEN_LIST / TOKEN_BRUTEFORCE 三边判定。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, subjects_with, pod_id, automount_token = _C.section, _C.subjects_with, _C.pod_id, _C.automount_token
pods = _C.pods


def analyze(snapshot: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    secrets = section(snapshot, "secrets")
    token_secrets = [s for s in secrets if "token" in str(s.get("type", ""))
                     or re_token_name(str(s.get("name", "")))]
    automount = [pod_id(p) for p in pods(snapshot) if automount_token(p)]
    exec_subjects = subjects_with(snapshot, "create", "pods/exec")
    get_secret = subjects_with(snapshot, "get", "secrets")
    list_secret = subjects_with(snapshot, "list", "secrets")
    create_pods = subjects_with(snapshot, "create", "pods")

    for subject in sorted(set(get_secret) | set(exec_subjects)):
        if automount or exec_subjects:
            out.append(finding(
                "critical",
                f"TOKEN_STEAL：{subject} 可读取 SA token（{len(automount)} 个 automount Pod）",
                "get secrets 或 pods/exec × 默认挂载 token = 直接窃取可用 API 凭据。",
                evidence=f"subject={subject} automount_pods={automount[:3]} exec={subject in exec_subjects}",
                mapping_text="KubeHound TOKEN_STEAL；KubeTrail token 审计",
                fix="bound token（短有效期/audience）+ secret get 收敛 + 禁 automount",
                edge="TOKEN_STEAL",
            ))
        else:
            out.append(finding(
                "high", f"TOKEN_STEAL：{subject} 可读取 Secret（无 automount 先例）",
                "Secret 读取仍可获取长期 token/镜像凭据。",
                evidence=f"subject={subject}", mapping_text="KubeHound TOKEN_STEAL",
                fix="secret get 收敛到平台组件", edge="TOKEN_STEAL",
            ))

    for subject in list_secret:
        out.append(finding(
            "high", f"TOKEN_LIST：{subject} 可枚举全部 Secret（{len(secrets)} 个）",
            "枚举可直接定位 legacy token / 权重桶 / 镜像仓库凭据。",
            evidence=f"subject={subject} secrets={len(secrets)} token_secrets={len(token_secrets)}",
            mapping_text="KubeHound TOKEN_LIST", fix="list secrets 收敛；开启 audit 告警",
            edge="TOKEN_LIST",
        ))

    predictable = [s.get("name") for s in token_secrets
                   if re_token_name(str(s.get("name", "")))]
    if predictable and list_secret:
        out.append(finding(
            "critical",
            f"TOKEN_BRUTEFORCE：{len(predictable)} 个 token 名称可枚举 × list 权限",
            "legacy token 命名遵循 <sa>-token-<随机>，结合 list 权限可批量爆破/定位有效 token。",
            evidence=f"subjects={list_secret} names={predictable[:4]}",
            mapping_text="KubeHound TOKEN_BRUTEFORCE（CM-08 扩展面）",
            fix="短有效期 bound token + 随机化 secret 名 + 禁 list secrets",
            edge="TOKEN_BRUTEFORCE",
        ))
    elif create_pods:
        out.append(finding(
            "medium", f"TOKEN_BRUTEFORCE 面：{len(create_pods)} 个主体可建 Pod（可挂载任意 SA token）",
            "create pods 可选择任意 serviceAccountName，等价 token 采集通道。",
            evidence=f"subjects={create_pods}", mapping_text="KubeHound TOKEN_BRUTEFORCE",
            fix="create pods 收敛 + 准入限制 serviceAccountName", edge="TOKEN_BRUTEFORCE",
        ))
    return out


def re_token_name(name: str) -> bool:
    return bool(name) and ("-token-" in name or name.endswith("-token"))


def extra(snapshot: dict, findings: list[dict]) -> dict:
    edges = sorted({f.get("edge") for f in findings if f.get("edge")})
    return {"edges": edges, "token_secrets": len([s for s in section(snapshot, "secrets")
                                                   if "token" in str(s.get("type", ""))
                                                   or re_token_name(str(s.get("name", "")))])}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeHound Token 边", extra=extra)
