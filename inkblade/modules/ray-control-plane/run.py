"""ray-control-plane — Ray 控制面侦察：RayCluster/RayService/RayJob、dashboard 暴露与认证、autoscaler 权限观察点。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    services = snapshot.get("services", [])
    ray_crs = list(snapshot.get("rayclusters", [])) + list(snapshot.get("rayservices", []))
    head_service_names = {rc.get("headService") for rc in ray_crs if rc.get("headService")}
    # 索引：name -> 第一个同名 Service（与 next(...) 首个匹配语义一致），把 O(raycrs×services) 降为线性
    service_by_name: dict = {}
    for svc_entry in services:
        service_by_name.setdefault(svc_entry.get("name"), svc_entry)

    for rc in ray_crs:
        ns = rc.get("namespace", "default")
        name = rc.get("name", "?")
        dash = rc.get("dashboardPort", "未标注")
        auth = rc.get("auth", "unknown")
        svc = service_by_name.get(rc.get("headService"))
        svc_type = svc.get("type", "未发现") if svc else "未发现"
        exposed = bool(svc) and svc.get("type") in ("LoadBalancer", "NodePort")
        if auth in ("none", "") and exposed:
            sev = "critical"
        elif exposed or auth in ("none", ""):
            sev = "high"
        else:
            sev = "medium"
        findings.append(finding(
            sev, f"RayCluster {ns}/{name}：dashboard {dash} 认证={auth}，head Service={rc.get('headService', '-')}（{svc_type}）",
            detail="Ray dashboard 提交 Job 即头节点执行入口：无认证且对外暴露时，任意可达主体可在头节点执行任意命令。",
            evidence=f"raycluster={ns}/{name} dashboardPort={dash} auth={auth} headService={rc.get('headService')} serviceType={svc_type}",
            mapping="链「Ray Dashboard → 集群控制」（ray-dashboard-job → 宽 ServiceAccount 提权）",
            fix="dashboard 8265 强制认证与 NetworkPolicy 限源；Job 提交面仅系统命名空间可达；head 最小权限 SA",
        ))
        sa = rc.get("autoscalerSA")
        if sa:
            findings.append(finding(
                "medium", f"Ray autoscaler/operator 权限观察点：ServiceAccount {sa}",
                detail="autoscaler/operator 以该 SA 创建与删除工作负载；权限过宽（如 pods/exec、roles create）即成提权支点。",
                evidence=f"autoscalerSA={sa} raycluster={ns}/{name}",
                mapping="交叉验证 rbac-mapping / overprivileged-sa-escalation",
                fix="autoscaler 收敛为 namespace 内最小 Role；禁止集群级 pods/exec 与 RBAC 写",
            ))
    rayjobs = snapshot.get("rayjobs", [])
    if rayjobs:
        names = ", ".join(j.get("name", "?") for j in rayjobs)
        findings.append(finding(
            "info", f"RayJob 清单：{len(rayjobs)} 条（{names}）",
            detail="RayJob 表示已有主体经 dashboard/GCS 提交作业——是入口有效性的旁证（结合审计日志核对提交者）。",
            evidence=f"rayjobs={len(rayjobs)}",
            mapping="Ray 控制面侦察",
            fix="开启 Ray 作业审计日志并核对提交主体白名单",
        ))
    for svc in services:
        if svc.get("name") in head_service_names:
            continue
        ports = [p.get("port") for p in svc.get("ports", [])]
        if 8265 in ports:
            findings.append(finding(
                "high", f"疑似 Ray dashboard 端口暴露：{svc.get('namespace', 'default')}/{svc.get('name')}:8265",
                detail="Service 暴露 8265 但快照无对应 RayCluster 记录（可能由 operator/Helm 间接创建），按 Ray 控制面入口核对。",
                evidence=f"service={svc.get('name')} port=8265 type={svc.get('type')}",
                mapping="链「Ray Dashboard → 集群控制」",
                fix="确认归属；8265 一律认证 + 限源",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="Ray 控制面侦察")
