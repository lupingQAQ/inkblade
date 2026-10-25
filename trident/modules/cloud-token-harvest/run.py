"""cloud-token-harvest — AWS/GCP/Azure 凭据与元数据收割面（CM-21）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface

PROVIDERS = ("aws", "gcp", "azure")


def _view(snapshot: dict) -> dict:
    return snapshot.get("inpod") or {}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    view = _view(snapshot)
    env = {str(k).upper(): str(v) for k, v in (view.get("environment") or {}).items()}
    metadata = view.get("cloud_metadata") or {}
    creds = [c for c in (view.get("credentials") or {}).get("files") or [] if c.get("readable")]
    out: list[dict] = []

    def add(provider: str, sev: str, title: str, detail: str, evidence: str, fix: str) -> None:
        out.append(finding(sev, f"[{provider.upper()}] {title}", detail, evidence=evidence,
                           mapping_text="Peirates 云凭据收割（CM-21）+ KubeTrail cloud_metadata",
                           fix=fix, provider=provider))

    aws_env = sorted(k for k in env if k.startswith("AWS_"))
    aws_meta = metadata.get("aws") or {}
    if aws_meta.get("reachable"):
        add("aws", "critical", "IMDS 可达（实例角色凭据）",
            f"可读取角色 {aws_meta.get('role', '?')} 的临时凭据 → 云侧横向。",
            f"role={aws_meta.get('role')} metadata=reachable", "IMDSv2 + hop limit 1 + 网络策略")
    if aws_env:
        add("aws", "medium", f"环境变量含 AWS 配置 {aws_env[:4]}",
            "AWS_* 环境变量可用于定位区域/角色（部分场景含静态凭据）。",
            f"env={aws_env[:4]}", "改用 IRSA/Pod Identity，禁静态 AK")

    gcp_env = sorted(k for k in env if k.startswith(("GOOGLE_", "GCP_")))
    gcp_meta = metadata.get("gcp") or {}
    if gcp_meta.get("reachable"):
        add("gcp", "critical", "GCE 元数据可达（服务账号 token）",
            "可读取默认 SA token/scopes → 云侧横向。",
            "metadata=reachable", "Workload Identity + metadata concealment")
    if gcp_env:
        add("gcp", "high", f"环境变量指向 GCP 凭据 {gcp_env[:4]}",
            "GOOGLE_APPLICATION_CREDENTIALS 常指向可读 SA JSON。",
            f"env={gcp_env[:4]}", "Workload Identity；禁挂载 SA key")

    azure_env = sorted(k for k in env if k.startswith(("AZURE_", "MSI_")))
    azure_meta = metadata.get("azure") or {}
    if azure_meta.get("reachable"):
        add("azure", "critical", "Azure IMDS/MSI 可达",
            "可读取托管身份 token → 订阅内横向。",
            f"msi={azure_meta.get('msi')}", "最小托管身份 + 网络策略")
    if azure_env:
        add("azure", "medium", f"环境变量含 Azure 身份线索 {azure_env[:4]}",
            "AZURE_CLIENT_ID/SECRET 等可定位托管身份或服务主体。",
            f"env={azure_env[:4]}", "改用 Workload Identity（联邦凭据）")

    for cred in creds:
        kind = str(cred.get("kind", ""))
        provider = {"aws": "aws", "gcp": "gcp", "azure": "azure", "docker": "aws"}.get(kind, "")
        if kind in ("aws", "gcp", "azure"):
            add(provider or kind, "high", f"凭据文件可读：{cred.get('path')}",
                "云凭据文件可被容器内进程读取并外带。",
                f"file={cred.get('path')} kind={kind}", "只读根文件系统 + 外部密钥管理")
        elif kind == "docker":
            add("aws", "medium", f"镜像仓库凭据可读：{cred.get('path')}",
                "registry 凭据可拉取/推送私有镜像（供应链横向）。",
                f"file={cred.get('path')}", "按工作负载最小 pull secret")

    kops = (snapshot.get("cloud") or {}).get("kops_state")
    if kops:
        add("aws", "high", f"kops state store 可见：{kops}",
            "kops state 含集群凭据/密钥（S3/GCS）。", f"kops_state={kops}",
            "限制 state bucket 访问 + 审计")
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    view = _view(snapshot)
    return {"providers_hit": sorted({f.get("provider") for f in findings if f.get("provider")}),
            "env_keys": sorted((view.get("environment") or {}).keys()),
            "metadata": {k: bool(v.get("reachable")) for k, v in (view.get("cloud_metadata") or {}).items()
                         if isinstance(v, dict)}}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="云 Token 收割面", extra=extra)
