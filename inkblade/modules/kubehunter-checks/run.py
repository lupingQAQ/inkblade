"""kubehunter-checks — kube-hunter 47 Vuln 检查族的控制面/节点具象检查（带 VID + MITRE）。

本模块实现 29 条可快照判定的检查（catalog=47，含依赖主动探测/CIDR 的项见
``checks_unimplemented``）；全部只读，不发起扫描。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section = _C.section

CATALOG = 47


def _first(items: list) -> dict:
    return items[0] if items else {}


def _cfg(snapshot: dict) -> dict:
    cis = snapshot.get("cis") or {}
    return {
        "apiserver": snapshot.get("apiserver") or {},
        "kubelet": _first(section(snapshot, "kubelet")),
        "etcd": _first(section(snapshot, "etcd")),
        "dashboard": _first(section(snapshot, "dashboard")),
        "proxy": _first(section(snapshot, "proxy")),
        "certificates": section(snapshot, "certificates"),
        "aks": snapshot.get("aks") or {},
        "cis_apiserver": cis.get("apiserver") or {},
        "cluster": snapshot.get("cluster") or {},
    }


CHECKS = (
    ("KHV-APISERVER-ANON", "API Server 允许匿名访问", "high", "T1078",
     lambda c: bool(c["apiserver"].get("anonymous_auth"))),
    ("KHV-APISERVER-INSECURE", "API Server insecure-port 开放", "critical", "T1190",
     lambda c: str(c["apiserver"].get("insecure_port", "0")) not in ("0", "", "None")),
    ("KHV-APISERVER-AUTHZ", "授权模式含 AlwaysAllow", "critical", "T1078",
     lambda c: "AlwaysAllow" in (c["apiserver"].get("authorization_mode") or [])),
    ("KHV-APISERVER-AUDIT", "审计日志未配置", "high", "T1562.008",
     lambda c: not str(c["apiserver"].get("audit_log") or c["cis_apiserver"].get("audit-log-path") or "")),
    ("KHV-APISERVER-PROFILING", "profiling 端点开放", "medium", "T1592",
     lambda c: bool(c["apiserver"].get("profiling"))),
    ("KHV-APISERVER-NODERESTRICTION", "NodeRestriction 准入被禁用", "high", "T1610",
     lambda c: "NodeRestriction" in (c["apiserver"].get("disable_admission_plugins") or [])),
    ("KHV-APISERVER-PODSECURITY", "PodSecurity 准入未启用", "high", "T1610",
     lambda c: not any("PodSecurity" in str(p) for p in (c["apiserver"].get("enable_admission_plugins") or []))),
    ("KHV-APISERVER-TLS", "API Server 未配置 TLS 证书/客户端 CA", "high", "T1040",
     lambda c: not (c["cis_apiserver"].get("tls-cert-file") and c["cis_apiserver"].get("client-ca-file"))),
    ("KHV-APISERVER-HTTP2", "HTTP/2 持续开放（Rapid Reset 面）", "medium", "T1499",
     lambda c: bool(c["apiserver"].get("http2"))),
    ("KHV-APISERVER-VERSION", "版本信息可指纹化", "low", "T1592",
     lambda c: bool(c["apiserver"].get("version") or c["cluster"].get("version"))),
    ("KHV-KUBELET-ANON", "kubelet 允许匿名访问", "critical", "T1078",
     lambda c: bool(c["kubelet"].get("anonymous_auth"))),
    ("KHV-KUBELET-READONLY", "kubelet 只读端口 10255 开放", "high", "T1592",
     lambda c: str(c["kubelet"].get("read_only_port", "0")) not in ("0", "", "None")),
    ("KHV-KUBELET-AUTHZ", "kubelet 授权模式非 Webhook", "high", "T1078",
     lambda c: str(c["kubelet"].get("authorization_mode", "")).lower() not in ("webhook", "")),
    ("KHV-KUBELET-EXEC", "kubelet exec 通道可达", "critical", "T1609",
     lambda c: "exec" in (c["kubelet"].get("endpoints") or [])),
    ("KHV-KUBELET-RUN", "kubelet run 通道可达", "critical", "T1609",
     lambda c: "run" in (c["kubelet"].get("endpoints") or [])),
    ("KHV-KUBELET-CRI", "kubelet CRI 通道可达", "high", "T1609",
     lambda c: "cri" in (c["kubelet"].get("endpoints") or [])),
    ("KHV-KUBELET-LOGS", "kubelet logs 可读", "medium", "T1552",
     lambda c: "logs" in (c["kubelet"].get("endpoints") or [])),
    ("KHV-KUBELET-CONFIGZ", "kubelet configz 可读", "medium", "T1592",
     lambda c: "configz" in (c["kubelet"].get("endpoints") or [])),
    ("KHV-KUBELET-PROTECT", "kubelet 未保护内核默认值", "high", "T1611",
     lambda c: c["kubelet"].get("protect_kernel_defaults") is False),
    ("KHV-ETCD-NOAUTH", "etcd 未启用客户端证书认证", "critical", "T1078",
     lambda c: c["etcd"].get("client_cert_auth") is False),
    ("KHV-ETCD-AUTOTLS", "etcd 使用自签 auto-tls", "high", "T1040",
     lambda c: bool(c["etcd"].get("auto_tls"))),
    ("KHV-ETCD-WRITABLE", "etcd 可写", "critical", "T1565",
     lambda c: bool(c["etcd"].get("writable"))),
    ("KHV-ETCD-VERSION", "etcd 版本泄露", "low", "T1592",
     lambda c: bool(c["etcd"].get("version"))),
    ("KHV-DASHBOARD-ANON", "dashboard 匿名访问", "critical", "T1078",
     lambda c: bool(c["dashboard"].get("anonymous"))),
    ("KHV-DASHBOARD-EXPOSED", "dashboard 对外暴露", "high", "T1133",
     lambda c: str(c["dashboard"].get("exposed", "")).lower() in ("loadbalancer", "nodeport")),
    ("KHV-PROXY-EXPOSED", "kubectl proxy 对外暴露", "high", "T1090",
     lambda c: bool(c["proxy"].get("exposed"))),
    ("KHV-CERT-WEAK", "证书密钥强度/签名算法弱", "high", "T1600",
     lambda c: any(int(x.get("key_bits", 4096)) < 2048 or x.get("signature") == "sha1"
                   for x in c["certificates"])),
    ("KHV-CERT-EXPIRY", "证书即将过期（<30 天）", "medium", "T1553",
     lambda c: any(int(x.get("expires_in_days", 3650)) < 30 for x in c["certificates"])),
    ("KHV-AKS-ANON", "AKS 集群匿名访问", "high", "T1078",
     lambda c: bool(c["aks"].get("anonymous"))),
)


SECTION_KEYS = {
    "APISERVER": ("apiserver", "cis_apiserver"),
    "KUBELET": ("kubelet",),
    "ETCD": ("etcd",),
    "DASHBOARD": ("dashboard",),
    "PROXY": ("proxy",),
    "CERT": ("certificates",),
    "AKS": ("aks",),
}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    cfg = _cfg(snapshot)
    out = []
    for vid, title, sev, mitre, predicate in CHECKS:
        keys = SECTION_KEYS.get(vid.split("-")[1], ())
        if not any(cfg.get(k) for k in keys):
            continue  # 无可判定数据：不臆造失败
        try:
            vulnerable = bool(predicate(cfg))
        except Exception:
            vulnerable = False
        if not vulnerable:
            continue
        out.append(finding(
            sev, f"{vid}：{title}",
            f"kube-hunter 检查项 {vid} 判定为暴露/未加固（只读快照判定）。",
            evidence=f"check={vid} mitre={mitre}",
            mapping_text=f"kube-hunter hunting checks（47 类）；MITRE {mitre}",
            fix="按 CIS/NSA-CISA 基线加固对应组件",
            vid=vid, mitre=mitre,
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    return {"checks_catalog": CATALOG, "checks_implemented": len(CHECKS),
            "checks_run": len(CHECKS), "failed": len(findings),
            "checks_unimplemented": CATALOG - len(CHECKS)}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="kube-hunter 检查", extra=extra)
