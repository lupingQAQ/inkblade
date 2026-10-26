"""kube-bench-cis — CIS 条目级检查（API Server/Controller Manager/Scheduler/etcd/kubelet/config）。

按 ``cis.profile`` 选择基线；每项给 CIS id、期望值、实测值、修复建议与分区。
缺失键视为 ``skipped``（不臆造失败）；判定口径保守但可解释。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface

# (cis_id, section, key, expectation, sev, title)
CHECKS = (
    ("1.2.1", "apiserver", "anonymous-auth", ("eq", "false"), "critical", "API Server 匿名认证"),
    ("1.2.2", "apiserver", "insecure-port", ("eq", "0"), "critical", "API Server insecure-port"),
    ("1.2.3", "apiserver", "authorization-mode", ("not_contains", "AlwaysAllow"), "critical", "授权模式"),
    ("1.2.4", "apiserver", "audit-log-path", ("nonempty",), "high", "审计日志"),
    ("1.2.5", "apiserver", "profiling", ("eq", "false"), "medium", "profiling"),
    ("1.2.6", "apiserver", "enable-admission-plugins", ("contains", "NodeRestriction"), "high", "准入插件"),
    ("1.2.7", "apiserver", "disable-admission-plugins", ("not_contains", "NodeRestriction"), "high", "NodeRestriction 禁用面"),
    ("1.2.8", "apiserver", "tls-cert-file", ("nonempty",), "high", "TLS 证书"),
    ("1.2.9", "apiserver", "client-ca-file", ("nonempty",), "high", "客户端 CA"),
    ("1.3.1", "controllermanager", "use-service-account-credentials", ("eq", "true"), "high", "SA 凭据分离"),
    ("1.3.2", "controllermanager", "insecure-port", ("eq", "0"), "high", "CM insecure-port"),
    ("1.3.3", "controllermanager", "profiling", ("eq", "false"), "medium", "CM profiling"),
    ("1.3.4", "controllermanager", "bind-address", ("eq", "127.0.0.1"), "high", "CM 绑定地址"),
    ("1.4.1", "scheduler", "profiling", ("eq", "false"), "medium", "Scheduler profiling"),
    ("1.4.2", "scheduler", "bind-address", ("eq", "127.0.0.1"), "high", "Scheduler 绑定地址"),
    ("2.1", "etcd", "client-cert-auth", ("eq", "true"), "critical", "etcd 客户端证书认证"),
    ("2.2", "etcd", "auto-tls", ("eq", "false"), "high", "etcd auto-tls"),
    ("2.3", "etcd", "peer-client-cert-auth", ("eq", "true"), "high", "etcd peer 证书认证"),
    ("4.2.1", "kubelet", "anonymous-auth", ("eq", "false"), "critical", "kubelet 匿名认证"),
    ("4.2.2", "kubelet", "authorization-mode", ("eq", "Webhook"), "high", "kubelet 授权模式"),
    ("4.2.3", "kubelet", "read-only-port", ("eq", "0"), "high", "kubelet 只读端口"),
    ("4.2.4", "kubelet", "protect-kernel-defaults", ("eq", "true"), "high", "kubelet 内核默认值保护"),
    ("4.2.5", "kubelet", "streaming-connection-idle-timeout", ("not_eq", "0"), "medium", "kubelet 流超时"),
    ("4.2.6", "kubelet", "make-iptables-util-chains", ("eq", "true"), "medium", "kubelet iptables 管理"),
    ("5.1.1", "config", "kubeconfig_permissions", ("eq", "600"), "critical", "kubeconfig 权限"),
    ("5.1.2", "config", "admin_cert_permissions", ("eq", "600"), "critical", "admin 证书权限"),
    ("5.1.3", "config", "etcd_data_permissions", ("eq", "700"), "high", "etcd 数据目录权限"),
)

SECTIONS = {
    "apiserver": "控制面 · API Server",
    "controllermanager": "控制面 · Controller Manager",
    "scheduler": "控制面 · Scheduler",
    "etcd": "控制面 · etcd",
    "kubelet": "节点 · kubelet",
    "config": "节点 · 配置文件权限",
}


def _check(value: str, expectation: tuple) -> bool:
    op = expectation[0]
    text = str(value).strip()
    lowered = text.lower()
    if op == "eq":
        return lowered == str(expectation[1]).lower()
    if op == "not_eq":
        return lowered != str(expectation[1]).lower()
    if op == "contains":
        return str(expectation[1]).lower() in lowered
    if op == "not_contains":
        return str(expectation[1]).lower() not in lowered
    if op == "nonempty":
        return bool(text)
    return False


def analyze(snapshot: dict, params: dict) -> list[dict]:
    cis = snapshot.get("cis") or {}
    out = []
    for cis_id, sect, key, expectation, sev, title in CHECKS:
        block = cis.get(sect) or {}
        if key not in block:
            continue
        value = block.get(key)
        if _check(value, expectation):
            continue
        expected = expectation[1] if len(expectation) > 1 else "<非空>"
        out.append(finding(
            sev, f"CIS {cis_id} 未通过：{title}",
            f"{SECTIONS.get(sect, sect)}：{key}={value!r}，期望 {expected}。",
            evidence=f"cis={cis.get('profile', '?')} section={sect} {key}={value}",
            mapping_text=f"kube-bench CIS {cis.get('profile', 'cis')} / 条目 {cis_id}",
            fix="按 CIS Benchmark 修复对应 flag/权限并回归",
            cis_id=cis_id, section=sect, key=key, value=value,
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    cis = snapshot.get("cis") or {}
    run = skipped = 0
    for _cis_id, sect, key, _exp, _sev, _title in CHECKS:
        if key in (cis.get(sect) or {}):
            run += 1
        else:
            skipped += 1
    passed = run - len(findings)
    return {"profile": cis.get("profile", ""), "checks_run": run, "passed": passed,
            "failed": len(findings), "skipped": skipped,
            "score": round(passed / run, 3) if run else 0.0}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="kube-bench CIS", extra=extra)
