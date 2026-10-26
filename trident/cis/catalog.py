# -*- coding: utf-8 -*-
"""CIS 基准目录 — Kubernetes v1.8.0（kube-bench cis-1.8 全量 130 项）
+ 前向兼容 1 项（cis-1.9 §4.3.1）+ 节点主机 CIS 26 项 + k3s 自管面 5 项。

设计口径：
- ``tier`` 区分来源：``cis-1.8`` / ``cis-1.9`` / ``cis-host`` / ``cis-k3s``；
- ``kind`` 是判定方式（flag / pair / file / owner / evidence / plugin / kubelet / manual），
  判定逻辑在 :mod:`trident.cis.engine`，本文件只存"事实与期望"，不执行任何写操作；
- ``scored`` 与 kube-bench profile 对齐（130 项中 63 项计分、40 项 Manual）；
- 缺失证据一律 ``manual``，不臆造 pass/fail。

来源：aquasecurity/kube-bench ``cfg/cis-1.8/*.yaml``（130 项，2026-10-26 核对）；
CIS Distribution Independent Linux v2.0.0；k3s security hardening 文档。
"""
from __future__ import annotations

OFFICIAL_SECTIONS = {
    "1.1": 21, "1.2": 30, "1.3": 7, "1.4": 2, "2": 7,
    "3.1": 3, "3.2": 2, "4.1": 10, "4.2": 13,
    "5.1": 13, "5.2": 13, "5.3": 2, "5.4": 2, "5.5": 1, "5.7": 4,
}

CRITICAL_IDS = {
    "1.1.21", "1.2.1", "1.2.2", "1.2.6", "1.2.25", "1.2.26", "1.2.28",
    "2.1", "2.2", "2.4", "4.1.5", "4.2.1", "4.2.3", "K3S-1", "K3S-3",
}

DEFAULT_FIX = "按 CIS 基线修复对应 flag/文件权限/配置并重新采集证据（只读复测）。"


def _c(cid, section, component, title, level, kind, *, tier="cis-1.8",
       scored=True, source="", fix="", **kw):
    if not source:
        if tier == "cis-1.8":
            source = f"CIS Kubernetes Benchmark v1.8.0 §{cid}（kube-bench cis-1.8 profile）"
        elif tier == "cis-1.9":
            source = f"CIS Kubernetes Benchmark v1.9.0 §{cid}（前向兼容项）"
        else:
            source = f"{tier} §{cid}"
    check = {
        "id": cid, "section": section, "component": component, "title": title,
        "level": level, "kind": kind, "tier": tier, "scored": bool(scored),
        "source": source, "remediation": fix or f"按 CIS §{cid} 修复 {component} 并复采证据。",
    }
    check.update(kw)
    return check


# 组件名 → snapshot.components 键（engine 里做别名兼容）
# ---------------------------------------------------------------- 1.1 文件权限
_MANIFEST = "/etc/kubernetes/manifests"
_PKI = "/etc/kubernetes/pki"
_APISERVER_YAML = f"{_MANIFEST}/kube-apiserver.yaml"
_CM_YAML = f"{_MANIFEST}/kube-controller-manager.yaml"
_SCHED_YAML = f"{_MANIFEST}/kube-scheduler.yaml"
_ETCD_YAML = f"{_MANIFEST}/etcd.yaml"
_CNI = "/etc/cni/net.d/10-calico.conflist"

_OFFICIAL = [
    _c("1.1.1", "1.1", "apiserver", "Ensure that the API server pod specification file permissions are set to 600 or more restrictive", 1, "file", paths=[_APISERVER_YAML], max_mode="600"),
    _c("1.1.2", "1.1", "apiserver", "Ensure that the API server pod specification file ownership is set to root:root", 1, "owner", paths=[_APISERVER_YAML], owner="root", group="root"),
    _c("1.1.3", "1.1", "controller-manager", "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive", 1, "file", paths=[_CM_YAML], max_mode="600"),
    _c("1.1.4", "1.1", "controller-manager", "Ensure that the controller manager pod specification file ownership is set to root:root", 1, "owner", paths=[_CM_YAML], owner="root", group="root"),
    _c("1.1.5", "1.1", "scheduler", "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive", 1, "file", paths=[_SCHED_YAML], max_mode="600"),
    _c("1.1.6", "1.1", "scheduler", "Ensure that the scheduler pod specification file ownership is set to root:root", 1, "owner", paths=[_SCHED_YAML], owner="root", group="root"),
    _c("1.1.7", "1.1", "etcd", "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive", 1, "file", paths=[_ETCD_YAML], max_mode="600"),
    _c("1.1.8", "1.1", "etcd", "Ensure that the etcd pod specification file ownership is set to root:root", 1, "owner", paths=[_ETCD_YAML], owner="root", group="root"),
    _c("1.1.9", "1.1", "node", "Ensure that the Container Network Interface file permissions are set to 600 or more restrictive", 1, "file", scored=False, paths=[_CNI], max_mode="600"),
    _c("1.1.10", "1.1", "node", "Ensure that the Container Network Interface file ownership is set to root:root", 1, "owner", scored=False, paths=[_CNI], owner="root", group="root"),
    _c("1.1.11", "1.1", "etcd", "Ensure that the etcd data directory permissions are set to 700 or more restrictive", 1, "file", paths=["/var/lib/etcd"], max_mode="700", dir=True),
    _c("1.1.12", "1.1", "etcd", "Ensure that the etcd data directory ownership is set to etcd:etcd", 1, "owner", paths=["/var/lib/etcd"], owner="etcd", group="etcd"),
    _c("1.1.13", "1.1", "node", "Ensure that the admin.conf file permissions are set to 600 or more restrictive", 1, "file", paths=["/etc/kubernetes/admin.conf"], max_mode="600"),
    _c("1.1.14", "1.1", "node", "Ensure that the admin.conf file ownership is set to root:root", 1, "owner", paths=["/etc/kubernetes/admin.conf"], owner="root", group="root"),
    _c("1.1.15", "1.1", "scheduler", "Ensure that the scheduler.conf file permissions are set to 600 or more restrictive", 1, "file", paths=["/etc/kubernetes/scheduler.conf"], max_mode="600"),
    _c("1.1.16", "1.1", "scheduler", "Ensure that the scheduler.conf file ownership is set to root:root", 1, "owner", paths=["/etc/kubernetes/scheduler.conf"], owner="root", group="root"),
    _c("1.1.17", "1.1", "controller-manager", "Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive", 1, "file", paths=["/etc/kubernetes/controller-manager.conf"], max_mode="600"),
    _c("1.1.18", "1.1", "controller-manager", "Ensure that the controller-manager.conf file ownership is set to root:root", 1, "owner", paths=["/etc/kubernetes/controller-manager.conf"], owner="root", group="root"),
    _c("1.1.19", "1.1", "node", "Ensure that the Kubernetes PKI directory and file ownership is set to root:root", 1, "owner", paths=[_PKI], owner="root", group="root", dir=True),
    _c("1.1.20", "1.1", "node", "Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive", 1, "file", scored=False, paths=[f"{_PKI}/apiserver.crt", f"{_PKI}/apiserver-etcd-client.crt", f"{_PKI}/ca.crt"], max_mode="600"),
    _c("1.1.21", "1.1", "node", "Ensure that the Kubernetes PKI key file permissions are set to 600", 1, "file", scored=False, paths=[f"{_PKI}/apiserver.key", f"{_PKI}/ca.key", f"{_PKI}/etcd/server.key"], max_mode="600"),

    # ------------------------------------------------------------ 1.2 API Server
    _c("1.2.1", "1.2", "apiserver", "Ensure that the --anonymous-auth argument is set to false", 1, "flag", scored=False, flag="anonymous-auth", op="eq", value="false", default="true"),
    _c("1.2.2", "1.2", "apiserver", "Ensure that the --token-auth-file parameter is not set", 1, "flag", flag="token-auth-file", op="unset"),
    _c("1.2.3", "1.2", "apiserver", "Ensure that the --DenyServiceExternalIPs admission plugin is set", 1, "plugin", scored=False, plugin="DenyServiceExternalIPs", mode="enabled"),
    _c("1.2.4", "1.2", "apiserver", "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set", 1, "pair", flags=["kubelet-client-certificate", "kubelet-client-key"]),
    _c("1.2.5", "1.2", "apiserver", "Ensure that the --kubelet-certificate-authority argument is set as appropriate", 1, "flag", flag="kubelet-certificate-authority", op="set"),
    _c("1.2.6", "1.2", "apiserver", "Ensure that the --authorization-mode argument is not set to AlwaysAllow", 1, "flag", flag="authorization-mode", op="not_contains", value="AlwaysAllow", default="AlwaysAllow"),
    _c("1.2.7", "1.2", "apiserver", "Ensure that the --authorization-mode argument includes Node", 1, "flag", flag="authorization-mode", op="contains", value="Node", default="AlwaysAllow"),
    _c("1.2.8", "1.2", "apiserver", "Ensure that the --authorization-mode argument includes RBAC", 1, "flag", flag="authorization-mode", op="contains", value="RBAC", default="AlwaysAllow"),
    _c("1.2.9", "1.2", "apiserver", "Ensure that the admission control plugin EventRateLimit is set", 2, "plugin", scored=False, plugin="EventRateLimit", mode="enabled"),
    _c("1.2.10", "1.2", "apiserver", "Ensure that the admission control plugin AlwaysAdmit is not set", 1, "plugin", plugin="AlwaysAdmit", mode="absent"),
    _c("1.2.11", "1.2", "apiserver", "Ensure that the admission control plugin AlwaysPullImages is set", 1, "plugin", scored=False, plugin="AlwaysPullImages", mode="enabled"),
    _c("1.2.12", "1.2", "apiserver", "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used", 2, "manual", scored=False, manual_reason="PSP 已移除，需结合 PSA/准入策略人工确认（kube-bench 标 auto 但无客观命令）。"),
    _c("1.2.13", "1.2", "apiserver", "Ensure that the admission control plugin ServiceAccount is set", 1, "plugin", plugin="ServiceAccount", mode="default-enabled"),
    _c("1.2.14", "1.2", "apiserver", "Ensure that the admission control plugin NamespaceLifecycle is set", 1, "plugin", plugin="NamespaceLifecycle", mode="default-enabled"),
    _c("1.2.15", "1.2", "apiserver", "Ensure that the admission control plugin NodeRestriction is set", 1, "plugin", plugin="NodeRestriction", mode="enabled"),
    _c("1.2.16", "1.2", "apiserver", "Ensure that the --profiling argument is set to false", 1, "flag", flag="profiling", op="eq", value="false", default="true"),
    _c("1.2.17", "1.2", "apiserver", "Ensure that the --audit-log-path argument is set", 1, "flag", flag="audit-log-path", op="set"),
    _c("1.2.18", "1.2", "apiserver", "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate", 1, "flag", flag="audit-log-maxage", op="gte", value="30"),
    _c("1.2.19", "1.2", "apiserver", "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate", 1, "flag", flag="audit-log-maxbackup", op="gte", value="10"),
    _c("1.2.20", "1.2", "apiserver", "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate", 1, "flag", flag="audit-log-maxsize", op="gte", value="100"),
    _c("1.2.21", "1.2", "apiserver", "Ensure that the --request-timeout argument is set as appropriate", 1, "manual", scored=False, manual_reason="超时值取决于集群规模，需人工评估。"),
    _c("1.2.22", "1.2", "apiserver", "Ensure that the --service-account-lookup argument is set to true", 1, "flag", flag="service-account-lookup", op="eq", value="true", default="false"),
    _c("1.2.23", "1.2", "apiserver", "Ensure that the --service-account-key-file argument is set as appropriate", 1, "flag", flag="service-account-key-file", op="set"),
    _c("1.2.24", "1.2", "apiserver", "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set", 1, "pair", flags=["etcd-certfile", "etcd-keyfile"]),
    _c("1.2.25", "1.2", "apiserver", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set", 1, "pair", flags=["tls-cert-file", "tls-private-key-file"]),
    _c("1.2.26", "1.2", "apiserver", "Ensure that the --client-ca-file argument is set as appropriate", 1, "flag", flag="client-ca-file", op="set"),
    _c("1.2.27", "1.2", "apiserver", "Ensure that the --etcd-cafile argument is set as appropriate", 1, "flag", flag="etcd-cafile", op="set"),
    _c("1.2.28", "1.2", "apiserver", "Ensure that the --encryption-provider-config argument is set as appropriate", 2, "flag", scored=False, flag="encryption-provider-config", op="set"),
    _c("1.2.29", "1.2", "apiserver", "Ensure that encryption providers are appropriately configured", 2, "evidence", scored=False, key="policies.encryption.provider_configured", op="eq", value=True),
    _c("1.2.30", "1.2", "apiserver", "Ensure that the API Server only makes use of strong cryptographic ciphers", 1, "flag", scored=False, flag="tls-cipher-suites", op="strong_ciphers", manual_if_empty=True),

    # ------------------------------------------------------- 1.3 Controller Manager
    _c("1.3.1", "1.3", "controller-manager", "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate", 1, "flag", scored=False, flag="terminated-pod-gc-threshold", op="set"),
    _c("1.3.2", "1.3", "controller-manager", "Ensure that the --profiling argument is set to false", 1, "flag", flag="profiling", op="eq", value="false", default="true"),
    _c("1.3.3", "1.3", "controller-manager", "Ensure that the --use-service-account-credentials argument is set to true", 1, "flag", flag="use-service-account-credentials", op="eq", value="true", default="false"),
    _c("1.3.4", "1.3", "controller-manager", "Ensure that the --service-account-private-key-file argument is set as appropriate", 1, "flag", flag="service-account-private-key-file", op="set"),
    _c("1.3.5", "1.3", "controller-manager", "Ensure that the --root-ca-file argument is set as appropriate", 1, "flag", flag="root-ca-file", op="set"),
    _c("1.3.6", "1.3", "controller-manager", "Ensure that the RotateKubeletServerCertificate feature gate is set to true", 1, "flag", flag="feature-gates", op="contains", value="RotateKubeletServerCertificate=true"),
    _c("1.3.7", "1.3", "controller-manager", "Ensure that the --bind-address argument is set to 127.0.0.1", 1, "flag", flag="bind-address", op="eq", value="127.0.0.1", default="0.0.0.0"),

    # -------------------------------------------------------------- 1.4 Scheduler
    _c("1.4.1", "1.4", "scheduler", "Ensure that the --profiling argument is set to false", 1, "flag", flag="profiling", op="eq", value="false", default="true"),
    _c("1.4.2", "1.4", "scheduler", "Ensure that the --bind-address argument is set to 127.0.0.1", 1, "flag", flag="bind-address", op="eq", value="127.0.0.1", default="0.0.0.0"),

    # ------------------------------------------------------------------ 2 etcd
    _c("2.1", "2", "etcd", "Ensure that the --cert-file and --key-file arguments are set as appropriate", 1, "pair", flags=["cert-file", "key-file"]),
    _c("2.2", "2", "etcd", "Ensure that the --client-cert-auth argument is set to true", 1, "flag", flag="client-cert-auth", op="eq", value="true", default="false"),
    _c("2.3", "2", "etcd", "Ensure that the --auto-tls argument is not set to true", 1, "flag", flag="auto-tls", op="not_eq", value="true", default="false"),
    _c("2.4", "2", "etcd", "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate", 1, "pair", flags=["peer-cert-file", "peer-key-file"]),
    _c("2.5", "2", "etcd", "Ensure that the --peer-client-cert-auth argument is set to true", 1, "flag", flag="peer-client-cert-auth", op="eq", value="true", default="false"),
    _c("2.6", "2", "etcd", "Ensure that the --peer-auto-tls argument is not set to true", 1, "flag", flag="peer-auto-tls", op="not_eq", value="true", default="false"),
    _c("2.7", "2", "etcd", "Ensure that a unique Certificate Authority is used for etcd", 1, "manual", scored=False, manual_reason="需比对 etcd 与 kube-apiserver 的 CA 指纹。"),

    # ---------------------------------------------------- 3 Control Plane Config
    _c("3.1.1", "3.1", "apiserver", "Client certificate authentication should not be used for users", 1, "manual", scored=False, manual_reason="需审计 kubeconfig/证书主体使用面。"),
    _c("3.1.2", "3.1", "apiserver", "Service account token authentication should not be used for users", 1, "manual", scored=False, manual_reason="需审计长期 SA token Secret 与用户绑定。"),
    _c("3.1.3", "3.1", "apiserver", "Bootstrap token authentication should not be used for users", 1, "manual", scored=False, manual_reason="需审计 bootstrap token Secret 生命周期。"),
    _c("3.2.1", "3.2", "apiserver", "Ensure that a minimal audit policy is created", 1, "evidence", scored=False, key="policies.audit_policy", op="set"),
    _c("3.2.2", "3.2", "apiserver", "Ensure that the audit policy covers key security concerns", 1, "manual", scored=False, manual_reason="需人工审阅 audit policy 规则覆盖（secrets/RBAC/exec）。"),

    # ------------------------------------------------------------ 4.1 Node files
    _c("4.1.1", "4.1", "kubelet", "Ensure that the kubelet service file permissions are set to 600 or more restrictive", 1, "file", paths=["/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"], max_mode="600"),
    _c("4.1.2", "4.1", "kubelet", "Ensure that the kubelet service file ownership is set to root:root", 1, "owner", paths=["/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"], owner="root", group="root"),
    _c("4.1.3", "4.1", "kubelet", "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive", 1, "file", scored=False, paths=["/etc/kubernetes/proxy.conf"], max_mode="600", optional=True),
    _c("4.1.4", "4.1", "kubelet", "If proxy kubeconfig file exists ensure ownership is set to root:root", 1, "owner", scored=False, paths=["/etc/kubernetes/proxy.conf"], owner="root", group="root", optional=True),
    _c("4.1.5", "4.1", "kubelet", "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive", 1, "file", paths=["/etc/kubernetes/kubelet.conf"], max_mode="600"),
    _c("4.1.6", "4.1", "kubelet", "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root", 1, "owner", paths=["/etc/kubernetes/kubelet.conf"], owner="root", group="root"),
    _c("4.1.7", "4.1", "kubelet", "Ensure that the certificate authorities file permissions are set to 600 or more restrictive", 1, "file", scored=False, paths=[f"{_PKI}/ca.crt"], max_mode="600"),
    _c("4.1.8", "4.1", "kubelet", "Ensure that the client certificate authorities file ownership is set to root:root", 1, "owner", scored=False, paths=[f"{_PKI}/ca.crt"], owner="root", group="root"),
    _c("4.1.9", "4.1", "kubelet", "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive", 1, "file", paths=["/var/lib/kubelet/config.yaml"], max_mode="600"),
    _c("4.1.10", "4.1", "kubelet", "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root", 1, "owner", paths=["/var/lib/kubelet/config.yaml"], owner="root", group="root"),

    # --------------------------------------------------------------- 4.2 Kubelet
    _c("4.2.1", "4.2", "kubelet", "Ensure that the --anonymous-auth argument is set to false", 1, "kubelet", key="authentication.anonymous.enabled", op="eq", value="false", default="true"),
    _c("4.2.2", "4.2", "kubelet", "Ensure that the --authorization-mode argument is not set to AlwaysAllow", 1, "kubelet", key="authorization.mode", op="not_eq", value="AlwaysAllow", default="AlwaysAllow"),
    _c("4.2.3", "4.2", "kubelet", "Ensure that the --client-ca-file argument is set as appropriate", 1, "kubelet", key="authentication.x509.clientCAFile", op="set", default=""),
    _c("4.2.4", "4.2", "kubelet", "Verify that the --read-only-port argument is set to 0", 1, "kubelet", scored=False, key="readOnlyPort", op="eq", value="0", default="0"),
    _c("4.2.5", "4.2", "kubelet", "Ensure that the --streaming-connection-idle-timeout argument is not set to 0", 1, "kubelet", scored=False, key="streamingConnectionIdleTimeout", op="not_in", value=["0", "0s", ""], default="4h0m0s"),
    _c("4.2.6", "4.2", "kubelet", "Ensure that the --make-iptables-util-chains argument is set to true", 1, "kubelet", key="makeIPTablesUtilChains", op="eq", value="true", default="true"),
    _c("4.2.7", "4.2", "kubelet", "Ensure that the --hostname-override argument is not set", 1, "kubelet", scored=False, key="hostnameOverride", op="unset", default=""),
    _c("4.2.8", "4.2", "kubelet", "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture", 1, "kubelet", scored=False, key="eventRecordQPS", op="gte", value="5", default="5"),
    _c("4.2.9", "4.2", "kubelet", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate", 1, "kubelet_pair", scored=False, keys=["tlsCertFile", "tlsPrivateKeyFile"]),
    _c("4.2.10", "4.2", "kubelet", "Ensure that the --rotate-certificates argument is not set to false", 1, "kubelet", key="rotateCertificates", op="not_eq", value="false", default="true"),
    _c("4.2.11", "4.2", "kubelet", "Verify that the RotateKubeletServerCertificate argument is set to true", 1, "kubelet", scored=False, key="featureGates.RotateKubeletServerCertificate", op="eq", value="true", default="false"),
    _c("4.2.12", "4.2", "kubelet", "Ensure that the Kubelet only makes use of strong cryptographic ciphers", 1, "kubelet", scored=False, key="tlsCipherSuites", op="strong_ciphers", default="", manual_if_empty=True),
    _c("4.2.13", "4.2", "kubelet", "Ensure that a limit is set on pod PIDs", 1, "kubelet", scored=False, key="podPidsLimit", op="gte", value="1", default="0"),

    # ----------------------------------------------------------- 4.3 kube-proxy
    # （1.9 前向项见 _FORWARD；不计入 cis-1.8 的 130 项）

    # ---------------------------------------------------------------- 5 Policies
    _c("5.1.1", "5.1", "node", "Ensure that the cluster-admin role is only used where required", 1, "manual", scored=False, manual_reason="审计 cluster-admin ClusterRoleBinding 主体。"),
    _c("5.1.2", "5.1", "node", "Minimize access to secrets", 1, "manual", scored=False, manual_reason="审计 get/list/watch secrets 的 Role/ClusterRole。"),
    _c("5.1.3", "5.1", "node", "Minimize wildcard use in Roles and ClusterRoles", 1, "manual", scored=False, manual_reason="审计 * verbs/resources/apiGroups。"),
    _c("5.1.4", "5.1", "node", "Minimize access to create pods", 1, "manual", scored=False, manual_reason="审计 create pods 及衍生的 token/secret 挂载面。"),
    _c("5.1.5", "5.1", "node", "Ensure that default service accounts are not actively used", 1, "manual", scored=False, manual_reason="审计 default SA 的 token 挂载与 RBAC 绑定。"),
    _c("5.1.6", "5.1", "node", "Ensure that Service Account Tokens are only mounted where necessary", 1, "manual", scored=False, manual_reason="审计 automountServiceAccountToken=false 覆盖率。"),
    _c("5.1.7", "5.1", "node", "Avoid use of system:masters group", 1, "manual", scored=False, manual_reason="审计 system:masters 证书/组绑定。"),
    _c("5.1.8", "5.1", "node", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", 1, "manual", scored=False, manual_reason="审计 bind/impersonate/escalate 权限。"),
    _c("5.1.9", "5.1", "node", "Minimize access to create persistent volumes", 1, "manual", scored=False, manual_reason="审计 create persistentvolumes。"),
    _c("5.1.10", "5.1", "node", "Minimize access to the proxy sub-resource of nodes", 1, "manual", scored=False, manual_reason="审计 nodes/proxy 访问（kubelet API 绕过）。"),
    _c("5.1.11", "5.1", "node", "Minimize access to the approval sub-resource of certificatesigningrequests objects", 1, "manual", scored=False, manual_reason="审计 certificatesigningrequests/approval。"),
    _c("5.1.12", "5.1", "node", "Minimize access to webhook configuration objects", 1, "manual", scored=False, manual_reason="审计 mutating/validatingwebhookconfigurations 写权限。"),
    _c("5.1.13", "5.1", "node", "Minimize access to the service account token creation", 1, "manual", scored=False, manual_reason="审计 serviceaccounts/token create。"),
    _c("5.2.1", "5.2", "node", "Ensure that the cluster has at least one active policy control mechanism in place", 1, "manual", scored=False, manual_reason="确认 PSA/Kyverno/Gatekeeper 至少一种生效。"),
    _c("5.2.2", "5.2", "node", "Minimize the admission of privileged containers", 1, "manual", scored=False, manual_reason="审计 privileged:true 工作负载。"),
    _c("5.2.3", "5.2", "node", "Minimize the admission of containers wishing to share the host process ID namespace", 1, "manual", scored=False, manual_reason="审计 hostPID:true。"),
    _c("5.2.4", "5.2", "node", "Minimize the admission of containers wishing to share the host IPC namespace", 1, "manual", scored=False, manual_reason="审计 hostIPC:true。"),
    _c("5.2.5", "5.2", "node", "Minimize the admission of containers wishing to share the host network namespace", 1, "manual", scored=False, manual_reason="审计 hostNetwork:true。"),
    _c("5.2.6", "5.2", "node", "Minimize the admission of containers with allowPrivilegeEscalation", 1, "manual", scored=False, manual_reason="审计 allowPrivilegeEscalation!=false。"),
    _c("5.2.7", "5.2", "node", "Minimize the admission of root containers", 1, "manual", scored=False, manual_reason="审计 runAsNonRoot/runAsUser。"),
    _c("5.2.8", "5.2", "node", "Minimize the admission of containers with the NET_RAW capability", 1, "manual", scored=False, manual_reason="审计 NET_RAW add/drop。"),
    _c("5.2.9", "5.2", "node", "Minimize the admission of containers with added capabilities", 1, "manual", scored=False, manual_reason="审计 capabilities.add 非默认集合。"),
    _c("5.2.10", "5.2", "node", "Minimize the admission of containers with capabilities assigned", 1, "manual", scored=False, manual_reason="审计 capabilities 是否 drop ALL。"),
    _c("5.2.11", "5.2", "node", "Minimize the admission of Windows HostProcess containers", 1, "manual", scored=False, manual_reason="Windows 节点审计 hostProcess。"),
    _c("5.2.12", "5.2", "node", "Minimize the admission of HostPath volumes", 1, "manual", scored=False, manual_reason="审计 hostPath 卷与敏感路径。"),
    _c("5.2.13", "5.2", "node", "Minimize the admission of containers which use HostPorts", 1, "manual", scored=False, manual_reason="审计 hostPort。"),
    _c("5.3.1", "5.3", "node", "Ensure that the CNI in use supports NetworkPolicies", 1, "manual", scored=False, manual_reason="确认 CNI 实现支持 NetworkPolicy。"),
    _c("5.3.2", "5.3", "node", "Ensure that all Namespaces have NetworkPolicies defined", 1, "manual", scored=False, manual_reason="逐 namespace 审计默认拒绝策略。"),
    _c("5.4.1", "5.4", "node", "Prefer using Secrets as files over Secrets as environment variables", 1, "manual", scored=False, manual_reason="审计 env.valueFrom.secretKeyRef 使用面。"),
    _c("5.4.2", "5.4", "node", "Consider external secret storage", 1, "manual", scored=False, manual_reason="确认外部密钥管理（Vault/KMS/SealedSecrets）。"),
    _c("5.5.1", "5.5", "node", "Configure Image Provenance using ImagePolicyWebhook admission controller", 1, "manual", scored=False, manual_reason="确认镜像签名/准入校验。"),
    _c("5.7.1", "5.7", "node", "Create administrative boundaries between resources using namespaces", 1, "manual", scored=False, manual_reason="审计命名空间与租户边界。"),
    _c("5.7.2", "5.7", "node", "Ensure that the seccomp profile is set to docker/default in your Pod definitions", 1, "manual", scored=False, manual_reason="审计 seccompProfile 覆盖。"),
    _c("5.7.3", "5.7", "node", "Apply SecurityContext to your Pods and Containers", 1, "manual", scored=False, manual_reason="审计 securityContext 覆盖率。"),
    _c("5.7.4", "5.7", "node", "The default namespace should not be used", 1, "manual", scored=False, manual_reason="审计 default namespace 工作负载。"),
]

# 1.9 前向兼容项（不计入 kube-bench cis-1.8 的 130 项口径）
_FORWARD = [
    _c("4.3.1", "4.3", "kube-proxy", "Ensure that the kube-proxy metrics service is bound to localhost", 1, "flag", tier="cis-1.9", flag="metrics-bind-address", op="eq", value="127.0.0.1:10249", default="0.0.0.0:10249"),
]


# ---------------------------------------------------------------- 主机加固（CIS DIL）
def _host(cid, section, title, key, op, value, fix, *, level=1, field=""):
    return _c(cid, section, "node", title, level, "evidence",
              tier="cis-host", key=key, op=op, value=value, field=field,
              source=f"CIS Distribution Independent Linux Benchmark v2.0.0 §{cid[3:]}（节点主机加固）",
              fix=fix)


_HOST = [
    _host("DL-1.1.1.1", "DL-1.1", "Ensure mounting of cramfs filesystems is disabled", "host.modules.cramfs", "in", ["disabled", "blacklisted"], "写入 modprobe.d blacklist 并卸载/禁止加载。"),
    _host("DL-1.1.1.2", "DL-1.1", "Ensure mounting of freevxfs filesystems is disabled", "host.modules.freevxfs", "in", ["disabled", "blacklisted"], "写入 modprobe.d blacklist。"),
    _host("DL-1.1.1.3", "DL-1.1", "Ensure mounting of jffs2 filesystems is disabled", "host.modules.jffs2", "in", ["disabled", "blacklisted"], "写入 modprobe.d blacklist。"),
    _host("DL-1.1.1.4", "DL-1.1", "Ensure mounting of hfs filesystems is disabled", "host.modules.hfs", "in", ["disabled", "blacklisted"], "写入 modprobe.d blacklist。"),
    _host("DL-1.1.1.5", "DL-1.1", "Ensure mounting of hfsplus filesystems is disabled", "host.modules.hfsplus", "in", ["disabled", "blacklisted"], "写入 modprobe.d blacklist。"),
    _host("DL-1.1.1.6", "DL-1.1", "Ensure mounting of squashfs filesystems is disabled (unless required by snap/containerd)", "host.modules.squashfs", "in", ["disabled", "blacklisted"], "如无 snap/容器镜像需求，blacklist squashfs。"),
    _host("DL-1.5.1", "DL-1.5", "Ensure core dumps are restricted", "host.sysctl.fs.suid_dumpable", "eq", "0", "设置 fs.suid_dumpable=0 并限制 RLIMIT_CORE。"),
    _host("DL-1.5.3", "DL-1.5", "Ensure address space layout randomization (ASLR) is enabled", "host.sysctl.kernel.randomize_va_space", "eq", "2", "设置 kernel.randomize_va_space=2。"),
    _host("DL-1.5.4", "DL-1.5", "Ensure prelink is disabled", "host.packages.prelink", "eq", False, "卸载 prelink，避免绕过文件完整性校验。"),
    _host("DL-3.2.1", "DL-3.2", "Ensure source routed packets are not accepted", "host.sysctl.net.ipv4.conf.all.accept_source_route", "eq", "0", "设置 net.ipv4.conf.all.accept_source_route=0。"),
    _host("DL-3.2.2", "DL-3.2", "Ensure ICMP redirects are not accepted", "host.sysctl.net.ipv4.conf.all.accept_redirects", "eq", "0", "设置 net.ipv4.conf.all.accept_redirects=0。"),
    _host("DL-3.2.3", "DL-3.2", "Ensure secure ICMP redirects are not accepted", "host.sysctl.net.ipv4.conf.all.secure_redirects", "eq", "0", "设置 net.ipv4.conf.all.secure_redirects=0。"),
    _host("DL-3.2.4", "DL-3.2", "Ensure suspicious packets are logged", "host.sysctl.net.ipv4.conf.all.log_martians", "eq", "1", "设置 net.ipv4.conf.all.log_martians=1。"),
    _host("DL-3.2.5", "DL-3.2", "Ensure broadcast ICMP requests are ignored", "host.sysctl.net.ipv4.icmp_echo_ignore_broadcasts", "eq", "1", "设置 net.ipv4.icmp_echo_ignore_broadcasts=1。"),
    _host("DL-3.2.6", "DL-3.2", "Ensure bogus ICMP responses are ignored", "host.sysctl.net.ipv4.icmp_ignore_bogus_error_responses", "eq", "1", "设置 net.ipv4.icmp_ignore_bogus_error_responses=1。"),
    _host("DL-3.3.1", "DL-3.3", "Ensure IPv6 router advertisements are not accepted", "host.sysctl.net.ipv6.conf.all.accept_ra", "eq", "0", "设置 net.ipv6.conf.all.accept_ra=0。"),
    _host("DL-4.1.1.1", "DL-4.1", "Ensure auditd is installed", "host.packages.auditd", "eq", True, "安装 auditd 并加入开机自启。"),
    _host("DL-4.1.2.1", "DL-4.1", "Ensure audit log storage size is configured", "host.auditd.max_log_file", "gte", "8", "在 auditd.conf 设置 max_log_file >= 8（MB）。"),
    _host("DL-5.2.5", "DL-5.2", "Ensure SSH MaxAuthTries is set to 4 or less", "host.sshd.maxauthtries", "lte", "4", "设置 MaxAuthTries 4。"),
    _host("DL-5.2.7", "DL-5.2", "Ensure SSH root login is disabled", "host.sshd.permitrootlogin", "eq", "no", "设置 PermitRootLogin no。"),
    _host("DL-6.1.2", "DL-6.1", "Ensure permissions on /etc/passwd are configured", "host.file_modes", "mode_max", "644", "chmod 644 /etc/passwd。", field="/etc/passwd"),
    _host("DL-6.1.3", "DL-6.1", "Ensure permissions on /etc/shadow are configured", "host.file_modes", "mode_max", "640", "chmod 640 /etc/shadow（root:shadow）。", field="/etc/shadow"),
    _host("DL-6.1.9", "DL-6.1", "Ensure permissions on /etc/group are configured", "host.file_modes", "mode_max", "644", "chmod 644 /etc/group。", field="/etc/group"),
    _host("DL-6.1.10", "DL-6.1", "Ensure permissions on /etc/gshadow are configured", "host.file_modes", "mode_max", "640", "chmod 640 /etc/gshadow。", field="/etc/gshadow"),
    _host("DL-6.2.1", "DL-6.2", "Ensure accounts without a valid password are secured", "host.accounts.empty_password", "eq", 0, "锁定空口令账号（passwd -l）。"),
]


# ---------------------------------------------------------------- k3s 自管面
def _k3s(cid, title, key, op, value, fix):
    return _c(cid, "K3S", "node", title, 1, "evidence", tier="cis-k3s",
              key=key, op=op, value=value,
              source=f"k3s security hardening / CIS k3s 自管面 §{cid}",
              fix=fix)


_K3S = [
    _k3s("K3S-1", "Ensure secrets encryption at rest is enabled", "k3s.secrets_encryption", "eq", True, "启动 k3s server 时启用 --secrets-encryption 并轮换密钥。"),
    _k3s("K3S-2", "Ensure etcd snapshot schedule is configured", "k3s.etcd_snapshot_schedule", "set", "", "配置 --etcd-snapshot-schedule-cron 并验证快照可恢复。"),
    _k3s("K3S-3", "Ensure API server audit policy is configured", "k3s.audit_policy", "eq", True, "配置 --audit-policy-file 与 --audit-log-path。"),
    _k3s("K3S-4", "Ensure the Traefik dashboard is disabled", "k3s.traefik_dashboard", "eq", False, "关闭 traefik dashboard 或加认证/网络策略。"),
    _k3s("K3S-5", "Ensure ServiceLB is disabled when unused", "k3s.servicelb", "eq", False, "如无 LoadBalancer 需求，--disable=servicelb。"),
]


CATALOG = tuple(_OFFICIAL + _FORWARD + _HOST + _K3S)
OFFICIAL_IDS = tuple(c["id"] for c in _OFFICIAL)


def kube_bench_counts() -> dict:
    """kube-bench cis-1.8 官方条目数（按 section）。"""
    counts = dict(OFFICIAL_SECTIONS)
    counts["total"] = sum(OFFICIAL_SECTIONS.values())
    counts["manual"] = 40
    counts["scored"] = 63
    return counts


def severity_of(check: dict) -> str:
    if check["id"] in CRITICAL_IDS:
        return "critical"
    return "high" if int(check.get("level", 1)) == 1 else "medium"


def by_section(checks=CATALOG) -> dict:
    out: dict[str, int] = {}
    for check in checks:
        out[check["section"]] = out.get(check["section"], 0) + 1
    return out
