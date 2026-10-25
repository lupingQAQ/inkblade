"""lab/cloud_six_sim.py — 六云「身份 / 桶 / 网络策略 / 快照」契约级仿真靶场（真 HTTP，仅 127.0.0.1）。

覆盖六云（每条云 7 条路由，共 42 条契约）：
    aws      AWS EKS + IAM（IRSA / STS AssumeRoleWithWebIdentity / S3 / EBS snapshot / SG / IMDSv2）
    azure    Azure AKS + Entra（Workload Identity 联邦凭据 / role assignment / Blob / Disk SAS / NSG）
    aliyun   阿里 ACK + RAM（OIDC 角色 / AssumeRole / OSS / ECS snapshot / 安全组）
    tencent  腾讯 TKE + CAM（OIDC 角色 / AssumeRole / COS / CBS snapshot / 安全组）
    gcp      GCP GKE + Workload Identity（KSA→GSA binding / IAM policy / GCS / image IAM / firewall）
    huawei   华为 CCE + IAM（agency / OBS / EVS snapshot / 安全组）

**边界（重要）**：这是**契约级仿真**——用各云公开 API 的字段形状（policy document、ACL、
security rule、snapshot permission）表达「同一类跨租户风险」，不是真实账号/集群，也不调用任何云 API。
仿真器只证明「六云的控制面语义可以被同一条检测链表达」，不证明目标云的实际配置。

两种姿态：
- vulnerable：通配 Principal / public ACL / 任意共享 / 0.0.0.0/0 + IMDS 宽松（fail-open 基线）；
- fixed：租户绑定 + 最小策略 + 私有 ACL + 同账号共享 + 最小 CIDR + IMDSv2（401/403/409）。

写盘边界：本仿真器不写任何文件（无持久化状态），所有数据在内存；`start_all()` 仅起 HTTP 服务。

命令行：
    python lab/cloud_six_sim.py [--port N] [--mode vulnerable|fixed]
    python lab/cloud_six_sim.py --matrix out.json   # 跑 4 个跨租户场景 × 6 云，输出矩阵
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
TENANTS = ("tenant-a", "tenant-b")
TENANT_TOKENS = {"tenant-a": "mock-cloud-tenant-a-token", "tenant-b": "mock-cloud-tenant-b-token"}
ACCOUNTS = {"tenant-a": {"aws": "111111111111", "azure": "sub-a", "aliyun": "1234567890",
                         "tencent": "100000000001", "gcp": "proj-a", "huawei": "proj-a"},
            "tenant-b": {"aws": "222222222222", "azure": "sub-b", "aliyun": "9876543210",
                         "tencent": "100000000002", "gcp": "proj-b", "huawei": "proj-b"}}

# 每云的能力面契约（字段名照公开 API 形状裁剪，保留判定所需的最小字段）
PROFILES: dict[str, dict] = {
    "aws": {
        "label": "AWS EKS + IAM",
        "identity_api": "sts:AssumeRoleWithWebIdentity + iam:GetRole",
        "bucket_api": "s3:GetBucketPolicy",
        "snapshot_api": "ec2:DescribeSnapshots / ec2:ModifySnapshotAttribute",
        "network_api": "ec2:DescribeSecurityGroups / DescribeInstanceMetadataDefaults",
        "sa_annotation": "eks.amazonaws.com/role-arn",
        "oidc": "oidc.eks.cn-north-1.amazonaws.com.cn/id/TRIDENTFIXTURE",
        "trust_vuln": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": "*"}, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringLike": {"*:sub": "*", "*:aud": "*"}}}]},
        "trust_fixed": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.eks"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"*:sub": "system:serviceaccount:ml:trainer", "*:aud": "sts.amazonaws.com"}}}]},
        "bucket_vuln": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::trident-ml-weights", "arn:aws:s3:::trident-ml-weights/*"]}]},
        "bucket_fixed": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::trident-ml-weights/*",
            "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]},
        "snapshot_perm": "createVolumePermission",
        "sg_vuln": {"GroupName": "ml-training", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "anywhere"}]}],
            "MetadataOptions": {"HttpTokens": "optional", "HttpPutResponseHopLimit": 2}},
        "sg_fixed": {"GroupName": "ml-training", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1}},
    },
    "azure": {
        "label": "Azure AKS + Entra",
        "identity_api": "Microsoft.ManagedIdentity/federatedIdentityCredentials + roleAssignments",
        "bucket_api": "Microsoft.Storage/storageAccounts/blobServices/containers (publicAccess)",
        "snapshot_api": "Microsoft.Compute/disks/beginGetAccess (SAS) + diskAccesses",
        "network_api": "Microsoft.Network/networkSecurityGroups/securityRules",
        "sa_annotation": "azure.workload.identity/use",
        "oidc": "https://oidc.prod-aks.azure.com/TRIDENTFIXTURE/",
        "trust_vuln": {"name": "fic-ml", "properties": {"issuer": "*", "subject": "*", "audiences": ["*"]}},
        "trust_fixed": {"name": "fic-ml", "properties": {
            "issuer": "https://oidc.prod-aks.azure.com/TRIDENTFIXTURE/",
            "subject": "system:serviceaccount:ml:trainer", "audiences": ["api://AzureADTokenExchange"]}},
        "bucket_vuln": {"container": "ml-weights", "properties": {"publicAccess": "Blob",
                                                                  "allowBlobPublicAccess": True}},
        "bucket_fixed": {"container": "ml-weights", "properties": {"publicAccess": "None",
                                                                   "allowBlobPublicAccess": False}},
        "snapshot_perm": "diskAccessSAS",
        "sg_vuln": {"name": "nsg-ml", "securityRules": [{
            "name": "allow-ssh", "properties": {"access": "Allow", "direction": "Inbound",
                                                "protocol": "Tcp", "destinationPortRange": "22",
                                                "sourceAddressPrefix": "*", "priority": 100}}]},
        "sg_fixed": {"name": "nsg-ml", "securityRules": [{
            "name": "allow-ssh-bastion", "properties": {"access": "Allow", "direction": "Inbound",
                                                         "protocol": "Tcp", "destinationPortRange": "22",
                                                         "sourceAddressPrefix": "10.0.0.0/8", "priority": 100}}]},
    },
    "aliyun": {
        "label": "阿里云 ACK + RAM",
        "identity_api": "sts:AssumeRole (OIDC provider) + ram:GetRole",
        "bucket_api": "oss:GetBucketAcl / GetBucketPolicy",
        "snapshot_api": "ecs:DescribeSnapshots / ModifySnapshotAttribute(IsPublic)",
        "network_api": "ecs:DescribeSecurityGroups / AuthorizeSecurityGroup",
        "sa_annotation": "ack.alibabacloud.com/role-arn",
        "oidc": "ack-oidc-cn-hangzhou-TRIDENTFIXTURE",
        "trust_vuln": {"Version": "1", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                       "Principal": {"RAM": ["*"]}}]},
        "trust_fixed": {"Version": "1", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                        "Principal": {"RAM": ["acs:ram::1234567890:role/ack-trainer"]},
                                                        "Condition": {"StringEquals": {"oidc:sub": "system:serviceaccount:ml:trainer"}}}]},
        "bucket_vuln": {"bucket": "trident-ml-weights", "AccessControlPolicy": {
            "AccessControlList": {"Grant": "public-read"}}},
        "bucket_fixed": {"bucket": "trident-ml-weights", "AccessControlPolicy": {
            "AccessControlList": {"Grant": "private"}}},
        "snapshot_perm": "IsPublic",
        "sg_vuln": {"SecurityGroupId": "sg-ml", "Permissions": [{
            "IpProtocol": "tcp", "PortRange": "22/22", "SourceCidrIp": "0.0.0.0/0"}]},
        "sg_fixed": {"SecurityGroupId": "sg-ml", "Permissions": [{
            "IpProtocol": "tcp", "PortRange": "22/22", "SourceCidrIp": "10.0.0.0/8"}]},
    },
    "tencent": {
        "label": "腾讯云 TKE + CAM",
        "identity_api": "cam:AssumeRole (OIDC) + GetRole",
        "bucket_api": "cos:GetBucketACL / GetBucketPolicy",
        "snapshot_api": "cbs:DescribeSnapshots / ModifySnapshotAttribute(SharePermission)",
        "network_api": "vpc:DescribeSecurityGroupPolicies / CreateSecurityGroupPolicies",
        "sa_annotation": "tke.cloud.tencent.com/role-arn",
        "oidc": "tke-oidc-gz-TRIDENTFIXTURE",
        "trust_vuln": {"version": "2.0", "statement": [{"effect": "allow", "action": "name/cam:AssumeRole",
                                                         "principal": {"qcs": ["*"]}}]},
        "trust_fixed": {"version": "2.0", "statement": [{"effect": "allow", "action": "name/cam:AssumeRole",
                                                          "principal": {"qcs": ["qcs::cam::uin/100000000001:roleName/tke-trainer"]},
                                                          "condition": {"string_equal": {"oidc:sub": "system:serviceaccount:ml:trainer"}}}]},
        "bucket_vuln": {"bucket": "trident-ml-weights-1250000000", "ACL": "public-read-write"},
        "bucket_fixed": {"bucket": "trident-ml-weights-1250000000", "ACL": "private"},
        "snapshot_perm": "SharePermission",
        "sg_vuln": {"SecurityGroupId": "sg-ml", "SecurityGroupPolicySet": {"Ingress": [{
            "Protocol": "TCP", "Port": "22", "CidrBlock": "0.0.0.0/0", "Action": "ACCEPT"}]}},
        "sg_fixed": {"SecurityGroupId": "sg-ml", "SecurityGroupPolicySet": {"Ingress": [{
            "Protocol": "TCP", "Port": "22", "CidrBlock": "10.0.0.0/8", "Action": "ACCEPT"}]}},
    },
    "gcp": {
        "label": "GCP GKE + Workload Identity",
        "identity_api": "iam.googleapis.com projects.serviceAccounts.getIamPolicy + KSA annotation",
        "bucket_api": "storage.objects.getIamPolicy / buckets.getIamPolicy",
        "snapshot_api": "compute.images.getIamPolicy / setIamPolicy",
        "network_api": "compute.firewalls (sourceRanges)",
        "sa_annotation": "iam.gke.io/gcp-service-account",
        "oidc": "https://container.googleapis.com/v1/projects/proj-a/locations/cn/zones/z/clusters/c",
        "trust_vuln": {"bindings": [{"role": "roles/iam.workloadIdentityUser",
                                      "members": ["principal://iam.googleapis.com/*"]}]},
        "trust_fixed": {"bindings": [{"role": "roles/iam.workloadIdentityUser",
                                       "members": ["serviceAccount:proj-a.svc.id.goog[ml/trainer]"]}]},
        "bucket_vuln": {"bucket": "trident-ml-weights", "iamPolicy": {
            "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}},
        "bucket_fixed": {"bucket": "trident-ml-weights", "iamPolicy": {
            "bindings": [{"role": "roles/storage.objectViewer",
                          "members": ["serviceAccount:trainer@proj-a.iam.gserviceaccount.com"]}]}},
        "snapshot_perm": "iamPolicy(allAuthenticatedUsers)",
        "sg_vuln": {"name": "fw-ml", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        "sg_fixed": {"name": "fw-ml", "direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"],
                     "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
    },
    "huawei": {
        "label": "华为云 CCE + IAM",
        "identity_api": "iam:CreateAgency / AssumeAgency (OIDC)",
        "bucket_api": "obs:GetBucketAcl",
        "snapshot_api": "evs:CreateSnapshot / UpdateSnapshot (share)",
        "network_api": "vpc:CreateSecurityGroupRule (remote_ip_prefix)",
        "sa_annotation": "everest.io/agency-name",
        "oidc": "cce-cn-north-4-TRIDENTFIXTURE",
        "trust_vuln": {"agency": "cce-trainer", "trust_domain": "*", "policy": {"Version": "1.1",
                                                                                 "Statement": [{"Effect": "Allow",
                                                                                                "Action": ["*"],
                                                                                                "Resource": ["*"]}]}},
        "trust_fixed": {"agency": "cce-trainer", "trust_domain": "op_svc_cce",
                        "policy": {"Version": "1.1", "Statement": [{
                            "Effect": "Allow", "Action": ["obs:object:GetObject"],
                            "Resource": ["obs:*:*:object:trident-ml-weights/*"]}]}},
        "bucket_vuln": {"bucket": "trident-ml-weights", "Acl": {"Owner": "tenant-a",
                                                                 "Grant": "public-read"}},
        "bucket_fixed": {"bucket": "trident-ml-weights", "Acl": {"Owner": "tenant-a",
                                                                 "Grant": "private"}},
        "snapshot_perm": "share",
        "sg_vuln": {"security_group_id": "sg-ml", "rules": [{
            "direction": "ingress", "protocol": "tcp", "port_range_min": 22, "port_range_max": 22,
            "remote_ip_prefix": "0.0.0.0/0"}]},
        "sg_fixed": {"security_group_id": "sg-ml", "rules": [{
            "direction": "ingress", "protocol": "tcp", "port_range_min": 22, "port_range_max": 22,
            "remote_ip_prefix": "10.0.0.0/8"}]},
    },
}

CLOUDS = tuple(PROFILES)


def _bearer(headers) -> str:
    raw = (headers.get("Authorization") or "").strip()
    return raw[7:].strip() if raw.lower().startswith("bearer ") else ""


class _Ctx:
    def __init__(self, mode, headers, body, query, cloud, entry):
        self.mode, self.headers, self.body, self.query = mode, headers, body, query
        self.cloud, self.entry = cloud, entry

    @property
    def tenant(self) -> str:
        return (self.headers.get("X-Tenant") or "").strip()

    @property
    def token(self) -> str:
        return _bearer(self.headers)

    def principal(self) -> str | None:
        if self.token and self.token == TENANT_TOKENS.get(self.tenant):
            return self.tenant
        return None

    def profile(self) -> dict:
        return PROFILES[self.cloud]

    def pick(self, vuln_key: str, fixed_key: str, default=None):
        return self.profile().get(vuln_key if self.mode == "vulnerable" else fixed_key, default)


def _identity(ctx: _Ctx):
    p = ctx.profile()
    if ctx.mode == "fixed" and not ctx.principal():
        return 401, {"error": "unauthorized", "api": p["identity_api"]}
    trust = p["trust_vuln"] if ctx.mode == "vulnerable" else p["trust_fixed"]
    return 200, {
        "cloud": ctx.cloud, "service": p["label"], "api": p["identity_api"],
        "oidc_issuer": p["oidc"], "sa_annotation": p["sa_annotation"],
        "trust_policy": trust,
        "wildcard": ctx.mode == "vulnerable",
        "note": "契约级仿真：字段形状照公开 API 裁剪，非真实账号",
    }


def _assume_role(ctx: _Ctx):
    p = ctx.profile()
    tenant = ctx.tenant or "anonymous"
    account = ACCOUNTS.get(tenant, {}).get(ctx.cloud, "unknown")
    if ctx.mode == "fixed":
        principal = ctx.principal()
        if not principal:
            return 401, {"error": "unauthorized", "api": p["identity_api"]}
        want = ctx.body.get("account") or ctx.body.get("uin") or ctx.body.get("project")
        if want and want != ACCOUNTS[principal].get(ctx.cloud):
            return 403, {"error": "AccessDenied", "reason": "cross-account assume denied",
                         "api": p["identity_api"]}
        return 200, {"cloud": ctx.cloud, "assumed": True, "principal": principal,
                     "account": ACCOUNTS[principal].get(ctx.cloud), "ttl_seconds": 900,
                     "credentials": "TRIDENT-MOCK-SESSION", "api": p["identity_api"]}
    return 200, {
        "cloud": ctx.cloud, "assumed": True, "principal": tenant, "account": account,
        "target_account": ctx.body.get("account") or "333333333333",
        "cross_account": True, "credentials": "TRIDENT-MOCK-SESSION", "ttl_seconds": 3600,
        "api": p["identity_api"], "trust": p["trust_vuln"],
    }


def _bucket_policy(ctx: _Ctx):
    p = ctx.profile()
    if ctx.mode == "fixed" and not ctx.principal():
        return 401, {"error": "unauthorized", "api": p["bucket_api"]}
    policy = p["bucket_vuln"] if ctx.mode == "vulnerable" else p["bucket_fixed"]
    return 200, {"cloud": ctx.cloud, "api": p["bucket_api"], "policy": policy,
                 "public": ctx.mode == "vulnerable"}


def _bucket_list(ctx: _Ctx):
    p = ctx.profile()
    bucket = (ctx.query.get("bucket") or ["trident-ml-weights"])[0]
    if ctx.mode == "fixed" and not ctx.principal():
        return 401, {"error": "unauthorized", "api": p["bucket_api"]}
    if ctx.mode == "vulnerable":
        return 200, {"cloud": ctx.cloud, "bucket": bucket,
                     "objects": ["checkpoints/step-1000.safetensors", "tokenizer.json",
                                 "config.json"], "tenant": ctx.tenant or "anonymous",
                     "cross_tenant": True, "api": p["bucket_api"]}
    return 200, {"cloud": ctx.cloud, "bucket": bucket, "objects": ["checkpoints/step-1000.safetensors"],
                 "tenant": ctx.principal(), "cross_tenant": False, "api": p["bucket_api"]}


def _snapshot(ctx: _Ctx):
    p = ctx.profile()
    if ctx.mode == "fixed" and not ctx.principal():
        return 401, {"error": "unauthorized", "api": p["snapshot_api"]}
    if ctx.mode == "vulnerable":
        return 200, {"cloud": ctx.cloud, "snapshots": [
            {"id": "snap-0a1b2c", "owner": "tenant-a", "shared_with": ["all"],
             "permission": p["snapshot_perm"], "encrypted": False, "size_gb": 500}],
            "api": p["snapshot_api"], "cross_tenant_visible": True}
    return 200, {"cloud": ctx.cloud, "snapshots": [
        {"id": "snap-0a1b2c", "owner": "tenant-a", "shared_with": [], "permission": "private",
         "encrypted": True, "size_gb": 500}],
        "api": p["snapshot_api"], "cross_tenant_visible": False}


def _snapshot_share(ctx: _Ctx):
    p = ctx.profile()
    if ctx.mode == "fixed":
        principal = ctx.principal()
        if not principal:
            return 401, {"error": "unauthorized", "api": p["snapshot_api"]}
        target = ctx.body.get("account") or ctx.body.get("target")
        if target and target != ACCOUNTS[principal].get(ctx.cloud):
            return 403, {"error": "AccessDenied", "reason": "cross-account snapshot share denied",
                         "api": p["snapshot_api"]}
        return 200, {"cloud": ctx.cloud, "shared": True, "target": target or "self",
                     "api": p["snapshot_api"]}
    target = ctx.body.get("account") or "333333333333"
    return 200, {"cloud": ctx.cloud, "snapshot": "snap-0a1b2c", "shared_with": [target],
                 "permission": p["snapshot_perm"], "public": True, "api": p["snapshot_api"]}


def _security_group(ctx: _Ctx):
    p = ctx.profile()
    if ctx.mode == "fixed" and not ctx.principal():
        return 401, {"error": "unauthorized", "api": p["network_api"]}
    group = p["sg_vuln"] if ctx.mode == "vulnerable" else p["sg_fixed"]
    return 200, {"cloud": ctx.cloud, "api": p["network_api"], "security_group": group,
                 "imds_open": ctx.mode == "vulnerable",
                 "metadata_endpoint": "169.254.169.254"}


def _authorize_ingress(ctx: _Ctx):
    p = ctx.profile()
    cidr = ctx.body.get("cidr") or "0.0.0.0/0"
    if ctx.mode == "fixed":
        principal = ctx.principal()
        if not principal:
            return 401, {"error": "unauthorized", "api": p["network_api"]}
        if cidr in ("0.0.0.0/0", "::/0", "*"):
            return 403, {"error": "AccessDenied", "reason": "world-open ingress denied",
                         "api": p["network_api"]}
    return 200, {"cloud": ctx.cloud, "authorized": True, "cidr": cidr, "port": ctx.body.get("port", 22),
                 "api": p["network_api"]}


def _matrix(ctx: _Ctx):
    rows = []
    for cloud, profile in PROFILES.items():
        rows.append({
            "cloud": cloud, "label": profile["label"],
            "capabilities": ["identity", "assume-role", "bucket-policy", "bucket-list",
                             "snapshot", "snapshot-share", "security-group"],
            "apis": {k: profile[k] for k in ("identity_api", "bucket_api", "snapshot_api", "network_api")},
        })
    return 200, {"mode": ctx.mode, "clouds": rows, "note": "契约级仿真，非真实环境"}


ROUTE_TABLE = [
    {"cloud": cloud, "method": "GET", "path": f"/api/{cloud}/identity", "behavior": _identity,
     "title": "工作负载身份与信任策略", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "POST", "path": f"/api/{cloud}/assume-role", "behavior": _assume_role,
     "title": "跨账户/跨租户角色假设", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "GET", "path": f"/api/{cloud}/bucket/policy", "behavior": _bucket_policy,
     "title": "桶策略/ACL", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "GET", "path": f"/api/{cloud}/bucket/list", "behavior": _bucket_list,
     "title": "桶列目录", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "GET", "path": f"/api/{cloud}/snapshot", "behavior": _snapshot,
     "title": "快照可见性", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "POST", "path": f"/api/{cloud}/snapshot/share", "behavior": _snapshot_share,
     "title": "快照跨账户共享", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "GET", "path": f"/api/{cloud}/security-group", "behavior": _security_group,
     "title": "安全组/NSG/防火墙与 IMDS", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": cloud, "method": "POST", "path": f"/api/{cloud}/security-group/authorize",
     "behavior": _authorize_ingress, "title": "放通入站规则（0.0.0.0/0 判定）", "writes": False}
    for cloud in CLOUDS
] + [
    {"cloud": "*", "method": "GET", "path": "/api/__matrix__", "behavior": _matrix,
     "title": "六云契约矩阵", "writes": False},
]

_EXACT: dict[tuple[str, str], dict] = {}
for _entry in ROUTE_TABLE:
    _EXACT.setdefault((_entry["method"], _entry["path"].rstrip("/") or "/"), _entry)
_METHODS = ("GET", "POST")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode):
        super().__init__(address, _Handler)
        self.lab_mode = mode


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentSixCloudLab/0.1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = split.path.rstrip("/") or "/"
        entry = _EXACT.get((method, norm))
        if entry is None:
            if any((other, norm) in _EXACT for other in _METHODS if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        ctx = _Ctx(self.server.lab_mode, self.headers, self._body() if method == "POST" else {},
                   parse_qs(split.query), entry["cloud"], entry)
        try:
            status, payload = entry["behavior"](ctx)
        except Exception as exc:  # 仿真器不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "detail": str(exc)})
            return
        self._send(status, payload)


class Server:
    def __init__(self, httpd, thread, mode):
        self._httpd, self._thread, self.mode = httpd, thread, mode
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{k: v for k, v in entry.items() if k != "behavior"} for entry in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE) -> Server:
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    httpd = _Server((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


# ---------------------------------------------------------------- 场景矩阵

SCENARIOS = (
    {"id": "irsa-wildcard", "title": "工作负载身份通配 → 跨租户 AssumeRole",
     "steps": ({"method": "GET", "path": "/api/{cloud}/identity", "expect": (200, 200)},
               {"method": "POST", "path": "/api/{cloud}/assume-role",
                "body": {"account": "333333333333"}, "expect": (200, 403)})},
    {"id": "bucket-public", "title": "公共桶策略 → 匿名/跨租户列目录",
     "steps": ({"method": "GET", "path": "/api/{cloud}/bucket/policy", "expect": (200, 200)},
               {"method": "GET", "path": "/api/{cloud}/bucket/list?bucket=trident-ml-weights",
                "anonymous": True, "expect": (200, 401)})},
    {"id": "snapshot-share", "title": "快照跨账户共享 → 他租户可挂载",
     "steps": ({"method": "GET", "path": "/api/{cloud}/snapshot", "expect": (200, 200)},
               {"method": "POST", "path": "/api/{cloud}/snapshot/share",
                "body": {"account": "333333333333"}, "expect": (200, 403)})},
    {"id": "sg-imds", "title": "安全组 0.0.0.0/0 + IMDS 宽松 → 凭据面暴露",
     "steps": ({"method": "GET", "path": "/api/{cloud}/security-group", "expect": (200, 200)},
               {"method": "POST", "path": "/api/{cloud}/security-group/authorize",
                "body": {"cidr": "0.0.0.0/0", "port": 22}, "expect": (200, 403)})},
)


def run_scenarios(mode: str = "vulnerable", port: int = 0) -> dict:
    """起一台仿真器，跑 4 场景 × 6 云，返回逐项状态码、是否符合预期与证据摘要。"""
    import urllib.error
    import urllib.request

    def call(server: Server, method: str, path: str, body: dict | None = None,
             tenant: str = "tenant-b", anonymous: bool = False) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(server.url(path), data=data, method=method)
        if not anonymous:
            req.add_header("X-Tenant", tenant)
            req.add_header("Authorization", f"Bearer {TENANT_TOKENS[tenant]}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8") or "{}")

    results = []
    with start_all(port=port, mode=mode) as server:
        for scenario in SCENARIOS:
            for cloud in CLOUDS:
                steps = []
                expected_ok = True
                for step in scenario["steps"]:
                    path = step["path"].format(cloud=cloud)
                    status, payload = call(server, step["method"], path, step.get("body"),
                                           anonymous=step.get("anonymous", False))
                    want = step["expect"][0 if mode == "vulnerable" else 1]
                    steps.append({"method": step["method"], "path": path, "status": status,
                                  "expect": want, "match": status == want,
                                  "evidence": _evidence(cloud, path, payload)})
                    expected_ok = expected_ok and status == want
                results.append({"scenario": scenario["id"], "title": scenario["title"],
                                "cloud": cloud, "steps": steps, "as_expected": expected_ok,
                                "cross_tenant_ok": all(s["status"] == 200 for s in steps)})
    return {"mode": mode, "scenarios": results,
            "contracts": len(ROUTE_TABLE), "clouds": len(CLOUDS),
            "all_as_expected": all(r["as_expected"] for r in results)}


def _evidence(cloud: str, path: str, payload: dict) -> str:
    if "wildcard" in payload:
        return f"wildcard={payload['wildcard']}"
    if "cross_account" in payload:
        return f"cross_account={payload['cross_account']} account={payload.get('target_account')}"
    if "shared_with" in payload:
        return f"shared_with={payload['shared_with']} public={payload.get('public')}"
    if "public" in payload:
        return f"public={payload['public']}"
    if "cross_tenant" in payload:
        return f"cross_tenant={payload['cross_tenant']}"
    if "cross_tenant_visible" in payload:
        return f"cross_tenant_visible={payload['cross_tenant_visible']}"
    if "imds_open" in payload:
        imds = payload.get("imds_open")
        return f"imds_open={imds}"
    if "authorized" in payload:
        return f"authorized={payload['authorized']} cidr={payload.get('cidr')}"
    if "error" in payload:
        return f"denied={payload.get('reason') or payload.get('error')}"
    return "ok"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Trident 六云契约级仿真靶场（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE)
    parser.add_argument("--matrix", default=None, help="跑 4 场景×6 云并输出 JSON 到该路径")
    args = parser.parse_args(argv)
    if args.matrix:
        payload = {"vulnerable": run_scenarios("vulnerable"), "fixed": run_scenarios("fixed")}
        from pathlib import Path

        Path(args.matrix).parent.mkdir(parents=True, exist_ok=True)
        Path(args.matrix).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"matrix -> {args.matrix}")
        return 0
    server = start_all(port=args.port, mode=args.mode)
    print(f"six-cloud lab: {server.url('/')} mode={server.mode} routes={len(ROUTE_TABLE)}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
