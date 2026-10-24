"""规则转化引擎（架构第七层）：链目录 + 演练发现 → K8s 防护规则 + SOC 检测规则 + 映射矩阵。

产物（<out_dir>/，YAML 一律经 core/yamlish.dump 输出，可直接 kubectl apply / 导入 SIEM）：
- kyverno/  ClusterPolicy × 准入规则（默认 monitor：validationFailureAction=Audit + trident.io 注解）
- gatekeeper/  ConstraintTemplate + Constraint（同语义，enforcementAction=dryrun）
- network/  NetworkPolicy 默认拒绝分区模板 per-CNI 三变体（native / Calico GlobalNetworkPolicy /
   Cilium CiliumNetworkPolicy）+ VPC-native 安全组补充 + RDMA/SR-IOV 不覆盖声明 + IB Partition 建议
- sigma/  K8s 审计/Ray 检测规则（custom.trident-mode=monitor + 调参建议）
- falco/  运行时规则（monitor 标签 + 调参建议）
- suricata/  网络签名（.rules DSL，metadata trident.mode=monitor）
- rbac-convergence.yaml  三 operator 集群级角色 → namespace 最小化改写参考清单
- mapping.json  规则↔链/模块映射矩阵（每规则 blocks_chains[]）+ 零日行为化签名登记（规则文本不含利用细节）

零日保护：zeroday 规则为行为化签名（异常行为特征），不含产品名/根因/端点等利用细节特征串。
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.chains import load_chains
from ..core.yamlish import dump as yaml_dump

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
CNI_VARIANTS = ("native", "calico", "cilium", "vpc-native")
MONITOR = "monitor"
TRIDENT_ANNOTATION = "trident.io/mode"
TRIDENT_TUNING_ANNOTATION = "trident.io/tuning"
TRIDENT_BLOCKS_ANNOTATION = "trident.io/blocks-chains"

# 准入/隔离类引擎：验证时以「策略文件在包内且齐备」判定拦截态
ENFORCEMENT_ENGINES = ("kyverno", "gatekeeper", "netpol", "vpc-sg")
ADVICE_ENGINES = ("ib-advice",)


class RuleCoverageError(ValueError):
    """存在未被任何规则覆盖的攻击链（生成即校验，0 规则链即失败）。"""


@dataclass
class RulePack:
    """规则包句柄：产物目录 + 规则元数据 + 覆盖矩阵。"""

    out_dir: str
    cni: str
    rules: list[dict] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    chains_covered: dict[str, list[str]] = field(default_factory=dict)
    mapping_path: str = ""

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def covered_chain_count(self) -> int:
        return len(self.chains_covered)


# ---------------------------------------------------------------- 目录加载

def load_catalog() -> dict[str, Any]:
    """加载 templates/ 规则目录（admission/netpol/sigma/falco/suricata/zeroday/probes）。"""
    catalog: dict[str, Any] = {}
    for path in sorted(TEMPLATES_DIR.glob("*.json")):
        catalog[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    missing = {"admission", "netpol", "sigma", "falco", "suricata", "zeroday", "probes"} - set(catalog)
    if missing:
        raise RuleCoverageError(f"规则模板目录缺文件: {sorted(missing)}")
    return catalog


def _chain_modules(chain: dict) -> set[str]:
    """链的关联模块集 = 步骤模块 ∪ 依赖（侦察前置）模块。"""
    mods = {st["module"] for st in chain.get("steps", [])}
    mods |= set(chain.get("requires", []))
    return mods


def _deterministic_uuid(seed: str) -> str:
    digest = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# ---------------------------------------------------------------- Kyverno 构造

def _kyverno_rule(spec: dict, blocks: list[str]) -> dict:
    """按准入规则 id 构造 Kyverno rule（deny 条件语义与 Gatekeeper rego 同源）。"""
    rid = spec["id"]
    msg = f"{spec['message']['zh']} / {spec['message']['en']}"
    if rid == "deny-privileged-pod":
        return {
            "name": "deny-privileged-workload",
            "match": {"anyResources": [{"kinds": ["Pod"]}]},
            "validate": {
                "message": msg,
                "deny": {
                    "conditions": {
                        "any": [
                            {"key": "{{ request.object.spec.containers[].securityContext.privileged[] || `[]` }}",
                             "operator": "AnyIn", "value": [True]},
                            {"key": "{{ request.object.spec.hostPID || `false` }}", "operator": "Equals", "value": True},
                            {"key": "{{ request.object.spec.hostIPC || `false` }}", "operator": "Equals", "value": True},
                            {"key": "{{ request.object.spec.hostNetwork || `false` }}", "operator": "Equals", "value": True},
                        ]
                    }
                },
            },
        }
    if rid == "deny-sensitive-hostpath":
        return {
            "name": "deny-sensitive-hostpath",
            "match": {"anyResources": [{"kinds": ["Pod"]}]},
            "validate": {
                "message": msg,
                "deny": {
                    "conditions": {
                        "any": [
                            {"key": "{{ request.object.spec.volumes[].hostPath.path[] || `[]` }}",
                             "operator": "AnyIn", "value": spec["params"]["prefixes"]},
                        ]
                    }
                },
            },
        }
    if rid == "deny-automount-serviceaccount-token":
        return {
            "name": "require-automount-disabled",
            "match": {"anyResources": [{"kinds": ["Pod"]}]},
            "validate": {
                "message": msg,
                "deny": {
                    "conditions": [
                        {"key": "{{ request.object.spec.automountServiceAccountToken || `true` }}",
                         "operator": "NotEquals", "value": False},
                    ]
                },
            },
        }
    if rid == "alert-rolebinding-creation":
        return {
            "name": "rolebinding-cluster-admin-guard",
            "match": {"anyResources": [{"kinds": ["RoleBinding", "ClusterRoleBinding"],
                                        "operations": ["CREATE"]}]},
            "validate": {
                "message": msg,
                "deny": {
                    "conditions": [
                        {"key": "{{ request.object.roleRef.name || `` }}",
                         "operator": "Equals", "value": "cluster-admin"},
                    ]
                },
            },
        }
    if rid == "alert-combo-signature":
        return {
            "name": "combo-weight-write-mutable-image",
            "match": {"anyResources": [{"kinds": ["Deployment"]}]},
            "validate": {
                "message": msg,
                "deny": {
                    "conditions": {
                        "all": [
                            {"key": "{{ request.object.spec.template.spec.containers[].image[] || `[]` }}",
                             "operator": "AnyIn", "value": ["*:latest", "*"]},
                            {"key": "{{ request.object.spec.template.spec.containers[].ports[].containerPort[] || `[]` }}",
                             "operator": "AnyIn", "value": [30000, 9000]},
                        ]
                    }
                },
            },
        }
    raise RuleCoverageError(f"未知准入规则 {rid}")


def _kyverno_policy(spec: dict, blocks: list[str]) -> dict:
    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": f"trident-{spec['id']}",
            "annotations": {
                TRIDENT_ANNOTATION: MONITOR,
                TRIDENT_TUNING_ANNOTATION: spec["tuning"]["zh"],
                TRIDENT_BLOCKS_ANNOTATION: ",".join(blocks),
            },
        },
        "spec": {
            "validationFailureAction": "Audit",
            "background": True,
            "rules": [_kyverno_rule(spec, blocks)],
        },
    }


# ---------------------------------------------------------------- Gatekeeper 构造

_REGO_BODIES = {
    "deny-privileged-pod": """
violation[{"msg": msg}] {
  c := input.review.object.spec.containers[_]
  c.securityContext.privileged == true
  msg := "privileged container denied (PSS baseline; GPU exception channel applies)"
}
violation[{"msg": msg}] {
  input.review.object.spec.hostPID == true
  msg := "hostPID denied"
}
violation[{"msg": msg}] {
  input.review.object.spec.hostIPC == true
  msg := "hostIPC denied"
}
violation[{"msg": msg}] {
  input.review.object.spec.hostNetwork == true
  msg := "hostNetwork denied (converge via exception namespace)"
}
""",
    "deny-sensitive-hostpath": """
violation[{"msg": msg}] {
  v := input.review.object.spec.volumes[_]
  startswith(v.hostPath.path, "/var/run/docker.sock")
  msg := "sensitive hostPath denied: runtime socket"
}
violation[{"msg": msg}] {
  v := input.review.object.spec.volumes[_]
  startswith(v.hostPath.path, "/var/run/containerd")
  msg := "sensitive hostPath denied: containerd socket"
}
violation[{"msg": msg}] {
  v := input.review.object.spec.volumes[_]
  v.hostPath.path == "/"
  msg := "sensitive hostPath denied: host root"
}
""",
    "deny-automount-serviceaccount-token": """
violation[{"msg": msg}] {
  input.review.object.spec.automountServiceAccountToken != false
  msg := "automountServiceAccountToken must be explicitly false (allowlisted namespaces excepted)"
}
""",
    "alert-rolebinding-creation": """
violation[{"msg": msg}] {
  input.review.object.roleRef.name == "cluster-admin"
  msg := "binding to cluster-admin denied; other binding creations are audit-alerted in monitor mode"
}
""",
    "alert-combo-signature": """
violation[{"msg": msg}] {
  c := input.review.object.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  p := c.ports[_].containerPort
  p == 30000
  msg := "combo signature: weight-write admin port with mutable image tag"
}
""",
}

_KINDS_BY_RULE = {
    "deny-privileged-pod": (["Pod"], "TridentDenyPrivilegedPod"),
    "deny-sensitive-hostpath": (["Pod"], "TridentDenySensitiveHostpath"),
    "deny-automount-serviceaccount-token": (["Pod"], "TridentDenyAutomountSAToken"),
    "alert-rolebinding-creation": (["RoleBinding", "ClusterRoleBinding"], "TridentAlertRoleBindingCreation"),
    "alert-combo-signature": (["Deployment", "apps/Deployment"], "TridentAlertComboSignature"),
}


def _gatekeeper_docs(spec: dict, blocks: list[str]) -> tuple[dict, dict]:
    kinds, kind = _KINDS_BY_RULE[spec["id"]]
    template = {
        "apiVersion": "templates.gatekeeper.sh/v1",
        "kind": "ConstraintTemplate",
        "metadata": {"name": spec["id"].replace("-", "")},
        "spec": {
            "crd": {"spec": {"names": {"kind": kind}}},
            "targets": [{
                "target": "admission.k8s.gatekeeper.sh",
                "rego": _REGO_BODIES[spec["id"]].strip(),
            }],
        },
    }
    constraint = {
        "apiVersion": "constraints.gatekeeper.sh/v1beta1",
        "kind": kind,
        "metadata": {
            "name": f"trident-{spec['id']}",
            "annotations": {
                TRIDENT_ANNOTATION: MONITOR,
                TRIDENT_TUNING_ANNOTATION: spec["tuning"]["zh"],
                TRIDENT_BLOCKS_ANNOTATION: ",".join(blocks),
            },
        },
        "spec": {
            "enforcementAction": "dryrun",
            "match": {"kinds": [{"apiGroups": ["", "apps", "rbac.authorization.k8s.io"], "kinds": kinds}]},
        },
    }
    return template, constraint


# ---------------------------------------------------------------- NetworkPolicy per-CNI

def _netpol_docs(cfg: dict) -> dict[str, list[dict]]:
    """三 CNI 变体：每变体 = 各分区默认拒绝 + 分区放行（模板，占位命名空间按客户改名）。"""
    zones = cfg["zones"]
    admin_cidr = cfg["admin_cidr"]
    admin_ports = cfg["admin_ports"]
    dns_port = cfg["dns_port"]

    native: list[dict] = []
    for zone in zones:
        ns = zone["namespace"]
        native.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "trident-default-deny", "namespace": ns,
                         "annotations": {TRIDENT_ANNOTATION: MONITOR,
                                         "trident.io/note": "默认拒绝（入站+出站）；试点后再全量铺开"}},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        })
        ingress_from = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": z["namespace"]}}}
            for z in zones if z["name"] in zone["allow_ingress_from"]
        ] + [{"ipBlock": {"cidr": admin_cidr}}]
        egress_to = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": z["namespace"]}}}
            for z in zones if z["name"] in zone["allow_egress_to"]
        ]
        zone_ports = [{"protocol": "TCP", "port": p} for p in zone["ports"]]
        allow = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "trident-partition-allow", "namespace": ns,
                         "annotations": {TRIDENT_ANNOTATION: MONITOR}},
            "spec": {
                "podSelector": {"matchLabels": {f"{zone['name']}.{zone['label']}/member": "true"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": ingress_from, "ports": zone_ports}],
                "egress": [
                    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}},
                            {"podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                     "ports": [{"protocol": "UDP", "port": dns_port}, {"protocol": "TCP", "port": dns_port}]},
                ] + ([{"to": egress_to}] if egress_to else []),
            },
        }
        native.append(allow)

    calico: list[dict] = [
        {
            "apiVersion": "projectcalico.org/v3",
            "kind": "GlobalNetworkPolicy",
            "metadata": {"name": "trident-default-deny",
                         "annotations": {TRIDENT_ANNOTATION: MONITOR,
                                         "trident.io/note": "顺序低于放行策略；RDMA/SR-IOV 面不覆盖，见 rdma-sriov-uncovered.md"}},
            "spec": {"selector": "all()", "order": 1000,
                     "types": ["Ingress", "Egress"],
                     "ingress": [{"action": "Deny"}], "egress": [{"action": "Deny"}]},
        }
    ]
    for zone in zones:
        peer_src = [f"{z['name']}.{zone['label']}/member == 'true'" for z in zones
                    if z["name"] in zone["allow_ingress_from"]]
        calico.append({
            "apiVersion": "projectcalico.org/v3",
            "kind": "GlobalNetworkPolicy",
            "metadata": {"name": f"trident-allow-{zone['name']}",
                         "annotations": {TRIDENT_ANNOTATION: MONITOR}},
            "spec": {
                "order": 900,
                "selector": f"{zone['name']}.{zone['label']}/member == 'true'",
                "types": ["Ingress", "Egress"],
                "ingress": [{
                    "action": "Allow",
                    "source": {"selector": " || ".join(peer_src) or "all()",
                               "nets": [admin_cidr]},
                    "ports": [{"protocol": "TCP", "port": p} for p in zone["ports"]],
                }],
                "egress": [{
                    "action": "Allow",
                    "destination": {"nets": ["0.0.0.0/0"]},
                }],
            },
        })

    cilium: list[dict] = []
    for zone in zones:
        ns = zone["namespace"]
        cilium.append({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "trident-default-deny", "namespace": ns,
                         "annotations": {TRIDENT_ANNOTATION: MONITOR}},
            "spec": {"endpointSelector": {}, "ingress": [], "egress": []},
        })
        from_rules = [
            {"fromEndpoints": [{"matchLabels": {f"io.kubernetes.podns": z["namespace"]}}]}
            for z in zones if z["name"] in zone["allow_ingress_from"]
        ] + [{"fromCIDR": [admin_cidr]}]
        cilium.append({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "trident-partition-allow", "namespace": ns,
                         "annotations": {TRIDENT_ANNOTATION: MONITOR}},
            "spec": {
                "endpointSelector": {"matchLabels": {f"{zone['name']}.{zone['label']}/member": "true"}},
                "ingress": from_rules and [{"fromEndpoints": [fr["fromEndpoints"][0] for fr in from_rules if "fromEndpoints" in fr],
                                            "fromCIDR": [admin_cidr],
                                            "toPorts": [{"ports": [{"port": str(p), "protocol": "TCP"} for p in zone["ports"]]}]}] or [],
                "egress": [
                    {"toEndpoints": [{"matchLabels": {"k8s-app": "kube-dns"}}],
                     "toPorts": [{"ports": [{"port": str(dns_port), "protocol": "UDP"},
                                            {"port": str(dns_port), "protocol": "TCP"}]}]},
                ] + [{"toEndpoints": [{"matchLabels": {f"io.kubernetes.podns": z["namespace"]}}]}
                     for z in zones if z["name"] in zone["allow_egress_to"]],
            },
        })
    return {"native": native, "calico": calico, "cilium": cilium}


def _vpc_supplement(cfg: dict, blocks: list[str]) -> dict:
    return {
        "apiVersion": "vpcresources.k8s.aws/v1beta1",
        "kind": "SecurityGroupPolicy",
        "metadata": {"name": "trident-training-partition-sg",
                     "annotations": {TRIDENT_ANNOTATION: MONITOR,
                                     TRIDENT_BLOCKS_ANNOTATION: ",".join(blocks),
                                     "trident.io/note": "VPC-native 双控制面：SG 与 NetworkPolicy 语义不一致，必须双侧核对"}},
        "spec": {
            "podSelector": {"matchLabels": {"trident-io-zone": "ml-training"}},
            "securityGroups": {"groupIds": ["sg-TRAINING_PARTITION_PLACEHOLDER"]},
        },
        "variants": {
            "eks-securitygroup-for-pods": "vpcresources.k8s.aws/v1beta1 SecurityGroupPolicy（本文件）",
            "aliyun-ack-terway": "Terway Pod 级安全组（trident.io/sg 注解方式，按 Terway 文档套用）",
            "tencent-tke-vpc-cni": "TKE VPC-CNI Pod 级安全组绑定（按 TKE 控制台/API 套用）",
            "azure-aks": "AKS Azure CNI + NSG（NSG 无 Pod 级语义，用 policy + NSG 双侧收敛）",
        },
        "warning": "VPC 安全组与 K8s NetworkPolicy 是两套控制面：入站以 SG 为准、出站以策略为准时最易错配；逐分区建立双侧对照表后再收敛。",
    }


def _ib_partition_advice(cfg: dict, blocks: list[str]) -> dict:
    return {
        "document": "ib-partition-advice",
        "annotations": {TRIDENT_ANNOTATION: MONITOR, TRIDENT_BLOCKS_ANNOTATION: ",".join(blocks)},
        "scope": "集合通信 fabric（IB / RoCE / GPUDirect RDMA / SR-IOV VF / IMEX ComputeDomain）",
        "explicit_declaration": cfg["rdma_statement"],
        "recommended_controls": [
            "IB Partition（PKey）按训练租户/作业组分隔离区，禁用默认全通 partition membership",
            "Subnet Manager 侧按 rail/plane 划分隔离域，跨 partition 流量显式白名单",
            "ib-kubernetes / NVIDIA Network Operator 的 NicClusterPolicy 显式配置 guid/pkey 池，禁 default partition",
            "RoCEv2 场景以 VRF/BD 分段 + PFC/ECN 基线替代 partition 语义",
            "hostNetwork/hostDevice 收敛清单（逐 DaemonSet 审计必要性）",
        ],
        "hostnetwork_convergence": cfg["hostnetwork_convergence"],
        "not_covered_by": ["NetworkPolicy (native)", "Calico GlobalNetworkPolicy", "Cilium CiliumNetworkPolicy", "VPC security groups"],
    }


def _rdma_declaration_md(cfg: dict) -> str:
    return f"""# RDMA / SR-IOV 不受 NetworkPolicy 覆盖 — 显式声明

{cfg["rdma_statement"]["zh"]}

## 适用范围
- SR-IOV VF / RDMA shared device / IB device plugin 直挂的 Pod 多网卡路径
- hostNetwork / hostDevice 工作负载（GPU 驱动容器、NCCL bootstrap 直连）
- GPUDirect RDMA / IB / RoCEv2 集合通信平面；GB200 NVL72 / IMEX ComputeDomain 跨节点 GPU 内存域

## 判定口径（对齐设计约束）
任何「网络可达」结论必须注明层级与判定方式；本声明意味着：上述路径上不存在 NetworkPolicy
（原生 / Calico / Cilium / VPC 安全组）语义的隔离结论，不得把「有 NetworkPolicy」等同于「隔离有效」。

## 补充控制（另见 ib-partition-advice.yaml）
- IB Partition（PKey）+ Subnet Manager 隔离为该平面的唯一隔离手段
- 预填充-解码 KV 传输（NIXL/Mooncake）按端口域与身份双向校验补强
- hostNetwork 收敛清单：
{chr(10).join("  - " + item for item in cfg["hostnetwork_convergence"])}

English declaration: {cfg["rdma_statement"]["en"]}
"""


# ---------------------------------------------------------------- Suricata DSL

def _suricata_rules_text(specs: list[dict]) -> str:
    lines = [
        "# Trident Suricata signatures (monitor mode) - deploy with HOME_NET/ML_NET vars",
        "# vars: ML_NET = ML 分区网段（training/inference/ray-system）；BASTION_NET = 管理网段",
        "",
    ]
    for spec in specs:
        lines.append(f"# --- {spec['id']}: {spec['title']} (tuning: {spec['tuning']['zh'][:60]}...) ---")
        sid = spec["sids"]["base"]
        if spec["id"] == "suricata-admin-endpoint-uri":
            for i, uri in enumerate(spec["uris"]):
                lines.append(
                    f'alert http any any -> $ML_NET any (msg:"TRIDENT admin endpoint URI {uri}"; '
                    f'flow:established,to_server; http.method; content:"POST"; http.uri; content:"{uri}"; '
                    f'sid:{sid + i}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
                )
        elif spec["id"] == "suricata-imds-egress":
            lines.append(
                f'alert ip $ML_NET any -> {spec["dest_ip"]} any (msg:"TRIDENT IMDS egress from ML partition"; '
                f'flow:to_server; sid:{sid}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
            )
            for i, path in enumerate(spec["paths"]):
                lines.append(
                    f'alert http $ML_NET any -> any any (msg:"TRIDENT metadata URI {path}"; '
                    f'flow:established,to_server; http.uri; content:"{path}"; '
                    f'sid:{sid + 1 + i}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
                )
        elif spec["id"] == "suricata-nccl-kv-ports":
            ports = ", ".join(str(p) for p in spec["ports"])
            lines.append(
                f'alert tcp any any -> $ML_NET [{ports}] (msg:"TRIDENT collective/KV transfer port access from outside partition"; '
                f'flow:to_server; flags:S; sid:{sid}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
            )
        elif spec["id"] == "suricata-gpu-cloud-tenant-uri":
            for i, uri in enumerate(spec["uris"]):
                lines.append(
                    f'alert http any any -> $ML_NET any (msg:"TRIDENT GPU pool / cloud tenant endpoint {uri}"; '
                    f'flow:established,to_server; http.uri; content:"{uri}"; '
                    f'sid:{sid + i}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
                )
        elif spec["id"] == "suricata-ai-gateway-admin-uri":
            for i, uri in enumerate(spec["uris"]):
                lines.append(
                    f'alert http any any -> $ML_NET any (msg:"TRIDENT AI gateway admin URI {uri} from non-admin source"; '
                    f'flow:established,to_server; http.uri; content:"{uri}"; '
                    f'sid:{sid + i}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
                )
        elif spec.get("uris"):
            for i, uri in enumerate(spec["uris"]):
                lines.append(
                    f'alert http any any -> $ML_NET any (msg:"TRIDENT long-context/KV endpoint {uri} from outside partition"; '
                    f'flow:established,to_server; http.uri; content:"{uri}"; '
                    f'sid:{sid + i}; rev:1; metadata:trident.mode=monitor, trident.rule={spec["id"]};)'
                )
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- 生成主流程

def generate_all(chains_dir: Path | str, findings: list | None = None,
                 cni: str = "native", out_dir: Path | str | None = None) -> RulePack:
    """把链目录 + 演练发现转化为规则包；每链 ≥1 规则（0 规则链抛 RuleCoverageError）。

    findings: 演练发现列表（step_key/module 标识），登记到规则 finding_links 供追溯。
    cni: 主 CNI（native/calico/cilium/vpc-native）——三变体始终全量产出，cni 仅标记主选。
    """
    findings = list(findings or [])
    if cni not in CNI_VARIANTS:
        raise ValueError(f"cni 必须是 {CNI_VARIANTS} 之一，收到 {cni!r}")
    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="trident-rulepack-")
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)

    chains = load_chains(chains_dir)
    if not chains:
        raise RuleCoverageError("链目录为空：无攻击方案可转化")
    catalog = load_catalog()
    written: list[str] = []
    rules_meta: list[dict] = []

    def write(rel: str, text: str) -> str:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(rel.replace("\\", "/"))
        return written[-1]

    def blocks_of(modules: list[str]) -> list[str]:
        modset = set(modules)
        return [cid for cid, chain in sorted(chains.items()) if modset & _chain_modules(chain)]

    def finding_links(modules: list[str]) -> list[str]:
        modset = set(modules)
        keys = set()
        for f in findings:
            for fieldname in ("step_key", "module"):
                if f.get(fieldname) in modset:
                    keys.add(f"{fieldname}:{f[fieldname]}")
        return sorted(keys)

    def register(rule_id: str, engines: list[str], title: dict, files: list[str],
                 tuning: dict, modules: list[str], match: dict | None = None,
                 log_source: dict | str | None = None) -> dict:
        blocks = blocks_of(modules)
        meta = {
            "id": rule_id,
            "engines": engines,
            "title": title,
            "files": files,
            "mode": MONITOR,
            "tuning": tuning,
            "log_source": log_source,
            "blocks_modules": sorted(set(modules)),
            "blocks_chains": blocks,
            "finding_links": finding_links(modules),
            "match": match,
        }
        rules_meta.append(meta)
        return meta

    # 1) 准入规则：Kyverno + Gatekeeper 双格式导出
    for spec in catalog["admission"]:
        files = []
        blocks = blocks_of(spec["blocks_modules"])
        files.append(write(f"kyverno/cluster-policy-{spec['id']}.yaml",
                           yaml_dump(_kyverno_policy(spec, blocks))))
        template, constraint = _gatekeeper_docs(spec, blocks)
        files.append(write(f"gatekeeper/templates/{spec['id']}.yaml", yaml_dump(template)))
        files.append(write(f"gatekeeper/constraints/{spec['id']}.yaml", yaml_dump(constraint)))
        register(spec["id"], ["kyverno", "gatekeeper"], spec["title"], files,
                 spec["tuning"], spec["blocks_modules"], log_source="K8s admission review")

    # 2) NetworkPolicy 分区模板 per-CNI 三变体 + VPC 补充 + RDMA 声明 + IB 建议
    netcfg = catalog["netpol"]
    docs = _netpol_docs(netcfg)
    netpol_files = []
    netpol_modules = ["network-policy-coverage", "framework-port-matching", "ray-control-plane",
                      "observability-exposure", "exposure-mapping", "collective-communication-surface",
                      "cni-stack-capability", "inference-gateway-pd"]
    netpol_blocks = blocks_of(netpol_modules)
    variant_files = {
        "native": "network/native/network-policy-default-deny.yaml",
        "calico": "network/calico/global-network-policy-default-deny.yaml",
        "cilium": "network/cilium/cilium-network-policy-default-deny.yaml",
    }
    for variant, rel in variant_files.items():
        text = "\n---\n".join(yaml_dump(doc) for doc in docs[variant])
        netpol_files.append(write(rel, text))
    register(
        "netpol-default-deny-partition", ["netpol"],
        {"zh": "NetworkPolicy 默认拒绝 + 按域放行（per-CNI 三变体）",
         "en": "Default-deny NetworkPolicy with zone allows (per-CNI variants)"},
        netpol_files,
        {"zh": "命名空间/标签为占位模板，按客户分区清单改名后再 apply；先在单分区试点观察 DNS/存储/云 API 依赖，再全量铺开；管理端口仅管理网段可达",
         "en": "Placeholder namespaces/labels must be renamed to the customer partition inventory; pilot one zone first (DNS/storage/cloud API dependencies) before rollout; admin ports reachable only from the admin CIDR"},
        netpol_modules, log_source="CNI policy engine",
    )

    vpc_modules = ["hybrid-cloud-egress-pivot", "cni-stack-capability"]
    vpc_files = [write("network/vpc-native/security-group-supplement.yaml",
                       yaml_dump(_vpc_supplement(netcfg, blocks_of(vpc_modules))))]
    register(
        "vpc-securitygroup-supplement", ["vpc-sg"],
        {"zh": "VPC-native CNI 安全组补充清单（EKS SG for Pods / Terway / TKE VPC-CNI / AKS）",
         "en": "VPC-native security-group supplement (EKS SG for Pods / Terway / TKE VPC-CNI / AKS)"},
        vpc_files,
        {"zh": "安全组规则与 NetworkPolicy 双控制面必须双侧核对（入站 SG、出站策略最易错配）；按分区建立对照表后收敛默认拒绝",
         "en": "Cross-check both control planes (inbound SG vs outbound policy is the classic mismatch); build a per-zone mapping table before tightening to default deny"},
        vpc_modules, log_source="cloud provider network API",
    )

    rdma_modules = ["multus-sriov-rdma-bypass", "fabric-topology-isolation", "collective-communication-surface"]
    rdma_files = [
        write("network/rdma-sriov-uncovered.md", _rdma_declaration_md(netcfg)),
        write("network/ib-partition-advice.yaml", yaml_dump(_ib_partition_advice(netcfg, blocks_of(rdma_modules)))),
    ]
    register(
        "rdma-sriov-ib-partition-advice", ["ib-advice"],
        {"zh": "RDMA/SR-IOV 不受 NetworkPolicy 覆盖声明 + IB Partition/SM 隔离建议",
         "en": "RDMA/SR-IOV not covered by NetworkPolicy declaration + IB Partition/SM isolation advice"},
        rdma_files,
        {"zh": "PKey/Partition 规划与 SM 隔离域随组网方案落地；hostNetwork 收敛清单逐 DaemonSet 过一遍；KV/NCCL 端口域与身份校验补强",
         "en": "Plan PKey partitions and SM isolation domains with the fabric team; walk the hostNetwork convergence list per DaemonSet; add identity checks on KV/NCCL port domains"},
        rdma_modules, log_source="fabric (IB SM / eBPF export)",
    )

    # 3) SOC 检测规则：Sigma / Falco / Suricata
    falco_rule_dicts: list[dict] = []
    for spec in catalog["sigma"]:
        doc = {
            "title": spec["title"],
            "id": _deterministic_uuid(f"trident-sigma-{spec['id']}"),
            "status": "stable",
            "description": spec["description"],
            "references": ["trident-rules-mapping: " + spec["id"]],
            "author": "Trident rules engine",
            "date": "2026/10/25",
            "logsource": spec["logsource"],
            "detection": spec["detection"],
            "falsepositives": spec["falsepositives"],
            "level": spec["level"],
            "tags": spec["tags"] + ["trident-mode-monitor"],
            "custom": {
                "trident-mode": MONITOR,
                "trident-tuning": spec["tuning"]["zh"],
                "trident-blocks-chains": ",".join(blocks_of(spec["blocks_modules"])),
            },
        }
        rel = write(f"sigma/{spec['id']}.yaml", yaml_dump(doc))
        register(spec["id"], ["sigma"], {"zh": spec["title"], "en": spec["title"]}, [rel],
                 spec["tuning"], spec["blocks_modules"], match=spec["match"],
                 log_source=spec["logsource"])

    for spec in catalog["falco"]:
        falco_rule_dicts.append({
            "rule": spec["rule"],
            "desc": spec["desc"],
            "condition": spec["condition"],
            "output": spec["output"],
            "priority": spec["priority"],
            "tags": spec["tags"] + ["mode-monitor"],
        })
    falco_file = write("falco/trident-rules.yaml", yaml_dump(falco_rule_dicts))
    for spec in catalog["falco"]:
        register(spec["id"], ["falco"], {"zh": spec["rule"], "en": spec["rule"]}, [falco_file],
                 spec["tuning"], spec["blocks_modules"], match=spec["match"],
                 log_source=spec.get("logsource", "Falco syscall/trace events"))

    suricata_text = _suricata_rules_text(catalog["suricata"])
    suricata_file = write("suricata/trident.rules", suricata_text)
    for spec in catalog["suricata"]:
        register(spec["id"], ["suricata"], {"zh": spec["title"], "en": spec["title"]}, [suricata_file],
                 spec["tuning"], spec["blocks_modules"], match=spec["match"],
                 log_source="Suricata EVE json")

    # 4) 零日行为化签名（不含利用细节特征串；公开 advisory 后可升级细节版）
    zeroday_entries: list[dict] = []
    for spec in catalog["zeroday"]["rules"]:
        blocks = blocks_of(spec["blocks_modules"])
        if spec["engine"] == "falco":
            falco_rule_dicts.append({
                "rule": spec["rule"],
                "desc": spec["desc"],
                "condition": spec["condition"],
                "output": spec["output"],
                "priority": spec["priority"],
                "tags": spec["tags"],
            })
            rel = write("falco/trident-rules.yaml", yaml_dump(falco_rule_dicts))
        else:
            doc = {
                "title": spec["title"],
                "id": _deterministic_uuid(f"trident-sigma-{spec['id']}"),
                "status": "stable",
                "description": spec["description"],
                "references": ["trident-rules-mapping: " + spec["id"]],
                "author": "Trident rules engine",
                "date": "2026/10/25",
                "logsource": spec["logsource"],
                "detection": spec["detection"],
                "falsepositives": spec["falsepositives"],
                "level": spec["level"],
                "tags": spec["tags"] + ["trident-mode-monitor"],
                "custom": {
                    "trident-mode": MONITOR,
                    "trident-tuning": spec["tuning"]["zh"],
                    "trident-blocks-chains": ",".join(blocks),
                },
            }
            rel = write(f"sigma/{spec['id']}.yaml", yaml_dump(doc))
        rules_meta.append({
            "id": spec["id"],
            "engines": [spec["engine"]],
            "title": {"zh": spec.get("title", spec.get("rule", "")), "en": spec.get("rule", spec.get("title", ""))},
            "files": [rel],
            "mode": MONITOR,
            "tuning": spec["tuning"],
            "log_source": spec.get("logsource") or (
                "Falco syscall/trace events" if spec["engine"] == "falco" else None),
            "blocks_modules": sorted(set(spec["blocks_modules"])),
            "blocks_chains": blocks,
            "finding_links": finding_links(spec["blocks_modules"]),
            "match": spec["match"],
        })
        zeroday_entries.append({
            "id": spec["id"],
            "engine": spec["engine"],
            "files": [rel],
            "related_modules": sorted(set(spec["blocks_modules"])),
            "behavioral": True,
            "note": "行为化签名：仅描述异常行为特征，不含利用细节特征串；公开 advisory 后可升级为细节版规则",
        })

    # 5) RBAC 收敛参考清单（三 operator 集群级角色 → namespace 最小化改写样本）
    rbac_doc = {
        "document": "rbac-convergence-reference",
        "annotations": {TRIDENT_ANNOTATION: MONITOR},
        "samples": [
            {
                "target": "vllm-operator / production-stack operator",
                "from": "cluster 级 roles/rolebindings 全 CRUD（集群接管面）",
                "to": "namespace 级 Role（仅本命名空间 roles/rolebindings），remove cluster-admin 引用",
            },
            {
                "target": "kuberay-operator",
                "from": "准 cluster-admin（pods/exec/nodes/CRD 全域）",
                "to": "命名空间 Role 限定 rayclusters.ray.io 等 CR + 去除 nodes/exec；dashboard 令牌与 8265 分区限源",
            },
            {
                "target": "lws-operator (LeaderWorkerSet)",
                "from": "集群级 secrets 读写 + 节点 patch",
                "to": "命名空间 secrets（仅 labelselector 命中的工作负载 secret）+ 取消节点 patch；webhook 关闭 automount 继承",
            },
        ],
        "verify": "收敛后以 trident 权限链模块复测（can-i 矩阵 + RoleBinding 创建探针）",
    }
    write("rbac-convergence.yaml", yaml_dump(rbac_doc))

    # 6) 覆盖校验：每链 ≥1 规则（0 规则即失败）
    covered: dict[str, list[str]] = {}
    for meta in rules_meta:
        for cid in meta["blocks_chains"]:
            covered.setdefault(cid, []).append(meta["id"])
    uncovered = [cid for cid in chains if cid not in covered]
    if uncovered:
        raise RuleCoverageError(f"以下攻击链无任何规则覆盖: {sorted(uncovered)}")

    mapping = {
        "generator": "trident.rules.generate",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cni_active": cni,
        "cni_variants": list(CNI_VARIANTS),
        "inputs": {"chains": len(chains), "findings": len(findings)},
        "rules": rules_meta,
        "chains": {
            cid: {
                "category": chain.get("category", ""),
                "title": chain.get("title", {}),
                "modules": sorted(_chain_modules(chain)),
                "rules": covered[cid],
            }
            for cid, chain in sorted(chains.items())
        },
        "zeroday": zeroday_entries,
        "rdma_declaration": {
            "files": ["network/rdma-sriov-uncovered.md", "network/ib-partition-advice.yaml"],
            "statement": netcfg["rdma_statement"],
        },
        "purple_validation": {
            "entry": "trident.rules.validate",
            "artifacts": ["coverage-matrix.json", "coverage-matrix.md"],
            "note": "对 lab mock vulnerable 靶场重放各链第一步探针 + 日志 fixture，用内置简化匹配器断言规则命中",
        },
    }
    mapping_rel = write("mapping.json", json.dumps(mapping, ensure_ascii=False, indent=2))

    return RulePack(
        out_dir=str(root),
        cni=cni,
        rules=rules_meta,
        files=written,
        chains_covered=covered,
        mapping_path=mapping_rel,
    )
