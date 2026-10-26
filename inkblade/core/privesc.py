"""全量提权矩阵与提权图（Privesc Matrix & Path Graph）。

数据源：``trident/core/data/privesc-matrix.json``（47 条向量，5 类）。
图模型：
- 节点：principal / capability / target；另可挂载证据与资产节点
- 边：一条向量可展开为多条原语边（原语 + 前置 + 证据 + 检测键 + 权重）
- 路径：``paths(from_principal, to='cluster-admin')`` 返回按权重/跳数排序的
  K 条简单路径；``explain(path)`` 输出逐步入话说明。

与 assets/evidence 联动：
- ``load_snapshot_from_evidence(store, run)`` 从 run 的 artifacts 中读取真实
  集群快照（kubectl get -o json / recon 快照），并附加 AssetInventory 资产；
- ``infer_principals(snapshot)`` 从 can-i 矩阵、RoleBinding、ClusterRoleBinding、
  ServiceAccount、Pod 推断当前主体及其权限，把权限作为 0.3 权重的“当前授权”边。

边界：图是授权/原语关系推演，不代表已执行；执行仍由 runner 的 ROE/备份闸门约束。
"""

from __future__ import annotations

import heapq
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

MATRIX_PATH = Path(__file__).resolve().parent / "data" / "privesc-matrix.json"

REQUIRED_VECTOR_FIELDS = (
    "id", "category", "title", "subject", "requires", "primitive", "impact",
    "detect", "module", "sources", "edges",
)

CATEGORY_REQUIRED: dict[str, tuple[str, ...]] = {
    "rbac": (
        "rbac-escalate-verb", "rbac-bind-verb", "rbac-impersonate",
        "rbac-sa-token-request", "rbac-pods-exec", "rbac-rolebinding-cluster-admin",
        "rbac-aggregated-clusterrole", "rbac-admission-webhook-write",
        "rbac-apiservice-hijack", "rbac-crd-conversion-webhook",
    ),
    "workload": (
        "workload-privileged-pod", "workload-hostpath-hostroot",
        "workload-hostpid-hostnetwork", "workload-dangerous-caps",
        "workload-ephemeral-container", "workload-init-container-override",
        "workload-hostpath-kubelet", "workload-hostpath-runtime-socket",
        "workload-static-pod-write",
    ),
    "credential": (
        "cred-sa-token-automount", "cred-projected-token", "cred-legacy-sa-secret",
        "cred-image-pull-secret", "cred-git-ci-token", "cred-ml-platform-token",
        "cred-cloud-imds", "cred-cloud-federation",
    ),
    "node": (
        "node-kubelet-10250-exec", "node-kubelet-10250-run", "node-etcd-direct",
        "node-proxy", "node-runtime-socket", "node-kernel-runc",
    ),
    "platform": (
        "platform-gpu-operator-driver", "platform-device-plugin", "platform-cni-plugin",
        "platform-csi-node-plugin", "platform-ingress-secret", "platform-cert-manager",
        "platform-argocd-flux", "platform-kueue-volcano",
        "platform-ray-kuberay-autoscaler", "platform-lws-operator",
        "platform-jupyter-notebook", "platform-mlflow-tracking",
    ),
}

_TARGETS = {
    "cluster-admin": "target:cluster-admin",
    "target:cluster-admin": "target:cluster-admin",
    "node-root": "target:node-root",
    "target:node-root": "target:node-root",
    "cloud-admin": "target:cloud-admin",
    "target:cloud-admin": "target:cloud-admin",
}

# 主体已具备 cluster-admin 等价权限时的直接路径（无原语边）。
GRANT_VECTOR = "inferred-grant"


class PrivescError(ValueError):
    """提权矩阵/图参数非法。"""


class UnknownPrincipal(PrivescError):
    """请求的起始主体不在快照/图中。"""


class UnknownTarget(PrivescError):
    """目标节点不存在。"""


# ---------------------------------------------------------------- 数据装载

def load_matrix(path: Path | str | None = None) -> dict:
    p = Path(path) if path else MATRIX_PATH
    raw = json.loads(p.read_text(encoding="utf-8"))
    if "vectors" not in raw:
        raise PrivescError(f"{p} 不是提权矩阵（缺少 vectors）")
    return raw


def _modules_available(modules) -> set[str]:
    if modules is None:
        return set()
    if isinstance(modules, dict):
        return set(modules)
    return {m.key for m in modules}


def validate_matrix(matrix: dict, modules: Any = None) -> dict:
    """结构 + 覆盖 + 模块引用校验；返回 ``{ok, errors, ...}``。"""
    errors: list[str] = []
    vectors = matrix.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return {"ok": False, "errors": ["vectors 必须是非空数组"], "vectors": 0,
                "rules": 0, "edges": 0, "categories": {}}
    seen: set[str] = set()
    cat_counts: dict[str, int] = {}
    edge_count = 0
    mods = _modules_available(modules)
    source_count = 0
    for v in vectors:
        if not isinstance(v, dict):
            errors.append("向量必须是对象")
            continue
        vid = str(v.get("id", ""))
        if not vid:
            errors.append("向量缺少 id")
            continue
        if vid in seen:
            errors.append(f"向量 id 重复: {vid}")
        seen.add(vid)
        for field in REQUIRED_VECTOR_FIELDS:
            if field not in v:
                errors.append(f"{vid}: 缺少字段 {field}")
        cat = v.get("category")
        if cat not in CATEGORY_REQUIRED:
            errors.append(f"{vid}: 未知 category {cat!r}")
        else:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        for scope in ("node", "cluster", "cloud"):
            if not isinstance(v.get("impact"), dict) or not str(v["impact"].get(scope, "")).strip():
                errors.append(f"{vid}: impact.{scope} 为空")
        detect = v.get("detect") or {}
        if detect.get("engine") not in ("sigma", "falco"):
            errors.append(f"{vid}: detect.engine 必须是 sigma/falco")
        if not str(detect.get("point", "")).strip():
            errors.append(f"{vid}: 缺少检测点")
        if not v.get("sources"):
            errors.append(f"{vid}: 缺少来源")
        for src in v.get("sources") or []:
            if not isinstance(src, dict) or not src.get("type") or not src.get("ref"):
                errors.append(f"{vid}: 来源字段不完整")
            else:
                source_count += 1
        edges = v.get("edges") or []
        if not edges:
            errors.append(f"{vid}: 缺少图边")
        for edge in edges:
            edge_count += 1
            src = str(edge.get("from", ""))
            dst = str(edge.get("to", ""))
            if not src.startswith(("principal:", "cap:")):
                errors.append(f"{vid}: from 非法 {src!r}")
            if not dst.startswith(("cap:", "target:", "cloud:")):
                errors.append(f"{vid}: to 非法 {dst!r}")
            if float(edge.get("weight", 1.0)) <= 0:
                errors.append(f"{vid}: 边权重必须 > 0")
        if mods and v.get("module") not in mods:
            errors.append(f"{vid}: 模块不存在 {v.get('module')!r}")
    for cat, required in CATEGORY_REQUIRED.items():
        missing = set(required) - seen
        if missing:
            errors.append(f"{cat}: 缺少必需向量 {sorted(missing)}")
    return {
        "ok": not errors,
        "errors": errors,
        "vectors": len(vectors),
        "rules": len(vectors),
        "edges": edge_count,
        "categories": cat_counts,
        "sources": source_count,
    }


# ---------------------------------------------------------------- 节点/边/主体

def _node_kind(node_id: str) -> str:
    if node_id.startswith(("system:serviceaccount:", "user:", "group:", "principal:")):
        return "principal"
    prefix = node_id.split(":", 1)[0]
    return {
        "cap": "capability",
        "target": "target",
        "cloud": "target",
        "resource": "resource",
    }.get(prefix, "resource")


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    label: str

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label}


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    vector: str
    vector_title: str
    primitive: str
    requires: tuple[str, ...]
    evidence: str
    detection: str
    weight: float
    module: str = ""
    kind: str = "attack"

    @property
    def detection_key(self) -> str:
        return self.detection

    def to_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "vector": self.vector,
            "title": self.vector_title, "primitive": self.primitive,
            "requires": list(self.requires), "evidence": self.evidence,
            "detection": self.detection, "weight": self.weight,
            "module": self.module, "kind": self.kind,
        }


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str
    namespace: str = ""
    capabilities: tuple[str, ...] = ()
    cluster_admin: bool = False
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "namespace": self.namespace,
            "capabilities": list(self.capabilities), "cluster_admin": self.cluster_admin,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class PrivescPath:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]

    @property
    def weight(self) -> float:
        return round(sum(e.weight for e in self.edges), 3)

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def vector_ids(self) -> list[str]:
        return [e.vector for e in self.edges]

    @property
    def start(self) -> Node:
        return self.nodes[0]

    @property
    def target(self) -> Node:
        return self.nodes[-1]

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "weight": self.weight,
            "hops": self.hops,
            "vector_ids": self.vector_ids,
        }


def _subject_id(kind: str, name: str, namespace: str = "") -> str:
    k = (kind or "").lower()
    if k == "serviceaccount":
        return f"system:serviceaccount:{namespace or 'default'}:{name}"
    if k == "user":
        return f"user:{name}"
    if k == "group":
        return f"group:{name}"
    if name.startswith(("system:serviceaccount:", "user:", "group:")):
        return name
    return f"principal:{name}"


def _allowed_text(item: Any) -> str:
    if isinstance(item, str):
        return item.lower()
    if isinstance(item, dict):
        return " ".join(str(item.get(k, "")) for k in ("verb", "resource", "apiGroup")).lower()
    return str(item).lower()


def _caps_from_allowed(allowed: Iterable[Any]) -> tuple[set[str], bool]:
    """把 can-i 字符串/规则投影为能力节点；返回 (caps, cluster_admin)。"""
    caps: set[str] = set()
    text = " ".join(_allowed_text(a) for a in allowed)
    tokens = set(text.replace("/", " ").replace(",", " ").split())
    if text.strip() in ("*", "* *", "*:*", "all all") or ("*" in tokens and "all" in tokens):
        return set(), True
    # 通配符 can-i 常见输出 “*.*” / “* *”；仅当动词与资源同时为 * 才视为全权。
    if " * " in f" {text} " and ("*" in tokens):
        # 进一步确认资源侧也是 *
        if text.count("*") >= 2 or " *.*" in text:
            return set(), True
    if any(k in text for k in ("escalate",)) and any(k in text for k in ("clusterrole", "role")):
        caps.add("cap:rbac-escalate")
    if any(k in text for k in ("bind",)) and any(k in text for k in ("clusterrole", "role")):
        caps.add("cap:rbac-bind")
    if "impersonate" in text:
        caps.add("cap:impersonate")
    if "serviceaccount" in text and "token" in text:
        caps.add("cap:sa-token-create")
    if "pods/exec" in text or ("pod" in text and "exec" in text):
        caps.add("cap:pod-exec")
    if "ephemeralcontainer" in text:
        caps.add("cap:ephemeral-container")
    if "create" in text and ("pod" in text or "deployment" in text or "daemonset" in text):
        caps.add("cap:pod-create")
    if "secret" in text and any(v in text for v in ("get", "list", "watch", "*")):
        caps.add("cap:secret-read")
    if "webhookconfiguration" in text:
        caps.add("cap:webhook-write")
    if "apiservice" in text:
        caps.add("cap:apiservice-write")
    if "customresourcedefinition" in text or " crd" in f" {text} ":
        caps.add("cap:crd-write")
    if "certificatesigningrequest" in text or " csr" in f" {text} ":
        caps.add("cap:csr-approve")
    if "nodes/proxy" in text or ("node" in text and "proxy" in text):
        caps.add("cap:node-proxy")
    if "clusterrole" in text and "create" in text:
        caps.add("cap:rbac-create-clusterrole")
    if ("rolebinding" in text or "clusterrolebinding" in text) and "create" in text:
        caps.add("cap:rbac-create-binding")
    if "etcd" in text:
        caps.add("cap:etcd-access")
    if "kubelet" in text:
        caps.add("cap:kubelet-10250")
    if any(k in text for k in ("imds", "169.254.169.254", "metadata")):
        caps.add("cap:cloud-imds")
    if any(k in text for k in ("irsa", "workload identity", "rrsa", "podidentity", "cam role")):
        caps.add("cap:cloud-identity")
    if any(k in text for k in ("gpu-operator", "nvidia", "gpu operator")):
        caps.add("cap:gpu-operator-write")
    if "device-plugin" in text or "device plugin" in text:
        caps.add("cap:device-plugin-write")
    if any(k in text for k in ("cni", "calico", "cilium")):
        caps.add("cap:cni-write")
    if " csi" in f" {text} " or "csi-" in text:
        caps.add("cap:csi-write")
    if "ingress" in text:
        caps.add("cap:ingress-write")
    if "cert-manager" in text or "certmanager" in text:
        caps.add("cap:cert-manager-write")
    if any(k in text for k in ("argocd", "flux", "gitops")):
        caps.add("cap:gitops-write")
    if any(k in text for k in ("kueue", "volcano")):
        caps.add("cap:queue-write")
    if "ray" in text and any(k in text for k in ("job", "cluster", "operator", "dashboard")):
        caps.add("cap:ray-control")
    if any(k in text for k in ("leaderworkerset", "lws")):
        caps.add("cap:lws-control")
    if "jupyter" in text or "notebook" in text:
        caps.add("cap:notebook-write")
    if "mlflow" in text:
        caps.add("cap:mlflow-write")
    if "git" in text and "token" in text:
        caps.add("cap:git-token")
    if any(k in text for k in ("hf_token", "hf token", "wandb", "ml-platform", "ml platform")):
        caps.add("cap:ml-platform-token")
    if any(k in text for k in ("runtime socket", "containerd.sock", "docker.sock", "crio.sock")):
        caps.add("cap:runtime-socket")
    if "hostpath" in text or "host path" in text:
        caps.add("cap:hostpath-pod-create")
    if "privileged" in text:
        caps.add("cap:privileged-pod-create")
    if "cap:rbac-bind" in caps and "cap:rbac-create-binding" in caps:
        caps.add("cap:rbac-bind-create")
    return caps, False


def _caps_from_rules(rules: Iterable[dict]) -> tuple[set[str], bool]:
    caps: set[str] = set()
    for r in rules or []:
        verbs = [str(x).lower() for x in r.get("verbs", [])]
        resources = [str(x).lower() for x in r.get("resources", [])]
        groups = [str(x).lower() for x in r.get("apiGroups", [])]
        if "*" in verbs and "*" in resources:
            return set(), True
        blob = " ".join(verbs + resources + groups)
        c, admin = _caps_from_allowed([blob])
        caps |= c
        if admin:
            return set(), True
    if "cap:rbac-bind" in caps and "cap:rbac-create-binding" in caps:
        caps.add("cap:rbac-bind-create")
    return caps, False


def _normalize_subject(entry: dict) -> str:
    kind = str(entry.get("kind") or "")
    name = str(entry.get("name") or "")
    namespace = str(entry.get("namespace") or "")
    if name.startswith(("system:serviceaccount:", "user:", "group:")):
        return name
    return _subject_id(kind, name, namespace)


def infer_principals(snapshot: dict | None, assets: list[dict] | None = None) -> list[Principal]:
    """从真实快照推断主体与能力（can-i + 绑定 + SA/Pod + 平台暴露）。"""
    snap = snapshot or {}
    acc: dict[str, dict[str, Any]] = {}

    def add(pid: str, **kwargs) -> None:
        row = acc.setdefault(pid, {"caps": set(), "cluster_admin": False, "evidence": set(),
                                   "kind": "serviceaccount" if pid.startswith("system:serviceaccount:") else "principal",
                                   "namespace": ""})
        row["caps"] |= set(kwargs.get("caps") or [])
        row["cluster_admin"] = row["cluster_admin"] or bool(kwargs.get("cluster_admin"))
        for e in kwargs.get("evidence") or []:
            row["evidence"].add(str(e))
        if kwargs.get("kind"):
            row["kind"] = kwargs["kind"]
        if kwargs.get("namespace"):
            row["namespace"] = kwargs["namespace"]

    # can-i 矩阵（支持 allowed 字符串 / 规则 dict / 直接 rules）
    for entry in snap.get("cani", []) or []:
        subject = str(entry.get("subject") or entry.get("principal") or "").strip()
        if not subject:
            continue
        allowed = entry.get("allowed") or entry.get("rules") or []
        caps, admin = _caps_from_allowed(allowed)
        add(subject, caps=caps, cluster_admin=admin,
            evidence=[f"can-i:{subject}"])

    # Role/ClusterRole + Binding
    role_rules: dict[str, list[dict]] = {}
    for key in ("clusterroles", "roles"):
        for role in snap.get(key, []) or []:
            if not isinstance(role, dict):
                continue
            name = str(role.get("name") or role.get("metadata", {}).get("name") or "")
            if name:
                role_rules[name] = list(role.get("rules") or [])
                role_rules[f"namespace:{role.get('namespace')}/{name}"] = list(role.get("rules") or [])
    for key, kind in (("clusterrolebindings", "ClusterRoleBinding"),
                      ("rolebindings", "RoleBinding")):
        for b in snap.get(key, []) or []:
            if not isinstance(b, dict):
                continue
            role = str(b.get("role") or b.get("roleRef", {}).get("name") or "")
            if not role:
                continue
            admin = role == "cluster-admin"
            caps, rule_admin = _caps_from_rules(role_rules.get(role, []))
            for subj in b.get("subjects", []) or []:
                pid = _normalize_subject(subj)
                add(pid, caps=caps, cluster_admin=admin or rule_admin,
                    evidence=[f"{kind}/{b.get('name', '?')}->{role}"],
                    kind=(subj.get("kind") or "").lower() or None,
                    namespace=subj.get("namespace", ""))

    # ServiceAccount / Pod 主体（可作为起点，即使没有显式 can-i）
    for sa in snap.get("serviceaccounts", []) or []:
        if not isinstance(sa, dict):
            continue
        ns = str(sa.get("namespace") or "default")
        name = str(sa.get("name") or "")
        if name:
            add(f"system:serviceaccount:{ns}:{name}", kind="serviceaccount", namespace=ns,
                evidence=[f"ServiceAccount {ns}/{name}"])
    for pod in snap.get("pods", []) or []:
        if not isinstance(pod, dict):
            continue
        ns = str(pod.get("namespace") or "default")
        name = str(pod.get("serviceAccount") or pod.get("serviceaccount") or "")
        if name:
            add(f"system:serviceaccount:{ns}:{name}", kind="serviceaccount", namespace=ns,
                evidence=[f"Pod {ns}/{pod.get('name', '?')} automount={pod.get('automountServiceAccountToken')}"])

    # 平台组件控制面主体：快照显式声明 / 资产 product 映射
    for item in (snap.get("platform_principals") or []) + (assets or []):
        if not isinstance(item, dict):
            continue
        product = str(item.get("product") or item.get("name") or "").lower()
        pid = str(item.get("subject") or item.get("principal") or "")
        if not pid and product:
            pid = f"principal:platform:{product}"
        if not pid:
            continue
        caps: set[str] = set()
        mapping = (
            ("gpu", "cap:gpu-operator-write"), ("nvidia", "cap:gpu-operator-write"),
            ("cni", "cap:cni-write"), ("calico", "cap:cni-write"), ("cilium", "cap:cni-write"),
            ("csi", "cap:csi-write"), ("ingress", "cap:ingress-write"),
            ("argocd", "cap:gitops-write"), ("flux", "cap:gitops-write"),
            ("kueue", "cap:queue-write"), ("volcano", "cap:queue-write"),
            ("ray", "cap:ray-control"), ("lws", "cap:lws-control"),
            ("jupyter", "cap:notebook-write"), ("mlflow", "cap:mlflow-write"),
        )
        for needle, cap in mapping:
            if needle in product:
                caps.add(cap)
        if caps:
            add(pid, caps=caps, evidence=[f"asset:{product}"])

    out: list[Principal] = []
    for pid, row in sorted(acc.items()):
        out.append(Principal(
            id=pid,
            kind=str(row["kind"]),
            namespace=str(row["namespace"]),
            capabilities=tuple(sorted(row["caps"])),
            cluster_admin=bool(row["cluster_admin"]),
            evidence=tuple(sorted(row["evidence"])),
        ))
    return out


# ---------------------------------------------------------------- 图

class PrivescGraph:
    """提权图：静态向量边 + 快照推断的当前授权边。"""

    def __init__(self, matrix: dict, snapshot: dict | None = None,
                 assets: list[dict] | None = None, max_depth: int = 12):
        self.matrix = matrix
        self.max_depth = max_depth
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = {}
        self.principals: list[Principal] = []
        self.assets = list(assets or [])
        labels = matrix.get("node_labels") or {}
        self._labels = labels
        self._add_vector_edges()
        self._apply_snapshot(snapshot)

    # ---- 构建
    def _ensure_node(self, node_id: str, label: str = "") -> Node:
        node = self.nodes.get(node_id)
        if node is None:
            kind = _node_kind(node_id)
            text = label or self._labels.get(node_id) or node_id.split(":", 1)[-1]
            node = Node(node_id, kind, text)
            self.nodes[node_id] = node
        return node

    def _add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adj.setdefault(edge.src, []).append(edge)

    def _add_vector_edges(self) -> None:
        for v in self.matrix.get("vectors", []):
            title = v.get("title", {})
            label = title.get("zh") if isinstance(title, dict) else str(title)
            primitive = str(v.get("primitive", ""))
            requires = tuple(str(x) for x in v.get("requires", []))
            detect = v.get("detect") or {}
            detection = f"{detect.get('engine', '?')}:{detect.get('point', '')}"
            sources = v.get("sources") or []
            evidence = (sources[0].get("ref") if isinstance(sources[0], dict) else str(sources[0])) if sources else ""
            for e in v.get("edges", []):
                src, dst = str(e["from"]), str(e["to"])
                self._ensure_node(src)
                self._ensure_node(dst)
                weight = float(e.get("weight", 1.0))
                self._add_edge(Edge(
                    src=src, dst=dst, vector=str(v["id"]), vector_title=str(label or v["id"]),
                    primitive=primitive, requires=requires, evidence=str(evidence),
                    detection=detection, weight=weight, module=str(v.get("module", "")),
                    kind="attack",
                ))

    def _apply_snapshot(self, snapshot: dict | None) -> None:
        if not snapshot:
            return
        self.principals = infer_principals(snapshot, self.assets)
        for p in self.principals:
            self._ensure_node(p.id, label=p.id)
            if p.cluster_admin:
                continue
            for cap in p.capabilities:
                self._ensure_node(cap)
                self._add_edge(Edge(
                    src=p.id, dst=cap, vector=GRANT_VECTOR,
                    vector_title="当前 RBAC 授权",
                    primitive="快照中该主体已持有该权限（can-i/RoleBinding 推断）",
                    requires=(), evidence="; ".join(p.evidence[:3]),
                    detection="—", weight=0.3, module="", kind="grant",
                ))
        for asset in self.assets:
            aid = f"resource:asset:{asset.get('kind', 'asset')}/{asset.get('namespace', '')}/{asset.get('name', '')}"
            self._ensure_node(aid, label=f"{asset.get('product') or asset.get('name')}")
        if self.assets:
            self._ensure_node("resource:assets", label=f"assets.db ({len(self.assets)})")

    # ---- 查询
    def _adjacency(self) -> dict[str, list[Edge]]:
        out: dict[str, list[Edge]] = {}
        for e in self.edges:
            out.setdefault(e.src, []).append(e)
        for src in out:
            out[src].sort(key=lambda e: (e.weight, e.dst, e.vector))
        return out

    def resolve_start(self, from_principal: str) -> Node:
        raw = str(from_principal or "").strip()
        if not raw:
            raise UnknownPrincipal("起始主体为空")
        candidates = [raw]
        if not raw.startswith(("principal:", "cap:", "target:", "cloud:", "system:serviceaccount:", "user:", "group:")):
            candidates += [f"principal:{raw}", f"user:{raw}", f"group:{raw}"]
        for c in candidates:
            if c in self.nodes and self.nodes[c].kind in ("principal", "capability"):
                return self.nodes[c]
        # 后缀匹配：允许 --from esc-sa 或命名空间/名称简写
        suffix = raw.split(":")[-1]
        matches = [n for n in self.nodes.values()
                   if n.kind == "principal" and (n.id.endswith(":" + suffix) or n.label.endswith(":" + suffix))]
        if len(matches) == 1:
            return matches[0]
        suggestions = ", ".join(sorted({n.label for n in self.nodes.values() if n.kind == "principal"})[:8])
        extra = f"；候选示例: {suggestions}" if suggestions else ""
        raise UnknownPrincipal(f"未知起始主体「{raw}」：快照未推断出该主体或其权限{extra}")

    def resolve_target(self, to: str) -> Node:
        target = _TARGETS.get(str(to), str(to))
        if target not in self.nodes:
            raise UnknownTarget(f"未知提权目标「{to}」；可用目标: {sorted(k for k in _TARGETS)}")
        return self.nodes[target]

    def paths(self, from_principal: str, to: str = "cluster-admin", limit: int = 5,
              mode: str = "weight") -> list[PrivescPath]:
        """K 条最短简单路径；mode=weight（权重优先）/ hops（跳数优先）。"""
        if mode not in ("weight", "hops"):
            raise PrivescError("mode 必须是 weight 或 hops")
        start = self.resolve_start(from_principal)
        target = self.resolve_target(to)
        principal = next((p for p in self.principals if p.id == start.id), None)
        if principal is not None and principal.cluster_admin and target.id == "target:cluster-admin":
            return [PrivescPath((start,), ())]
        adj = self._adjacency()
        if start.id == target.id:
            return [PrivescPath((start,), ())]
        limit = max(1, int(limit))
        heap: list[tuple[float, int, float, int, tuple[str, ...], tuple[Edge, ...]]] = [
            (0.0, 0, 0.0, 0, (start.id,), ())
        ]
        results: list[PrivescPath] = []
        expansions = 0
        seq = 1
        while heap and len(results) < limit and expansions < 50000:
            cost, hops, weight_sum, _seq, node_ids, edges = heapq.heappop(heap)
            expansions += 1
            if node_ids[-1] == target.id:
                results.append(PrivescPath(tuple(self.nodes[n] for n in node_ids), edges))
                continue
            if hops >= self.max_depth:
                continue
            for e in adj.get(node_ids[-1], []):
                if e.dst in node_ids:
                    continue
                step = e.weight if mode == "weight" else 1.0
                heapq.heappush(heap, (
                    round(cost + step, 6), hops + 1, round(weight_sum + e.weight, 6), seq,
                    node_ids + (e.dst,), edges + (e,),
                ))
                seq += 1
        # 去重（同 vector 序列），保持稳定
        seen: set[tuple[str, ...]] = set()
        unique: list[PrivescPath] = []
        for p in results:
            key = tuple(p.vector_ids)
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        if mode == "hops":
            unique.sort(key=lambda p: (p.hops, p.weight, tuple(p.vector_ids)))
        else:
            unique.sort(key=lambda p: (p.weight, p.hops, tuple(p.vector_ids)))
        return unique[:limit]

    def shortest(self, from_principal: str, to: str = "cluster-admin",
                 mode: str = "weight") -> PrivescPath | None:
        paths = self.paths(from_principal, to=to, limit=1, mode=mode)
        return paths[0] if paths else None

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [e.to_dict() for e in sorted(self.edges, key=lambda e: (e.src, e.dst, e.vector))],
            "principals": [p.to_dict() for p in self.principals],
            "assets": len(self.assets),
        }

    def as_simple_graph(self) -> dict:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label}
                      for n in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [{"src": e.src, "dst": e.dst, "vector": e.vector,
                       "weight": e.weight, "kind": e.kind, "detection": e.detection}
                      for e in self.edges],
        }


# ---------------------------------------------------------------- 解释

def distinct_vectors(path: PrivescPath) -> list[str]:
    """按出现顺序去重向量 id（同一向量的多条图边只算一个原语步骤）。"""
    out: list[str] = []
    for e in path.edges:
        if e.vector not in out:
            out.append(e.vector)
    return out


def explain(path: PrivescPath, lang: str = "zh") -> str:
    """把路径翻译成人话：每步的原语、前置、证据与检测键。"""
    if lang == "en":
        head = (f"From {path.start.label} to {path.target.label}: "
                f"{path.hops} steps, weight {path.weight:g}")
    else:
        head = (f"从「{path.start.label}」到「{path.target.label}」："
                f"{path.hops} 步，权重 {path.weight:g}")
    lines = [head]
    if not path.edges:
        lines.append("主体已具备直接 cluster-admin 等价权限（快照显示直接绑定/通配符），无需再提权。"
                     if lang != "en" else
                     "The principal already holds cluster-admin-equivalent permissions; no escalation needed.")
        return "\n".join(lines)
    shown = 0
    last_vector = ""
    for e in path.edges:
        if e.vector == last_vector:
            continue  # 同一向量的后续图边（如既有绑定生效）不重复展开
        last_vector = e.vector
        shown += 1
        if e.vector == GRANT_VECTOR:
            lines.append(f"{shown}. 当前权限：{e.primitive}（{e.evidence}）")
            continue
        lines.append(f"{shown}. [{e.vector}] {e.vector_title}")
        lines.append(f"   原语：{e.primitive}")
        if e.requires:
            lines.append(f"   前置：{'；'.join(e.requires)}")
        lines.append(f"   证据：{e.evidence}")
        lines.append(f"   检测：{e.detection}")
    lines.append("结论：沿上述原语可到达目标；执行前需通过 ROE 级别、范围与备份闸门。"
                 if lang != "en" else
                 "Conclusion: the path reaches the target; runner ROE/scope/backup gates still apply.")
    return "\n".join(lines)


def render_path_mermaid(path: PrivescPath) -> str:
    """单条路径的 Mermaid 图（报告用）。"""
    lines = ["```mermaid", "flowchart LR"]
    ids: dict[str, str] = {}
    for idx, node in enumerate(path.nodes):
        nid = f"n{idx}"
        ids[node.id] = nid
        label = node.label.replace('"', "'")
        lines.append(f'    {nid}["{label}"]')
    for idx, edge in enumerate(path.edges):
        src, dst = ids.get(edge.src), ids.get(edge.dst)
        if not src or not dst:
            continue
        vec = "当前权限" if edge.vector == GRANT_VECTOR else edge.vector
        lines.append(f'    {src} -->|"{vec}"| {dst}')
    lines += [
        "    classDef principal fill:#eef,stroke:#557;",
        "    classDef capability fill:#efe,stroke:#575;",
        "    classDef target fill:#fee,stroke:#a55;",
    ]
    for idx, node in enumerate(path.nodes):
        cls = {"principal": "principal", "capability": "capability", "target": "target"}.get(node.kind)
        if cls:
            lines.append(f"    class n{idx} {cls};")
    lines.append("```")
    return "\n".join(lines)


# ---------------------------------------------------------------- 矩阵/报告渲染

def _category_label(matrix: dict, cat: str) -> str:
    meta = (matrix.get("categories") or {}).get(cat) or {}
    return str(meta.get("zh") or cat)


def matrix_summary(matrix: dict) -> dict:
    vectors = matrix.get("vectors", [])
    cats: dict[str, int] = {}
    nodes: set[str] = set()
    edges = 0
    for v in vectors:
        cats[v["category"]] = cats.get(v["category"], 0) + 1
        for e in v.get("edges", []):
            edges += 1
            nodes.add(e["from"])
            nodes.add(e["to"])
    return {
        "vectors": len(vectors),
        "categories": cats,
        "edges": edges,
        "nodes": len(nodes),
        "targets": sorted(n for n in nodes if n.startswith("target:")),
        "sources": sum(len(v.get("sources", [])) for v in vectors),
        "rules": len(vectors),
    }


def render_matrix_md(matrix: dict | None = None) -> str:
    """确定性生成 docs/PRIVESC-MATRIX.md（含「提权面」与「选择依据」）。"""
    m = matrix or load_matrix()
    s = matrix_summary(m)
    graph = PrivescGraph(m)
    canonical = graph.shortest("cap:pod-create", to="cluster-admin")
    lines = [
        "# Trident 全量提权矩阵（Privesc Matrix）",
        "",
        "> 本文件由 `trident privesc matrix --out docs/PRIVESC-MATRIX.md` 确定性生成；"
        "请改 `trident/core/data/privesc-matrix.json` 后重生成，勿手改。",
        "",
        "## 提权面",
        "",
        f"- 提权向量：**{s['vectors']}** 条（RBAC {s['categories'].get('rbac', 0)} / "
        f"工作负载 {s['categories'].get('workload', 0)} / 凭据 {s['categories'].get('credential', 0)} / "
        f"节点 {s['categories'].get('node', 0)} / 平台组件 {s['categories'].get('platform', 0)}）",
        f"- 提权图：**{s['nodes']}** 个节点 / **{s['edges']}** 条原语边；目标 {', '.join(s['targets'])}",
        f"- 检测覆盖：每向量 ≥1 条 Sigma/Falco 规则（共 {s['rules']} 条，紫队重放见 `trident privesc detections`）",
        f"- 来源：K8s 官方文档、MITRE ATT&CK、KubeHound/kube-hunter/Peirates/CDK、云厂商与平台组件文档"
        f"（共 {s['sources']} 条引用）",
        "",
        "### 提权路径图（规范示例）",
        "",
        "从「创建 Pod」能力到 cluster-admin 的最短路径（权重优先）：",
        "",
    ]
    if canonical:
        lines += render_path_mermaid(canonical).splitlines()
        lines += ["", explain(canonical), ""]
    else:
        lines += ["（当前矩阵未找到规范路径）", ""]
    lines += [
        "### 选择依据",
        "",
        "objective 在阶段③（提权）前自动调用 `paths(from, to='cluster-admin')`：",
        "",
        "1. 以证据快照推断当前主体与权限，生成 0.3 权重的「当前授权」边；",
        "2. 对攻击向量边按总权重做 K 条最短简单路径搜索（同权重按跳数少、再按向量 id 字典序稳定排序）；",
        "3. 首选路径要求每条边的模块均已在注册表登记；执行失败时按排序回退下一条路径；",
        "4. 选择理由、备选路径与每条边的检测键写入 objective 报告「提权面」章节。",
        "",
        "## 向量总表",
        "",
        "| ID | 类别 | 主体条件 | 所需权限 | 原语 | 节点影响 | 集群影响 | 云影响 | 模块 | 检测点 | 来源 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for v in m["vectors"]:
        def esc(x: Any) -> str:
            return str(x).replace("|", "\\|").replace("\n", " ").strip()
        sources = "; ".join(str(x.get("ref")) for x in v.get("sources", []))
        lines.append("| `{}` | {} | {} | {} | {} | {} | {} | {} | `{}` | {} | {} |".format(
            v["id"], _category_label(m, v["category"]), esc(v["subject"]),
            esc("；".join(v["requires"])), esc(v["primitive"]),
            esc(v["impact"]["node"]), esc(v["impact"]["cluster"]), esc(v["impact"]["cloud"]),
            v["module"], esc(v["detect"]["point"]), esc(sources),
        ))
    lines += ["", "## 逐向量详情", ""]
    for v in m["vectors"]:
        lines += [
            f"### `{v['id']}` — {v['title']['zh']}",
            "",
            f"- 类别：{_category_label(m, v['category'])}",
            f"- 主体条件：{v['subject']}",
            f"- 所需权限：{'；'.join(v['requires'])}",
            f"- 原语：{v['primitive']}",
            f"- 影响：节点={v['impact']['node']}；集群={v['impact']['cluster']}；云={v['impact']['cloud']}",
            f"- 检测点：{v['detect']['point']}（{v['detect']['engine']}）",
            f"- 模块键：`{v['module']}`",
            f"- 来源：{'；'.join(str(x['ref']) for x in v['sources'])}",
            "- 图边：" + "；".join("`%s → %s`" % (e["from"], e["to"]) for e in v["edges"]),
            "",
        ]
    lines += [
        "## 紫队检测覆盖",
        "",
        "运行 `trident privesc detections --out reports/rules-pack` 可导出每向量的 Sigma/Falco 规则、"
        "Kyverno 准入策略与 `coverage.json`；`trident rules generate` 会把提权规则包追加到主规则包。",
        "",
    ]
    return "\n".join(lines)


def render_privesc_section(matrix: dict | None = None, paths: list[PrivescPath] | None = None,
                           principal: str = "", rationale: str = "") -> list[str]:
    """报告「提权面」章节（路径图 + 选择依据 + 备选）。"""
    m = matrix or load_matrix()
    s = matrix_summary(m)
    chosen = paths[0] if paths else None
    lines = [
        "## 提权面",
        "",
        f"- 提权向量 {s['vectors']} 条；图节点 {s['nodes']} / 边 {s['edges']}；"
        f"目标 {', '.join(s['targets'])}",
        f"- 当前主体：`{principal or (chosen.start.id if chosen else '未提供')}`",
        "- 检测：每向量 ≥1 条 Sigma/Falco 规则，紫队重放结果见 `privesc/coverage.json`",
        "",
        "### 提权路径图",
        "",
    ]
    if chosen:
        lines += render_path_mermaid(chosen).splitlines()
        lines += ["", explain(chosen), ""]
    else:
        lines += ["（无可行提权路径；保持当前权限并转人工核验）", ""]
    lines += ["### 选择依据", ""]
    if rationale:
        lines.append(rationale)
    elif chosen:
        lines.append(
            f"按总权重优先选择：`{' → '.join(distinct_vectors(chosen))}`；"
            f"权重 {chosen.weight:g}，{chosen.hops} 步。"
            "同权重按跳数少优先；所有边模块均已在注册表登记；"
            "失败时按备选路径顺序回退。"
        )
    else:
        lines.append("无路径可选。")
    lines += ["", "### 备选路径", ""]
    if paths and len(paths) > 1:
        for i, p in enumerate(paths[1:], 1):
            lines.append(f"{i}. 权重 {p.weight:g} / {p.hops} 步：`{' → '.join(distinct_vectors(p))}`")
    else:
        lines.append("（无备选；或当前主体已是 cluster-admin）")
    lines.append("")
    return lines


# ---------------------------------------------------------------- assets/evidence 联动

def load_snapshot(source: dict | str | Path | None) -> dict:
    """snapshot 支持 dict / JSON 路径。"""
    if isinstance(source, dict):
        return source
    if source is None:
        raise PrivescError("缺少 snapshot（dict 或 JSON 文件路径）")
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _json_from_archive(path: Path) -> dict | None:
    """从 evidence 步骤归档（tar.gz/zst）中找快照 JSON。"""
    import io
    import tarfile

    try:
        if path.suffix == ".zst":
            import zstandard

            raw = zstandard.ZstdDecompressor().decompress(path.read_bytes())
            tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        else:
            tf = tarfile.open(path, mode="r:*")
    except Exception:
        return None
    try:
        for member in sorted(tf.getmembers(), key=lambda m: m.name):
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            try:
                doc = json.loads(tf.extractfile(member).read().decode("utf-8"))
            except Exception:
                continue
            if isinstance(doc, dict) and any(
                    k in doc for k in ("clusterroles", "cani", "pods", "serviceaccounts")):
                return doc
    finally:
        tf.close()
    return None


def _load_snapshot_artifact(run) -> dict | None:
    # 1) 模块主动落盘的 artifacts 目录（runner 常见路径）
    art_dir = run.dir / "artifacts"
    candidates = [
        art_dir / "snapshot.json",
        run.dir / "snapshot.json",
        art_dir / "cluster-snapshot.json",
    ]
    for p in candidates:
        if p.is_file():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if isinstance(doc, dict):
                return doc
    if art_dir.is_dir():
        for p in sorted(art_dir.glob("*.json")):
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if isinstance(doc, dict) and any(
                    k in doc for k in ("clusterroles", "cani", "pods", "serviceaccounts")):
                return doc
    # 2) evidence 三层归档（steps/*.tar.gz|zst）：真实 collect_snapshot 走这里
    rows = run.query("SELECT step_key, archive FROM steps ORDER BY id DESC")
    for _step, rel in rows:
        p = run.dir / str(rel)
        if not p.is_file():
            continue
        doc = _json_from_archive(p)
        if doc is not None:
            return doc
    return None


def load_snapshot_from_evidence(store, run_name: str) -> dict:
    """从 EvidenceStore 的 artifacts/归档读取快照，并附加 assets.db 资产。"""
    run = store.open_run(run_name)
    snapshot = _load_snapshot_artifact(run)
    if snapshot is None:
        raise FileNotFoundError(
            f"run {run_name} 的 artifacts/步骤归档未找到集群快照（snapshot.json / cluster-snapshot.json）")
    snapshot = dict(snapshot)
    # assets.db 联动：只读资产清单，不改变 RBAC 推断结论
    try:
        from .discovery import AssetInventory

        assets = AssetInventory(store).list()
        if assets:
            snapshot["assets"] = assets
    except Exception:  # assets.db 不存在/未初始化不阻断提权推断
        pass
    snapshot.setdefault("_evidence", {"run": run_name, "artifact": "snapshot.json"})
    return snapshot


def paths_from_evidence(store, run_name: str, from_principal: str,
                        to: str = "cluster-admin", limit: int = 5,
                        mode: str = "weight", matrix: dict | None = None) -> list[PrivescPath]:
    snapshot = load_snapshot_from_evidence(store, run_name)
    graph = PrivescGraph(matrix or load_matrix(), snapshot=snapshot)
    return graph.paths(from_principal, to=to, limit=limit, mode=mode)
