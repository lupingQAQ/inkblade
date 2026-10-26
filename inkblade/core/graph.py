"""可达性图数据模型：七层网络 + 判定方式标注（设计基线 5.6 设计约束一）。

任何「网络可达」结论必须注明层级与判定方式；不把「有 NetworkPolicy」等同
于「隔离有效」。
"""

from __future__ import annotations

from dataclasses import dataclass

# 七层网络模型（名称即标识，禁编号）
LAYERS = (
    "物理 Fabric 层",
    "主机网络层",
    "CNI 与 Overlay 层",
    "服务与网关层",
    "集合通信层",
    "存储数据面层",
    "云与混合边界层",
)

# 判定方式枚举
METHODS = (
    "静态策略推演",
    "配置证据",
    "主动实测",
    "人工核验",
)

# 五维可达矩阵维度（键固定）
DIMENSIONS = (
    "pod 到 pod",
    "pod 到宿主",
    "pod 到 IB",
    "pod 到元数据",
    "跨集群",
)

# 目标节点类型 → 矩阵维度；未列出的类型按层回退（见 _dimension_of）
_KIND_DIMENSIONS = {
    "pod": "pod 到 pod",
    "宿主": "pod 到宿主",
    "节点": "pod 到宿主",
    "SR-IOV 网络": "pod 到 IB",
    "IB 网络": "pod 到 IB",
    "RDMA 网络": "pod 到 IB",
    "旁路网络": "pod 到 IB",
    "云元数据": "pod 到元数据",
    "IMDS": "pod 到元数据",
    "远端集群": "跨集群",
    "云内网段": "跨集群",
}

_LAYER_FALLBACK = {
    "主机网络层": "pod 到宿主",
    "物理 Fabric 层": "pod 到 IB",
    "集合通信层": "pod 到 IB",
    "云与混合边界层": "跨集群",
}


@dataclass
class Node:
    node_id: str
    kind: str
    layer: str

    def to_dict(self) -> dict:
        return {"node_id": self.node_id, "kind": self.kind, "layer": self.layer}


@dataclass
class Edge:
    src: str
    dst: str
    verdict: str
    method: str

    def to_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "verdict": self.verdict, "method": self.method}


def _dimension_of(dst: Node) -> str:
    if dst.kind in _KIND_DIMENSIONS:
        return _KIND_DIMENSIONS[dst.kind]
    return _LAYER_FALLBACK.get(dst.layer, "pod 到 pod")


class Graph:
    """可达性图：节点（类型+层级）与边（结论+判定方式）。"""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []

    # ---------- 构造 ----------
    def add_node(self, node_id: str, kind: str, layer: str) -> Node:
        if layer not in LAYERS:
            raise ValueError(f"未知网络层：{layer!r}（须为七层之一）")
        node = Node(node_id=node_id, kind=kind, layer=layer)
        self._nodes[node_id] = node  # 幂等：同 id 重复添加即覆盖
        return node

    def add_edge(self, src: str, dst: str, verdict: str, method: str) -> Edge:
        if method not in METHODS:
            raise ValueError(f"未知判定方式：{method!r}（须为四种枚举之一）")
        for nid in (src, dst):
            if nid not in self._nodes:
                raise ValueError(f"边引用了未定义节点：{nid!r}")
        edge = Edge(src=src, dst=dst, verdict=verdict, method=method)
        self._edges.append(edge)
        return edge

    # ---------- 查询 ----------
    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges)

    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def reachable(self, a: str, b: str) -> Edge | None:
        """直达边查询：返回 a→b 的第一条边，无则 None。"""
        for e in self._edges:
            if e.src == a and e.dst == b:
                return e
        return None

    # ---------- 呈现 ----------
    def render_matrix(self) -> dict[str, list[dict]]:
        """五维可达矩阵：每维一组 {src,dst,kind,verdict,method}；空维度保留键。"""
        matrix: dict[str, list[dict]] = {dim: [] for dim in DIMENSIONS}
        for e in self._edges:
            dst = self._nodes[e.dst]
            matrix[_dimension_of(dst)].append(
                {
                    "src": e.src,
                    "dst": e.dst,
                    "kind": dst.kind,
                    "layer": dst.layer,
                    "verdict": e.verdict,
                    "method": e.method,
                }
            )
        return matrix
