"""CNI 语义感知可达性推演：规则按设计基线 5.6 约束，默认静态推演/配置证据。

规则（设计基线 5.6）：
  一、hostNetwork Pod → 任意节点面：可达（配置证据）
  二、SR-IOV/IB 附件存在 且 NetworkPolicy 覆盖 → 旁路边（配置证据）
  三、VPC-native CNI 且安全组缺口 → 云内横向（静态策略推演）
  四、IB 无 Partition → 集合通信可达（静态策略推演）

主动实测仅在主动探测/利用验证级别且授权下执行（本模块不发起任何网络请求）。
持久化复用 evidence.Run 的 graph_nodes/graph_edges 表（run 为可选参数）。
"""

from __future__ import annotations

from .graph import DIMENSIONS, Graph

MATRIX_DIMENSIONS = DIMENSIONS

_SOURCE_NODE = "workload-pod"


def infer(fingerprints: dict, run=None) -> Graph:
    """由侦察指纹推演可达性图；传入 run 则同时落库。"""
    g = Graph()
    g.add_node(_SOURCE_NODE, "pod", "CNI 与 Overlay 层")

    fp = {k: v for k, v in fingerprints.items() if v is True}

    # 规则一：hostNetwork Pod 绕过 CNI 与 NetworkPolicy，直抵任意节点面
    if "hostnetwork-pod" in fp:
        g.add_node("node-plane", "宿主", "主机网络层")
        g.add_edge(_SOURCE_NODE, "node-plane", "可达", "配置证据")

    # 规则二：SR-IOV/IB 附件流量不受 NetworkPolicy 约束 → 即使策略覆盖也是旁路边
    if "network-policy-coverage" in fp:
        if "sriov-attachment" in fp:
            g.add_node("sriov-network", "SR-IOV 网络", "CNI 与 Overlay 层")
            g.add_edge(_SOURCE_NODE, "sriov-network", "旁路", "配置证据")
        if "ib-attachment" in fp:
            g.add_node("ib-fabric", "IB 网络", "物理 Fabric 层")
            g.add_edge(_SOURCE_NODE, "ib-fabric", "旁路", "配置证据")

    # 规则三：VPC-native CNI 与安全组是两套控制面，安全组缺口即云内横向
    if "vpc-native-cni" in fp and "security-group-gap" in fp:
        g.add_node("cloud-intranet", "云内网段", "云与混合边界层")
        g.add_edge(_SOURCE_NODE, "cloud-intranet", "可达", "静态策略推演")

    # 规则四：IB 无 Partition 时集合通信无隔离（无内建认证）
    if "ib-fabric" in fp and "ib-partition" not in fp:
        g.add_node("collective-endpoint", "集合通信端点", "集合通信层")
        g.add_edge(_SOURCE_NODE, "collective-endpoint", "可达", "静态策略推演")

    if run is not None:
        persist(g, run)
    return g


def persist(g: Graph, run) -> None:
    """写入 evidence.Run 的 graph_nodes/graph_edges 表。"""
    for n in g.nodes:
        run.upsert_node(n.node_id, n.kind, n.layer)
    for e in g.edges:
        run.add_edge(e.src, e.dst, e.verdict, e.method)


def load_graph(run) -> Graph:
    """从 graph_nodes/graph_edges 表读回可达性图。"""
    g = Graph()
    for row in run.query("SELECT node_id, kind, layer FROM graph_nodes"):
        g.add_node(row[0], row[1], row[2])
    for row in run.query("SELECT src, dst, verdict, method FROM graph_edges"):
        g.add_edge(row[0], row[1], row[2], row[3])
    return g
