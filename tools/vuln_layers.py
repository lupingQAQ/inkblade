"""Layer assignment shared by the document and demo builders.

The registry has 152 rows.  Each row belongs to exactly one of the ten layers
used by docs/VULNERABILITY-LAYERS.md.  Assignment is intentionally explicit
for cross-cutting items and keyword-based for the long tail of static AST
rules.
"""

from __future__ import annotations

LAYER_TITLES = {
    1: "架构层：万卡拓扑、PD 分离与 KV 生命周期",
    2: "产品与框架层：十八个栈的默认面",
    3: "组件与 Operator 层：发牌的人",
    4: "网络与 fabric 层：策略管不到的地方",
    5: "数据与权重层：训练状态的信任链",
    6: "租户与隔离层：分区不等于清零",
    7: "供应链与身份层：加载即执行",
    8: "缓存安全层：命中就是泄露",
    9: "跨组合层：单看都合规",
    10: "防护绕过层：看得见与看不见",
}

LAYER_SHORT = {
    1: "架构/PD/KV",
    2: "产品框架",
    3: "Operator/节点",
    4: "网络 fabric",
    5: "数据权重",
    6: "GPU 租户",
    7: "供应链身份",
    8: "缓存",
    9: "组合",
    10: "防护绕过",
}

_L1 = {
    "NCCL-NCCLPLUGIN-HW", "UCX-UCT-HW", "ucxpy-server-py-pickle-loads-l42-regex",
    "CVE-2026-92972", "CVE-2026-3059", "CVE-2026-3060", "CVE-2025-29783",
    "CVE-2025-32444", "CVE-2025-47277", "CVE-2026-7301",
}
_L6 = {
    "HAMI-ADV-2026-01", "CGPU-ADV-2026-01", "CVE-2024-0132", "CVE-2024-0133",
    "CVE-2025-23266", "CVE-2025-23267",
}
_L8 = {"CVE-2025-59425", "CVE-2026-15978"}
_L9 = {
    "KUBERAY-ADV-2026-01", "LWS-ADV-2026-01",
    "dradriver-process-go-exec-command-l94-regex",
    "gpuoperator-0500-daemonset-yaml-elevated-pod-spec-l108-regex",
    "gpuoperator-main-go-exec-command-l669-regex",
}
_L10 = {
    "cephcsi-httpserver-go-pprof-exposed-l37-regex",
    "juicefscsi-controller-manager-go-go-bind-all-l71-regex",
    "kueue-server-go-pprof-exposed-l30-regex",
    "volcano-scheduler-server-go-pprof-exposed-l162-regex",
    "GHSA-h26v-922j-28cg", "CVE-2025-23374",
}
_L4_COMPONENTS = {"cumulus", "sonic", "sonicrestapi"}
_L3_COMPONENTS = {"bmc", "runc", "containerd", "linux-kernel", "cephcsi",
                  "juicefscsi", "kueue", "volcano"}
_L5_MARKERS = ("checkpoint", "dataset-pickle", "torch-load", "mlflow-model")
_L7_MARKERS = ("trust", "revision", "loader")


def layer_for_id(cid: str, component: str = "", module: str = "") -> int:
    if cid in _L1:
        return 1
    if cid in _L6:
        return 6
    if cid in _L8:
        return 8
    if cid in _L9:
        return 9
    if cid in _L10:
        return 10
    if component in _L4_COMPONENTS:
        return 4
    if component in _L3_COMPONENTS:
        return 3
    if component == "pytorch" or any(m in (module or "") for m in _L5_MARKERS):
        return 5
    if (cid == "LITELLM-DEFAULT-KEY" or component == "wandb"
            or component == "transformers"
            or any(m in (module or "") for m in _L7_MARKERS)
            or any(m in cid for m in _L7_MARKERS)):
        return 7
    return 2


def layer_for_entry(entry: dict) -> int:
    return layer_for_id(entry.get("id", ""), entry.get("component", ""),
                        entry.get("module", "") or "")
