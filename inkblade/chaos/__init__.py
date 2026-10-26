"""混沌/扰动鲁棒编排：实验目录 + 运行时 + 编排器。

对齐 Chaos Mesh / Litmus / Chaos Toolkit 的核心抽象（稳态假设 → 注入 → 中止
条件 → 自动回滚 → 度量），并把「ML 训练/推理面」的独有实验（训练步时退化、
KV 命中率、梯度噪声阈值、PFC 风暴联动 fabric-sim、GPU Xid 注入、NCCL 慢
rank）补成三大通用混沌工具没有的目录，详见 docs/CHAOS-PARITY.md。

边界声明：所有注入都只作用于本地 mock/仿真靶场（fabric-dos-sim /
fabric-sim / longctx-sim / mock-targets / FaultProxy），绝不对真实集群或
真实 GPU/交换机执行破坏动作；真实集群编排需要部署对应 injector（文档中
显式列为未达成）。
"""

from .catalog import (
    EXPERIMENTS,
    Action,
    ChaosExperiment,
    Probe,
    experiment_by_id,
    list_experiments,
)
from .errors import (
    ChaosAbortSignalled,
    ChaosError,
    ChaosRollbackError,
    ChaosSteadyStateError,
)
from .orchestrator import ChaosOrchestrator, abort_active_run, active_abort_file

__all__ = [
    "EXPERIMENTS",
    "Action",
    "ChaosExperiment",
    "Probe",
    "ChaosError",
    "ChaosAbortSignalled",
    "ChaosSteadyStateError",
    "ChaosRollbackError",
    "ChaosOrchestrator",
    "abort_active_run",
    "active_abort_file",
    "experiment_by_id",
    "list_experiments",
]
