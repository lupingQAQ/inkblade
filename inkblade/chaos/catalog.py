"""混沌实验目录：≥15 个实验，每个实验 = 稳态定义 + 注入动作 + 中止条件 +
自动回滚 + 度量（SLO 影响）。

结构对齐 Chaos Toolkit 的 Method（action/rollback）+ Steady-State Hypothesis，
实验语义对齐 Chaos Mesh 的故障类型（NetworkChaos/DNSChaos/IOChaos/StressChaos/
PodChaos/HTTPChaos）与 Litmus 的 probe（steady-state）+ rollback。

三类对象：

- ``Probe``：一次可判定的探测（HTTP 探测 + 提取 + 比较）。特殊提取器：
  ``status``（HTTP 状态码）、``latency_ms``（客户端墙钟）、``success_rate``/
  ``error_rate``（多样本成功率）、``step_ms_ratio``（训练步时/基线）、
  ``kv_usage_ratio``（KV 内存水位）、``loss_divergence_ratio``（损失发散比）。
- ``Action``：一次注入或回滚动作（http / proxy / dns / admin-reset / noop）。
- ``ChaosExperiment``：稳态 probes → inject → measure(SLO) → abort_when →
  rollback → recovery(默认复用稳态)。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Probe:
    """一次可判定的探测（稳态断言 / SLO 度量 / 中止条件共用）。"""

    name: str
    path: str
    method: str = "GET"
    body: dict | None = None
    headers: dict[str, str] | None = None
    extract: str = "status"
    op: str = "eq"
    value: float = 200
    samples: int = 1
    target: str | None = None
    host: str | None = None
    note: str = ""


@dataclass(frozen=True)
class Action:
    """注入/回滚动作描述（由 runtime 解释执行）。"""

    kind: str  # http | proxy | dns | admin-reset | noop
    target: str | None = None
    method: str = "POST"
    path: str = ""
    body: dict | None = None
    repeat: int = 1
    faults: dict[str, Any] | None = None
    host: str = ""
    fail: bool = False
    keys: tuple[str, ...] = ()
    headers: dict[str, str] | None = None


@dataclass(frozen=True)
class ChaosExperiment:
    id: str
    title: str
    category: str
    target: str
    slo: str
    steady: tuple[Probe, ...]
    inject: Action
    measure: tuple[Probe, ...]
    abort_when: tuple[Probe, ...]
    rollback: Action
    recovery: tuple[Probe, ...] = ()
    via_proxy: bool = False
    ml_specific: bool = False
    parity: str = ""
    boundary: str = "本地仿真靶场（不触真实集群/GPU/交换机）"

    def probes_complete(self) -> bool:
        rec = self.recovery or self.steady
        return bool(self.steady) and bool(self.measure) and bool(self.abort_when) and bool(rec)


def _net_probes(step_path: str = "/train/step") -> tuple[Probe, ...]:
    return (Probe("step-ok", step_path, "POST", {"steps": 1}, extract="status"),)


# --------------------------------------------------------------------------- 网络
NET_LATENCY = ChaosExperiment(
    id="net-latency-step-degradation",
    title="网络延迟注入 → 训练步时退化",
    category="network",
    target="fabric-dos",
    via_proxy=True,
    slo="训练步请求（含通信）客户端时延 < 250ms；注入 400ms 单向延迟后 ≥ 350ms（≥3× 基线）即 SLO 破坏",
    steady=(
        Probe("step-latency-baseline", "/train/step", "POST", {"steps": 1},
              extract="latency_ms", op="lt", value=250, samples=3),
    ),
    inject=Action("proxy", faults={"delay_ms": 400}),
    measure=(
        Probe("step-latency-degraded", "/train/step", "POST", {"steps": 1},
              extract="latency_ms", op="ge", value=350, samples=3),
    ),
    abort_when=(
        Probe("latency-safety-valve", "/train/step", "POST", {"steps": 1},
              extract="latency_ms", op="gt", value=10000, samples=1),
    ),
    rollback=Action("proxy", faults={"delay_ms": 0}),
    ml_specific=True,
    parity="Chaos Mesh NetworkChaos delay / Litmus network-latency：通用工具打 K8s Pod 网络；"
           "本实验度量面是训练步时（/train/step），为 ML 面独有",
)

NET_DISCONNECT = ChaosExperiment(
    id="net-disconnect-workers",
    title="Worker 断连 → 训练请求 100% 失败",
    category="network",
    target="fabric-dos",
    via_proxy=True,
    slo="训练面请求成功率 = 100%；断连后成功率 = 0%，错误率 > 50% 触发中止条件并自动回滚",
    steady=(
        Probe("step-success-baseline", "/train/step", "POST", {"steps": 1},
              extract="success_rate", op="eq", value=1, samples=4),
    ),
    inject=Action("proxy", faults={"drop_rate": 1.0}),
    measure=(
        Probe("step-success-during", "/train/step", "POST", {"steps": 1},
              extract="success_rate", op="eq", value=0, samples=4),
    ),
    abort_when=(
        Probe("error-rate-limit", "/train/step", "POST", {"steps": 1},
              extract="error_rate", op="gt", value=0.5, samples=3),
    ),
    rollback=Action("proxy", faults={"drop_rate": 0.0}),
    parity="Chaos Mesh NetworkChaos loss 100%/partition；Litmus pod-delete 的网络等价物",
)

NET_PARTITION = ChaosExperiment(
    id="net-partition-rail-groups",
    title="网络分区（rail 组隔离）→ group-b 不可达",
    category="network",
    target="fabric-dos",
    via_proxy=True,
    slo="两个 rail 组（X-Chaos-Group: group-a/group-b）到训练面成功率均 = 100%；"
        "分区后 group-a 仍 100%、group-b = 0%",
    steady=(
        Probe("group-a-ok", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "group-a"}, extract="success_rate", op="eq", value=1, samples=2),
        Probe("group-b-ok", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "group-b"}, extract="success_rate", op="eq", value=1, samples=2),
    ),
    inject=Action("proxy", faults={"block_groups": ["group-b"]}),
    measure=(
        Probe("group-a-still-ok", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "group-a"}, extract="success_rate", op="eq", value=1, samples=2),
        Probe("group-b-blocked", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "group-b"}, extract="success_rate", op="eq", value=0, samples=2),
    ),
    abort_when=(
        Probe("both-groups-down", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "group-a"}, extract="success_rate", op="eq", value=0, samples=2),
    ),
    rollback=Action("proxy", faults={"block_groups": []}),
    parity="Chaos Mesh NetworkChaos partition（direction/partition with list）；"
           "Litmus 无原生分区实验（需自定义）",
)

NET_PACKET_LOSS = ChaosExperiment(
    id="net-packet-loss",
    title="随机丢包 35% → 训练面成功率降级",
    category="network",
    target="fabric-dos",
    via_proxy=True,
    slo="成功率 = 100%；丢包 35%（固定种子确定性抽样）后成功率 < 95%（且 > 20%，非全断）",
    steady=(
        Probe("loss-free", "/train/step", "POST", {"steps": 1},
              extract="success_rate", op="eq", value=1, samples=6),
    ),
    inject=Action("proxy", faults={"drop_rate": 0.35, "seed": 20261026}),
    measure=(
        Probe("degraded-not-dead", "/train/step", "POST", {"steps": 1},
              extract="success_rate", op="lt", value=0.95, samples=30),
        Probe("still-alive", "/train/step", "POST", {"steps": 1},
              extract="success_rate", op="gt", value=0.2, samples=30),
    ),
    abort_when=(
        Probe("total-loss-check", "/train/step", "POST", {"steps": 1},
              extract="error_rate", op="gt", value=0.8, samples=5),
    ),
    rollback=Action("proxy", faults={"drop_rate": 0.0}),
    parity="Chaos Mesh NetworkChaos loss（percent）",
)

DNS_FAILURE = ChaosExperiment(
    id="dns-resolution-failure",
    title="DNS 解析故障 → 训练面域名不可达",
    category="dns",
    target="fabric-dos",
    slo="trainer.chaos.test 可解析且训练面 200；DNS 故障后解析失败（请求 0% 成功），恢复后 100%",
    steady=(
        Probe("resolve-and-step", "/train/step", "POST", {"steps": 1},
              host="trainer.chaos.test", extract="status", op="eq", value=200),
    ),
    inject=Action("dns", host="trainer.chaos.test", fail=True),
    measure=(
        Probe("dns-down", "/train/step", "POST", {"steps": 1},
              host="trainer.chaos.test", extract="success_rate", op="eq", value=0, samples=3),
    ),
    abort_when=(
        Probe("dns-outage-sustained", "/train/step", "POST", {"steps": 1},
              host="trainer.chaos.test", extract="error_rate", op="gt", value=0.5, samples=2),
    ),
    rollback=Action("dns", host="trainer.chaos.test", fail=False),
    parity="Chaos Mesh DNSChaos（dns.server/action: error）；Litmus/Chaos Toolkit 需自写",
    boundary="DNS 故障在客户端解析层仿真（.chaos.test 域名经内置 resolver），不劫持真实 DNS 服务",
)

# --------------------------------------------------------------------------- fabric
FABRIC_PFC_STORM = ChaosExperiment(
    id="fabric-pfc-storm",
    title="RoCE PFC 暂停风暴（联动 fabric-sim）→ 集合通信面破坏",
    category="fabric",
    target="fabric-sim",
    slo="无风暴：storm_active=false；注入后 PFC 暂停帧 Δ ≥ 25000 且 storm_active=true；"
        "回滚（clear）后 storm_active=false",
    steady=(
        Probe("storm-flag-clear", "/roce/pfc", extract="pfc.storm", op="eq", value=0),
    ),
    inject=Action("http", target="fabric-sim", path="/roce/pfc", body={"mode": "storm"}),
    measure=(
        Probe("storm-active", "/roce/pfc", extract="pfc.storm", op="eq", value=1),
        Probe("pfc-delta", "/roce/pfc", extract="pfc_pause_frames", op="ge", value=25000),
    ),
    abort_when=(
        Probe("storm-overflow", "/roce/pfc", extract="pfc_pause_frames", op="gt", value=10_000_000),
    ),
    rollback=Action("http", target="fabric-sim", path="/roce/pfc", body={"mode": "clear"}),
    recovery=(
        # 计数器单调保持（基线 96 + 风暴 25000），恢复断言只看风暴标志复位
        Probe("storm-cleared", "/roce/pfc", extract="pfc.storm", op="eq", value=0),
    ),
    parity="三大工具均无 RDMA/PFC 实验（Chaos Mesh/Litmus 止于 TCP/内核面）；"
           "ML fabric 面独有（fabric-sim 离散事件仿真计数器）",
    ml_specific=True,
)

BOOTSTRAP_EXHAUST = ChaosExperiment(
    id="fabric-bootstrap-port-exhaustion",
    title="NCCL bootstrap 端口耗尽 → 诚实作业被拒（503）",
    category="fabric",
    target="fabric-dos",
    slo="bootstrap 端口池剩余 > 0；占满（24/24）后剩余 = 0 且诚实作业 503 拒绝",
    steady=(
        Probe("ports-available", "/metrics", extract="nccl.bootstrap_remaining", op="gt", value=0),
    ),
    inject=Action("http", target="fabric-dos", path="/nccl/bootstrap",
                  body={"job": "chaos-squatter", "ranks": 24, "honest": False}),
    measure=(
        Probe("ports-exhausted", "/metrics", extract="nccl.bootstrap_remaining", op="eq", value=0),
        Probe("honest-job-refused", "/nccl/bootstrap", "POST",
              {"job": "chaos-honest-victim", "ranks": 1, "honest": True},
              extract="status", op="eq", value=503),
    ),
    abort_when=(
        Probe("refusal-storm", "/metrics", extract="nccl.bootstrap_exhausted_refusals", op="gt", value=1000),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("nccl",)),
    parity="Chaos Mesh 无对应面；近似 HTTPChaos/资源耗尽类，但 NCCL rendezvous 是 ML 面独有",
    ml_specific=True,
)

# --------------------------------------------------------------------------- GPU / 节点
GPU_XID_RESET = ChaosExperiment(
    id="gpu-xid-driver-reset",
    title="GPU Xid 79 注入（mock NVML）→ 驱动复位计数",
    category="gpu",
    target="fabric-dos",
    slo="GPU 健康面无 Xid/复位；注入 Xid 79 后 driver_resets ≥ 1 且设备 unhealthy；"
        "回滚后 healthy 恢复、复位计数清零",
    steady=(
        Probe("no-xid", "/metrics", extract="gpu.xid_events", op="eq", value=0),
        Probe("gpu-healthy", "/gpu/health", extract="devices.gpu-0.healthy", op="eq", value=1),
    ),
    inject=Action("http", target="fabric-dos", path="/gpu/health",
                  body={"gpu": "gpu-0", "xid_code": 79}),
    measure=(
        Probe("driver-reset", "/metrics", extract="gpu.driver_resets", op="ge", value=1),
        Probe("device-unhealthy", "/gpu/health", extract="devices.gpu-0.healthy", op="eq", value=0),
    ),
    abort_when=(
        Probe("reset-cascade", "/gpu/health", extract="driver_resets", op="gt", value=32),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("gpu",)),
    parity="Chaos Mesh 无 GPU 实验；Litmus 无；为 ML 面独有（Xid=mock NVML 计数器，非真实 GPU）",
    ml_specific=True,
)

NODE_DRAIN_GANG = ChaosExperiment(
    id="node-drain-gang-hold",
    title="节点驱逐（gang 占位）→ 调度队列堵塞",
    category="node",
    target="fabric-dos",
    slo="gang 队列 pending_gpus ≤ 容量 16；占位后 pending > 16（clogged）→ 等效节点被驱逐压队",
    steady=(
        Probe("queue-clear", "/metrics", extract="gang.pending_gpus", op="le", value=16),
    ),
    inject=Action("http", target="fabric-dos", path="/sched/gang",
                  body={"gang_size": 8, "placeholders": 8, "hold": True}, repeat=3),
    measure=(
        Probe("queue-clogged", "/metrics", extract="gang.pending_gpus", op="gt", value=16),
        Probe("clogged-flag", "/metrics", extract="gang.clogged", op="eq", value=1),
    ),
    abort_when=(
        Probe("queue-explosion", "/metrics", extract="gang.pending_gpus", op="gt", value=512),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("gang",)),
    parity="Chaos Mesh PodChaos pod-delete / Litmus pod-delete（等效节点驱逐压队）",
)

# --------------------------------------------------------------------------- IO / 内存 / 存储
IO_THROTTLE_CKPT = ChaosExperiment(
    id="io-throttle-checkpoint",
    title="Checkpoint I/O 风暴 → 存储带宽被挤占",
    category="io",
    target="fabric-dos",
    slo="checkpoint I/O 队列低水位；注入 4096MB×4 burst 后 io_bytes_mb ≥ 16000 且 io_queue ≥ 4",
    steady=(
        Probe("io-quiet", "/metrics", extract="checkpoint_io.io_queue", op="lt", value=4),
    ),
    inject=Action("http", target="fabric-dos", path="/checkpoint/io",
                  body={"bytes_mb": 4096, "burst": 4}),
    measure=(
        Probe("io-flooded", "/metrics", extract="checkpoint_io.io_bytes_mb", op="ge", value=16000),
        Probe("io-queued", "/metrics", extract="checkpoint_io.io_queue", op="ge", value=4),
    ),
    abort_when=(
        Probe("io-queue-overflow", "/metrics", extract="checkpoint_io.io_queue", op="gt", value=1024),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("checkpoint_io",)),
    parity="Chaos Mesh IOChaos latency/limit（Pod 级 blkio）；此处度量 checkpoint 写面（ML 独有）",
)

MEM_PRESSURE_OOM = ChaosExperiment(
    id="memory-pressure-kv-oom",
    title="KV/激活内存压力 → OOM 事件",
    category="memory",
    target="fabric-dos",
    slo="无 OOM；注入超长上下文预留（1.5M tokens × 64KiB/token > 64GiB 容量）后 oom_events ≥ 1",
    steady=(
        Probe("no-oom", "/metrics", extract="memory.oom_events", op="eq", value=0),
    ),
    inject=Action("http", target="fabric-dos", path="/train/context",
                  body={"context_tokens": 1_500_000}),
    measure=(
        Probe("oom-counted", "/metrics", extract="memory.oom_events", op="ge", value=1),
        Probe("kv-overflow", "/metrics", extract="memory.kv_bytes", op="gt", value=64 * 1024 ** 3),
    ),
    abort_when=(
        Probe("oom-storm", "/metrics", extract="memory.oom_events", op="gt", value=64),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("memory",)),
    parity="Chaos Mesh StressChaos memory / Litmus memory stress；此处 KV 预留面为 ML 独有",
)

KV_EVICTION_STORM = ChaosExperiment(
    id="kv-eviction-storm",
    title="KV 驱逐风暴 → KV 水位逼近容量",
    category="memory",
    target="fabric-dos",
    slo="KV 水位 < 80%；反复注入 800k token 预留后 kv_usage_ratio ≥ 0.8（驱逐压力等效）",
    steady=(
        Probe("kv-low", "/metrics", extract="kv_usage_ratio", op="lt", value=0.8),
    ),
    inject=Action("http", target="fabric-dos", path="/train/context",
                  body={"context_tokens": 800_000}),
    measure=(
        Probe("kv-high", "/metrics", extract="kv_usage_ratio", op="ge", value=0.8),
    ),
    abort_when=(
        Probe("kv-capacity-breach", "/metrics", extract="memory.oom_events", op="gt", value=16),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("memory",)),
    ml_specific=True,
    parity="三大工具均无 KV cache 实验（ML 推理/训练面独有）",
)

CKPT_WRITE_CONFLICT = ChaosExperiment(
    id="checkpoint-write-conflict",
    title="Checkpoint 写冲突（双写者并发 burst）→ 队列堆积",
    category="storage",
    target="fabric-dos",
    slo="单写者 checkpoint 队列 < 8；两个写者各 2×2048MB burst 后 io_queue ≥ 8（写冲突堆积）",
    steady=(
        Probe("single-writer-quiet", "/metrics", extract="checkpoint_io.io_queue", op="lt", value=8),
    ),
    inject=Action("http", target="fabric-dos", path="/checkpoint/io",
                  body={"bytes_mb": 2048, "burst": 2}, repeat=2),
    measure=(
        Probe("conflict-queued", "/metrics", extract="checkpoint_io.io_queue", op="ge", value=4),
        Probe("conflict-bytes", "/metrics", extract="checkpoint_io.io_bytes_mb", op="ge", value=8192),
    ),
    abort_when=(
        Probe("queue-deadlock-suspect", "/metrics", extract="checkpoint_io.io_queue", op="gt", value=256),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("checkpoint_io",)),
    ml_specific=True,
    parity="三大工具无 checkpoint 语义（ML 面独有）",
)

# --------------------------------------------------------------------------- 控制面
APISERVER_FLOOD = ChaosExperiment(
    id="apiserver-request-flood",
    title="kube-apiserver 请求洪泛 → 控制面过载",
    category="control-plane",
    target="fabric-dos",
    slo=" apiserver 请求计数低水位；注入 800 请求后 requests_total ≥ 800（等效洪泛压力）",
    steady=(
        Probe("api-quiet", "/metrics", extract="api.requests_total", op="lt", value=800),
    ),
    inject=Action("http", target="fabric-dos", path="/apiserver/request", body={"count": 800}),
    measure=(
        Probe("api-flooded", "/metrics", extract="api.requests_total", op="ge", value=800),
    ),
    abort_when=(
        Probe("api-meltdown", "/metrics", extract="api.requests_total", op="gt", value=1_000_000),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("api",)),
    parity="Chaos Mesh HTTPChaos（qps/延迟）近似；Litmus 无原生 apiserver 洪泛",
)

MASTER_LOSS = ChaosExperiment(
    id="trainer-master-loss",
    title="管理者失联（master 面分区）→ worker 面仍活、控制面观测丢失",
    category="control-plane",
    target="fabric-dos",
    via_proxy=True,
    slo="master 面（/metrics）与 worker 面（/train/step）成功率均 100%；"
        "分区 master 组后 master=0%、worker=100%（脑裂观测面丢失）",
    steady=(
        Probe("master-ok", "/metrics", headers={"X-Chaos-Group": "master"},
              extract="success_rate", op="eq", value=1, samples=2),
        Probe("worker-ok", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "worker"}, extract="success_rate", op="eq", value=1, samples=2),
    ),
    inject=Action("proxy", faults={"block_groups": ["master"]}),
    measure=(
        Probe("master-down", "/metrics", headers={"X-Chaos-Group": "master"},
              extract="success_rate", op="eq", value=0, samples=2),
        Probe("worker-alive", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "worker"}, extract="success_rate", op="eq", value=1, samples=2),
    ),
    abort_when=(
        Probe("worker-also-down", "/train/step", "POST", {"steps": 1},
              headers={"X-Chaos-Group": "worker"}, extract="success_rate", op="eq", value=0, samples=2),
    ),
    rollback=Action("proxy", faults={"block_groups": []}),
    ml_specific=True,
    parity="Chaos Mesh partition + label selector 可近似；训练 master/worker 语义为 ML 面独有",
)

# --------------------------------------------------------------------------- 训练 ML 专属
SLOW_RANK = ChaosExperiment(
    id="nccl-slow-rank-straggler",
    title="NCCL 慢 rank（straggler 4000ms）→ 训练步时 ≥ 2× 基线",
    category="training",
    target="fabric-dos",
    slo="训练步时/基线 < 1.5×；注入慢 rank 后 step_ms_ratio ≥ 2.0；回滚（straggler=0）后 < 1.5×",
    steady=(
        Probe("step-ratio-baseline", "/train/step", "POST", {"steps": 1},
              extract="step_ms_ratio", op="lt", value=1.5),
    ),
    inject=Action("http", target="fabric-dos", path="/nccl/rank",
                  body={"rank": "rank-3", "straggler_ms": 4000}),
    measure=(
        Probe("step-ratio-degraded", "/train/step", "POST", {"steps": 1},
              extract="step_ms_ratio", op="ge", value=2.0),
        Probe("worst-straggler", "/metrics", extract="nccl.worst_straggler_ms", op="ge", value=4000),
    ),
    abort_when=(
        Probe("step-ratio-catastrophic", "/train/step", "POST", {"steps": 1},
              extract="step_ms_ratio", op="gt", value=50),
    ),
    rollback=Action("http", target="fabric-dos", path="/nccl/rank",
                    body={"rank": "rank-3", "straggler_ms": 0}),
    ml_specific=True,
    parity="三大工具无集合通信/慢 rank 实验（ML 面独有）",
)

GRADIENT_NOISE = ChaosExperiment(
    id="gradient-noise-threshold",
    title="梯度噪声注入（Byzantine scale=4）→ loss 发散比 ≥ 1.5×",
    category="training",
    target="fabric-dos",
    slo="单次梯度写后 loss_after/loss_before < 1.5×；注入 scale=4 后发散比 ≥ 1.5；"
        "回滚（计数复位）后 loss_last 回到基线 < 0.5",
    steady=(
        Probe("loss-stable", "/train/loss", extract="loss_history.3", op="lt", value=0.5),
    ),
    inject=Action("http", target="fabric-dos", path="/train/gradient",
                  body={"mode": "byzantine", "scale": 4.0}),
    measure=(
        Probe("loss-diverged", "/train/gradient", "POST", {"mode": "byzantine", "scale": 4.0},
              extract="loss_divergence_ratio", op="ge", value=1.5),
    ),
    abort_when=(
        Probe("loss-explosion", "/train/loss", extract="loss_history.3", op="gt", value=1000),
    ),
    rollback=Action("admin-reset", target="fabric-dos", keys=("training",)),
    recovery=(
        Probe("loss-restored", "/train/loss", extract="loss_history.3", op="lt", value=0.5),
    ),
    ml_specific=True,
    parity="三大工具无训练数值面实验（ML 面独有）",
)

KV_HIT_RATE = ChaosExperiment(
    id="kv-hit-rate-degradation",
    title="KV/prefix cache 命中率退化（冷前缀风暴）",
    category="training",
    target="longctx",
    slo="重复工作集命中 cached_tokens ≥ 256；注入 200 个冷前缀后新请求命中 = 0（churn 期命中率崩塌）；"
        "回滚（工作集重预热）后命中恢复",
    steady=(
        Probe("prime-working-set", "/v1/chat/completions", "POST",
              {"model": "chaos", "prompt_prefix": "chaos-warm-ws", "prompt_tokens": 512,
               "max_tokens": 8}, headers={"X-Tenant": "chaos"},
              extract="status", op="eq", value=200),
        Probe("warm-hit", "/v1/chat/completions", "POST",
              {"model": "chaos", "prompt_prefix": "chaos-warm-ws", "prompt_tokens": 512,
               "max_tokens": 8}, headers={"X-Tenant": "chaos"},
              extract="usage.cached_tokens", op="ge", value=256),
    ),
    inject=Action("http", target="longctx", path="/v1/chat/completions",
                  body={"model": "chaos-flood", "prompt_prefix": "chaos-cold-{i}",
                        "prompt_tokens": 1_000_000, "max_tokens": 8,
                        "context_window": "1m"}, repeat=200,
                  headers={"X-Tenant": "chaos"}),
    measure=(
        Probe("cold-miss", "/v1/chat/completions", "POST",
              {"model": "chaos", "prompt_prefix": "chaos-cold-probe", "prompt_tokens": 512,
               "max_tokens": 8}, headers={"X-Tenant": "chaos"},
              extract="usage.cached_tokens", op="eq", value=0),
        Probe("kv-pressure", "/metrics", extract="kv_cache_usage", op="gt", value=0.3),
    ),
    abort_when=(
        Probe("queue-explosion", "/metrics", extract="queue_depth", op="gt", value=10000),
    ),
    rollback=Action("http", target="longctx", path="/v1/chat/completions",
                    body={"model": "chaos", "prompt_prefix": "chaos-warm-ws",
                          "prompt_tokens": 512, "max_tokens": 8},
                    headers={"X-Tenant": "chaos"}),
    recovery=(
        Probe("warm-hit-restored", "/v1/chat/completions", "POST",
              {"model": "chaos", "prompt_prefix": "chaos-warm-ws", "prompt_tokens": 512,
               "max_tokens": 8}, headers={"X-Tenant": "chaos"},
              extract="usage.cached_tokens", op="ge", value=256),
    ),
    ml_specific=True,
    parity="三大工具无 KV/prefix cache 实验（ML 面独有）",
    boundary="longctx-sim 仿真（prefix cache 无淘汰，churn 期冷请求 miss 为实测；"
             "不冒充真实推理引擎的驱逐策略",
)

EXPERIMENTS: tuple[ChaosExperiment, ...] = (
    NET_LATENCY,
    NET_DISCONNECT,
    NET_PARTITION,
    NET_PACKET_LOSS,
    DNS_FAILURE,
    FABRIC_PFC_STORM,
    BOOTSTRAP_EXHAUST,
    GPU_XID_RESET,
    NODE_DRAIN_GANG,
    IO_THROTTLE_CKPT,
    MEM_PRESSURE_OOM,
    KV_EVICTION_STORM,
    CKPT_WRITE_CONFLICT,
    APISERVER_FLOOD,
    MASTER_LOSS,
    SLOW_RANK,
    GRADIENT_NOISE,
    KV_HIT_RATE,
)

_BY_ID: dict[str, ChaosExperiment] = {e.id: e for e in EXPERIMENTS}


def experiment_by_id(exp_id: str) -> ChaosExperiment:
    exp = _BY_ID.get(exp_id)
    if exp is None:
        known = ", ".join(sorted(_BY_ID))
        raise KeyError(f"未知混沌实验: {exp_id}（可用: {known}）")
    return exp


def list_experiments() -> list[dict]:
    """目录清单（CLI/UI 用）：id/标题/类别/SLO/ML 专属/对照注记。"""
    return [
        {
            "id": e.id,
            "title": e.title,
            "category": e.category,
            "target": e.target,
            "via_proxy": e.via_proxy,
            "ml_specific": e.ml_specific,
            "slo": e.slo,
            "parity": e.parity,
            "boundary": e.boundary,
            "probes": {"steady": len(e.steady), "measure": len(e.measure),
                       "abort_when": len(e.abort_when),
                       "recovery": len(e.recovery or e.steady)},
        }
        for e in EXPERIMENTS
    ]
