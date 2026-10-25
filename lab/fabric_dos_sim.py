"""lab/fabric_dos_sim.py — 万卡 fabric 破坏性漏洞面仿真服务（仅标准库，仅 127.0.0.1）。

语义同构对象（对应 docs/FABRIC-ATTACK-SURFACE.md，语料见 arch-intel/corpus）：
- SHARP/SHARPv3 在网聚合会话面（/sharp/*）：无鉴权入组 + 篡改 reduce 结果 = 静默损坏
- IB Subnet Manager/Partition 面（/ib/sm/partition）：可改成员即改信任域
- RoCE PFC/ECN 面（/roce/pfc）：配置可写引发暂停风暴（计数器度量，不真破坏）
- NCCL bootstrap/rendezvous（/nccl/bootstrap）：端口耗尽 + 慢 rank（straggler）/弹性组拖垮步时
- checkpoint I/O（/checkpoint/io）：限速缺失 → I/O 风暴
- apiserver/IMDS 请求洪（/apiserver/request、/imds/request）：配额缺失
- KV/激活内存（/train/context）：超长上下文无 max 生效 → OOM 计数
- EPP/gang 调度（/sched/gang）：占位 job 拖垮队列
- GPU Xid/驱动复位（/gpu/health）：健康接口可写 → 复位计数
- 拓扑 rail（/nccl/rail）：强制 rail 错配 → 跨 rail 流计数

两种姿态：
- vulnerable：控制/写面无鉴权、无限速/配额/上限（fail-open），破坏效果以计数器/状态变化度量；
- fixed：写面 401（管理密钥/作业令牌 200）、超限 400/429、配额与上限强制。

写盘边界：本仿真完全内存态（不落盘）；shutdown 仅关服务。
命令行：python lab/fabric_dos_sim.py [--port N] [--mode vulnerable|fixed]
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
ADMIN_TOKEN = "fabric-admin-key"
JOB_TOKEN = "fabric-job-token"

# ---- 容量/阈值（数字小而确定，使模块与测试可用有界请求表达集群级行为）----
BOOTSTRAP_PORT_CAPACITY = 24       # NCCL bootstrap 可分配端口池
STRAGGLER_DEFAULT_MS = 5000        # 慢 rank 注入缺省步时增量
STEP_BASE_MS = 120.0               # 健康集群单步基线（ms）
CKPT_BYTES_PER_CALL = 4096         # 每次 I/O 风暴写入 MiB
CKPT_BURST_PER_CALL = 4            # 每次 I/O 风暴并发 burst
CKPT_RATE_LIMIT_MB = 512           # fixed：单调用限速（MiB）
API_QUOTA_FIXED = 60               # fixed：apiserver/IMDS 匿名每窗口配额
MEMORY_CAPACITY_BYTES = 64 * 1024 ** 3   # 64 GiB KV/激活池
KV_BYTES_PER_TOKEN = 64 * 1024           # 每 token KV+激活预留
MAX_CONTEXT_TOKENS_FIXED = 131072        # fixed：上下文上限
GANG_QUEUE_CAPACITY = 16           # gang 队列容量（占位数）
PFC_PAUSE_PER_STORM = 25000        # 每次风暴调用的暂停帧计数增量
RESET_XID_CODES = (48, 63, 79, 94, 119)  # 触发驱动复位的 Xid 族
SEED_SHARP_SESSION = "train-job-alpha"
SEED_PKEY = "0x8001"
SEED_RANKS = 8


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _int_of(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _FabricState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        # SHARP 在网聚合
        self.sharp_sessions: dict[str, dict] = {
            SEED_SHARP_SESSION: {
                "job": SEED_SHARP_SESSION,
                "members": [f"rank-{i}" for i in range(SEED_RANKS)],
                "reduces": [],
                "seq": 0,
            }
        }
        self.sharp_tampered_reduces = 0
        self.sharp_joins_unauth = 0
        # IB Subnet Manager / Partition
        self.ib_partitions: dict[str, dict] = {
            SEED_PKEY: {"name": "train-a", "members": ["guid-a1", "guid-a2", "guid-a3"], "default": False},
            "0x7fff": {"name": "default", "members": ["guid-any"], "default": True},
        }
        self.ib_membership_changes = 0
        # RoCE PFC/ECN
        self.pfc = {"enabled": True, "storm": False, "interfaces": ["port-1", "port-2"]}
        self.pfc_pause_frames = 0
        self.ecn_marks = 0
        # NCCL bootstrap / rank / rail
        self.bootstrap_capacity = BOOTSTRAP_PORT_CAPACITY
        self.bootstrap_allocated: dict[str, int] = {}
        self.bootstrap_exhausted = 0          # 受害作业被拒次数
        self.rank_state = {f"rank-{i}": {"straggler_ms": 0} for i in range(SEED_RANKS)}
        self.rail_map = {f"rank-{i}": f"rail-{i}" for i in range(SEED_RANKS)}
        self.cross_rail_flows = 0
        # checkpoint I/O
        self.ckpt_io_bytes = 0
        self.ckpt_io_queue = 0
        self.ckpt_rate_limited = False        # 是否限速（fixed=true）
        self.ckpt_throttled = 0
        # apiserver / IMDS
        self.api_requests = 0
        self.imds_requests = 0
        self.api_quota_enforced = False       # fixed=true
        self.api_throttled = 0
        # KV/激活内存
        self.kv_bytes = 0
        self.oom_events = 0
        self.max_context_enforced = False     # fixed=true
        self.over_context_accepted = 0
        # gang 调度
        self.gang_queue: list[dict] = []
        self.gang_placeholder_jobs = 0
        # GPU 健康 / Xid
        self.xid_events = 0
        self.driver_resets = 0
        self.devices = {"gpu-0": {"healthy": True, "xid": []}}
        # 训练数值（静默损坏面）
        self.loss_history = [0.42, 0.40, 0.38, 0.37]
        self.corruption_events = 0


class _RequestContext:
    def __init__(self, mode, state, headers, body, path, query, params, entry):
        self.mode = mode
        self.state = state
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.params = params
        self.entry = entry

    @property
    def admin(self) -> bool:
        return (self.headers.get("Authorization") or "") == f"Bearer {ADMIN_TOKEN}"

    @property
    def job(self) -> bool:
        return (self.headers.get("X-Job-Token") or "") == JOB_TOKEN


# ---------------------------------------------------------------------------
# 路由行为
# ---------------------------------------------------------------------------


def _sharp_sessions(ctx: _RequestContext):
    """POST 入组 SHARP 在网 all-reduce 会话（无鉴权可入组）。"""
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "fabric-sharp",
                     "hint": "fixed 模式入组需要作业令牌或管理密钥"}
    state = ctx.state
    op = str(ctx.body.get("op") or "join").lower()
    session_id = str(ctx.body.get("session_id") or SEED_SHARP_SESSION)
    rank = str(ctx.body.get("rank") or f"external-{int(time.time() * 1000) % 100000}")
    with state.lock:
        session = state.sharp_sessions.setdefault(
            session_id, {"job": session_id, "members": [], "reduces": [], "seq": 0})
        if op == "join":
            joined = rank not in session["members"]
            if joined:
                session["members"].append(rank)
                state.sharp_joins_unauth += 1
            payload = {
                "service": "fabric-sharp", "op": "join", "session_id": session_id,
                "rank": rank, "joined": joined, "member_count": len(session["members"]),
                "members": list(session["members"]),
            }
            return 200, payload
        if op == "leave":
            session["members"] = [m for m in session["members"] if m != rank]
            return 200, {"service": "fabric-sharp", "op": "leave", "session_id": session_id,
                         "rank": rank, "member_count": len(session["members"])}
    return 400, {"error": "unsupported_op", "supported": ["join", "leave"]}


def _sharp_session_get(ctx: _RequestContext):
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "fabric-sharp"}
    sid = (ctx.params or {}).get("session") or ""
    with ctx.state.lock:
        session = ctx.state.sharp_sessions.get(sid)
    if session is None:
        return 404, {"error": "session_not_found", "session_id": sid}
    return 200, {"service": "fabric-sharp", "session_id": sid,
                 "members": session["members"], "member_count": len(session["members"]),
                 "reduces": session["reduces"][-4:]}


def _sharp_reduce(ctx: _RequestContext):
    """POST 在网 reduce：vulnerable 接受外部贡献与篡改因子（结果静默偏离）。

    body: {session_id?, contributions:[num], tamper_factor?|tamper_delta?}
    vulnerable：result = sum(contributions) + tamper_delta（无告警，silent=true）
    fixed：401；管理密钥下 peer 校验失败 400（篡改因子拒绝）。
    """
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "fabric-sharp",
                     "hint": "fixed 模式在网 reduce 需要管理密钥"}
    values = ctx.body.get("contributions")
    if not isinstance(values, list) or not values:
        return 400, {"error": "missing_contributions"}
    try:
        nums = [float(v) for v in values]
    except (TypeError, ValueError):
        return 400, {"error": "invalid_contributions"}
    tamper_delta = 0.0
    if ctx.body.get("tamper_factor") is not None:
        try:
            tamper_delta = (float(ctx.body["tamper_factor"]) - 1.0) * sum(nums)
        except (TypeError, ValueError):
            return 400, {"error": "invalid_tamper_factor"}
    if ctx.body.get("tamper_delta") is not None:
        try:
            tamper_delta = float(ctx.body["tamper_delta"])
        except (TypeError, ValueError):
            return 400, {"error": "invalid_tamper_delta"}
    if ctx.mode == "fixed" and tamper_delta:
        return 400, {"error": "peer_contribution_rejected",
                     "hint": "fixed 模式拒绝带篡改因子的外部贡献"}
    session_id = str(ctx.body.get("session_id") or SEED_SHARP_SESSION)
    correct = sum(nums)
    result = correct + tamper_delta
    state = ctx.state
    with state.lock:
        session = state.sharp_sessions.setdefault(
            session_id, {"job": session_id, "members": [], "reduces": [], "seq": 0})
        session["seq"] += 1
        session["reduces"].append({
            "seq": session["seq"], "op": "all-reduce",
            "contributions": len(nums), "result": result,
            "tampered": bool(tamper_delta), "ts": _utcnow_iso(),
        })
        if tamper_delta:
            state.sharp_tampered_reduces += 1
        seq = session["seq"]
    return 200, {
        "service": "fabric-sharp", "op": "all-reduce", "session_id": session_id,
        "seq": seq, "result": result, "contributions": len(nums),
        "tampered": bool(tamper_delta), "silent": bool(tamper_delta) and ctx.mode == "vulnerable",
    }


def _ib_partition_get(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "ib-sm"}
    with ctx.state.lock:
        partitions = {k: dict(v, members=list(v["members"]))
                      for k, v in ctx.state.ib_partitions.items()}
    return 200, {"service": "ib-sm", "op": "list", "partitions": partitions,
                 "membership_changes": ctx.state.ib_membership_changes}


def _ib_partition_post(ctx: _RequestContext):
    """POST 修改 IB Partition 成员（SM 面可写 = 信任域可改）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "ib-sm",
                     "hint": "fixed 模式 SM Partition 写面需要管理密钥"}
    pkey = str(ctx.body.get("pkey") or SEED_PKEY)
    add = ctx.body.get("add_members") or []
    remove = ctx.body.get("remove_members") or []
    if not add and not remove:
        return 400, {"error": "missing_membership_change"}
    state = ctx.state
    with state.lock:
        part = state.ib_partitions.setdefault(
            pkey, {"name": str(ctx.body.get("name") or pkey), "members": [], "default": False})
        part["members"] = [m for m in part["members"] if m not in set(remove)]
        for member in add:
            if member not in part["members"]:
                part["members"].append(member)
        state.ib_membership_changes += 1
        members = list(part["members"])
    return 200, {"service": "ib-sm", "op": "modify", "pkey": pkey,
                 "added": list(add), "removed": list(remove),
                 "members": members, "member_count": len(members)}


def _roce_pfc_get(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "roce-pfc"}
    state = ctx.state
    with state.lock:
        return 200, {
            "service": "roce-pfc", "pfc": dict(state.pfc),
            "pfc_pause_frames": state.pfc_pause_frames,
            "ecn_marks": state.ecn_marks,
        }


def _roce_pfc_post(ctx: _RequestContext):
    """POST 写 PFC 配置：mode=storm 在 vulnerable 触发暂停风暴（仅计数器）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "roce-pfc",
                     "hint": "fixed 模式 PFC 配置写面需要管理密钥"}
    mode = str(ctx.body.get("mode") or "").lower()
    if ctx.mode == "fixed" and mode == "storm":
        return 400, {"error": "storm_profile_rejected",
                     "hint": "fixed 模式拒绝风暴配置档"}
    state = ctx.state
    with state.lock:
        if mode == "storm":
            interfaces = ctx.body.get("interfaces") or list(state.pfc["interfaces"])
            state.pfc["storm"] = True
            state.pfc["interfaces"] = [str(i) for i in interfaces]
            state.pfc_pause_frames += PFC_PAUSE_PER_STORM
            state.ecn_marks += PFC_PAUSE_PER_STORM // 10
            pause_frames = state.pfc_pause_frames
            return 200, {
                "service": "roce-pfc", "op": "storm", "mode": "storm",
                "interfaces": state.pfc["interfaces"],
                "pfc_pause_frames": pause_frames, "storm_active": True,
            }
        if mode in ("on", "enable"):
            state.pfc["enabled"] = True
        elif mode in ("off", "disable"):
            state.pfc["enabled"] = False
        else:
            return 400, {"error": "unsupported_mode", "supported": ["storm", "on", "off"]}
        return 200, {"service": "roce-pfc", "op": "configure", "pfc": dict(state.pfc),
                     "pfc_pause_frames": state.pfc_pause_frames}


def _nccl_bootstrap(ctx: _RequestContext):
    """POST bootstrap/rendezvous 端口分配（端口耗尽 + 受害作业拒绝证据）。"""
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "nccl-bootstrap",
                     "hint": "fixed 模式 rendezvous 需要作业令牌；且按作业限端口"}
    job = str(ctx.body.get("job") or "trident-probe")
    ranks = _int_of(ctx.body.get("ranks"), 1)
    honest = bool(ctx.body.get("honest"))
    state = ctx.state
    with state.lock:
        used = sum(state.bootstrap_allocated.values())
        remaining = state.bootstrap_capacity - used
        if ctx.mode == "fixed":
            job_used = state.bootstrap_allocated.get(job, 0)
            if job_used + ranks > 4:
                return 429, {"error": "per_job_port_cap", "job": job,
                             "allocated": job_used, "cap": 4}
        if remaining <= 0:
            state.bootstrap_exhausted += 1
            return (503, {
                "error": "bootstrap_ports_exhausted", "job": job,
                "capacity": state.bootstrap_capacity, "exhausted_refusals": state.bootstrap_exhausted,
                "honest": honest,
            })
        alloc = min(ranks, remaining)
        state.bootstrap_allocated[job] = state.bootstrap_allocated.get(job, 0) + alloc
        used = sum(state.bootstrap_allocated.values())
        remaining = state.bootstrap_capacity - used
        return 200, {
            "service": "nccl-bootstrap", "op": "allocate", "job": job,
            "ports_allocated": alloc, "ports_remaining": remaining,
            "capacity": state.bootstrap_capacity, "honest": honest,
        }


def _nccl_rank(ctx: _RequestContext):
    """POST 注入慢 rank / 弹性组成员（straggler 拖垮步时）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "nccl-rank",
                     "hint": "fixed 模式 rank 状态写面需要管理密钥"}
    rank = str(ctx.body.get("rank") or "rank-7")
    straggler_ms = _int_of(ctx.body.get("straggler_ms"), STRAGGLER_DEFAULT_MS)
    if ctx.mode == "fixed" and straggler_ms > 500:
        return 400, {"error": "straggler_rejected",
                     "hint": "fixed 模式拒绝异常慢 rank 注入", "rank": rank}
    state = ctx.state
    with state.lock:
        if rank not in state.rank_state:
            state.rank_state[rank] = {"straggler_ms": 0}
        state.rank_state[rank]["straggler_ms"] = straggler_ms
        worst = max(r["straggler_ms"] for r in state.rank_state.values())
    return 200, {"service": "nccl-rank", "op": "straggler", "rank": rank,
                 "straggler_ms": straggler_ms, "worst_straggler_ms": worst}


def _nccl_rail_get(ctx: _RequestContext):
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "nccl-rail"}
    with ctx.state.lock:
        return 200, {"service": "nccl-rail", "rail_map": dict(ctx.state.rail_map),
                     "cross_rail_flows": ctx.state.cross_rail_flows}


def _nccl_rail_post(ctx: _RequestContext):
    """POST 强制 rail 错配（破坏 rail-optimized 局部性 → 跨 rail 流）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "nccl-rail",
                     "hint": "fixed 模式 rail 绑定写面需要管理密钥"}
    rank = str(ctx.body.get("rank") or "rank-7")
    force_rail = str(ctx.body.get("force_rail") or "rail-0")
    state = ctx.state
    with state.lock:
        if rank not in state.rail_map:
            return 404, {"error": "rank_not_found", "rank": rank}
        original = state.rail_map[rank]
        mismatched = original != force_rail
        if mismatched:
            state.rail_map[rank] = force_rail
            state.cross_rail_flows += 1
        cross = state.cross_rail_flows
    return 200, {"service": "nccl-rail", "op": "force", "rank": rank,
                 "original_rail": original, "forced_rail": force_rail,
                 "mismatch": mismatched, "cross_rail_flows": cross}


def _train_step(ctx: _RequestContext):
    """POST 训练步计时（受 straggler/rail 错配影响；两态均 200 的度量端点）。"""
    steps = max(1, _int_of(ctx.body.get("steps"), 1))
    state = ctx.state
    with state.lock:
        worst = max(r["straggler_ms"] for r in state.rank_state.values())
        cross_penalty = state.cross_rail_flows * 15.0
        step_ms = STEP_BASE_MS + worst + cross_penalty
    return 200, {"service": "fabric-train", "op": "step", "steps": steps,
                 "step_ms": round(step_ms, 3), "total_ms": round(step_ms * steps, 3),
                 "base_step_ms": STEP_BASE_MS}


def _train_context(ctx: _RequestContext):
    """POST KV/激活内存预留（超长上下文无 max 生效 → OOM 计数）。"""
    context_tokens = _int_of(ctx.body.get("context_tokens"), 0)
    declared = _int_of(ctx.body.get("declared_context_tokens"), context_tokens)
    if context_tokens < 1:
        return 400, {"error": "missing_context_tokens"}
    state = ctx.state
    if ctx.mode == "fixed":
        if context_tokens > MAX_CONTEXT_TOKENS_FIXED:
            state.max_context_enforced = True
            return 400, {"error": "context_limit_enforced",
                         "max_context_tokens": MAX_CONTEXT_TOKENS_FIXED,
                         "context_tokens": context_tokens}
        with state.lock:
            state.kv_bytes = min(state.kv_bytes + context_tokens * KV_BYTES_PER_TOKEN,
                                 MEMORY_CAPACITY_BYTES)
        return 200, {"service": "fabric-train", "op": "context",
                     "context_tokens": context_tokens, "accepted": True,
                     "oom": False, "kv_bytes": state.kv_bytes}
    with state.lock:
        state.over_context_accepted += 1
        state.kv_bytes += context_tokens * KV_BYTES_PER_TOKEN
        oom = state.kv_bytes > MEMORY_CAPACITY_BYTES
        if oom:
            state.oom_events += 1
        kv_bytes = state.kv_bytes
    return 200, {"service": "fabric-train", "op": "context",
                 "context_tokens": context_tokens, "declared_context_tokens": declared,
                 "accepted": True, "oom": oom, "oom_events": ctx.state.oom_events,
                 "kv_bytes": kv_bytes, "capacity_bytes": MEMORY_CAPACITY_BYTES,
                 "silent": True}


def _train_gradient(ctx: _RequestContext):
    """POST Byzantine 梯度/损失篡改（vulnerable：loss 静默发散，无报错）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "fabric-train",
                     "hint": "fixed 模式梯度写面需要管理密钥 + peer 校验"}
    mode = str(ctx.body.get("mode") or "byzantine").lower()
    scale = float(ctx.body.get("scale") or 2.0)
    if ctx.mode == "fixed":
        return 400, {"error": "gradient_peer_check_rejected",
                     "hint": "fixed 模式梯度面 peer 校验拒绝异常贡献"}
    state = ctx.state
    with state.lock:
        last = state.loss_history[-1]
        nxt = last * (1.0 + 0.4 * scale) + 0.01
        state.loss_history.append(round(nxt, 6))
        state.corruption_events += 1
        history = list(state.loss_history[-6:])
    return 200, {"service": "fabric-train", "op": "gradient", "mode": mode,
                 "scale": scale, "loss_before": last,
                 "loss_after": history[-1], "silent": True,
                 "loss_history": history,
                 "corruption_events": state.corruption_events}


def _train_loss_get(ctx: _RequestContext):
    with ctx.state.lock:
        return 200, {"service": "fabric-train", "loss_history": list(ctx.state.loss_history[-12:]),
                     "corruption_events": ctx.state.corruption_events}


def _checkpoint_io(ctx: _RequestContext):
    """POST checkpoint I/O 风暴（vulnerable 无限速；fixed 限速/配额 429）。"""
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "ckpt-io",
                     "hint": "fixed 模式 checkpoint I/O 需要作业令牌"}
    bytes_mb = max(1, _int_of(ctx.body.get("bytes_mb"), CKPT_BYTES_PER_CALL))
    burst = max(1, _int_of(ctx.body.get("burst"), CKPT_BURST_PER_CALL))
    state = ctx.state
    if ctx.mode == "fixed" and bytes_mb * burst > CKPT_RATE_LIMIT_MB:
        with state.lock:
            state.ckpt_rate_limited = True
            state.ckpt_throttled += 1
        return 429, {"error": "io_rate_limit", "limit_mb": CKPT_RATE_LIMIT_MB,
                     "requested_mb": bytes_mb * burst}
    with state.lock:
        state.ckpt_io_bytes += bytes_mb * burst
        state.ckpt_io_queue += burst
        io_bytes, io_queue = state.ckpt_io_bytes, state.ckpt_io_queue
    return 200, {"service": "ckpt-io", "op": "write", "bytes_mb": bytes_mb,
                 "burst": burst, "io_bytes_mb": io_bytes, "io_queue": io_queue,
                 "rate_limited": False}


def _apiserver_request(ctx: _RequestContext):
    """POST apiserver 请求洪（vulnerable 无配额；fixed 配额 429）。"""
    count = max(1, _int_of(ctx.body.get("count"), 50))
    state = ctx.state
    if ctx.mode == "fixed" and count > API_QUOTA_FIXED:
        with state.lock:
            state.api_quota_enforced = True
            state.api_throttled += 1
        return 429, {"error": "request_quota", "quota": API_QUOTA_FIXED,
                     "requested": count}
    with state.lock:
        state.api_requests += count
        total = state.api_requests
    return 200, {"service": "apiserver", "op": "flood", "count": count,
                 "requests_total": total, "quota_enforced": False}


def _imds_request(ctx: _RequestContext):
    """POST IMDS 请求洪（同 apiserver 配额语义）。"""
    count = max(1, _int_of(ctx.body.get("count"), 50))
    state = ctx.state
    if ctx.mode == "fixed" and count > API_QUOTA_FIXED:
        with state.lock:
            state.api_quota_enforced = True
            state.api_throttled += 1
        return 429, {"error": "request_quota", "quota": API_QUOTA_FIXED,
                     "requested": count}
    with state.lock:
        state.imds_requests += count
        total = state.imds_requests
    return 200, {"service": "imds", "op": "flood", "count": count,
                 "requests_total": total, "quota_enforced": False}


def _sched_gang(ctx: _RequestContext):
    """POST gang/占位 job（vulnerable 拖垮队列；fixed 配额 429）。"""
    if ctx.mode == "fixed" and not (ctx.admin or ctx.job):
        return 401, {"error": "unauthorized", "service": "gang-sched",
                     "hint": "fixed 模式作业提交需要作业令牌"}
    gang_size = max(1, _int_of(ctx.body.get("gang_size"), 8))
    placeholders = max(0, _int_of(ctx.body.get("placeholders"), gang_size))
    hold = bool(ctx.body.get("hold", True))
    job_id = str(ctx.body.get("job_id") or f"placeholder-{int(time.time() * 1000) % 100000}")
    state = ctx.state
    pending = 0
    with state.lock:
        pending = sum(j["gang_size"] for j in state.gang_queue)
        if ctx.mode == "fixed" and pending + gang_size > GANG_QUEUE_CAPACITY:
            return 429, {"error": "gang_quota", "capacity": GANG_QUEUE_CAPACITY,
                         "pending": pending}
        state.gang_queue.append({"job_id": job_id, "gang_size": gang_size,
                                 "placeholders": placeholders, "hold": hold})
        if placeholders:
            state.gang_placeholder_jobs += 1
        pending = sum(j["gang_size"] for j in state.gang_queue)
        clogged = pending > GANG_QUEUE_CAPACITY
        queued = len(state.gang_queue)
    return 200, {"service": "gang-sched", "op": "submit", "job_id": job_id,
                 "gang_size": gang_size, "placeholders": placeholders, "hold": hold,
                 "pending_gpus": pending, "queue_length": queued,
                 "capacity": GANG_QUEUE_CAPACITY, "clogged": clogged}


def _gpu_health_get(ctx: _RequestContext):
    state = ctx.state
    with state.lock:
        return 200, {"service": "gpu-health", "devices": {
            k: dict(v, xid=list(v["xid"])) for k, v in state.devices.items()},
            "xid_events": state.xid_events, "driver_resets": state.driver_resets}


def _gpu_health_post(ctx: _RequestContext):
    """POST 写 GPU 健康面（Xid 注入 → 驱动复位计数；vulnerable 无鉴权）。"""
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "gpu-health",
                     "hint": "fixed 模式健康写面需要管理密钥；Xid 仅驱动源接受"}
    gpu = str(ctx.body.get("gpu") or "gpu-0")
    xid_code = _int_of(ctx.body.get("xid_code"), 79)
    state = ctx.state
    with state.lock:
        device = state.devices.setdefault(gpu, {"healthy": True, "xid": []})
        device["xid"].append(xid_code)
        state.xid_events += 1
        reset = xid_code in RESET_XID_CODES
        if reset:
            state.driver_resets += 1
            device["healthy"] = False
        payload = {"service": "gpu-health", "op": "xid", "gpu": gpu,
                   "xid_code": xid_code, "reset_triggered": reset,
                   "xid_events": state.xid_events, "driver_resets": state.driver_resets,
                   "healthy": device["healthy"]}
    return 200, payload


def _metrics(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "fabric-metrics",
                     "hint": "fixed 模式指标面需要管理密钥"}
    state = ctx.state
    with state.lock:
        used = sum(state.bootstrap_allocated.values())
        worst = max(r["straggler_ms"] for r in state.rank_state.values())
        return 200, {
            "service": "fabric-metrics", "generated_at": _utcnow_iso(),
            "sharp": {"sessions": len(state.sharp_sessions),
                      "joins_unauth": state.sharp_joins_unauth,
                      "tampered_reduces": state.sharp_tampered_reduces},
            "ib": {"partitions": len(state.ib_partitions),
                   "membership_changes": state.ib_membership_changes},
            "roce": {"pfc_pause_frames": state.pfc_pause_frames,
                     "ecn_marks": state.ecn_marks, "storm_active": state.pfc["storm"]},
            "nccl": {"bootstrap_capacity": state.bootstrap_capacity,
                     "bootstrap_used": used,
                     "bootstrap_remaining": state.bootstrap_capacity - used,
                     "bootstrap_exhausted_refusals": state.bootstrap_exhausted,
                     "worst_straggler_ms": worst,
                     "cross_rail_flows": state.cross_rail_flows},
            "checkpoint_io": {"io_bytes_mb": state.ckpt_io_bytes,
                              "io_queue": state.ckpt_io_queue,
                              "rate_limited": state.ckpt_rate_limited,
                              "throttled": state.ckpt_throttled},
            "api": {"requests_total": state.api_requests,
                    "imds_requests_total": state.imds_requests,
                    "quota_enforced": state.api_quota_enforced,
                    "throttled": state.api_throttled},
            "memory": {"kv_bytes": state.kv_bytes,
                       "capacity_bytes": MEMORY_CAPACITY_BYTES,
                       "oom_events": state.oom_events,
                       "over_context_accepted": state.over_context_accepted,
                       "max_context_enforced": state.max_context_enforced},
            "gang": {"queue_length": len(state.gang_queue),
                     "pending_gpus": sum(j["gang_size"] for j in state.gang_queue),
                     "capacity": GANG_QUEUE_CAPACITY,
                     "placeholder_jobs": state.gang_placeholder_jobs,
                     "clogged": sum(j["gang_size"] for j in state.gang_queue) > GANG_QUEUE_CAPACITY},
            "gpu": {"xid_events": state.xid_events,
                    "driver_resets": state.driver_resets},
            "training": {"loss_last": state.loss_history[-1],
                         "corruption_events": state.corruption_events,
                         "step_base_ms": STEP_BASE_MS},
        }


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "trident-fabric-lab",
        "mode": ctx.mode,
        "host": HOST,
        "admin_token_hint": f"fixed 模式管理密钥 = Authorization: Bearer {ADMIN_TOKEN}",
        "job_token_hint": f"fixed 模式作业令牌 = X-Job-Token: {JOB_TOKEN}",
        "route_count": len(ROUTE_TABLE),
        "routes": [{k: v for k, v in entry.items() if k != "behavior"}
                   for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 路由表（vulnerable/fixed = 基线请求状态码；行为函数内部再做细粒度判定）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "fabric-sharp", "title": "SHARP 在网聚合会话入组", "method": "POST",
     "path": "/sharp/sessions", "vulnerable": 200, "fixed": 401, "gate": "job",
     "writes": False, "description": "vulnerable 无鉴权入组；fixed 作业令牌/管理密钥 200",
     "behavior": _sharp_sessions},
    {"service": "fabric-sharp", "title": "SHARP 会话详情", "method": "GET",
     "path": "/sharp/sessions/{session}", "wildcard": True, "vulnerable": 200,
     "fixed": 401, "gate": "job", "writes": False,
     "description": "成员/reduce 记录读回；fixed 401（令牌 200）",
     "behavior": _sharp_session_get},
    {"service": "fabric-sharp", "title": "SHARP 在网 all-reduce", "method": "POST",
     "path": "/sharp/reduce", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True,
     "description": "vulnerable 接受外部贡献与篡改因子（结果静默偏离）；fixed 401（管理密钥 200，篡改 400）",
     "behavior": _sharp_reduce},
    {"service": "ib-sm", "title": "IB SM Partition 清单", "method": "GET",
     "path": "/ib/sm/partition", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False, "description": "vulnerable 无鉴权枚举 partition 成员", "behavior": _ib_partition_get},
    {"service": "ib-sm", "title": "IB SM Partition 成员修改", "method": "POST",
     "path": "/ib/sm/partition", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 无鉴权增删成员（信任域可改）", "behavior": _ib_partition_post},
    {"service": "roce-pfc", "title": "RoCE PFC/ECN 配置与计数", "method": "GET",
     "path": "/roce/pfc", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False, "description": "PFC 配置 + 暂停帧/ECN 计数", "behavior": _roce_pfc_get},
    {"service": "roce-pfc", "title": "RoCE PFC 配置写入（风暴档）", "method": "POST",
     "path": "/roce/pfc", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 接受 storm 档引发暂停风暴计数；fixed 401/400",
     "behavior": _roce_pfc_post},
    {"service": "nccl-bootstrap", "title": "NCCL bootstrap 端口分配", "method": "POST",
     "path": "/nccl/bootstrap", "vulnerable": 200, "fixed": 401, "gate": "job",
     "writes": False,
     "description": "vulnerable 端口池可被占满（耗尽后诚实作业 503）；fixed 令牌 + 按作业上限 429",
     "behavior": _nccl_bootstrap},
    {"service": "nccl-rank", "title": "NCCL rank 状态（straggler 注入）", "method": "POST",
     "path": "/nccl/rank", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 可注入慢 rank；fixed 401（>500ms 400）",
     "behavior": _nccl_rank},
    {"service": "nccl-rail", "title": "NCCL rail 绑定图", "method": "GET",
     "path": "/nccl/rail", "vulnerable": 200, "fixed": 401, "gate": "job",
     "writes": False, "description": "rail 绑定与跨 rail 流计数", "behavior": _nccl_rail_get},
    {"service": "nccl-rail", "title": "NCCL rail 强制错配", "method": "POST",
     "path": "/nccl/rail", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 可强制 rank 跨 rail（破坏局部性）", "behavior": _nccl_rail_post},
    {"service": "fabric-train", "title": "训练步计时（度量端点）", "method": "POST",
     "path": "/train/step", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False, "description": "受 straggler/rail 错配影响的步时（两态 200）",
     "behavior": _train_step},
    {"service": "fabric-train", "title": "KV/激活上下文预留", "method": "POST",
     "path": "/train/context", "vulnerable": 200, "fixed": 400, "gate": "limit",
     "writes": False,
     "description": "vulnerable 超长上下文无上限（OOM 计数）；fixed 超限 400",
     "behavior": _train_context},
    {"service": "fabric-train", "title": "梯度/损失写面（Byzantine）", "method": "POST",
     "path": "/train/gradient", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 梯度贡献无 peer 校验（loss 静默发散）；fixed 401/400",
     "behavior": _train_gradient},
    {"service": "fabric-train", "title": "损失轨迹读回", "method": "GET",
     "path": "/train/loss", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False, "description": "loss 历史 + 篡改事件计数（两态 200）", "behavior": _train_loss_get},
    {"service": "ckpt-io", "title": "checkpoint I/O 写入", "method": "POST",
     "path": "/checkpoint/io", "vulnerable": 200, "fixed": 401, "gate": "quota",
     "writes": False,
     "description": "vulnerable 无限速（I/O 风暴计数）；fixed 令牌 + 限速 429",
     "behavior": _checkpoint_io},
    {"service": "apiserver", "title": "apiserver 请求洪", "method": "POST",
     "path": "/apiserver/request", "vulnerable": 200, "fixed": 429, "gate": "quota",
     "writes": False, "description": "vulnerable 无配额；fixed 超配额 429", "behavior": _apiserver_request},
    {"service": "imds", "title": "IMDS 请求洪", "method": "POST",
     "path": "/imds/request", "vulnerable": 200, "fixed": 429, "gate": "quota",
     "writes": False, "description": "vulnerable 无配额；fixed 超配额 429", "behavior": _imds_request},
    {"service": "gang-sched", "title": "gang/占位作业提交", "method": "POST",
     "path": "/sched/gang", "vulnerable": 200, "fixed": 401, "gate": "quota",
     "writes": False,
     "description": "vulnerable 占位 job 拖垮队列（pending>capacity）；fixed 令牌 + 配额 429",
     "behavior": _sched_gang},
    {"service": "gpu-health", "title": "GPU 健康读回", "method": "GET",
     "path": "/gpu/health", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False, "description": "设备健康/Xid/复位计数（两态 200）", "behavior": _gpu_health_get},
    {"service": "gpu-health", "title": "GPU 健康写面（Xid 注入）", "method": "POST",
     "path": "/gpu/health", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable Xid 可注入触发驱动复位计数；fixed 401",
     "behavior": _gpu_health_post},
    {"service": "fabric-metrics", "title": "fabric 指标总览", "method": "GET",
     "path": "/metrics", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False, "description": "全部破坏效果计数器；fixed 401（管理密钥 200）",
     "behavior": _metrics},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "返回本清单 JSON（供测试与模块发现）", "behavior": _routes_manifest},
]


# ---------------------------------------------------------------------------
# 路由索引 + HTTP 服务（与 longctx_sim 同构）
# ---------------------------------------------------------------------------


def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


def _prefix_of(entry: dict) -> str:
    return entry["path"].replace("{session}", "").rstrip("/")


_EXACT_ROUTES: dict[tuple[str, str], list[dict]] = {}
_PREFIX_ROUTES: list[tuple[str, str, dict]] = []
for _entry in ROUTE_TABLE:
    if _entry.get("wildcard"):
        _PREFIX_ROUTES.append((_entry["method"], _prefix_of(_entry), _entry))
    else:
        _EXACT_ROUTES.setdefault((_entry["method"], _normalize(_entry["path"])), []).append(_entry)


def _entries_for(method: str, norm: str) -> list[dict]:
    found = list(_EXACT_ROUTES.get((method, norm), []))
    for prefix_method, prefix, entry in _PREFIX_ROUTES:
        if prefix_method == method and (norm == prefix or norm.startswith(prefix + "/")):
            found.append(entry)
    return found


def _resolve(method: str, norm: str) -> dict | None:
    entries = _entries_for(method, norm)
    return entries[0] if entries else None


def _path_params(entry: dict, norm: str) -> dict[str, str]:
    prefix = _prefix_of(entry)
    rest = norm[len(prefix):].strip("/")
    return {"session": rest} if rest else {}


class _FabricHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str):
        super().__init__(address, _FabricHandler)
        self.lab_mode = mode
        self.lab_state = _FabricState()


class _FabricHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TridentFabricSim/0.1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        return

    def _send(self, status: int, payload, extra_headers: dict | None = None):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"_raw": raw.decode("utf-8", "replace")}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _resolve(method, norm)
        if entry is None:
            if any(_entries_for(other, norm) for other in ("GET", "POST") if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _FabricHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            state=server.lab_state,
            headers=self.headers,
            body=self._read_body() if method == "POST" else {},
            path=split.path,
            query=parse_qs(split.query),
            params=_path_params(entry, norm),
            entry=entry,
        )
        try:
            outcome = entry["behavior"](ctx)
        except Exception as exc:  # noqa: BLE001 —— 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        status, payload = outcome[0], outcome[1]
        extra = outcome[2] if len(outcome) > 2 else None
        self._send(status, payload, extra)


class Server:
    """仿真服务句柄：.port/.mode + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _FabricHTTPServer, thread: threading.Thread, mode: str):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{k: v for k, v in entry.items() if k != "behavior"}
                for entry in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE) -> Server:
    """启动 fabric 破坏面仿真服务（单服务器，仅 127.0.0.1，内存态）。

    port=0 自动分配；mode ∈ {vulnerable, fixed}。
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _FabricHTTPServer((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 万卡 fabric 破坏面仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode)
    print(f"fabric-dos-sim listening on {server.url('/')} mode={server.mode}")
    print(f"routes manifest: {server.url('/__routes__')}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
