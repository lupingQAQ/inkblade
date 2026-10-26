"""trident/verify-effects.py — 实效验证：本机真实进程 + 真实 HTTP 逐项证明攻击效果。

用法::

    python -m trident.verify-effects --out reports/samples/effects/
    python trident/verify-effects.py --out reports/samples/effects/ --no-docs

验证项（全部在本机 127.0.0.1 回环完成，结果可复现）：
a) 未授权管理面利用：sglang-admin-failopen 真实 200 且服务端状态文件变更；
b) 权重投毒实效：slime-weight-pull-poison 对权重文件副本真实写入 benign marker，
   sha256 前后不同且内容含 run marker；
c) 备份回滚实效：backup_targets 快照 → 投毒 → rollback → sha256 与原始完全一致；
d) RCE 实效：areal-setenv-engine-rce 触发 mock 侧真实落地 marker 文件（含 run 标记）；
e) 数据泄露实效：training-data-leak 读到 fixture 假密钥，报告仅以尾4位出现；
f) 检测规则实效：规则引擎对本次靶场重放 validate，断言 ≥1 条规则命中；
g) 端到端链：flat-network-admin-plane-weight-poison dry-run → execute
   （全影响演示级 + 备份），断言链完成且证据三层完整；
h) 长上下文超窗：long-context-window-exhaustion 真实 200 且 /metrics queue_depth 增长；
i) prefix cache 跨租户：无 cache_salt 复用他租户 prefix，usage.cached_tokens>0；
j) PD KV 通道：kv-cache-integrity-poison 真实写入 benign marker 并独立读回（sha256 一致）；
k) checkpoint 分片回滚：checkpoint-shard-poison 写后 sha256 变化，rollback 后与原始完全一致；
l) GPU 跨租户残留：gpu-tenant-residue 分配→释放→读回 benign marker（含释放后），sha256 一致；
m) 云身份跨账户：通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏）；
n) 云桶跨租户：公共桶策略 + 跨租户列目录成功（权重/检查点清单）；
o) AI 网关默认 master key：/config 读到上游 provider MOCK key，报告仅尾 4 位；
p) X-Forwarded-User 伪造：/key/info 返回 admin 全局视图 + /logs 全租户明文；
q) 语义缓存跨租户：tenant-a 以共享前缀键命中 tenant-b 缓存条目；
r) SHARP 在网聚合投毒：入组后篡改 reduce，结果前后差分 + 服务端 tampered_reduces 计数；
s) PFC 暂停风暴：配置写入后 pfc_pause_frames 计数暴增（≥50000）；
t) 慢 rank 注入：straggler 使训练步时劣化 ≥2×（计时差分）；
u) BMC 默认凭据：Redfish 默认凭据登录 200 + IPMI over LAN/匿名管理详情；
v) 固件清单篡改：blob 篡改后哈希不匹配（签名仍有效），finding 为 high；
w) optimizer state 分片：benign marker 写入 → 读回 sha256 一致 → 文件真实变更（回滚精确复原）；
x) 数据管线篡改：分片追加重复/未知样本 → 采样器重算 sha256 检出（expected≠actual）；
y) chat template 注入：模板/default_system 改写 → 渲染 system 槽含注入指令并检出（回滚精确复原）。

边界（写入报告，不隐藏）：本验证是**本机真实进程/真实 HTTP 效果级**，靶场为
``lab/mock_targets.py``、``lab/longctx_sim.py``、``lab/gpu_cloud_sim.py`` 与
``lab/trainstack_sim.py``（均仅 127.0.0.1），
**不是 live K8s 集群 / 真实 GPU 驱动**；KIND（hostNetwork 绕过 NetworkPolicy）与 ARTEX 黑盒
对标需启用虚拟化后按 ``lab/kind/run-proof.sh`` 与 ``lab/bench/artex-bench.sh`` 执行。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.mock_targets import _safe_name, start_all  # noqa: E402
from lab.longctx_sim import checkpoint_shard_path, start_all as start_longctx  # noqa: E402
from lab.gpu_cloud_sim import start_all as start_gpu_cloud  # noqa: E402
from lab.fabric_dos_sim import start_all as start_fabric  # noqa: E402
from lab.privesc_sim import SCENARIOS as PRIVESC_SCENARIOS, run_fake_closure  # noqa: E402
from lab.hardware_sim import FIXTURES as HARDWARE_FIXTURES, start_all as start_hardware  # noqa: E402
from lab.cve_sim import start_all as start_cve_sim  # noqa: E402
from lab.trainstack_sim import (  # noqa: E402
    data_shard_path as trainstack_data_shard,
    optimizer_state_path as trainstack_optimizer_shard,
    start_all as start_trainstack,
    template_path as trainstack_template,
)
from trident.cve_effects import run_cve_checks  # noqa: E402
from trident.depth_effects import run_depth_checks  # noqa: E402
from lab.ai_gateway_sim import (  # noqa: E402
    MASTER_KEY as AI_GATEWAY_MASTER_KEY,
    TENANT_KEYS as AI_GATEWAY_TENANT_KEYS,
    UPSTREAMS as AI_GATEWAY_UPSTREAMS,
    start_all as start_ai_gateway,
)
from trident.core.backup import BackupManager  # noqa: E402
from trident.core.chains import dry_run, execute, load_chains  # noqa: E402
from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.roe import init_roe  # noqa: E402
from trident.core.runner import run_module  # noqa: E402
from trident.core.users import UserStore  # noqa: E402
from trident.reports.render import render_pentest  # noqa: E402
from trident.rules.generate import generate_all  # noqa: E402
from trident.rules.validate import validate  # noqa: E402

MODULES_DIR = REPO_ROOT / "trident" / "modules"
CHAINS_DIR = REPO_ROOT / "trident" / "chains"
THEFT_FIXTURES = REPO_ROOT / "lab" / "fixtures" / "theft"
TARGET_CHAIN = "flat-network-admin-plane-weight-poison"
FAKE_TOKEN = "hf_FAKEtokenDoNotUseSampleABCD1234wxyz"

SCOPE = (
    "本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场：mock_targets / longctx_sim / gpu_cloud_sim / "
    "ai_gateway_sim / fabric_dos_sim / hardware_sim）+ fake-kubectl 提权闭环（lab/privesc_sim.py）"
    "效果级验证；非 live K8s 集群 / 真实 GPU 驱动 / "
    "真实 BMC / 真实交换机 / 真实云账号。"
    "KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行；"
    "真集群提权见 docs/PRIVESC-VERIFICATION.md。"
)
LIMITATIONS = [
    "靶场为 lab/mock_targets.py + lab/longctx_sim.py + lab/gpu_cloud_sim.py + lab/ai_gateway_sim.py + lab/fabric_dos_sim.py + lab/hardware_sim.py 单进程仿真"
    "（仅 127.0.0.1），非真实 K8s API/容器运行时/GPU 推理/云账号。",
    "sglang/areal/slime 的写面以 mock server 侧真实文件落盘为证据，不是远端生产文件系统。",
    "长上下文仿真以 token 计数提示 + KV 计数器表达 128K–1M 窗口行为，不执行真实 attention/KV 传输。",
    "GPU 池化/云租户仿真以池状态文件与 benign marker 表达 MIG/MPS/显存残留与云身份/桶策略，不调用真实 nvidia-smi/STS/S3。",
    "AI 网关仿真为内存态（key/别名/缓存/配额/日志），上游 provider key 一律 MOCK 前缀；不连接真实模型厂商。",
    "fabric 破坏面仿真以内存计数器/状态位表达 SHARP 篡改、PFC 暂停帧、端口耗尽、I/O 洪与驱动复位等效果，"
    "不触碰真实交换机/IB SM/NCCL 进程/GPU 驱动；破坏效果均以计数器与状态变化度量（不真破坏）。",
    "硬件/交换机面为 lab/hardware_sim.py 的只读 mock（Redfish/SONiC/NVSwitch/DPU/telemetry）与 "
    "lab/hardware-fixtures 的合成 fixture；无真实 GPU/BMC/交换机验证，固件签名仅 HMAC fixture，"
    "不等于厂商 PKI/生产供应链。",
    "KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。",
    "ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。",
    "提权 4 项（escalate/bind/SA token/webhook）使用 lab/privesc_sim.py 的 fake-kubectl 内存态闭环；"
    "QEMU k3s 真集群 4 条路径证据见 reports/samples/privesc/real-paths.json 与 docs/PRIVESC-VERIFICATION.md。",
    "训练栈仿真是 lab/trainstack_sim.py（真实 HTTP + 真实文件落盘）：不加载 Megatron/DeepSpeed 权重、"
    "不执行 LLaMA-Factory/ms-swift/TRL 训练、不连接真实 MLflow/W&B/TensorBoard 或 etcd。",
    "研究级深度六项（depth-*）为 lab/depth_sim.py 双态 HTTP、配置快照与准入/信任语义引擎："
    "不连接 live K8s、真实 GPU 驱动、真实交换机/IB SM/SHARP 或真实云账号；"
    "vLLM 240 用例只读探针不投递真实 pickle、不下载权重。",
]

_ABS_PATH_RES = (
    re.compile(r"[A-Za-z]:\\\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
    re.compile(r"[A-Za-z]:\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
)


# ---------------------------------------------------------------- 通用工具


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path | str) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _rel(path: Path | str, root: Path | str) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _scrub(text: str) -> str:
    """公开报告不落本机绝对路径。"""
    for rx in _ABS_PATH_RES:
        text = rx.sub("<abs-path>", text)
    return text


def _load_trace(run, module_key: str) -> dict:
    path = run.dir / "traces" / f"{module_key}.json"
    if not path.is_file():
        raise AssertionError(f"模块未落 HTTP trace：{path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _trace_entry(trace: dict, method: str, suffix: str) -> dict:
    for entry in trace.get("entries", []):
        if entry.get("method") == method and str(entry.get("url", "")).endswith(suffix):
            return entry
    raise AssertionError(f"trace 未命中 {method} {suffix}")


def _trace_match(trace: dict, method: str, needle: str) -> dict:
    """按 URL 子串匹配 trace 条目（查询参数内含动态 allocation id 时使用）。"""
    for entry in reversed(trace.get("entries", [])):
        if entry.get("method") == method and needle in str(entry.get("url", "")):
            return entry
    raise AssertionError(f"trace 未命中 {method} *{needle}*")


def _http_json(url: str, method: str = "GET", body=None, headers: dict | None = None) -> dict:
    """独立 HTTP 调用（verify-effects 侧直连，不复用模块 trace）。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return {"status": status, "payload": payload, "text": text}


class _Checks:
    """逐项 PASS/FAIL 清单；异常即 FAIL（不中断后续检查，便于一次看全）。"""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def run(self, cid: str, title: str, fn: Callable[[], dict[str, Any]]) -> None:
        item: dict[str, Any] = {"id": cid, "title": title, "status": "FAIL", "evidence": {}, "detail": ""}
        started = time.time()
        try:
            item["evidence"] = fn() or {}
            item["status"] = "PASS"
        except Exception as exc:  # noqa: BLE001 —— 任何断言/运行异常都记为该检查 FAIL
            item["detail"] = f"{type(exc).__name__}: {exc}"
        item["elapsed_ms"] = round((time.time() - started) * 1000, 1)
        self.items.append(item)

    @property
    def passed(self) -> int:
        return sum(1 for item in self.items if item["status"] == "PASS")

    @property
    def failed(self) -> int:
        return len(self.items) - self.passed


# ---------------------------------------------------------------- 主流程


def run_verification(out_dir: Path | str, write_docs: bool = True) -> dict[str, Any]:
    """执行全部实效验证项（当前含 fabric 三项与硬件两项）；输出 effects.json + effects.md（可选写 docs/EFFECT-VERIFICATION.md）。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    checks = _Checks()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    state: dict[str, Any] = {}
    result: dict[str, Any] = {}

    with TemporaryDirectory(prefix="trident-effects-") as tmp:
        root = Path(tmp)
        lab_root = root / "lab"
        # 并行在途链可能暂不可解析；效果验证只使用通过契约校验的链（生产 CLI 仍严格失败）
        chains_dir = root / "chains"
        chains_dir.mkdir(parents=True, exist_ok=True)
        for cid, chain in load_chains(CHAINS_DIR, skip_invalid=True).items():
            (chains_dir / f"{cid}.json").write_text(
                json.dumps(chain, ensure_ascii=False, indent=2), encoding="utf-8")
        store = EvidenceStore(root / "workspace", workspace="effects-lab")
        users = UserStore(root / "users.json")
        users.create_user("effects-tester", "x", "tester", ["effects-lab"])
        tester = users.verify("effects-tester", "x")
        init_roe(store, fields={
            "level": "全影响演示",
            "namespaces": ["default", "train", "infer", "ray-system", "ml-agent"],
            "cidrs": ["127.0.0.0/8"],
            "window": f"effects-verification {stamp}",
            "client": "Trident 本机 mock 靶场（授权实验室）",
        })
        run = store.create_run(f"effects-{stamp}")
        lab = start_all(mode="vulnerable", root=lab_root)
        longctx = start_longctx(mode="vulnerable", root=lab_root / "longctx")
        gpu_cloud = start_gpu_cloud(mode="vulnerable", root=lab_root / "gpu-cloud")
        fabric = start_fabric(mode="vulnerable")
        ai_gateway = start_ai_gateway(mode="vulnerable")
        hardware = start_hardware(mode="vulnerable")
        cve_sim = start_cve_sim(mode="vulnerable", root=lab_root / "cve")
        trainstack = start_trainstack(mode="vulnerable", root=lab_root / "trainstack")
        try:
            def admin_plane() -> dict[str, Any]:
                state_path = lab_root / "sglang" / "admin-state.json"
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps({"/pause": {"applied": False, "mode": "seed"}}, ensure_ascii=False),
                    encoding="utf-8",
                )
                before_sha = _sha256_file(state_path)
                run_module(
                    store, tester, "sglang-admin-failopen",
                    {"target": lab.url(""), "mode": "probe-only"},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "sglang-admin-failopen")
                pause = _trace_entry(trace, "POST", "/pause")
                if pause.get("status") != 200:
                    raise AssertionError(f"/pause 未返回 200（实际 {pause.get('status')}）")
                response = pause.get("response") or {}
                if response.get("applied") is not True:
                    raise AssertionError("管理面未报告 applied=true")
                after = json.loads(state_path.read_text(encoding="utf-8"))
                after_sha = _sha256_file(state_path)
                if after.get("/pause", {}).get("applied") is not True:
                    raise AssertionError("服务端状态文件未变更为 applied=true")
                if before_sha == after_sha:
                    raise AssertionError("服务端状态文件 sha256 前后相同")
                return {
                    "http_status": pause["status"],
                    "route": "/pause",
                    "state_file": _rel(state_path, lab_root),
                    "state_sha256_before": before_sha,
                    "state_sha256_after": after_sha,
                    "state_applied": True,
                    "state_response_sha256": response.get("state_sha256", ""),
                }

            checks.run("admin-plane-failopen", "未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更", admin_plane)

            def weight_poison() -> dict[str, Any]:
                marker = f"TRIDENT-{run.name}"
                safe = _safe_name(f"/checkpoints/victim-{marker}", "checkpoint")
                victim = lab_root / "slime" / safe / "model.safetensors"
                victim.parent.mkdir(parents=True, exist_ok=True)
                original = b"TRIDENT-MOCK-WEIGHTS-ORIGINAL\nseed=weights-copy\n"
                victim.write_bytes(original)
                before_sha = _sha256_file(victim)
                state.update({"victim": victim, "original": original, "sha_before": before_sha, "marker": marker})
                run_module(
                    store, tester, "slime-weight-pull-poison",
                    {
                        "target": lab.url(""),
                        "mode": "backup-write",
                        "backup_targets": [{"kind": "file", "path": str(victim)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "slime-weight-pull-poison")
                pull = _trace_entry(trace, "POST", "/pull_weights")
                if pull.get("status") != 200:
                    raise AssertionError(f"/pull_weights 未返回 200（实际 {pull.get('status')}）")
                after_sha = _sha256_file(victim)
                content = victim.read_text(encoding="utf-8", errors="replace")
                if after_sha == before_sha:
                    raise AssertionError("权重文件副本 sha256 前后相同（未真实写入）")
                if marker not in content:
                    raise AssertionError("权重文件副本未含 run marker")
                response = pull.get("response") or {}
                if response.get("weights_sha256") != after_sha:
                    raise AssertionError("mock 响应 weights_sha256 与实际文件不一致")
                return {
                    "http_status": pull["status"],
                    "file": _rel(victim, lab_root),
                    "sha256_before": before_sha,
                    "sha256_after": after_sha,
                    "marker": marker,
                    "marker_present": True,
                    "server_weights_sha256": response.get("weights_sha256"),
                }

            checks.run("weight-poison-write", "权重投毒实效：文件副本 sha256 变化 + benign marker", weight_poison)

            def backup_rollback() -> dict[str, Any]:
                victim = state["victim"]
                before_sha = state["sha_before"]
                original = state["original"]
                bm = BackupManager(store, run)
                result = bm.rollback("slime-weight-pull-poison")
                rows = result["restored"]
                restored_sha = _sha256_file(victim)
                if result["attempted"] < 1:
                    raise AssertionError("未找到备份回执（rollback 行数为 0）")
                if rows < 1:
                    raise AssertionError(f"文件类回滚未还原：{result['items']}")
                if restored_sha != before_sha:
                    raise AssertionError(f"回滚后 sha256 不一致：{restored_sha} != {before_sha}")
                if victim.read_bytes() != original:
                    raise AssertionError("回滚后文件字节与原始副本不一致")
                backups = run.query(
                    "SELECT target, backup_path, sha256 FROM backups WHERE run=? AND step_key=? ORDER BY id",
                    (run.name, "slime-weight-pull-poison"),
                )
                if not backups or backups[0][2] != before_sha:
                    raise AssertionError("备份回执 sha256 与原始文件不一致")
                return {
                    "rollback_rows": rows,
                    "sha256_original": before_sha,
                    "sha256_after_rollback": restored_sha,
                    "exact_restore": True,
                    "backup_receipt_sha256": backups[0][2],
                }

            checks.run("backup-rollback", "备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致", backup_rollback)

            def rce_marker() -> dict[str, Any]:
                marker = f"TRIDENT-{run.name}"
                run_module(
                    store, tester, "areal-setenv-engine-rce",
                    {
                        "target": lab.url(""),
                        "mode": "backup-write",
                        "backup_targets": [{"kind": "http", "url": lab.url("/set_env"), "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "areal-setenv-engine-rce")
                env = _trace_entry(trace, "POST", "/set_env")
                engine = _trace_entry(trace, "POST", "/create_engine")
                call = _trace_entry(trace, "POST", "/call")
                statuses = {"set_env": env.get("status"), "create_engine": engine.get("status"), "call": call.get("status")}
                if statuses != {"set_env": 200, "create_engine": 200, "call": 200}:
                    raise AssertionError(f"三步链状态异常：{statuses}")
                call_resp = call.get("response") or {}
                marker_path = Path(str(call_resp.get("marker", "")))
                if not marker_path.is_file():
                    raise AssertionError("mock 侧 /call 未落地 marker 文件")
                content = marker_path.read_text(encoding="utf-8", errors="replace")
                if marker not in content:
                    raise AssertionError("marker 文件内容不含 run 标记")
                env_marker = Path(str((env.get("response") or {}).get("marker", "")))
                return {
                    "http_statuses": statuses,
                    "marker_file": _rel(marker_path, lab_root),
                    "env_marker_file": _rel(env_marker, lab_root) if env_marker.is_file() else "",
                    "marker": marker,
                    "marker_present": True,
                    "engine_id": call_resp.get("engine_id", ""),
                }

            checks.run("rce-marker", "RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记）", rce_marker)

            def gpu_tenant_residue_marker() -> dict[str, Any]:
                run_module(
                    store, tester, "gpu-tenant-residue",
                    {
                        "target": gpu_cloud.url(""),
                        "mode": "backup-write",
                        "tenant": "tenant-a",
                        "victim_tenant": "tenant-b",
                        "device": "gpu-b-0",
                        "own_device": "gpu-a-1",
                        "backup_targets": [{"kind": "http",
                                            "url": gpu_cloud.url("/gpu/residue"),
                                            "state": {"retained": False}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "gpu-tenant-residue")
                alloc = _trace_match(trace, "POST", "/gpu/allocate")
                release = _trace_match(trace, "POST", "/gpu/release")
                readback = _trace_match(trace, "GET", "/gpu/residue?device=gpu-a-1")
                victim = _trace_match(trace, "GET", "/gpu/residue?device=gpu-b-0")
                statuses = {"allocate": alloc.get("status"), "release": release.get("status"),
                            "readback": readback.get("status"), "victim": victim.get("status")}
                if statuses != {"allocate": 200, "release": 200, "readback": 200, "victim": 200}:
                    raise AssertionError(f"GPU 残留链路状态异常：{statuses}")
                marker = str((alloc.get("body") or {}).get("marker", ""))
                if not marker.startswith("TRIDENT-BENIGN-"):
                    raise AssertionError(f"未使用 benign marker：{marker!r}")
                release_payload = release.get("response") or {}
                readback_payload = readback.get("response") or {}
                entry = (readback_payload.get("residue") or [{}])[0]
                if not entry.get("readable_after_release"):
                    raise AssertionError("残留未标记为 released/readable")
                expected = _sha256_bytes(marker.encode("utf-8"))
                if entry.get("marker_sha256") != expected:
                    raise AssertionError("读回 marker sha256 与写入不一致")
                if entry.get("marker") != marker:
                    raise AssertionError("读回 marker 内容与写入不一致")
                if release_payload.get("residue_sha256") != entry.get("file_sha256"):
                    raise AssertionError("释放响应 residue_sha256 与读回文件 sha256 不一致")
                residue_file = gpu_cloud.root / str(entry.get("residue_file", ""))
                if not residue_file.is_file():
                    raise AssertionError("残留文件未真实落盘")
                file_sha = _sha256_file(residue_file)
                if file_sha != entry.get("file_sha256"):
                    raise AssertionError("残留文件实际 sha256 与响应不一致")
                victim_entry = ((victim.get("response") or {}).get("residue") or [{}])[0]
                if victim_entry.get("tenant") != "tenant-b":
                    raise AssertionError("跨租户残留未命中 tenant-b")
                return {
                    "allocate_status": alloc.get("status"),
                    "release_status": release.get("status"),
                    "readback_status": readback.get("status"),
                    "victim_read_status": victim.get("status"),
                    "tenant": "tenant-a",
                    "victim_tenant": victim_entry.get("tenant"),
                    "device": "gpu-a-1",
                    "victim_device": "gpu-b-0",
                    "marker": marker,
                    "marker_sha256": entry.get("marker_sha256"),
                    "expected_marker_sha256": expected,
                    "readback_file_sha256": entry.get("file_sha256"),
                    "residue_file_sha256": release_payload.get("residue_sha256"),
                    "actual_file_sha256": file_sha,
                    "residue_file": _rel(residue_file, gpu_cloud.root),
                    "readback_after_release": True,
                    "victim_marker_sha256": victim_entry.get("marker_sha256"),
                    "victim_readable": bool(victim_entry),
                }

            checks.run("gpu-tenant-residue-marker",
                       "GPU 跨租户残留实效：benign marker 分配→释放→读回（含释放后）+ sha256 一致",
                       gpu_tenant_residue_marker)

            def cloud_assume_role_cross_account() -> dict[str, Any]:
                run_module(
                    store, tester, "cloud-irsa-trust-wildcard",
                    {
                        "target": gpu_cloud.url(""),
                        "role": "weight-reader",
                        "source_account": "999999999999",
                        "tenant": "tenant-a",
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "cloud-irsa-trust-wildcard")
                identity = _trace_entry(trace, "GET", "/cloud/identity?role=weight-reader")
                assume = _trace_entry(trace, "POST", "/cloud/identity/assume-role")
                if identity.get("status") != 200 or assume.get("status") != 200:
                    raise AssertionError(f"身份/AssumeRole 状态异常：{identity.get('status')}/{assume.get('status')}")
                identity_payload = identity.get("response") or {}
                assume_payload = assume.get("response") or {}
                statement = ((identity_payload.get("trust_policy") or {}).get("Statement") or [{}])[0]
                if statement.get("Principal") != "*":
                    raise AssertionError(f"trust policy Principal 非通配：{statement.get('Principal')!r}")
                if not assume_payload.get("cross_account"):
                    raise AssertionError("AssumeRole 未标记跨账户")
                creds = assume_payload.get("credentials") or {}
                full = "MOCKAKIACROSSTENANT0001"
                findings_text = json.dumps(
                    [f for f in run.findings if f.get("step_key") == "cloud-irsa-trust-wildcard"],
                    ensure_ascii=False)
                if full in findings_text:
                    raise AssertionError("finding 泄漏完整 mock 凭据")
                return {
                    "identity_status": identity.get("status"),
                    "assume_role_status": assume.get("status"),
                    "role_arn": assume_payload.get("role_arn"),
                    "source_account": assume_payload.get("source_account"),
                    "cross_account": True,
                    "wildcard_principal": bool(identity_payload.get("wildcard_principal")),
                    "trust_policy_principal": statement.get("Principal"),
                    "external_id_required": bool(identity_payload.get("external_id_required")),
                    "masked_credentials": {
                        "AccessKeyId": f"MOCK****{str(creds.get('AccessKeyId', ''))[-4:]}",
                        "SecretAccessKey": f"MOCK****{str(creds.get('SecretAccessKey', ''))[-4:]}",
                        "SessionToken": f"MOCK****{str(creds.get('SessionToken', ''))[-4:]}",
                    },
                    "full_credential_absent": True,
                }

            checks.run("cloud-assume-role-cross-account",
                       "云身份实效：通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏）",
                       cloud_assume_role_cross_account)

            def cloud_bucket_public_listing() -> dict[str, Any]:
                run_module(
                    store, tester, "cloud-bucket-cross-tenant",
                    {"target": gpu_cloud.url(""), "bucket": "weights-b", "tenant": "tenant-a"},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "cloud-bucket-cross-tenant")
                policy = _trace_entry(trace, "GET", "/cloud/bucket/policy?bucket=weights-b")
                listing = _trace_entry(trace, "GET", "/cloud/bucket/list?bucket=weights-b&prefix=")
                if policy.get("status") != 200 or listing.get("status") != 200:
                    raise AssertionError(f"桶策略/列目录状态异常：{policy.get('status')}/{listing.get('status')}")
                policy_payload = policy.get("response") or {}
                list_payload = listing.get("response") or {}
                objects = list_payload.get("objects") or []
                keys = [o.get("key") for o in objects]
                if not policy_payload.get("public"):
                    raise AssertionError("桶策略未标记 public")
                if not list_payload.get("cross_tenant"):
                    raise AssertionError("列目录未标记跨租户")
                if not any(str(k).startswith("tenant-b/") for k in keys):
                    raise AssertionError(f"未列出 tenant-b 对象：{keys}")
                return {
                    "policy_status": policy.get("status"),
                    "list_status": listing.get("status"),
                    "bucket": "weights-b",
                    "bucket_owner": list_payload.get("bucket_owner"),
                    "requester": list_payload.get("requester"),
                    "public": True,
                    "cross_tenant": True,
                    "object_count": len(objects),
                    "objects": keys,
                    "policy_principal": ((policy_payload.get("policy") or {}).get("Statement") or [{}])[0].get("Principal"),
                }

            checks.run("cloud-bucket-public-listing",
                       "云桶实效：公共桶策略 + 跨租户列目录成功（权重/检查点清单）",
                       cloud_bucket_public_listing)

            def longctx_window_overflow() -> dict[str, Any]:
                before = _http_json(longctx.url("/metrics"))
                chat = _http_json(
                    longctx.url("/v1/chat/completions"),
                    "POST",
                    {
                        "model": "longctx-mock",
                        "messages": [{"role": "user", "content": "trident effects window probe"}],
                        "context_window": "128k",
                        "prompt_tokens": 200000,
                        "max_tokens": 32,
                        "cache_salt": f"effects-{stamp}",
                    },
                    {"X-Tenant": "tenant-a"},
                )
                after = _http_json(longctx.url("/metrics"))
                if before["status"] != 200 or after["status"] != 200:
                    raise AssertionError(f"/metrics 不可达：{before['status']}/{after['status']}")
                if chat["status"] != 200:
                    raise AssertionError(f"超窗请求未被接受（实际 {chat['status']}）")
                usage = chat["payload"]["usage"]
                window = int(chat["payload"]["context_window"])
                prefill = int(usage["prefill_tokens"])
                if prefill <= window:
                    raise AssertionError(f"prefill_tokens {prefill} 未超窗口 {window}")
                q_before = int(before["payload"]["queue_depth"])
                q_after = int(after["payload"]["queue_depth"])
                if q_after - q_before < 1:
                    raise AssertionError(f"queue_depth 未增长：{q_before} → {q_after}")
                return {
                    "http_status": chat["status"],
                    "context_window_tokens": window,
                    "prefill_tokens": prefill,
                    "queue_depth_before": q_before,
                    "queue_depth_after": q_after,
                    "queue_depth_delta": q_after - q_before,
                    "prefill_pool": after["payload"].get("prefill_pool"),
                    "route": "/v1/chat/completions",
                }

            checks.run("longctx-window-overflow",
                       "长上下文超窗实效：真实 HTTP 200 + prefill_tokens 超窗 + queue_depth 增长",
                       longctx_window_overflow)

            def longctx_prefix_reuse() -> dict[str, Any]:
                prefix = f"TRIDENT-PREFIX-{run.name}"
                body = {
                    "model": "longctx-mock",
                    "messages": [{"role": "user", "content": "trident prefix cache probe"}],
                    "context_window": "128k",
                    "prompt_prefix": prefix,
                    "prefix_tokens": 4096,
                    "prompt_tokens": 4096,
                    "max_tokens": 1,
                }
                prime = _http_json(longctx.url("/v1/chat/completions"), "POST",
                                   dict(body, cache_salt="effects-salt-a"), {"X-Tenant": "tenant-a"})
                reuse = _http_json(longctx.url("/v1/chat/completions"), "POST",
                                   dict(body, cache_salt=None), {"X-Tenant": "tenant-b"})
                if prime["status"] != 200:
                    raise AssertionError(f"租户 A 预热失败：{prime['status']}")
                if reuse["status"] != 200:
                    raise AssertionError(f"租户 B 复用请求未被接受：{reuse['status']}")
                cached = int(reuse["payload"]["usage"]["cached_tokens"])
                if cached <= 0:
                    raise AssertionError("跨租户复用 cached_tokens 为 0")
                if int(prime["payload"]["usage"]["cached_tokens"]) != 0:
                    raise AssertionError("预热请求不应命中缓存")
                return {
                    "prime_status": prime["status"],
                    "reuse_status": reuse["status"],
                    "prime_tenant": "tenant-a",
                    "reuse_tenant": "tenant-b",
                    "cache_salt_present_on_reuse": False,
                    "cached_tokens": cached,
                    "cross_tenant": True,
                    "route": "/v1/chat/completions",
                }

            checks.run("longctx-prefix-reuse",
                       "prefix cache 跨租户实效：无 cache_salt 复用他租户 prefix（cached_tokens>0）",
                       longctx_prefix_reuse)

            def longctx_kv_channel() -> dict[str, Any]:
                block_id = f"kv-block-{run.name}"
                run_module(
                    store, tester, "kv-cache-integrity-poison",
                    {
                        "target": longctx.url(""),
                        "mode": "backup-write",
                        "block_id": block_id,
                        "backup_targets": [{"kind": "http",
                                            "url": longctx.url("/kv/transfer"),
                                            "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "kv-cache-integrity-poison")
                write = _trace_entry(trace, "POST", "/kv/transfer")
                if write.get("status") != 200:
                    raise AssertionError(f"KV 写入未返回 200（实际 {write.get('status')}）")
                write_sha = (write.get("response") or {}).get("sha256", "")
                read = _http_json(
                    longctx.url("/kv/transfer") + "?block_id=" + quote(block_id, safe=""))
                if read["status"] != 200:
                    raise AssertionError(f"KV 读回未返回 200（实际 {read['status']}）")
                payload = read["payload"]
                if not payload.get("found"):
                    raise AssertionError("KV 块读回 not found")
                value = str(payload.get("value") or "")
                marker = f"TRIDENT-{run.name}"
                if marker not in value:
                    raise AssertionError("KV 读回内容不含 run marker")
                read_sha = _sha256_bytes(value.encode("utf-8"))
                if read_sha != write_sha:
                    raise AssertionError(f"KV 读回 sha256 与写入不一致：{read_sha} != {write_sha}")
                return {
                    "write_status": write["status"],
                    "readback_status": read["status"],
                    "block_id": block_id,
                    "readback_found": True,
                    "readback_marker_present": True,
                    "write_sha256": write_sha,
                    "readback_sha256": read_sha,
                    "bytes": len(value.encode("utf-8")),
                }

            checks.run("longctx-kv-channel-write",
                       "PD KV 通道实效：benign marker 真实写入并独立读回（sha256 一致）",
                       longctx_kv_channel)

            def longctx_checkpoint_rollback() -> dict[str, Any]:
                shard_id = "trident-effects-shard"
                path = checkpoint_shard_path(longctx.root, shard_id)
                path.parent.mkdir(parents=True, exist_ok=True)
                original = b"TRIDENT-CHECKPOINT-ORIGINAL\nshard=effects\nepoch=1\n"
                path.write_bytes(original)
                before_sha = _sha256_file(path)
                marker = f"TRIDENT-{run.name}"
                run_module(
                    store, tester, "checkpoint-shard-poison",
                    {
                        "target": longctx.url(""),
                        "mode": "backup-write",
                        "shard_id": shard_id,
                        "backup_targets": [{"kind": "file", "path": str(path)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "checkpoint-shard-poison")
                write = _trace_entry(trace, "POST", "/checkpoint/shards")
                if write.get("status") != 200:
                    raise AssertionError(f"分片写入未返回 200（实际 {write.get('status')}）")
                after_sha = _sha256_file(path)
                if after_sha == before_sha:
                    raise AssertionError("分片文件 sha256 前后相同（未真实写入）")
                content = path.read_text(encoding="utf-8", errors="replace")
                if marker not in content:
                    raise AssertionError("分片文件未含 run marker")
                bm = BackupManager(store, run)
                result = bm.rollback("checkpoint-shard-poison")
                rows = result["restored"]
                restored_sha = _sha256_file(path)
                if result["attempted"] < 1:
                    raise AssertionError("未找到分片备份回执（rollback 行数为 0）")
                if rows < 1:
                    raise AssertionError(f"分片回滚未还原：{result['items']}")
                if restored_sha != before_sha:
                    raise AssertionError(f"回滚后 sha256 不一致：{restored_sha} != {before_sha}")
                if path.read_bytes() != original:
                    raise AssertionError("回滚后分片字节与原始不一致")
                return {
                    "http_status": write["status"],
                    "shard_file": _rel(path, longctx.root),
                    "sha256_before": before_sha,
                    "sha256_after": after_sha,
                    "sha256_after_rollback": restored_sha,
                    "rollback_rows": rows,
                    "exact_restore": True,
                    "marker_present": True,
                    "write_status": write["status"],
                }

            checks.run("longctx-checkpoint-rollback",
                       "checkpoint 分片实效：投毒 sha256 变化 + rollback 后 sha256 与原始完全一致",
                       longctx_checkpoint_rollback)

            def gateway_master_key_exfil() -> dict[str, Any]:
                run_module(
                    store, tester, "aigateway-upstream-key-exfil",
                    {"target": ai_gateway.url(""), "master_key": AI_GATEWAY_MASTER_KEY},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "aigateway-upstream-key-exfil")
                config = _trace_entry(trace, "GET", "/config")
                if config.get("status") != 200:
                    raise AssertionError(f"默认 master key 读 /config 未返回 200（实际 {config.get('status')}）")
                payload = config.get("response") or {}
                upstream_keys = [str(u.get("api_key") or "") for u in payload.get("upstreams") or []]
                if not upstream_keys:
                    raise AssertionError("/config 未返回任何上游 provider key")
                if not all(key.startswith("MOCK-") for key in upstream_keys):
                    raise AssertionError("上游 provider key 非 MOCK 前缀（仿真边界异常）")
                sample = AI_GATEWAY_UPSTREAMS[0]["api_key"]
                if sample not in upstream_keys:
                    raise AssertionError("未读到预期上游 provider key")
                tail4 = sample[-4:]
                findings = [f for f in run.findings if f.get("step_key") == "aigateway-upstream-key-exfil"]
                if not findings:
                    raise AssertionError("上游 key 外泄未产出 finding")
                joined = json.dumps(findings, ensure_ascii=False)
                if sample in joined:
                    raise AssertionError("finding 泄漏完整上游 provider key")
                if f"MOCK****{tail4}" not in joined:
                    raise AssertionError("finding 未以尾4位呈现上游 provider key")
                run.finalize_run()
                report = render_pentest(store, run.name)
                if sample in report:
                    raise AssertionError("报告泄漏完整上游 provider key")
                if f"MOCK****{tail4}" not in report:
                    raise AssertionError("报告未以尾4位呈现上游 provider key")
                return {
                    "http_status": config.get("status"),
                    "route": "/config",
                    "master_key_class": "default",
                    "master_key_used": True,
                    "upstream_key_count": len(upstream_keys),
                    "upstream_providers": [str(u.get("provider")) for u in payload.get("upstreams") or []],
                    "upstream_key_tail4": tail4,
                    "upstream_key_masked": f"MOCK****{tail4}",
                    "full_key_in_finding": False,
                    "report_full_key_absent": True,
                    "report_redacted_sample": f"MOCK****{tail4}",
                }

            checks.run("gateway-default-master-key-exfil",
                       "AI 网关默认 master key：/config 读到上游 MOCK key，报告仅尾4位",
                       gateway_master_key_exfil)

            def gateway_forwarded_user_impersonation() -> dict[str, Any]:
                run_module(
                    store, tester, "aigateway-auth-bypass",
                    {"target": ai_gateway.url(""), "master_key": AI_GATEWAY_MASTER_KEY,
                     "tenant_key": AI_GATEWAY_TENANT_KEYS["tenant-a"], "spoof_user": "admin"},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "aigateway-auth-bypass")
                info = _trace_entry(trace, "GET", "/key/info")
                logs = _trace_entry(trace, "GET", "/logs")
                if info.get("status") != 200:
                    raise AssertionError(f"伪造 X-Forwarded-User 访问 /key/info 未返回 200（实际 {info.get('status')}）")
                info_payload = info.get("response") or {}
                if info_payload.get("scope") != "global" or info_payload.get("subject") != "admin":
                    raise AssertionError(f"/key/info 未返回 admin 全局视图：{info_payload.get('scope')}/{info_payload.get('subject')}")
                tenants = info_payload.get("visible_tenants") or []
                if not tenants or "tenant-b" not in tenants:
                    raise AssertionError(f"/key/info 未暴露他租户：{tenants}")
                if logs.get("status") != 200:
                    raise AssertionError(f"伪造 X-Forwarded-User 访问 /logs 未返回 200（实际 {logs.get('status')}）")
                entries = (logs.get("response") or {}).get("entries") or []
                log_tenants = sorted({str(e.get("tenant")) for e in entries})
                if len(log_tenants) < 2:
                    raise AssertionError(f"/logs 未返回多租户日志：{log_tenants}")
                findings = [f for f in run.findings if f.get("step_key") == "aigateway-auth-bypass"]
                if not any("X-Forwarded-User" in f.get("title", "") for f in findings):
                    raise AssertionError("伪造身份头越权未产出 finding")
                return {
                    "impersonated_user": "admin",
                    "key_info_status": info.get("status"),
                    "scope": info_payload.get("scope"),
                    "visible_tenants": tenants,
                    "logs_status": logs.get("status"),
                    "logs_tenants": log_tenants,
                    "log_entry_count": len(entries),
                    "finding_count": len(findings),
                }

            checks.run("gateway-forwarded-user-impersonation",
                       "AI 网关伪造 X-Forwarded-User：admin 全局 key 视图 + 全租户日志",
                       gateway_forwarded_user_impersonation)

            def gateway_semantic_cache_cross_tenant() -> dict[str, Any]:
                run_module(
                    store, tester, "aigateway-cache-cross-tenant",
                    {"target": ai_gateway.url(""),
                     "tenant_key": AI_GATEWAY_TENANT_KEYS["tenant-a"],
                     "victim_tenant_key": AI_GATEWAY_TENANT_KEYS["tenant-b"],
                     "requester_tenant": "tenant-a", "victim_tenant": "tenant-b"},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "aigateway-cache-cross-tenant")
                lookups = [e for e in trace.get("entries", [])
                           if e.get("method") == "POST" and str(e.get("url", "")).endswith("/cache/lookup")]
                if len(lookups) < 2:
                    raise AssertionError("缓存 trace 缺少 requester/victim 两次 lookup")
                requester_entry, victim_entry = lookups[0], lookups[1]
                requester = requester_entry.get("response") or {}
                victim = victim_entry.get("response") or {}
                if requester_entry.get("status") != 200 or not requester.get("hit"):
                    raise AssertionError(f"tenant-a 未命中 tenant-b 缓存：{requester}")
                entry = requester.get("entry") or {}
                if entry.get("tenant") != "tenant-b":
                    raise AssertionError(f"缓存条目租户不是 tenant-b：{entry.get('tenant')}")
                if requester.get("requester_tenant") != "tenant-a":
                    raise AssertionError("缓存 requester_tenant 记录异常")
                if requester.get("cache_key") != victim.get("cache_key"):
                    raise AssertionError("跨租户 lookup 的 cache_key 不一致（共享前缀键证据不成立）")
                findings = [f for f in run.findings if f.get("step_key") == "aigateway-cache-cross-tenant"]
                if not findings:
                    raise AssertionError("语义缓存跨租户命中未产出 finding")
                return {
                    "requester_status": requester_entry.get("status"),
                    "victim_status": victim_entry.get("status"),
                    "hit": True,
                    "requester_tenant": "tenant-a",
                    "entry_tenant": "tenant-b",
                    "cache_key": requester.get("cache_key"),
                    "victim_cache_key": victim.get("cache_key"),
                    "shared_key": True,
                    "cross_tenant": True,
                    "finding_count": len(findings),
                }

            checks.run("gateway-semantic-cache-cross-tenant",
                       "AI 网关语义缓存跨租户：tenant-a 命中 tenant-b 缓存条目（共享前缀键）",
                       gateway_semantic_cache_cross_tenant)

            def fabric_sharp_reduce_tamper() -> dict[str, Any]:
                run_module(
                    store, tester, "sharp-in-network-poison",
                    {
                        "target": fabric.url(""),
                        "mode": "backup-write",
                        "session_id": "train-job-alpha",
                        "backup_targets": [{"kind": "http",
                                            "url": fabric.url("/sharp/sessions"),
                                            "state": {}},
                                           {"kind": "http",
                                            "url": fabric.url("/sharp/reduce"),
                                            "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "sharp-in-network-poison")
                joins = [e for e in trace["entries"]
                         if e["method"] == "POST" and e["url"].endswith("/sharp/sessions")]
                reduces = [e for e in trace["entries"]
                           if e["method"] == "POST" and e["url"].endswith("/sharp/reduce")]
                if not joins or joins[0].get("status") != 200:
                    raise AssertionError(f"SHARP 入组未返回 200：{joins[0].get('status') if joins else 'no-call'}")
                if len(reduces) < 2:
                    raise AssertionError("缺少基线/篡改两次 reduce")
                baseline, tampered = reduces[0], reduces[1]
                if baseline.get("status") != 200 or tampered.get("status") != 200:
                    raise AssertionError(f"reduce 状态异常：{baseline.get('status')}/{tampered.get('status')}")
                baseline_result = float((baseline.get("response") or {}).get("result"))
                tampered_result = float((tampered.get("response") or {}).get("result"))
                if tampered_result == baseline_result:
                    raise AssertionError("篡改 reduce 结果与基线一致（静默损坏未成立）")
                metrics = _http_json(fabric.url("/metrics"))
                tampered_reduces = int(metrics["payload"]["sharp"]["tampered_reduces"])
                if tampered_reduces < 1:
                    raise AssertionError("服务端 tampered_reduces 计数未增长")
                return {
                    "join_status": joins[0]["status"],
                    "baseline_status": baseline["status"],
                    "tamper_status": tampered["status"],
                    "baseline_result": baseline_result,
                    "tampered_result": tampered_result,
                    "results_differ": tampered_result != baseline_result,
                    "silent": bool((tampered.get("response") or {}).get("silent")),
                    "tampered_reduces": tampered_reduces,
                    "route": "/sharp/sessions,/sharp/reduce",
                }

            checks.run("fabric-sharp-reduce-tamper",
                       "SHARP 在网聚合实效：入组后 reduce 结果被改（前后值差分 + 服务端计数）",
                       fabric_sharp_reduce_tamper)

            def fabric_pfc_storm() -> dict[str, Any]:
                before = _http_json(fabric.url("/roce/pfc"))
                if before["status"] != 200:
                    raise AssertionError(f"/roce/pfc 读失败：{before['status']}")
                run_module(
                    store, tester, "roce-pfc-storm",
                    {
                        "target": fabric.url(""),
                        "mode": "backup-write",
                        "rounds": 3,
                        "backup_targets": [{"kind": "http",
                                            "url": fabric.url("/roce/pfc"),
                                            "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                after = _http_json(fabric.url("/roce/pfc"))
                if after["status"] != 200:
                    raise AssertionError(f"/roce/pfc 复读失败：{after['status']}")
                pause_before = int(before["payload"]["pfc_pause_frames"])
                pause_after = int(after["payload"]["pfc_pause_frames"])
                delta = pause_after - pause_before
                if delta < 50000:
                    raise AssertionError(f"暂停帧计数未达风暴阈值：Δ={delta}")
                if not after["payload"].get("pfc", {}).get("storm"):
                    raise AssertionError("服务端 storm_active 未置位")
                return {
                    "read_status": before["status"],
                    "pfc_pause_frames_before": pause_before,
                    "pfc_pause_frames_after": pause_after,
                    "pfc_pause_frames_delta": delta,
                    "ecn_marks": int(after["payload"].get("ecn_marks") or 0),
                    "storm_active": True,
                    "route": "/roce/pfc",
                }

            checks.run("fabric-pfc-storm-counter",
                       "PFC 风暴实效：配置写入后暂停帧计数暴增（≥50000）",
                       fabric_pfc_storm)

            def fabric_straggler_slowdown() -> dict[str, Any]:
                run_module(
                    store, tester, "nccl-straggler-injection",
                    {
                        "target": fabric.url(""),
                        "mode": "backup-write",
                        "rank": "rank-7",
                        "straggler_ms": 5000,
                        "backup_targets": [{"kind": "http",
                                            "url": fabric.url("/nccl/rank"),
                                            "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "nccl-straggler-injection")
                steps = [e for e in trace["entries"]
                         if e["method"] == "POST" and e["url"].endswith("/train/step")]
                if len(steps) < 2:
                    raise AssertionError("缺少基线/注入后两次步时测量")
                baseline_ms = float((steps[0].get("response") or {}).get("step_ms"))
                slowed_ms = float((steps[-1].get("response") or {}).get("step_ms"))
                ratio = slowed_ms / baseline_ms if baseline_ms > 0 else 0.0
                if ratio < 2.0:
                    raise AssertionError(f"步时劣化不足：{baseline_ms}ms → {slowed_ms}ms（{ratio:.2f}×）")
                injects = [e for e in trace["entries"]
                           if e["method"] == "POST" and e["url"].endswith("/nccl/rank")]
                if not injects or injects[0].get("status") != 200:
                    raise AssertionError("慢 rank 注入未成功")
                return {
                    "inject_status": injects[0]["status"],
                    "baseline_step_ms": baseline_ms,
                    "slowed_step_ms": slowed_ms,
                    "step_time_ratio": round(ratio, 3),
                    "straggler_ms": 5000,
                    "route": "/nccl/rank,/train/step",
                }

            checks.run("fabric-straggler-step-slowdown",
                       "慢 rank 注入实效：训练步时被拖慢 ≥2×（计时差分）",
                       fabric_straggler_slowdown)

            def hardware_bmc_default_credential() -> dict[str, Any]:
                run_module(
                    store, tester, "bmc-ipmi-exposure",
                    {
                        "target": hardware.url(""),
                        "check_default_credentials": True,
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "bmc-ipmi-exposure")
                logins = [e for e in trace["entries"]
                          if e["method"] == "GET"
                          and "/redfish/v1/Systems/1" in e["url"]
                          and e.get("status") == 200]
                if not logins:
                    raise AssertionError("默认凭据未获得 /redfish/v1/Systems/1 200")
                high = [f for f in run.findings
                        if f["step_key"] == "bmc-ipmi-exposure" and f["severity"] == "high"]
                if not high:
                    raise AssertionError("BMC 默认凭据未产出 high finding")
                detail = json.loads(high[0]["detail"])
                for key in ("default_login_status", "ipmi_over_lan", "ipmi_port",
                            "anonymous_manager_read", "credential_class"):
                    if key not in detail:
                        raise AssertionError(f"BMC finding 缺少字段 {key}")
                if detail["default_login_status"] != 200:
                    raise AssertionError("default_login_status != 200")
                if detail["credential_class"] != "vendor-default":
                    raise AssertionError("credential_class 不是 vendor-default")
                if not detail["ipmi_over_lan"] or detail["ipmi_port"] != 623:
                    raise AssertionError("IPMI over LAN/623 未检出")
                if not detail["anonymous_manager_read"]:
                    raise AssertionError("匿名管理详情未检出")
                return {
                    "http_status": logins[0]["status"],
                    "default_login_status": detail["default_login_status"],
                    "default_username": detail.get("default_username", ""),
                    "credential_class": detail["credential_class"],
                    "ipmi_over_lan": detail["ipmi_over_lan"],
                    "ipmi_port": detail["ipmi_port"],
                    "anonymous_manager_read": detail["anonymous_manager_read"],
                    "accounts_status": detail.get("accounts_status"),
                    "network_protocol_status": detail.get("network_protocol_status"),
                    "detected": bool(detail.get("detected")),
                    "route": "/redfish/v1/Systems/1",
                }

            checks.run("hardware-bmc-default-credential",
                       "BMC 默认凭据实效：Redfish 默认凭据登录 200 + IPMI/匿名管理面（mock）",
                       hardware_bmc_default_credential)

            def hardware_firmware_manifest_tamper() -> dict[str, Any]:
                source = HARDWARE_FIXTURES / "firmware"
                target = lab_root / "firmware-tamper"
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target)
                blob = target / "blobs" / "nvswitch-fw-1.8.2.bin"
                before = _sha256_file(blob)
                blob.write_bytes(blob.read_bytes() + b"\nTRIDENT-TAMPER\n")
                after = _sha256_file(blob)
                if before == after:
                    raise AssertionError("固件 blob 篡改后 sha256 未变化")
                run_module(
                    store, tester, "hardware-supply-chain",
                    {
                        "manifest": str(target / "manifest.json"),
                        "key_file": str(source / "fixture-signing-key.txt"),
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                high = [f for f in run.findings
                        if f["step_key"] == "hardware-supply-chain" and f["severity"] == "high"]
                if not high:
                    raise AssertionError("固件清单篡改未产出 high finding")
                rows = run.query(
                    "SELECT result_summary FROM steps WHERE run=? AND step_key=? ORDER BY id DESC LIMIT 1",
                    (run.name, "hardware-supply-chain"),
                )
                summary = json.loads(rows[0][0]) if rows else {}
                detail = json.loads(high[0]["detail"])
                if summary.get("signature_status") != "valid":
                    raise AssertionError("清单签名状态不是 valid（篡改的是 blob，不是清单）")
                if "nvswitch-fw" not in (summary.get("tampered_components") or []):
                    raise AssertionError("tampered_components 未包含 nvswitch-fw")
                if detail.get("expected_sha256") == detail.get("actual_sha256"):
                    raise AssertionError("expected/actual sha256 相同")
                return {
                    "manifest": _rel(target / "manifest.json", lab_root),
                    "tampered_components": summary["tampered_components"],
                    "expected_sha256": detail["expected_sha256"],
                    "actual_sha256": detail["actual_sha256"],
                    "sha256_before": before,
                    "sha256_after": after,
                    "signature_status": summary["signature_status"],
                    "detected": bool(detail.get("detected")),
                    "route": "firmware manifest + blob sha256",
                }

            checks.run("hardware-firmware-manifest-tamper",
                       "固件清单篡改实效：blob 哈希不匹配（签名仍有效），finding 为 high",
                       hardware_firmware_manifest_tamper)

            def data_leak() -> dict[str, Any]:
                run_module(
                    store, tester, "training-data-leak",
                    {"data_root": str(THEFT_FIXTURES)},
                    modules_dir=MODULES_DIR, run=run,
                )
                findings = [f for f in run.findings if f.get("step_key") == "training-data-leak"]
                joined = json.dumps(findings, ensure_ascii=False)
                tail4 = FAKE_TOKEN[-4:]
                if FAKE_TOKEN in joined:
                    raise AssertionError("finding 泄漏完整假密钥")
                if f"****{tail4}" not in joined:
                    raise AssertionError("finding 未保留尾4位指纹")
                run.finalize_run()
                report = render_pentest(store, run.name)
                if FAKE_TOKEN in report:
                    raise AssertionError("报告泄漏完整假密钥")
                if f"****{tail4}" not in report:
                    raise AssertionError("报告未以尾4位呈现假密钥")
                return {
                    "finding_count": len(findings),
                    "tail4": tail4,
                    "redacted_sample": f"****{tail4}",
                    "full_token_absent": True,
                    "report_full_token_absent": True,
                    "report_redacted_sample": f"****{tail4}",
                }

            checks.run("data-leak-redaction", "数据泄露实效：fixture 假密钥仅尾4位进入报告", data_leak)

            rule_pack = root / "rules-pack"

            def rules_detection() -> dict[str, Any]:
                if rule_pack.exists():
                    shutil.rmtree(rule_pack)
                findings = [
                    {"step_key": f["step_key"], "severity": f["severity"], "title": f["title"],
                     "detail": f["detail"], "is_zeroday": bool(f.get("is_zeroday"))}
                    for f in run.findings
                ]
                generate_all(chains_dir, findings=findings, cni="native", out_dir=rule_pack)
                matrix = validate(str(rule_pack), lab.url("/"))
                summary = matrix["summary"]
                hits = int(summary["rules_detected"]) + int(summary["rules_blocked"])
                if hits < 1:
                    raise AssertionError(f"规则引擎 0 命中：{summary}")
                sample_hit = ""
                for cid, row in matrix.get("chains", {}).items():
                    for cell in row.get("rules", []):
                        if cell.get("status") in ("检测", "拦截"):
                            sample_hit = f"{cid} · {cell['rule']} · {cell['status']}"
                            break
                    if sample_hit:
                        break
                shutil.copyfile(rule_pack / "coverage-matrix.json", out / "rules-coverage-matrix.json")
                shutil.copyfile(rule_pack / "coverage-matrix.md", out / "rules-coverage-matrix.md")
                return {
                    "rules_evaluated": int(summary["rules_evaluated"]),
                    "rules_detected": int(summary["rules_detected"]),
                    "rules_blocked": int(summary["rules_blocked"]),
                    "rules_missed": int(summary["rules_missed"]),
                    "hits": hits,
                    "sample_hit": sample_hit,
                    "matrix_ok": bool(matrix.get("ok")),
                    "coverage_file": "rules-coverage-matrix.json",
                }

            checks.run("rules-detection", "检测规则实效：规则引擎对本次靶场重放 ≥1 条命中", rules_detection)

            chain_run = store.create_run(f"effects-chain-{stamp}")

            def chain_e2e() -> dict[str, Any]:
                chain = copy.deepcopy(load_chains(chains_dir)[TARGET_CHAIN])
                chain_marker = f"TRIDENT-{chain_run.name}"
                safe = _safe_name(f"/checkpoints/victim-{chain_marker}", "checkpoint")
                chain_victim = lab_root / "slime" / safe / "model.safetensors"
                chain_victim.parent.mkdir(parents=True, exist_ok=True)
                chain_victim.write_bytes(b"TRIDENT-CHAIN-WEIGHTS-ORIGINAL\n")
                chain_before = _sha256_file(chain_victim)
                for step in chain["steps"]:
                    step.setdefault("params", {})["target"] = lab.url("")
                    if step["module"] == "slime-weight-pull-poison":
                        step["params"]["mode"] = "backup-write"
                        step["params"]["backup_targets"] = [{"kind": "file", "path": str(chain_victim)}]
                findings = run.findings
                plan = dry_run(chain, findings, modules_dir=MODULES_DIR)
                write_steps = [s for s in plan["steps"] if s["writes"]]
                if not write_steps or not write_steps[0]["backup_actions"]:
                    raise AssertionError("dry-run 计划缺少写类步骤/备份动作")
                res = execute(chain, store, tester, modules_dir=MODULES_DIR,
                              findings=findings, workers=2, run=chain_run)
                if not res.get("ok"):
                    raise AssertionError(f"链执行失败：{res['steps']}")
                statuses = {sid: st["status"] for sid, st in res["steps"].items()}
                receipts = chain_run.query(
                    "SELECT COUNT(*) FROM backups WHERE run=? AND step_key='slime-weight-pull-poison'",
                    (chain_run.name,),
                )
                receipts = int(receipts[0][0]) if receipts else 0
                if receipts < 1:
                    raise AssertionError("链内权重投毒步骤无备份回执")
                chain_after = _sha256_file(chain_victim)
                chain_content = chain_victim.read_text(encoding="utf-8", errors="replace")
                if chain_after == chain_before or chain_marker not in chain_content:
                    raise AssertionError("链内权重投毒未真实改写权重副本")
                chain_run.finalize_run()
                context_ok = (chain_run.dir / "context.jsonl.gz").is_file()
                db_ok = (chain_run.dir / "evidence.db").is_file()
                archives = [p for p in (chain_run.dir / "steps").glob("*") if p.is_file()]
                manifest_ok = store.verify_manifest(chain_run.name)
                if not (context_ok and db_ok and archives and manifest_ok):
                    raise AssertionError(
                        f"三层证据不完整：context={context_ok} db={db_ok} archives={len(archives)} manifest={manifest_ok}"
                    )
                return {
                    "chain": TARGET_CHAIN,
                    "verdict": plan["verdict"],
                    "missing": plan["missing"],
                    "ok": True,
                    "steps": statuses,
                    "backup_receipts": receipts,
                    "weights_sha256_before": chain_before,
                    "weights_sha256_after": chain_after,
                    "marker_present": chain_marker in chain_content,
                    "layers": {
                        "context": context_ok,
                        "database": db_ok,
                        "archives": len(archives),
                        "manifest": manifest_ok,
                    },
                    "run": chain_run.name,
                }

            checks.run("chain-e2e", "端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据）", chain_e2e)

            def trainstack_optimizer_marker() -> dict[str, Any]:
                shard_id = "ckpt-optim-effects"
                path = trainstack_optimizer_shard(trainstack.root, shard_id)
                path.parent.mkdir(parents=True, exist_ok=True)
                original = b'{"shard": "ckpt-optim-effects", "step": 1, "exp_avg_norm": 0.5}\n'
                path.write_bytes(original)
                before_sha = _sha256_file(path)
                marker = f"TRIDENT-{run.name}"
                run_module(
                    store, tester, "checkpoint-optimizer-state-poison",
                    {
                        "target": trainstack.url(""),
                        "mode": "backup-write",
                        "shard_id": shard_id,
                        "backup_targets": [{"kind": "file", "path": str(path)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "checkpoint-optimizer-state-poison")
                write = _trace_entry(trace, "POST", "/ckpt/optimizer")
                read = _trace_match(trace, "GET", f"/ckpt/optimizer/{shard_id}")
                if write.get("status") != 200 or read.get("status") != 200:
                    raise AssertionError(
                        f"optimizer state 写/读状态异常：{write.get('status')}/{read.get('status')}")
                after_sha = _sha256_file(path)
                readback = (read.get("response") or {}).get("payload")
                if not isinstance(readback, str) or not readback:
                    raise AssertionError("optimizer state 读回缺少 payload")
                if after_sha == before_sha:
                    raise AssertionError("optimizer state 分片 sha256 前后相同（未真实写入）")
                if marker not in readback or marker not in path.read_text(
                        encoding="utf-8", errors="replace"):
                    raise AssertionError("optimizer state 未含 run marker")
                if _sha256_bytes(readback.encode("utf-8")) != after_sha:
                    raise AssertionError("读回 payload sha256 与落盘文件不一致")
                if (read.get("response") or {}).get("optimizer_state") is not True:
                    raise AssertionError("读回未标记 optimizer_state=true")
                bm = BackupManager(store, run)
                receipt = bm.rollback("checkpoint-optimizer-state-poison")
                restored_sha = _sha256_file(path)
                if receipt["restored"] < 1:
                    raise AssertionError(f"optimizer state 回滚未还原：{receipt['items']}")
                if restored_sha != before_sha or path.read_bytes() != original:
                    raise AssertionError("optimizer state 回滚后与原始不一致")
                return {
                    "http_statuses": {"write": write["status"], "read": read["status"]},
                    "shard_file": _rel(path, trainstack.root),
                    "sha256_before": before_sha,
                    "sha256_after": after_sha,
                    "sha256_after_rollback": restored_sha,
                    "readback_sha256": _sha256_bytes(readback.encode("utf-8")),
                    "marker": marker,
                    "marker_present": True,
                    "optimizer_state": True,
                    "rollback_rows": receipt["restored"],
                    "exact_restore": True,
                }

            checks.run("trainstack-optimizer-state-marker",
                       "optimizer state 实效：benign marker 写入并读回（sha256 一致）+ 回滚精确复原",
                       trainstack_optimizer_marker)

            def trainstack_data_tamper() -> dict[str, Any]:
                shard_id = "shard-0001"
                path = trainstack_data_shard(trainstack.root, shard_id)
                before_sha = _sha256_file(path)
                run_module(
                    store, tester, "data-pipeline-poison",
                    {
                        "target": trainstack.url(""),
                        "mode": "backup-write",
                        "shard_id": shard_id,
                        "backup_targets": [{"kind": "file", "path": str(path)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "data-pipeline-poison")
                write = _trace_entry(trace, "POST", "/data/shard")
                sampler_entries = [e for e in trace.get("entries", [])
                                   if e.get("method") == "GET"
                                   and "/data/sampler" in str(e.get("url", ""))]
                if write.get("status") != 200:
                    raise AssertionError(f"数据分片写未返回 200（实际 {write.get('status')}）")
                if len(sampler_entries) < 2:
                    raise AssertionError("缺少篡改前后两次 sampler 采样")
                after = sampler_entries[-1].get("response") or {}
                if not after.get("tamper_detected"):
                    raise AssertionError("采样器未检出数据篡改")
                if after.get("expected_sha256") == after.get("actual_sha256"):
                    raise AssertionError("expected/actual sha256 相同（篡改不可检出）")
                if int(after.get("duplicate_ids") or 0) < 1:
                    raise AssertionError("未检出重复样本 id")
                if int(after.get("unknown_ids") or 0) < 1:
                    raise AssertionError("未检出未知样本 id")
                actual_sha = _sha256_file(path)
                if actual_sha != after.get("actual_sha256"):
                    raise AssertionError("采样器 actual_sha256 与文件实际 sha256 不一致")
                if actual_sha == before_sha:
                    raise AssertionError("数据分片 sha256 前后相同（未真实追加）")
                bm = BackupManager(store, run)
                receipt = bm.rollback("data-pipeline-poison")
                restored_sha = _sha256_file(path)
                if receipt["restored"] < 1:
                    raise AssertionError(f"数据分片回滚未还原：{receipt['items']}")
                if restored_sha != before_sha:
                    raise AssertionError("数据分片回滚后 sha256 与原始不一致")
                return {
                    "http_status": write["status"],
                    "shard_file": _rel(path, trainstack.root),
                    "appended": int((write.get("response") or {}).get("appended") or 0),
                    "expected_sha256": after.get("expected_sha256"),
                    "actual_sha256": after.get("actual_sha256"),
                    "tamper_detected": True,
                    "duplicate_ids": int(after.get("duplicate_ids") or 0),
                    "unknown_ids": int(after.get("unknown_ids") or 0),
                    "order_changed": bool(after.get("order_changed")),
                    "sha256_after_rollback": restored_sha,
                    "exact_restore": True,
                }

            checks.run("trainstack-data-tamper-detect",
                       "数据采样篡改实效：分片追加重复/未知样本，采样器重算 sha256 检出并可回滚",
                       trainstack_data_tamper)

            def trainstack_template_injection() -> dict[str, Any]:
                path = trainstack_template(trainstack.root)
                original = path.read_bytes()
                before_sha = _sha256_file(path)
                marker = f"TRIDENT-{run.name}"
                run_module(
                    store, tester, "tokenizer-template-injection",
                    {
                        "target": trainstack.url(""),
                        "mode": "backup-write",
                        "backup_targets": [{"kind": "file", "path": str(path)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "tokenizer-template-injection")
                write = _trace_entry(trace, "POST", "/tokenizer/template")
                renders = [e for e in trace.get("entries", [])
                           if e.get("method") == "POST"
                           and str(e.get("url", "")).endswith("/tokenizer/render")]
                if write.get("status") != 200:
                    raise AssertionError(f"模板写入未返回 200（实际 {write.get('status')}）")
                if len(renders) < 2:
                    raise AssertionError("缺少注入前后两次渲染")
                render = renders[-1].get("response") or {}
                if not render.get("template_modified"):
                    raise AssertionError("渲染端未标记模板被改写")
                if not render.get("injected_directive"):
                    raise AssertionError("渲染端未检出注入指令")
                if render.get("sanitized"):
                    raise AssertionError("渲染端仍标记 sanitized=true（未原样拼接）")
                system_block = str(render.get("system_block") or "")
                if marker not in system_block:
                    raise AssertionError("system 槽未包含 run marker 指令")
                after_sha = _sha256_file(path)
                if after_sha == before_sha:
                    raise AssertionError("模板文件 sha256 前后相同（未真实写入）")
                bm = BackupManager(store, run)
                receipt = bm.rollback("tokenizer-template-injection")
                restored_sha = _sha256_file(path)
                if receipt["restored"] < 1:
                    raise AssertionError(f"模板回滚未还原：{receipt['items']}")
                if restored_sha != before_sha or path.read_bytes() != original:
                    raise AssertionError("模板回滚后与原始不一致")
                return {
                    "http_status": write["status"],
                    "template_file": _rel(path, trainstack.root),
                    "sha256_before": before_sha,
                    "sha256_after": after_sha,
                    "template_modified": True,
                    "injected_directive": True,
                    "sanitized": False,
                    "system_block_sha256": _sha256_bytes(system_block.encode("utf-8")),
                    "marker": marker,
                    "marker_in_system_block": True,
                    "sha256_after_rollback": restored_sha,
                    "rollback_rows": receipt["restored"],
                    "exact_restore": True,
                }

            checks.run("trainstack-template-injection-detect",
                       "模板注入实效：system 槽被注入 run marker 指令并检出（原样渲染）+ 回滚精确复原",
                       trainstack_template_injection)

            run_cve_checks(checks, store=store, tester=tester, run=run,
                           lab_root=lab_root, cve_server=cve_sim)

            # 研究级深度六类效果：vLLM 接口 fuzz、准入学、eBPF、GPU、fabric、身份联邦
            run_depth_checks(checks)

            # 提权原语 4 项：fake-kubectl 内存态闭环（真集群证据另见 docs/PRIVESC-VERIFICATION.md）
            fake_privesc = run_fake_closure()
            for item in fake_privesc["checks"]:
                def _privesc_check(item=item):
                    if item["status"] != "PASS":
                        raise AssertionError(f"{item['id']} fake-kubectl 检查失败: {item}")
                    return item["evidence"]
                checks.run(f"privesc-{item['id']}", item["title"], _privesc_check)

            result = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "scope": SCOPE,
                "limitations": LIMITATIONS,
                "run": run.name,
                "chain_run": chain_run.name,
                "privesc_fake_closure": fake_privesc["summary"],
                "checks": checks.items,
                "summary": {
                    "total": len(checks.items),
                    "passed": checks.passed,
                    "failed": checks.failed,
                    "ok": checks.failed == 0,
                },
                "environment": {
                    "python": sys.version.split()[0],
                    "platform": sys.platform,
                    "mock_mode": "vulnerable",
                    "mock_host": "127.0.0.1",
                },
            }
        finally:
            trainstack.shutdown()
            hardware.shutdown()
            cve_sim.shutdown()
            ai_gateway.shutdown()
            fabric.shutdown()
            gpu_cloud.shutdown()
            longctx.shutdown()
            lab.shutdown()

    _write_outputs(out, result, write_docs=write_docs)
    return result


# ---------------------------------------------------------------- 输出


def _md_table(result: dict[str, Any]) -> list[str]:
    lines = [
        "# Trident 实效验证报告（Effect Verification）",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 验证 Run：`{result['run']}`；链 Run：`{result['chain_run']}`",
        f"- 范围与边界：{result['scope']}",
        f"- 汇总：**{result['summary']['passed']}/{result['summary']['total']} PASS**"
        f"（FAIL {result['summary']['failed']}）",
        "",
        "> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级"
        "（`lab/mock_targets.py` + `lab/longctx_sim.py` + `lab/gpu_cloud_sim.py` + `lab/ai_gateway_sim.py`，"
        "仅 127.0.0.1），**非 live K8s 集群 / 真实 GPU 驱动 / 真实云账号**。"
        "KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，"
        "分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；"
        "在虚拟化启用前，这两项不构成本报告的 PASS 结论。",
        "",
        "| 项 | 验证内容 | 结果 | 证据摘要 |",
        "|---|---|---|---|",
    ]
    for item in result["checks"]:
        status = "PASS" if item["status"] == "PASS" else "**FAIL**"
        evidence = json.dumps(item.get("evidence", {}), ensure_ascii=False)
        if item.get("detail"):
            evidence = (evidence + " " + item["detail"]).strip()
        evidence = evidence.replace("|", "\\|").replace("\n", " ")
        if len(evidence) > 420:
            evidence = evidence[:417] + "…"
        lines.append(f"| `{item['id']}` | {item['title']} | {status} | {evidence} |")
    lines += ["", "## 逐项证据", ""]
    for item in result["checks"]:
        lines.append(f"### {item['id']} — {'PASS' if item['status'] == 'PASS' else 'FAIL'}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(item.get("evidence", {}), ensure_ascii=False, indent=2))
        lines.append("```")
        if item.get("detail"):
            lines.append("")
            lines.append(f"失败明细：`{item['detail']}`")
        lines.append("")
    lines += ["## 环境与限制", ""]
    for key, value in result["environment"].items():
        lines.append(f"- {key}: `{value}`")
    for limit in result["limitations"]:
        lines.append(f"- 限制：{limit}")
    lines += [
        "",
        "## 复现命令",
        "",
        "```bash",
        "python -m trident.verify-effects --out reports/samples/effects/",
        "python -m unittest tests.test_verify_effects -v",
        "```",
        "",
    ]
    return lines


def _write_outputs(out: Path, result: dict[str, Any], write_docs: bool) -> None:
    payload = _scrub(json.dumps(result, ensure_ascii=False, indent=2))
    (out / "effects.json").write_text(payload, encoding="utf-8")
    md = _scrub("\n".join(_md_table(result)))
    (out / "effects.md").write_text(md, encoding="utf-8")
    if write_docs:
        docs = REPO_ROOT / "docs" / "EFFECT-VERIFICATION.md"
        docs.parent.mkdir(parents=True, exist_ok=True)
        docs.write_text(md, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    parser = argparse.ArgumentParser(description="Trident 实效验证（本机真实 HTTP，仅 127.0.0.1）")
    parser.add_argument("--out", default=str(REPO_ROOT / "reports" / "samples" / "effects"),
                        help="输出目录（effects.json + effects.md）")
    parser.add_argument("--no-docs", action="store_true", help="不写 docs/EFFECT-VERIFICATION.md")
    args = parser.parse_args(argv)
    result = run_verification(Path(args.out), write_docs=not args.no_docs)
    for item in result["checks"]:
        mark = "PASS" if item["status"] == "PASS" else "FAIL"
        print(f"[{mark}] {item['id']} — {item['title']}"
              + (f"（{item['detail']}）" if item.get("detail") else ""))
    print(f"verify-effects: {result['summary']['passed']}/{result['summary']['total']} PASS"
          f" → {Path(args.out) / 'effects.json'}")
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
