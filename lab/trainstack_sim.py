# -*- coding: utf-8 -*-
"""lab/trainstack_sim.py — 预训练 / SFT / RL 训练栈仿真靶场（仅标准库，仅 127.0.0.1）。

两种姿态（与真实训练栈修复语义同构）：

- ``vulnerable``：训练配置/环境变量对全网开放（HF/W&B 令牌可见）、etcd rendezvous
  无鉴权无 TLS、checkpoint optimizer state 分片可写、数据分片可追加篡改（采样器
  只能"事后检出"）、chat template/default_system 可改写并原样渲染、MLflow/W&B/
  TensorBoard 无鉴权（跨租户 run 与凭据）、LLaMA-Factory/ms-swift/TRL 提交面开放
  （file:// 数据路径 + trust_remote_code）、RL rollout 缓冲跨租户可读写、
  奖励曲线多指标异常（长度膨胀/KL 坍塌/熵下降/裁判一致率下降）、
  作业提交面接受 hostPath+privileged+共享 trainer-admin SA。
- ``fixed``：以上读面需管理密钥（401）、写面 401、跨租户轨迹 403、
  渲染器转义保留 token（sanitized）、奖励指标健康、配置脱敏（trust_remote_code=false，
  令牌 MOCK****尾4位）。

路由清单（``GET /__routes__`` 返回同表 JSON）见 ``ROUTE_TABLE``。

写盘边界：仅 ``Server.root``（默认临时目录，shutdown 清理）；所有 shard id 经
``_safe_name`` 归一，路径穿越在仿真器内被消除。
命令行：``python lab/trainstack_sim.py [--port N] [--mode vulnerable|fixed] [--root DIR]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
ADMIN_TOKEN = "trainstack-admin-key"
TENANT_HEADER = "X-Tenant"
ALLOWED_TENANTS = ("tenant-a", "tenant-b", "tenant-c")

WORLD_SIZE = 512
DEFAULT_TEMPLATE = (
    "<|im_start|>system\n{{ system }}<|im_end|>\n"
    "<|im_start|>user\n{{ user }}<|im_end|>\n"
    "<|im_start|>assistant\n"
)
DEFAULT_SYSTEM = "You are a helpful assistant."
SPECIAL_TOKENS = ["<|im_start|>", "<|im_end|>", "<|endoftext|>", "<<SYS>>", "[INST]"]

TRAIN_CONFIG = {
    "framework": "megatron-core + deepspeed",
    "version": "core_v0.19.2 / v0.19.8",
    "world_size": WORLD_SIZE,
    "parallelism": {"tp": 8, "pp": 4, "ep": 32, "cp": 4, "sp": 2},
    "micro_batch_size": 2,
    "global_batch_size": 2048,
    "checkpoint_dir": "/shared/checkpoints/tenant-a/megatron",
    "optimizer_state_dir": "/shared/checkpoints/tenant-a/optim",
    "data_dir": "/shared/datasets/tenant-a/webdataset",
    "trust_remote_code": True,
    "rendezvous": {"backend": "etcd", "endpoint": "10.0.0.11:2379", "tls": False},
    "distributed_backend": "nccl",
    "nccl_bootstrap_port": 29500,
}

TRAIN_ENV = [
    {"name": "MASTER_ADDR", "value": "10.0.0.11"},
    {"name": "MASTER_PORT", "value": "29500"},
    {"name": "HF_TOKEN", "value": "MOCK-hf-trainstack-9f3c"},
    {"name": "WANDB_API_KEY", "value": "MOCK-wandb-trainstack-71ae"},
    {"name": "NCCL_IB_DISABLE", "value": "0"},
    {"name": "TRANSFORMERS_OFFLINE", "value": "0"},
]

ELASTIC = {
    "rdzv_backend": "etcd",
    "rdzv_endpoint": "10.0.0.11:2379",
    "etcd_auth": "none",
    "tls": False,
    "dynamic_membership": True,
    "standalone": False,
    "c10d_port": 29500,
    "members": ["trainer-0", "trainer-1", "trainer-2", "trainer-3"],
}

MLFLOW_RUNS = [
    {"run_id": "run-a-001", "experiment": "tenant-a-sft", "tenant": "tenant-a",
     "artifact_uri": "s3://mlflow/tenant-a/run-a-001", "status": "FINISHED"},
    {"run_id": "run-b-001", "experiment": "tenant-b-finetune", "tenant": "tenant-b",
     "artifact_uri": "s3://weights-b/mlflow/run-b-001", "status": "RUNNING"},
    {"run_id": "run-b-002", "experiment": "tenant-b-rl", "tenant": "tenant-b",
     "artifact_uri": "s3://weights-b/mlflow/run-b-002", "status": "RUNNING"},
]

MLFLOW_CONFIG = {
    "tracking_uri": "http://mlflow.internal:5000",
    "backend_store": "postgresql://mlflow:mlflow@mlflow-db:5432/mlflow",
    "artifact_root": "s3://weights-b/mlflow",
    "auth": "none",
    "exposed": True,
}

WANDB_KEYS = {
    "entity": "shared-ml",
    "keys": [
        {"name": "WANDB_API_KEY", "tenant": "tenant-a", "value": "MOCK-wandb-runner-3d21"},
        {"name": "WANDB_API_KEY", "tenant": "tenant-b", "value": "MOCK-wandb-runner-88b0"},
    ],
    "auth": "none",
}

TENSORBOARD_RUNS = [
    {"run": "tenant-a/exp-1", "tenant": "tenant-a", "event_dir": "/shared/tb/tenant-a/exp-1",
     "scalars": ["loss", "lr"]},
    {"run": "tenant-b/exp-1", "tenant": "tenant-b", "event_dir": "/shared/tb/tenant-b/exp-1",
     "scalars": ["loss", "reward", "kl"]},
]

SFT_DATASETS = [
    {"name": "alpaca-gpt4-zh", "tenant": "tenant-a", "path": "/shared/sft/alpaca-gpt4-zh"},
    {"name": "tenant-b-private-sft", "tenant": "tenant-b",
     "path": "/shared/sft/tenant-b-private-sft"},
]

REWARD_SERIES_VULNERABLE = {
    "reward_mean": [0.21, 0.24, 0.29, 0.33, 0.38, 0.44, 0.49, 0.55, 0.61, 0.68, 0.74, 0.81],
    "pass_rate": [0.31, 0.31, 0.30, 0.31, 0.30, 0.31, 0.31, 0.30, 0.31, 0.30, 0.31, 0.30],
    "response_length": [180, 210, 260, 320, 400, 520, 660, 820, 1010, 1240, 1500, 1800],
    "kl": [0.021, 0.020, 0.018, 0.015, 0.012, 0.009, 0.006, 0.004, 0.002, 0.0010, 0.0005, 0.0002],
    "entropy": [2.4, 2.3, 2.1, 1.9, 1.7, 1.5, 1.3, 1.1, 0.9, 0.7, 0.5, 0.35],
    "judge_agreement": [0.92, 0.90, 0.87, 0.83, 0.78, 0.72, 0.66, 0.60, 0.54, 0.48, 0.42, 0.36],
    "unique_answer_ratio": [0.88, 0.84, 0.79, 0.72, 0.64, 0.55, 0.47, 0.39, 0.31,
                            0.25, 0.19, 0.14],
    "train_eval_gap": [0.02, 0.03, 0.05, 0.08, 0.11, 0.15, 0.20, 0.26, 0.33, 0.41, 0.50, 0.60],
}

REWARD_SERIES_HEALTHY = {
    "reward_mean": [0.20, 0.23, 0.26, 0.29, 0.32, 0.35, 0.38, 0.41, 0.44, 0.47, 0.50, 0.53],
    "pass_rate": [0.30, 0.32, 0.34, 0.36, 0.38, 0.40, 0.42, 0.44, 0.46, 0.48, 0.50, 0.52],
    "response_length": [180, 182, 185, 183, 186, 184, 187, 185, 188, 186, 189, 187],
    "kl": [0.021, 0.021, 0.022, 0.021, 0.020, 0.021, 0.022, 0.021, 0.020, 0.021, 0.022, 0.021],
    "entropy": [2.40, 2.39, 2.41, 2.38, 2.40, 2.39, 2.37, 2.38, 2.36, 2.37, 2.35, 2.36],
    "judge_agreement": [0.92, 0.92, 0.93, 0.92, 0.93, 0.92, 0.93, 0.92, 0.93, 0.92, 0.93, 0.92],
    "unique_answer_ratio": [0.88, 0.87, 0.88, 0.87, 0.88, 0.87, 0.88, 0.87, 0.88,
                            0.87, 0.88, 0.87],
    "train_eval_gap": [0.02, 0.02, 0.03, 0.02, 0.02, 0.03, 0.02, 0.02, 0.03, 0.02, 0.02, 0.03],
}


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_name(value: str, fallback: str = "unnamed") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return cleaned or fallback


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=1) + "\n"
    path.write_bytes(text.encode("utf-8"))


# ---------------------------------------------------------------- 路径约定
def optimizer_state_path(root: Path | str, shard_id: str) -> Path:
    """optimizer state 分片落盘路径（测试/实效验证与仿真器共用）。"""
    return Path(root) / "ckpt" / "optimizer" / f"{_safe_name(shard_id, 'shard')}.pt"


def data_shard_path(root: Path | str, shard_id: str) -> Path:
    return Path(root) / "data" / f"{_safe_name(shard_id, 'shard')}.jsonl"


def data_manifest_path(root: Path | str) -> Path:
    return Path(root) / "data" / "manifest.json"


def template_path(root: Path | str) -> Path:
    return Path(root) / "tokenizer" / "template.jinja"


def rollout_buffer_path(root: Path | str) -> Path:
    return Path(root) / "rl" / "rollout.jsonl"


def sft_jobs_path(root: Path | str) -> Path:
    return Path(root) / "sft" / "jobs.json"


def jobs_path(root: Path | str) -> Path:
    return Path(root) / "jobs" / "submitted.json"


# ---------------------------------------------------------------- 状态播种
def _seed_shard(root: Path, shard_id: str, samples: list[dict]) -> dict:
    path = data_shard_path(root, shard_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(s, ensure_ascii=False) for s in samples]
    content = "\n".join(lines) + "\n"
    path.write_bytes(content.encode("utf-8"))
    return {
        "shard_id": shard_id,
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256_text(content),
        "samples": [{"id": s["id"], "sha256": _sha256_text(json.dumps(s, ensure_ascii=False))}
                    for s in samples],
    }


class _State:
    def __init__(self, root: Path):
        self.lock = threading.Lock()
        self.root = root
        (root / "config").mkdir(parents=True, exist_ok=True)
        (root / "ckpt" / "optimizer").mkdir(parents=True, exist_ok=True)
        (root / "data").mkdir(parents=True, exist_ok=True)
        (root / "tokenizer").mkdir(parents=True, exist_ok=True)
        (root / "tracker").mkdir(parents=True, exist_ok=True)
        (root / "sft").mkdir(parents=True, exist_ok=True)
        (root / "rl").mkdir(parents=True, exist_ok=True)
        (root / "jobs").mkdir(parents=True, exist_ok=True)

        _write_json(root / "config" / "train-config.json", TRAIN_CONFIG)
        _write_json(root / "config" / "train-env.json", {"env": TRAIN_ENV})
        _write_json(root / "config" / "elastic.json", ELASTIC)

        for shard_id in ("ckpt-optim-smoke", "ckpt-optim-0001"):
            target = optimizer_state_path(root, shard_id)
            if not target.is_file():
                target.write_text(
                    json.dumps({"shard": shard_id, "step": 100, "exp_avg_norm": 0.42,
                                "seed": "inkblade-mock"}, ensure_ascii=False) + "\n",
                    encoding="utf-8")

        self.manifest = {"schema": "inkblade-trainstack-data-v1", "shards": [
            _seed_shard(root, "shard-0001", [
                {"id": "s-0001", "text": "INKBLADE-SAMPLE-ALPHA"},
                {"id": "s-0002", "text": "INKBLADE-SAMPLE-BRAVO"},
                {"id": "s-0003", "text": "INKBLADE-SAMPLE-CHARLIE"},
                {"id": "s-0004", "text": "INKBLADE-SAMPLE-DELTA"},
            ]),
        ], "sampler": {"seed": 7, "strategy": "epoch-rotate"}}
        _write_json(data_manifest_path(root), self.manifest)

        self.template = DEFAULT_TEMPLATE
        self.baseline_template_sha = _sha256_text(DEFAULT_TEMPLATE)
        self.default_system = DEFAULT_SYSTEM
        self.baseline_system = DEFAULT_SYSTEM
        self.special_tokens = list(SPECIAL_TOKENS)
        template_path(root).write_bytes(self.template.encode("utf-8"))
        _write_json(root / "tokenizer" / "special_tokens.json",
                    {"special_tokens": self.special_tokens,
                     "default_system": self.default_system})

        _write_json(root / "tracker" / "runs.json", {"runs": MLFLOW_RUNS, "auth": "none"})
        _write_json(root / "tracker" / "mlflow-config.json", MLFLOW_CONFIG)
        _write_json(root / "tracker" / "wandb-keys.json", WANDB_KEYS)
        _write_json(root / "tracker" / "tensorboard-runs.json", {"runs": TENSORBOARD_RUNS})

        _write_json(root / "sft" / "datasets.json", {"datasets": SFT_DATASETS, "auth": "none"})
        _write_json(root / "sft" / "jobs.json", {"jobs": []})

        buffer = rollout_buffer_path(root)
        if not buffer.is_file():
            seed_lines = [
                json.dumps({"tenant": "tenant-a", "trajectory_id": "traj-a-0",
                            "samples": [{"prompt": "p", "response": "r", "reward": 0.1}],
                            "sha256": "seed", "written_at": _utcnow_iso()},
                           ensure_ascii=False),
                json.dumps({"tenant": "tenant-b", "trajectory_id": "traj-b-0",
                            "samples": [{"prompt": "p", "response": "r", "reward": 0.9}],
                            "sha256": "seed", "written_at": _utcnow_iso()},
                           ensure_ascii=False),
            ]
            buffer.write_bytes(("\n".join(seed_lines) + "\n").encode("utf-8"))

        _write_json(jobs_path(root), {"jobs": []})


# ---------------------------------------------------------------- 请求上下文
class _RequestContext:
    def __init__(self, mode, root, state, headers, body, path, query, params, entry):
        self.mode = mode
        self.root = root
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
    def tenant(self) -> str:
        return (self.headers.get(TENANT_HEADER) or self.headers.get("x-tenant") or "").strip()

    @property
    def fixed(self) -> bool:
        return self.mode == "fixed"

    def require_admin(self) -> tuple[int, dict] | None:
        """fixed 姿态读/写面统一要求管理密钥（vulnerable 保持 fail-open）。"""
        if self.fixed and not self.admin:
            return 401, {"error": "unauthorized", "service": "trainstack",
                         "hint": "fixed 模式需要 Authorization: Bearer <admin key>"}
        return None


def _metric_values(series: dict, key: str) -> list:
    return list(series.get(key) or [])


# ---------------------------------------------------------------- 训练配置面
def _train_config(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    cfg = dict(TRAIN_CONFIG)
    if ctx.fixed:
        cfg["trust_remote_code"] = False
        cfg["checkpoint_dir"] = "/shared/checkpoints/<tenant>"
        cfg["optimizer_state_dir"] = "/shared/checkpoints/<tenant>/optim"
        cfg["data_dir"] = "/shared/datasets/<tenant>/webdataset"
        cfg["env"] = {item["name"]: "MOCK****" + item["value"][-4:] for item in TRAIN_ENV}
        cfg["rendezvous"] = {"backend": "etcd", "endpoint": "etcd:2379", "tls": True}
    return 200, cfg


def _train_env(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    if ctx.fixed:
        env = [{"name": item["name"], "value": "MOCK****" + item["value"][-4:]}
               for item in TRAIN_ENV]
    else:
        env = [dict(item) for item in TRAIN_ENV]
    return 200, {"service": "trainstack", "env": env, "count": len(env),
                 "tenant": ctx.tenant or "tenant-a"}


def _train_elastic(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = dict(ELASTIC)
    if ctx.fixed:
        payload.update({"etcd_auth": "mtls", "tls": True, "dynamic_membership": False,
                        "members": []})
    return 200, payload


# ---------------------------------------------------------------- checkpoint 面
def _ckpt_write(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    shard_id = _safe_name(str(ctx.body.get("shard_id") or ""), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    if ctx.body.get("payload") is None:
        return 400, {"error": "missing_payload"}
    text = _as_text(ctx.body.get("payload"))
    path = optimizer_state_path(ctx.root, shard_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return 200, {
        "service": "trainstack", "shard_id": shard_id, "optimizer_state": True,
        "bytes": len(text.encode("utf-8")), "sha256": _sha256_text(text),
        "path": path.relative_to(ctx.root).as_posix(), "updated_at": _utcnow_iso(),
    }


def _ckpt_read(ctx: _RequestContext):
    shard_id = _safe_name(str((ctx.params or {}).get("shard") or ""), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    path = optimizer_state_path(ctx.root, shard_id)
    if not path.is_file():
        return 404, {"error": "shard_not_found", "shard_id": shard_id}
    text = path.read_bytes().decode("utf-8", "replace")
    return 200, {
        "service": "trainstack", "shard_id": shard_id, "optimizer_state": True,
        "payload": text, "bytes": len(text.encode("utf-8")), "sha256": _sha256_text(text),
    }


# ---------------------------------------------------------------- 数据管线面
def _data_manifest(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    return 200, ctx.state.manifest


def _data_write(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    shard_id = _safe_name(str(ctx.body.get("shard_id") or ""), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    payload = ctx.body.get("payload")
    if payload is None:
        return 400, {"error": "missing_payload"}
    text = _as_text(payload)
    lines = [line for line in text.splitlines() if line.strip()]
    path = data_shard_path(ctx.root, shard_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        for line in lines:
            fh.write((line + "\n").encode("utf-8"))
    content = path.read_text(encoding="utf-8")
    return 200, {
        "service": "trainstack", "shard_id": shard_id, "appended": len(lines),
        "bytes": len(text.encode("utf-8")), "sha256": _sha256_text(content),
        "path": path.relative_to(ctx.root).as_posix(), "updated_at": _utcnow_iso(),
    }


def _rotate(items: list, offset: int) -> list:
    if not items:
        return []
    offset %= len(items)
    return items[offset:] + items[:offset]


def _data_sampler(ctx: _RequestContext):
    epoch = int((ctx.query.get("epoch") or ["0"])[0] or 0)
    state = ctx.state
    seed = int(state.manifest.get("sampler", {}).get("seed") or 0)
    expected_ids: list[str] = []
    tampered: list[dict] = []
    duplicate_ids = 0
    unknown_ids = 0
    actual_ids: list[str] = []
    first_expected = ""
    first_actual = ""
    for shard in state.manifest.get("shards") or []:
        expected_ids.extend(s.get("id", "") for s in shard.get("samples") or [])
        path = ctx.root / shard["path"]
        if not first_expected:
            first_expected = str(shard.get("sha256") or "")
        if not path.is_file():
            tampered.append({"shard_id": shard["shard_id"], "reason": "missing"})
            continue
        content = path.read_text(encoding="utf-8")
        if not first_actual:
            first_actual = _sha256_text(content)
        if _sha256_text(content) != shard.get("sha256"):
            counts: dict[str, int] = {}
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    sample = json.loads(line)
                except ValueError:
                    sample = {"id": ""}
                sid = str(sample.get("id") or "")
                counts[sid] = counts.get(sid, 0) + 1
                actual_ids.append(sid)
            duplicate_ids += sum(1 for c in counts.values() if c > 1)
            known = {s.get("id") for s in shard.get("samples") or []}
            unknown_ids += len([i for i in counts if i and i not in known])
            tampered.append({
                "shard_id": shard["shard_id"],
                "expected_sha256": shard.get("sha256"),
                "actual_sha256": _sha256_text(content),
            })
    expected_order = _rotate(expected_ids, seed * epoch)
    actual_order = _rotate(actual_ids, seed * epoch) if actual_ids else list(expected_order)
    return 200, {
        "service": "trainstack", "epoch": epoch, "strategy": "epoch-rotate", "seed": seed,
        "expected_order": expected_order, "order": actual_order,
        "order_changed": actual_order != expected_order,
        "expected_sha256": first_expected, "actual_sha256": first_actual or first_expected,
        "tamper_detected": bool(tampered) or actual_order != expected_order,
        "tampered_shards": tampered,
        "duplicate_ids": duplicate_ids, "unknown_ids": unknown_ids,
        "samples_total": len(actual_ids) or len(expected_ids),
    }


def _data_samples(ctx: _RequestContext):
    shard_id = _safe_name(str((ctx.query.get("shard") or [""])[0]), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    try:
        index = int((ctx.query.get("index") or ["0"])[0])
    except ValueError:
        return 400, {"error": "invalid_index"}
    path = data_shard_path(ctx.root, shard_id)
    if not path.is_file():
        return 404, {"error": "shard_not_found", "shard_id": shard_id}
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if index < 0 or index >= len(lines):
        return 404, {"error": "sample_not_found", "shard_id": shard_id, "index": index}
    line = lines[index]
    return 200, {"service": "trainstack", "shard_id": shard_id, "index": index,
                 "sample": json.loads(line), "sha256": _sha256_text(line),
                 "samples_total": len(lines)}


# ---------------------------------------------------------------- tokenizer / template 面
def _tokenizer_template(ctx: _RequestContext):
    state = ctx.state
    payload = {
        "service": "trainstack", "template": state.template,
        "default_system": state.default_system, "special_tokens": state.special_tokens,
        "sha256": _sha256_text(state.template),
        "baseline_sha256": state.baseline_template_sha,
    }
    if ctx.fixed:
        payload["special_tokens"] = list(state.special_tokens)
    return 200, payload


def _tokenizer_write(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    template = ctx.body.get("template")
    if not isinstance(template, str) or not template:
        return 400, {"error": "missing_template"}
    if "{{ user }}" not in template:
        return 400, {"error": "template_missing_user_slot"}
    state = ctx.state
    state.template = template
    state.default_system = str(ctx.body.get("default_system") or state.default_system)
    template_path(ctx.root).write_bytes(state.template.encode("utf-8"))
    _write_json(ctx.root / "tokenizer" / "special_tokens.json",
                {"special_tokens": state.special_tokens,
                 "default_system": state.default_system})
    return 200, {
        "service": "trainstack", "accepted": True,
        "sha256": _sha256_text(state.template),
        "default_system": state.default_system,
        "template_modified": _sha256_text(state.template) != state.baseline_template_sha,
        "updated_at": _utcnow_iso(),
    }


def _reserved_in(text: str, tokens: list[str]) -> list[str]:
    return sorted({token for token in tokens if token in text})


def _tokenizer_render(ctx: _RequestContext):
    state = ctx.state
    messages = ctx.body.get("messages")
    if not isinstance(messages, list) or not messages:
        return 400, {"error": "missing_messages"}
    user = "\n".join(str((m or {}).get("content", "")) for m in messages
                     if isinstance(m, dict))
    system = str(ctx.body.get("system") or state.default_system)
    if ctx.fixed:
        user_safe = user.replace("<", "&lt;").replace(">", "&gt;")
        system_safe = system
        sanitized = True
    else:
        user_safe, system_safe, sanitized = user, system, False
    rendered = (state.template.replace("{{ system }}", system_safe)
                .replace("{{ user }}", user_safe))
    head = state.template.split("{{ user }}")[0].replace("{{ system }}", system_safe)
    template_modified = _sha256_text(state.template) != state.baseline_template_sha
    system_modified = state.default_system != state.baseline_system
    return 200, {
        "service": "trainstack", "rendered": rendered,
        "system_block": head, "user_block": user_safe,
        "template_sha256": _sha256_text(state.template),
        "baseline_sha256": state.baseline_template_sha,
        "template_modified": template_modified,
        "default_system_modified": system_modified,
        "reserved_in_user": _reserved_in(user, state.special_tokens),
        "sanitized": sanitized,
        "injected_directive": bool(template_modified or system_modified) and not ctx.fixed,
    }


# ---------------------------------------------------------------- 实验追踪面
def _tracker_runs(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    runs = MLFLOW_RUNS
    if ctx.fixed:
        runs = [r for r in MLFLOW_RUNS if r["tenant"] == (ctx.tenant or "tenant-a")]
    return 200, {"service": "mlflow", "runs": [dict(r) for r in runs],
                 "total": len(runs), "auth": "none" if not ctx.fixed else "bearer"}


def _tracker_config(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = dict(MLFLOW_CONFIG)
    if ctx.fixed:
        payload.update({"backend_store": "postgresql://mlflow:****@mlflow-db:5432/mlflow",
                        "artifact_root": "s3://<tenant>/mlflow", "auth": "bearer",
                        "exposed": False})
    return 200, payload


def _tracker_wandb(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    keys = WANDB_KEYS["keys"]
    if ctx.fixed:
        keys = [{"name": k["name"], "tenant": k["tenant"],
                 "value": "MOCK****" + k["value"][-4:]} for k in keys
                if k["tenant"] == (ctx.tenant or "tenant-a")]
    return 200, {"service": "wandb", "entity": WANDB_KEYS["entity"],
                 "keys": [dict(k) for k in keys], "auth": "none" if not ctx.fixed else "bearer"}


def _tracker_tensorboard(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    runs = TENSORBOARD_RUNS
    if ctx.fixed:
        runs = [r for r in TENSORBOARD_RUNS if r["tenant"] == (ctx.tenant or "tenant-a")]
    return 200, {"service": "tensorboard", "runs": [dict(r) for r in runs],
                 "auth": "none" if not ctx.fixed else "bearer"}


# ---------------------------------------------------------------- SFT 框架面
def _sft_llamafactory_status(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = {"service": "llamafactory", "version": "v0.9.5", "bind": "0.0.0.0:7860",
               "auth": False, "data_dir": "/shared/sft", "trust_remote_code": True,
               "webui": True}
    if ctx.fixed:
        payload.update({"bind": "127.0.0.1:7860", "auth": True, "trust_remote_code": False})
    return 200, payload


def _sft_llamafactory_options(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = {"service": "llamafactory", "trust_remote_code": True,
               "allow_file_scheme": True, "dataset_dir": "/shared/sft",
               "accepted_schemes": ["file", "s3", "hf"]}
    if ctx.fixed:
        payload.update({"trust_remote_code": False, "allow_file_scheme": False,
                        "dataset_dir": "/shared/sft/<tenant>",
                        "accepted_schemes": ["s3", "hf"]})
    return 200, payload


def _sft_llamafactory_train(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    config = ctx.body.get("config")
    if not isinstance(config, dict):
        return 400, {"error": "missing_config"}
    dataset_dir = str(config.get("dataset_dir") or "")
    scheme = dataset_dir.split("://", 1)[0] if "://" in dataset_dir else "path"
    run_name = str(config.get("run_name") or f"sft-{uuid.uuid4().hex[:8]}")
    job = {
        "job_id": "sft-" + uuid.uuid4().hex[:12], "run_name": run_name,
        "dataset_dir": dataset_dir, "data_path_scheme": scheme,
        "trust_remote_code": bool(config.get("trust_remote_code")),
        "submitted_at": _utcnow_iso(),
    }
    path = ctx.root / "sft" / "jobs.json"
    doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"jobs": []}
    doc.setdefault("jobs", []).append(job)
    _write_json(path, doc)
    return 200, {"service": "llamafactory", "accepted": True, **job,
                 "auth": "none" if not ctx.fixed else "bearer"}


def _sft_swift_datasets(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    datasets = SFT_DATASETS
    if ctx.fixed:
        datasets = [d for d in SFT_DATASETS if d["tenant"] == (ctx.tenant or "tenant-a")]
    return 200, {"service": "ms-swift", "datasets": [dict(d) for d in datasets],
                 "auth": "none" if not ctx.fixed else "bearer"}


def _sft_trl_status(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = {"service": "trl", "dev_mode": True, "auth": False,
               "host": "0.0.0.0", "port": 8000}
    if ctx.fixed:
        payload.update({"dev_mode": False, "auth": True, "host": "127.0.0.1"})
    return 200, payload


# ---------------------------------------------------------------- RL 轨迹缓冲面
def _rl_write(ctx: _RequestContext):
    tenant = str(ctx.body.get("tenant") or ctx.tenant or "")
    if not tenant:
        return 400, {"error": "missing_tenant"}
    trailer = ctx.tenant
    cross_tenant = bool(trailer and tenant != trailer)
    if ctx.fixed and cross_tenant:
        return 403, {"error": "cross_tenant_rollout_write_denied",
                     "writer_tenant": trailer, "target_tenant": tenant}
    trajectory_id = str(ctx.body.get("trajectory_id") or "")
    if not trajectory_id:
        return 400, {"error": "missing_trajectory_id"}
    samples = ctx.body.get("samples")
    if not isinstance(samples, list):
        return 400, {"error": "missing_samples"}
    entry = {"tenant": tenant, "trajectory_id": trajectory_id, "samples": samples,
             "sha256": _sha256_text(_as_text(samples)), "written_at": _utcnow_iso(),
             "writer_tenant": trailer or tenant}
    path = rollout_buffer_path(ctx.root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        fh.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
    return 200, {"service": "trainstack-rl", "accepted": True, "trajectory_id": trajectory_id,
                 "tenant": tenant, "samples": len(samples), "sha256": entry["sha256"],
                 "cross_tenant": cross_tenant, "shared_buffer": not ctx.fixed}


def _rl_read(ctx: _RequestContext):
    tenant = str((ctx.query.get("tenant") or [ctx.tenant])[0] or "")
    trajectory_id = str((ctx.query.get("trajectory_id") or [""])[0] or "")
    cross_tenant = bool(ctx.tenant and tenant != ctx.tenant)
    if ctx.fixed and cross_tenant:
        return 403, {"error": "cross_tenant_rollout_read_denied",
                     "reader_tenant": ctx.tenant, "target_tenant": tenant}
    path = rollout_buffer_path(ctx.root)
    if not path.is_file():
        return 404, {"error": "buffer_not_found"}
    found = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("tenant") == tenant and (
                not trajectory_id or item.get("trajectory_id") == trajectory_id):
            found = item
    if found is None:
        return 404, {"error": "trajectory_not_found", "tenant": tenant,
                     "trajectory_id": trajectory_id}
    return 200, {"service": "trainstack-rl", "trajectory": found,
                 "cross_tenant_read": cross_tenant}


def _rl_stats(ctx: _RequestContext):
    path = rollout_buffer_path(ctx.root)
    entries = []
    if path.is_file():
        entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
    tenants = sorted({e.get("tenant") for e in entries if e.get("tenant")})
    if ctx.fixed:
        own = ctx.tenant or "tenant-a"
        entries = [e for e in entries if e.get("tenant") == own]
        tenants = sorted({own})
    return 200, {"service": "trainstack-rl", "trajectories": len(entries),
                 "tenants": tenants, "shared_buffer": not ctx.fixed,
                 "tenant": ctx.tenant or "tenant-a"}


# ---------------------------------------------------------------- 奖励指标面
def _rl_reward_metrics(ctx: _RequestContext):
    run = str((ctx.query.get("run") or ["grpo-1"])[0])
    series = REWARD_SERIES_HEALTHY if ctx.fixed else REWARD_SERIES_VULNERABLE
    steps = len(_metric_values(series, "reward_mean"))
    return 200, {"service": "trainstack-rl", "run": run, "mode": ctx.mode,
                 "steps": steps,
                 "series": {key: list(values) for key, values in series.items()}}


# ---------------------------------------------------------------- 作业提交面
def _jobs_cluster(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    payload = {"service": "trainstack-jobs", "scheduler": "slurm+kubernetes",
               "shared_service_account": "trainer-admin",
               "host_network": True, "privileged_allowed": True,
               "submitters": ["tenant-a", "tenant-b"], "queue": "gpu-train"}
    if ctx.fixed:
        payload.update({"shared_service_account": "<per-job>", "host_network": False,
                        "privileged_allowed": False, "submitters": [ctx.tenant or "tenant-a"]})
    return 200, payload


def _jobs_submit(ctx: _RequestContext):
    denial = ctx.require_admin()
    if denial:
        return denial
    spec = ctx.body.get("job_spec")
    if not isinstance(spec, dict):
        return 400, {"error": "missing_job_spec"}
    job = {
        "job_id": "job-" + uuid.uuid4().hex[:12],
        "name": str(spec.get("name") or "train-job"),
        "service_account": str(spec.get("service_account") or "trainer-admin"),
        "host_path": str(spec.get("host_path") or ""),
        "privileged": bool(spec.get("privileged")),
        "image": str(spec.get("image") or "pytorch/pytorch:2.9-cuda12.8"),
        "submitted_at": _utcnow_iso(),
    }
    path = jobs_path(ctx.root)
    doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"jobs": []}
    doc.setdefault("jobs", []).append(job)
    _write_json(path, doc)
    return 200, {"service": "trainstack-jobs", "accepted": True, "job_id": job["job_id"],
                 "service_account": job["service_account"], "host_path": job["host_path"],
                 "privileged": job["privileged"]}


def _jobs_read(ctx: _RequestContext):
    job_id = _safe_name(str((ctx.params or {}).get("job") or ""), "")
    if not job_id:
        return 400, {"error": "missing_job_id"}
    path = jobs_path(ctx.root)
    if not path.is_file():
        return 404, {"error": "job_not_found", "job_id": job_id}
    doc = json.loads(path.read_text(encoding="utf-8"))
    for job in doc.get("jobs") or []:
        if job.get("job_id") == job_id:
            return 200, {"service": "trainstack-jobs", "job": job}
    return 404, {"error": "job_not_found", "job_id": job_id}


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "inkblade-trainstack-lab", "mode": ctx.mode, "host": HOST,
        "admin_token_hint": f"fixed 模式管理密钥 = Authorization: Bearer {ADMIN_TOKEN}",
        "tenant_header": TENANT_HEADER, "route_count": len(ROUTE_TABLE),
        "routes": [{k: v for k, v in entry.items() if k != "behavior"}
                   for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------- 路由表
ROUTE_TABLE = [
    {"service": "trainstack", "title": "训练配置（并行度/checkpoint/环境）",
     "method": "GET", "path": "/train/config", "vulnerable": 200, "fixed": 401,
     "gate": "admin", "writes": False,
     "description": "vulnerable 暴露 world_size/TP-PP-EP-CP-SP/checkpoint 路径/信任远程代码；fixed 401（脱敏）",
     "behavior": _train_config},
    {"service": "trainstack", "title": "训练环境变量", "method": "GET", "path": "/train/env",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable 明文 HF/W&B 令牌；fixed 401（管理密钥返回 MOCK****尾4位）",
     "behavior": _train_env},
    {"service": "trainstack", "title": "torchrun 弹性 rendezvous", "method": "GET",
     "path": "/train/elastic", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable etcd 无鉴权无 TLS + 动态成员；fixed 401（mTLS/固定成员）",
     "behavior": _train_elastic},
    {"service": "trainstack", "title": "optimizer state 分片写入", "method": "POST",
     "path": "/ckpt/optimizer", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True,
     "description": "vulnerable 无鉴权写 optimizer state 分片（真实落盘）；fixed 401",
     "behavior": _ckpt_write},
    {"service": "trainstack", "title": "optimizer state 分片读回", "method": "GET",
     "path": "/ckpt/optimizer/{shard}", "wildcard": True, "vulnerable": 200,
     "fixed": 200, "gate": "open", "writes": False,
     "description": "两态均允许读回已存在分片（缺失 404）", "behavior": _ckpt_read},
    {"service": "trainstack", "title": "数据清单/样本指纹", "method": "GET",
     "path": "/data/manifest", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 暴露分片清单与逐样本 sha256；fixed 401",
     "behavior": _data_manifest},
    {"service": "trainstack", "title": "数据分片追加写入", "method": "POST",
     "path": "/data/shard", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True,
     "description": "vulnerable 无鉴权追加样本（重复/未知 id）；fixed 401",
     "behavior": _data_write},
    {"service": "trainstack", "title": "采样器顺序与完整性校验", "method": "GET",
     "path": "/data/sampler", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False,
     "description": "按 manifest 重算 sha256/顺序；篡改后 tamper_detected=true（两态同语义）",
     "behavior": _data_sampler},
    {"service": "trainstack", "title": "单样本读回", "method": "GET", "path": "/data/samples",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "按 shard+index 读回样本与 sha256", "behavior": _data_samples},
    {"service": "trainstack", "title": "chat template 读取", "method": "GET",
     "path": "/tokenizer/template", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False,
     "description": "两态可读模板与基线 sha（模板是否被改写由调用方判定）",
     "behavior": _tokenizer_template},
    {"service": "trainstack", "title": "chat template 写入", "method": "POST",
     "path": "/tokenizer/template", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True,
     "description": "vulnerable 可改模板/default_system（真实落盘）；fixed 401",
     "behavior": _tokenizer_write},
    {"service": "trainstack", "title": "chat template 渲染", "method": "POST",
     "path": "/tokenizer/render", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False,
     "description": "vulnerable 原样拼接保留 token；fixed 转义用户内容（sanitized=true）",
     "behavior": _tokenizer_render},
    {"service": "mlflow", "title": "MLflow run 列表", "method": "GET",
     "path": "/tracker/mlflow/api/2.0/mlflow/runs", "vulnerable": 200, "fixed": 401,
     "gate": "admin", "writes": False,
     "description": "vulnerable 无鉴权返回跨租户 run；fixed 401（按租户）",
     "behavior": _tracker_runs},
    {"service": "mlflow", "title": "MLflow 后端与 artifact 配置", "method": "GET",
     "path": "/tracker/mlflow/config", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 暴露 postgres 连接串与 s3 artifact root；fixed 401（脱敏）",
     "behavior": _tracker_config},
    {"service": "wandb", "title": "W&B API key 列表", "method": "GET",
     "path": "/tracker/wandb/keys", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 返回多租户 MOCK key；fixed 401（本租户 MOCK****尾4位）",
     "behavior": _tracker_wandb},
    {"service": "tensorboard", "title": "TensorBoard run 目录", "method": "GET",
     "path": "/tracker/tensorboard/runs", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 列出跨租户 event 目录与 scalar；fixed 401",
     "behavior": _tracker_tensorboard},
    {"service": "llamafactory", "title": "LLaMA-Factory WebUI/API 状态", "method": "GET",
     "path": "/sft/llamafactory/api/status", "vulnerable": 200, "fixed": 401,
     "gate": "admin", "writes": False,
     "description": "vulnerable 0.0.0.0 绑定 + 无鉴权；fixed 401（127.0.0.1 + auth）",
     "behavior": _sft_llamafactory_status},
    {"service": "llamafactory", "title": "SFT 数据路径与远程代码选项", "method": "GET",
     "path": "/sft/llamafactory/api/options", "vulnerable": 200, "fixed": 401,
     "gate": "admin", "writes": False,
     "description": "vulnerable 接受 file:// 数据路径 + trust_remote_code；fixed 401",
     "behavior": _sft_llamafactory_options},
    {"service": "llamafactory", "title": "SFT 训练任务提交", "method": "POST",
     "path": "/sft/llamafactory/api/train", "vulnerable": 200, "fixed": 401,
     "gate": "admin", "writes": True,
     "description": "vulnerable 无鉴权接受任务（记录到 sft/jobs.json）；fixed 401",
     "behavior": _sft_llamafactory_train},
    {"service": "ms-swift", "title": "ms-swift 数据集清单", "method": "GET",
     "path": "/sft/ms-swift/datasets", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 返回跨租户数据集路径；fixed 401（本租户）",
     "behavior": _sft_swift_datasets},
    {"service": "trl", "title": "TRL 服务状态", "method": "GET", "path": "/sft/trl/status",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable dev_mode + 0.0.0.0；fixed 401", "behavior": _sft_trl_status},
    {"service": "trainstack-rl", "title": "轨迹写入回放缓冲", "method": "POST",
     "path": "/rl/rollout", "vulnerable": 200, "fixed": 200, "gate": "tenant",
     "writes": True,
     "description": "vulnerable 共享缓冲可跨租户写；fixed 跨租户 403（本租户可写）",
     "behavior": _rl_write},
    {"service": "trainstack-rl", "title": "轨迹读回", "method": "GET", "path": "/rl/rollout",
     "vulnerable": 200, "fixed": 403, "gate": "tenant", "writes": False,
     "description": "vulnerable 可读他租户轨迹；fixed 跨租户 403",
     "behavior": _rl_read},
    {"service": "trainstack-rl", "title": "回放缓冲统计", "method": "GET",
     "path": "/rl/buffer/stats", "vulnerable": 200, "fixed": 200, "gate": "tenant",
     "writes": False,
     "description": "vulnerable 共享缓冲全局计数；fixed 仅本租户计数",
     "behavior": _rl_stats},
    {"service": "trainstack-rl", "title": "奖励/长度/KL/熵多指标序列", "method": "GET",
     "path": "/rl/reward/metrics", "vulnerable": 200, "fixed": 200, "gate": "open",
     "writes": False,
     "description": "vulnerable 奖励升而能力不升（多指标异常）；fixed 健康共变",
     "behavior": _rl_reward_metrics},
    {"service": "trainstack-jobs", "title": "作业提交面与共享 SA", "method": "GET",
     "path": "/jobs/cluster", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": False,
     "description": "vulnerable 共享 trainer-admin SA + hostNetwork 允许；fixed 401",
     "behavior": _jobs_cluster},
    {"service": "trainstack-jobs", "title": "预训练作业提交", "method": "POST",
     "path": "/jobs/submit", "vulnerable": 200, "fixed": 403, "gate": "admin",
     "writes": True,
     "description": "vulnerable 接受 hostPath=/ + privileged + 共享 SA；fixed 403",
     "behavior": _jobs_submit},
    {"service": "trainstack-jobs", "title": "已提交作业读回", "method": "GET",
     "path": "/jobs/submitted/{job}", "wildcard": True, "vulnerable": 200, "fixed": 200,
     "gate": "open", "writes": False,
     "description": "按 job_id 读回已记录作业（缺失 404）", "behavior": _jobs_read},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "返回本清单 JSON（供测试与模块发现）", "behavior": _routes_manifest},
]


# ---------------------------------------------------------------- 路由索引
def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


def _prefix_of(entry: dict) -> str:
    return entry["path"].split("{")[0].rstrip("/")


_EXACT_ROUTES: dict[tuple[str, str], list[dict]] = {}
_PREFIX_ROUTES: list[tuple[str, str, dict]] = []
for _entry in ROUTE_TABLE:
    if "{" in _entry["path"]:
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
    name = entry["path"].rsplit("{", 1)[1].rstrip("}") if "{" in entry["path"] else "param"
    return {name: rest} if rest else {}


# ---------------------------------------------------------------- HTTP 服务
class _TrainstackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, root: Path):
        super().__init__(address, _TrainstackHandler)
        self.lab_mode = mode
        self.lab_root = root
        self.lab_state = _State(root)


class _TrainstackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeTrainstackSim/0.1.0"

    def log_message(self, fmt, *args):
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
        server = self.server  # type: _TrainstackHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode, root=server.lab_root, state=server.lab_state,
            headers=self.headers, body=self._read_body() if method == "POST" else {},
            path=split.path, query=parse_qs(split.query),
            params=_path_params(entry, norm), entry=entry,
        )
        try:
            outcome = entry["behavior"](ctx)
        except Exception as exc:  # 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        status, payload = outcome[0], outcome[1]
        extra = outcome[2] if len(outcome) > 2 else None
        self._send(status, payload, extra)


class Server:
    """仿真服务句柄：.port/.mode/.root + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _TrainstackHTTPServer, thread: threading.Thread, mode: str,
                 root: Path, owns_root: bool):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self.root = root
        self._owns_root = owns_root
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
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join(timeout=5)
        finally:
            if self._owns_root:
                shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE,
              root: Path | str | None = None) -> Server:
    """启动训练栈仿真（单服务器，仅 127.0.0.1）。

    port=0 自动分配；mode ∈ {vulnerable, fixed}；root 缺省临时目录（shutdown 清理），可注入。
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    if root is None:
        root_path = Path(tempfile.mkdtemp(prefix="inkblade-trainstack-"))
        owns_root = True
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        owns_root = False
    httpd = _TrainstackHTTPServer((HOST, int(port)), mode, root_path)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode, root_path, owns_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade 训练栈仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    parser.add_argument("--root", default=None, help="sandbox 根目录（缺省临时目录，退出清理）")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, root=args.root)
    print(f"trainstack sim: {server.url('/')} mode={server.mode} root={server.root}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭训练栈仿真…")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
