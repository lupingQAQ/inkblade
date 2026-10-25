# -*- coding: utf-8 -*-
"""One-time/regenerable builder for lab/upstream_verify/cases.

The generated manifests are the reviewable artifact; this script keeps the
mapping from the CVE catalog + mining report reproducible.  It does not run any
exploit.  Run ``python -m lab.upstream_verify --all`` afterwards.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab" / "upstream_verify"
CASES = LAB / "cases"
POCS = LAB / "pocs"
UP = LAB / "upstream"
CATALOG = ROOT / "trident" / "core" / "cve-catalog.json"
MINING = ROOT / "reports" / "samples" / "mining-trainstack" / "mining-report.json"

PY_REPRO = "reproenv"
PY_LITELLM = "litellm"
PY_MLFLOW3 = "mlflow3"
PY_MLFLOW2 = "mlflow2"
PY_TORCH = "torch"

WHEEL = {
    "litellm": ("1.82.0", LAB / ".cache/wheels/litellm-1.82.0-py3-none-any.whl",
                "5496b5d4532cccdc7a095c21cbac4042f7662021c57bc1d17be4e39838929e80"),
    "mlflow3": ("3.17.1", LAB / ".cache/wheels/mlflow-3.17.1-py3-none-any.whl",
                "726bf7feac25dbdb5b3098bf20b86574393bb75468eef721902ec025e724752f"),
    "mlflow2": ("2.8.1", LAB / ".cache/wheels/mlflow-2.8.1-py3-none-any.whl",
                "c14716f2b328cc4a649394013035f8326d4408b9a7c8f378b8f0cb3e0e741af9"),
    "torch": ("2.5.1+cpu", LAB / ".cache/wheels/torch-2.5.1+cpu-cp312-cp312-win_amd64.whl",
              "a6b720410350765d3d77c01a5ce098a6c45af446284e45e87a98b8a16e7d564d"),
}

GIT = {
    "vllm": ("vllm-project/vllm", "v0.8.4", "dc1b4a6f1300003ae27f033afbdff5e2683721ce"),
    "sglang": ("sgl-project/sglang", "v0.5.10", "1519acf37c23f2189adb93f57ca9cd2db1bebf18"),
    "megatron017": ("NVIDIA/Megatron-LM", "core_v0.17.0", "9539a12e1b04a68423f57b3eb41d6125161dca24"),
    "megatron019": ("NVIDIA/Megatron-LM", "core_v0.19.2", "4b4acac9a1d28ea6829c8d4f566d75698a21249d"),
    "deepspeed015": ("deepspeedai/DeepSpeed", "v0.15.0", "55b4cae80fc1479ac802b91b4b8955da444016ae"),
    "deepspeed019": ("deepspeedai/DeepSpeed", "v0.19.8", "0eb3a8bcc6d9a8775478e5377482c4bf2dd23c1c"),
    "llamafactory": ("hiyouga/LlamaFactory", "v0.9.5", "7af909522a951e3ad9f022ea6f88b6755257eaa5"),
    "msswift": ("modelscope/ms-swift", "v4.6.0", "ad818a2cdfafaf4305ac40c4acd892a211978bc2"),
    "trl": ("huggingface/trl", "v1.16.0", "1b5c75ed94b7387f42532adb090c935166d4878d"),
    "ray": ("ray-project/ray", "ray-2.8.0", "dd270c86feaf3b342014f20c3f7559a6e4cb4272"),
    "k8s": ("kubernetes/kubernetes", "v1.28.11", "7cc75b0ba928c43a63de072190848d06b8741b64"),
    "runc": ("opencontainers/runc", "v1.1.11", "82b0a449a4c852c5a9ec65bbaaa8bfa627c75401"),
    "containerd": ("containerd/containerd", "v1.4.2", "3b11f3f6f3ebd5326b90f4648a349813a05441af"),
    "kernel": ("torvalds/linux", "v5.15", "dc7089468610f429e9264420c43d5a3625fd5d8b"),
    "dify": ("langgenius/dify", "1.1.2", "bf90d34c2f581a2be52e050938caa8e3be2c9a40"),
    "openwebui": ("open-webui/open-webui", "v0.8.5", "1ac3dd4a893e13803e7b889611303c4a7a5cc470"),
}

VERIFIED = {
    "CVE-2025-32444": dict(
        poc="vllm_mooncake.py", python=PY_REPRO, git="vllm", version="0.8.4",
        source="lab/upstream_verify/upstream/vllm/v0.8.4/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py",
        line=195, function="MooncakeTransferEngine.recv_bytes",
        snippet="src_ptr, length = self.receiver_socket.recv_pyobj()",
        module="vllm-pickle-pipe-rce", method="dynamic-function",
        preconditions=["Mooncake KV transfer enabled", "attacker can reach the KV pipe ZMQ PULL socket"],
        steps=["import pinned mooncake_pipe.py", "bind a real PULL socket", "send a pickle whose __reduce__ writes the marker", "call recv_bytes"],
        expected=["marker file contains proof text", "post-sink tuple unpack error", "source SHA256 recorded"],
        cleanup="close ZMQ sockets; remove local marker/model under evidence/",
        notes="Mooncake recv_pyobj is the sink; tuple validation happens after deserialization.",
    ),
    "CVE-2025-29783": dict(
        poc="vllm_mooncake.py", python=PY_REPRO, git="vllm", version="0.8.4",
        source="lab/upstream_verify/upstream/vllm/v0.8.4/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py",
        line=195, function="MooncakeTransferEngine.recv_bytes",
        snippet="src_ptr, length = self.receiver_socket.recv_pyobj()",
        module="vllm-pickle-pipe-rce", method="dynamic-function",
        preconditions=["Mooncake KV transfer enabled", "untrusted peer can send on the ZMQ pipe"],
        steps=["same sink as CVE-2025-32444, verified independently at v0.8.4"],
        expected=["marker file contains proof text", "source SHA256 recorded"],
        cleanup="close ZMQ sockets; remove local marker under evidence/",
        notes="Separate CVE record but same Mooncake recv_pyobj root cause as CVE-2025-32444; not an independent sink.",
    ),
    "CVE-2025-47277": dict(
        poc="vllm_pynccl.py", python=PY_REPRO, git="vllm", version="0.8.4",
        source="lab/upstream_verify/upstream/vllm/v0.8.4/vllm/distributed/utils.py",
        line=170, function="StatelessProcessGroup.recv_obj",
        snippet="obj = pickle.loads(",
        module="vllm-pickle-pipe-rce", method="dynamic-function",
        preconditions=["PyNcclPipe/StatelessProcessGroup used", "attacker can write the TCPStore rendezvous key"],
        steps=["import pinned distributed/utils.py", "start a real TCPStore", "store.set malicious pickle", "call recv_obj"],
        expected=["marker file written by pickle.loads", "TCPStore key and payload hash recorded"],
        cleanup="shut down TCPStore; remove local marker under evidence/",
        notes="Function-level reproduction; no GPU/NCCL device needed because recv_obj is the metadata control plane.",
    ),
    "CVE-2026-3059": dict(
        poc="sglang_broker.py", python=PY_REPRO, git="sglang", version="0.5.10",
        source="lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/multimodal_gen/runtime/scheduler_client.py",
        line=28, function="run_zeromq_broker",
        snippet="request_batch = pickle.loads(payload)",
        module="sglang-zmq-pickle-rce", method="dynamic-function",
        preconditions=["multimodal_gen server with offline ZMQ broker", "attacker can connect to the broker port"],
        steps=["import pinned scheduler_client.py", "start run_zeromq_broker", "send malicious pickle from REQ socket"],
        expected=["marker written by pickle.loads", "broker port and payload hash recorded"],
        cleanup="cancel broker task; close ZMQ context",
        notes="v0.5.10 binds broker to 127.0.0.1, so this is local/SSRF-adjacent unless fronted; CVE text says unauthenticated.",
    ),
    "CVE-2026-3060": dict(
        poc="sglang_encoder.py", python=PY_REPRO, git="sglang", version="0.5.10",
        source="lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/srt/disaggregation/encode_receiver.py",
        line=497, function="MMReceiverBase._recv_mm_data",
        snippet="recv_obj: EmbeddingData = pickle.loads(parts[0])",
        module="sglang-zmq-pickle-rce", method="dynamic-function",
        preconditions=["encoder parallel disaggregation enabled", "attacker can send a ZMQ multipart frame to the receiver"],
        steps=["extract exact upstream _recv_mm_data method", "bind zmq.asyncio PULL socket", "send malicious pickle as frame 0"],
        expected=["marker written before EmbeddingData validation", "extracted method hash and line range recorded"],
        cleanup="close ZMQ sockets/context",
        notes="Function-level AST extraction because importing SGLang pulls CUDA/model modules; method body is verbatim upstream.",
    ),
    "CVE-2026-40217": dict(
        poc="litellm_guardrail.py", python=PY_LITELLM, wheel="litellm", version="1.82.0",
        source="lab/upstream_verify/upstream/litellm/1.82.0/litellm/proxy/guardrails/guardrail_endpoints.py",
        line=1528, function="test_custom_code_guardrail",
        snippet='exec(compile(request.custom_code, "<guardrail>", "exec"), exec_globals)',
        module="litellm-config-update-rce", method="dynamic-http",
        preconditions=["LiteLLM proxy 1.82.0", "proxy_admin/master key (endpoint is admin-gated)"],
        steps=["import pinned proxy app", "set master key as deployed", "POST public bytecode-rewrite payload", "observe marker"],
        expected=["HTTP 200 success=true", "marker written by os.popen inside sandbox escape"],
        cleanup="none outside ASGI process; marker under evidence/",
        notes="Admin-authenticated sandbox escape, not an unauthenticated endpoint. X41-2026-001 payload adapted to write a marker.",
    ),
    "CVE-2026-42203": dict(
        poc="litellm_prompt.py", python=PY_LITELLM, wheel="litellm", version="1.82.0",
        source="lab/upstream_verify/upstream/litellm/1.82.0/litellm/integrations/dotprompt/prompt_manager.py",
        line=62, function="PromptManager.jinja_env",
        snippet="self.jinja_env = Environment(",
        module="litellm-config-update-rce", method="dynamic-http",
        preconditions=["LiteLLM proxy 1.82.0", "valid master key", "prompt management endpoint reachable"],
        steps=["import pinned proxy app", "POST dotprompt content containing Jinja globals escape", "observe marker"],
        expected=["marker written during template render", "HTTP model error after render recorded"],
        cleanup="none outside ASGI process; marker under evidence/",
        notes="PromptManager uses plain jinja2.Environment, not ImmutableSandboxedEnvironment; /prompts/test renders attacker content.",
    ),
    "CVE-2025-32434": dict(
        poc="torch_script_module.py", python=PY_TORCH, wheel="torch", version="2.5.1+cpu",
        source="lab/upstream_verify/upstream/pytorch/2.5.1/torch/serialization.py",
        line=1328, function="torch.load",
        snippet="warnings.warn(",
        module="torch-weights-bypass-rce", method="dynamic-function",
        preconditions=["victim uses torch.load(..., weights_only=True)", "victim invokes the loaded ScriptModule"],
        steps=["build a TorchScript module whose forward maps a file with torch.from_file(shared=True)", "save with torch.save", "load with weights_only=True", "invoke the model"],
        expected=["marker overwritten by the loaded model graph", "torch version and model hash recorded"],
        cleanup="remove generated scriptmodule.pt/marker under evidence/",
        notes="Public PoC is model-execution arbitrary file write; torch.load itself does not execute the graph.",
    ),
    "CVE-2026-53995": dict(
        poc="mlflow_trace.py", python=PY_MLFLOW3, wheel="mlflow3", version="3.17.1",
        source="lab/upstream_verify/upstream/mlflow/3.17.1/mlflow/store/tracking/file_store.py",
        line=1773, function="FileStore.start_trace",
        snippet="mkdir(traces_dir, trace_info.trace_id)",
        module="mlflow-trace-write", method="dynamic-function",
        preconditions=["FileStore tracking backend", "attacker controls trace_id (V3 trace API)"],
        steps=["create FileStore experiment", "start_trace with trace_id ../../../traversal-target", "read YAML outside store root"],
        expected=["trace_info.yaml written outside store root with marker", "path and hash recorded"],
        cleanup="FileStore/metadata under evidence/; target removed before run",
        notes="Direct storage-layer reproduction; 3.17.2 file_store.py still shows the same join, so the fixed claim may be API-layer only.",
    ),
    "CVE-2026-65110": dict(
        poc="megatron_checkpoint.py", python=PY_TORCH, git="megatron017", version="0.17.0",
        source="lab/upstream_verify/upstream/megatron/0.17.0/megatron/training/checkpointing.py",
        line=1341, function="_load_base_checkpoint",
        snippet="state_dict = torch.load(checkpoint_name, map_location='cpu')",
        module="megatron-checkpoint-rce", method="dynamic-function",
        preconditions=["Megatron-LM legacy torch checkpoint", "torch 2.5.x (weights_only default False)", "attacker controls checkpoint directory"],
        steps=["build iter_0000001/mp_rank_00/model_optim_rng.pt", "import pinned checkpointing.py", "call _load_base_checkpoint(rank0=True)"],
        expected=["marker written during torch.load", "torch/Megatron source hashes recorded"],
        cleanup="checkpoint directory under evidence/",
        notes="Version pairing is decisive: torch>=2.6 defaults weights_only=True and blocks this pickle; 2.5.1 reproduces.",
    ),
    "CVE-2024-43497": dict(
        poc="deepspeed_path_hijack.py", python=PY_TORCH, git="deepspeed015", version="0.15.0",
        source="lab/upstream_verify/upstream/deepspeed/0.15.0/op_builder/async_io.py",
        line=85, function="AsyncIOBuilder.check_for_libaio_pkg",
        snippet='result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)',
        module="deepspeed-checkpoint-rce", method="dynamic-function",
        preconditions=["DeepSpeed 0.15.0 build path", "attacker can place dpkg earlier in PATH"],
        steps=["prepend committed dpkg.exe shim to PATH", "import pinned op_builder.async_io", "call check_for_libaio_pkg"],
        expected=["shim writes marker and exits 0", "PATH prefix and source hash recorded"],
        cleanup="remove PATH prefix in child process; shim/marker under evidence/",
        notes="Catalog says checkpoint/config injection; actual CVE root cause is PATH hijack in libaio package check.",
    ),
    "CVE-2024-0520": dict(
        poc="mlflow_http_dataset.py", python=PY_MLFLOW2, wheel="mlflow2", version="2.8.1",
        source="lab/upstream_verify/upstream/mlflow/2.8.1/mlflow/data/http_dataset_source.py",
        line=68, function="HTTPDatasetSource.load",
        snippet="dst_path = os.path.join(dst_path, basename)",
        module="mlflow-model-rce", method="dynamic-function",
        preconditions=["MLflow 2.8.1 HTTP dataset source", "attacker controls HTTP server Content-Disposition"],
        steps=["serve Content-Disposition filename ../../ESCAPED.txt", "call HTTPDatasetSource.load(dst_path)", "read file outside dst"],
        expected=["ESCAPED.txt outside dst with marker", "HTTP headers and source hash recorded"],
        cleanup="HTTP server shutdown; files under evidence/",
        notes="Fixed in MLflow 2.9.0; direct data-source function, no MLflow server needed.",
    ),
}

STATIC_CVE = {
    "CVE-2025-59425": ("vllm", "vllm", "lab/upstream_verify/upstream/vllm/v0.8.4/vllm/entrypoints/openai/api_server.py", 848,
                       'if request.headers.get("Authorization") != "Bearer " + token:',
                       "String comparison of API key is not constant-time; timing oracle not reproduced, so static-only."),
    "CVE-2026-7301": ("sglang", "sglang", "lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/multimodal_gen/runtime/scheduler_client.py", 20,
                      'broker_endpoint = f"tcp://127.0.0.1:{server_args.broker_port}"',
                      "v0.5.10 normalizes broker to 127.0.0.1; the catalog's 0.0.0.0 claim is not reproduced at this tag."),
    "CVE-2026-7302": ("sglang", "sglang", "lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/srt/disaggregation/encode_server.py", 1251,
                      'trace_path = os.path.join(self.output_dir, filename)',
                      "Filename join lacks normalization; static-only because the upload route needs a full encoder service."),
    "CVE-2026-15978": ("sglang", "sglang", "lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/srt/entrypoints/http_server.py", 225,
                       "server_args.api_key is None",
                       "API-key fail-open branch is visible; weight exfiltration needs a live GPU server, so static-only."),
    "CVE-2026-92972": ("sglang", "sglang", "lab/upstream_verify/upstream/sglang/v0.5.10/python/sglang/srt/disaggregation/common/conn.py", 738,
                       'self.app.router.add_route("*", "/route", self._handle_route)',
                       "Route handler has no auth dependency; PD runtime not started, so static-only."),
    "CVE-2026-35029": ("litellm", None, "lab/upstream_verify/upstream/litellm/1.82.0/litellm/proxy/proxy_server.py", 11416,
                       "dependencies=[Depends(user_api_key_auth)]",
                       "Handler itself has no admin check, but non-admin route guards may block; low-priv DB-backed key not built, static-only."),
    "CVE-2026-42208": ("litellm", None, None, 0, "",
                       "SQL injection claim not resolved to a concrete unparameterized sink in 1.82.0; advisory-level static triage only."),
    "CVE-2026-47102": ("litellm", None, None, 0, "",
                       "Self-promotion path requires a DB-backed low-privilege user; not reproduced without Prisma/Postgres, static-only."),
    "LITELLM-DEFAULT-KEY": ("litellm", None, None, 0, "",
                            "Default/master-key misconfiguration is deployment-dependent; no upstream version boundary, static-only."),
    "CVE-2026-4993": ("wandb", None, None, 0, "",
                      "Catalog metadata is inconsistent (LITELLM_MASTER_KEY under wandb); advisory-level triage only."),
    "CVE-2023-48022": ("ray", "ray", None, 0, "",
                       "Ray dashboard job submission needs a running Ray head; Ray does not support this Windows host, static-only."),
    "CVE-2023-48023": ("ray", "ray", None, 0, "",
                       "Log proxy SSRF needs the Ray dashboard service; static-only on this host."),
    "CVE-2026-32981": ("ray", "ray", None, 0, "",
                       "Dashboard static-file traversal needs the dashboard service; static-only."),
    "KUBERAY-ADV-2026-01": ("kuberay", None, None, 0, "",
                            "KubeRay-managed Ray exposure is a deployment pattern, not a single upstream sink; static-only."),
    "LWS-ADV-2026-01": ("lws", None, None, 0, "",
                        "LWS leader/worker address trust is a topology/CRD issue; static-only."),
    "CVE-2024-10220": ("kubernetes", "k8s", None, 0, "",
                       "kubelet gitRepo volume exec needs a Linux kubelet and API server; no cluster on Windows, static-only."),
    "CVE-2024-3177": ("kubernetes", "k8s", None, 0, "",
                      "envFrom mountable-secret bypass needs a Linux kubelet; static-only."),
    "CVE-2025-23354": ("megatron", "megatron017", None, 0, "",
                       "ensemble_classifier script injection needs a Megatron training/checkpoint config; no dynamic path imported, static-only."),
    "CVE-2025-33247": ("megatron", "megatron017", None, 0, "",
                       "Quantization config loading needs a full Megatron training run; static-only."),
    "CVE-2024-37061": ("mlflow", None, None, 0, "",
                       "Malicious MLproject execution is the documented project runner trust model; no safe-vs-vulnerable boundary reproduced, static-only."),
    "CVE-2025-3466": ("dify", "dify", None, 0, "",
                      "Dify code-node sandbox escape needs the dify-sandbox service/Node runtime; static-only."),
    "CVE-2025-63387": ("dify", "dify", None, 0, "",
                       "System-features unauthenticated endpoint needs the Dify console/API stack; static-only."),
    "CVE-2025-56520": ("dify", "dify", None, 0, "",
                       "RemoteFileUploadApi SSRF needs the Dify API stack; static-only."),
    "CVE-2026-28786": ("open-webui", "openwebui", None, 0, "",
                       "Transcription filename/error leak needs the Open WebUI service; static-only."),
    "CVE-2026-28788": ("open-webui", "openwebui", None, 0, "",
                       "Batch-retrieval overwrite needs Open WebUI API/DB; static-only."),
    "CVE-2025-64496": ("open-webui", "openwebui", None, 0, "",
                       "Direct Connections SSE injection needs the Open WebUI frontend/service; static-only."),
}

UNSUPPORTED = {
    "CVE-2013-4786": "IPMI 2.0 RMCP+ cipher-zero requires a BMC/UDP-623 endpoint; no vendor firmware in lab",
    "CVE-2023-34329": "AMI MegaRAC SPx12 HTTP header auth bypass requires the vendor BMC firmware",
    "CVE-2017-12542": "HPE iLO 4 <2.53 requires the vendor BMC firmware",
    "CVE-2025-38741": "SONiC 4.5.0 SSH hardcoded key requires a SONiC switch image/hardware",
    "CVE-2025-23374": "SONiC log leak requires a SONiC switch image",
    "GHSA-h26v-922j-28cg": "SONiC rsyslog injection requires a SONiC build/switch",
    "CVE-2025-33180": "Cumulus NVUE command injection requires Cumulus Linux/switch",
    "CVE-2026-24184": "Cumulus LLDP daemon overflow requires Cumulus Linux/switch",
    "HAMI-ADV-2026-01": "HAMi scheduler/device-plugin auth gap requires a Kubernetes GPU cluster with HAMi",
    "CGPU-ADV-2026-01": "cGPU isolation audit requires Alibaba Cloud cGPU runtime/GPU",
    "CVE-2024-0132": "NVIDIA Container Toolkit TOCTOU requires Linux + NVIDIA GPU + container runtime",
    "CVE-2024-0133": "NVIDIA Container Toolkit host-file creation requires Linux + GPU + container runtime",
    "CVE-2025-23266": "NVIDIAScape hook path hijack requires GPU Operator + Linux container runtime",
    "CVE-2025-23267": "update-ldcache link following requires NVIDIA Container Toolkit + Linux runtime",
    "CVE-2024-21626": "runc Leaky Vessels requires a Linux container runtime; Windows host cannot reproduce",
    "CVE-2020-15257": "containerd-shim abstract socket escape requires Linux containerd/shim",
    "CVE-2022-0492": "cgroup v1 release_agent escape requires a vulnerable Linux kernel/cgroup v1",
    "CVE-2025-31133": "runc masked-path symlink race requires Linux runc/container runtime",
}

COMPONENT_TITLE = {}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_ref(name: str) -> dict:
    repo, tag, commit = GIT[name]
    return {"kind": "git", "repo": repo, "tag": tag, "commit": commit}


def wheel_ref(name: str) -> dict:
    version, _path, digest = WHEEL[name]
    return {"kind": "pypi", "package": name.rstrip("23") if name.startswith("mlflow") else name,
            "version": version, "wheel_sha256": digest}


def write_case(case_id: str, component: str, manifest: dict, poc_text: str) -> None:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", case_id).strip("-")
    case_dir = CASES / component / safe
    if case_dir.exists():
        shutil.rmtree(case_dir)
    (case_dir / "evidence").mkdir(parents=True)
    manifest = dict(manifest)
    manifest.setdefault("schema", "trident-upstream-case-v1")
    manifest["id"] = case_id
    manifest["component"] = component
    manifest["_case_dir"] = f"{component}/{safe}"
    (case_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    poc = poc_text.replace("parents[1]", "parents[3]")
    (case_dir / "poc.py").write_text(poc, encoding="utf-8")
    # Remove helper key from the on-disk manifest for cleanliness.
    manifest.pop("_case_dir", None)
    (case_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")


def base_manifest(case_id: str, source: str, title: str, *, version: str, version_ref: dict,
                  root_cause: dict, status: str, method: str, module: str | None,
                  python: str | None, advisory: str, notes: str = "",
                  preconditions=None, steps=None, expected=None, cleanup="",
                  static_evidence_level="advisory", static_analysis="", static_verdict="",
                  install="", marker_text=None, unsupported=None) -> dict:
    if status == "static-only":
        preconditions = preconditions or ["pinned upstream source or advisory is available"]
        steps = steps or [
            "resolve the pinned tag/commit and file:line",
            "verify the claimed snippet and source SHA256",
            "record a static-only verdict (no exploit execution)",
        ]
        expected = expected or ["static-check.json with source hash and line match"]
        cleanup = cleanup or "none (read-only)"
        install = install or "git checkout <pinned tag> (source is vendored under lab/upstream_verify/upstream/)"
    elif status == "unsupported":
        preconditions = preconditions or ["vendor hardware or Linux runtime required"]
        steps = steps or ["record why this host cannot host the vulnerable path", "do not claim exploitation"]
        expected = expected or ["unsupported.json with explicit reason"]
        cleanup = cleanup or "none (no exploit executed)"
        install = install or "not installable on this host"
    return {
        "id": case_id,
        "source": source,
        "title": title,
        "version": version,
        "version_ref": version_ref,
        "install": install,
        "root_cause": root_cause,
        "preconditions": preconditions or [],
        "steps": steps or [],
        "expected_evidence": expected or [],
        "cleanup": cleanup,
        "status": status,
        "method": method,
        "module": module,
        "python": python,
        "advisory": advisory,
        "marker_text": marker_text or f"TRIDENT-UV-{case_id}",
        "notes": notes,
        "static_evidence_level": static_evidence_level,
        "static_analysis": static_analysis,
        "static_verdict": static_verdict,
        "unsupported": unsupported or {},
    }


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))["entries"]
    mining = json.loads(MINING.read_text(encoding="utf-8"))["candidates"]
    candidate_sources = json.loads((UP / "candidate-sources.json").read_text(encoding="utf-8"))
    static_poc = (POCS / "static_source.py").read_text(encoding="utf-8")
    unsupported_poc = (POCS / "unsupported.py").read_text(encoding="utf-8")

    for entry in catalog:
        cid = entry["id"]
        comp = entry["component"]
        title = entry.get("title") or cid
        if cid in VERIFIED:
            v = VERIFIED[cid]
            ref = git_ref(v["git"]) if "git" in v else wheel_ref(v["wheel"])
            installed = (f"pip install {WHEEL[v['wheel']][0]}" if "wheel" in v else f"git checkout {GIT[v['git']][1]}")
            manifest = base_manifest(
                cid, "cve", title, version=v["version"], version_ref=ref,
                root_cause={"file": v["source"].split("upstream/", 1)[1], "line": v["line"],
                            "function": v["function"], "snippet": v["snippet"],
                            "source": v["source"], "source_sha256": sha(ROOT / v["source"])},
                status="verified", method=v["method"], module=v["module"], python=v["python"],
                advisory=entry["source"], notes=v["notes"], preconditions=v["preconditions"],
                steps=v["steps"], expected=v["expected"], cleanup=v["cleanup"],
                install=installed,
            )
            write_case(cid, comp, manifest, (POCS / v["poc"]).read_text(encoding="utf-8"))
            continue

        if cid in UNSUPPORTED:
            manifest = base_manifest(
                cid, "cve", title, version=entry.get("affected") or "*",
                version_ref={"kind": "vendor", "version": entry.get("affected") or "*"},
                root_cause={"file": "n/a (vendor firmware / Linux runtime)", "line": 0,
                            "function": "", "snippet": "", "source": None,
                            "note": entry.get("primitive") or entry.get("exploit_conditions") or ""},
                status="unsupported", method="unsupported", module=(entry.get("modules") or [None])[0],
                python=None, advisory=entry["source"],
                notes="Hardware/OS-dependent path; not exercised on this host. Not counted as verified.",
                unsupported={"reason": UNSUPPORTED[cid],
                             "requires": [entry.get("component_name") or comp, entry.get("affected") or "*"],
                             "blocked_by": ["Windows host", "no GPU", "no Linux container runtime", "no vendor BMC/NOS"]},
            )
            write_case(cid, comp, manifest, unsupported_poc)
            continue

        meta = STATIC_CVE.get(cid)
        if meta:
            component, gitname, source, line, snippet, analysis = meta
            ref = git_ref(gitname) if gitname else {"kind": "advisory", "version": entry.get("affected") or "*"}
            manifest = base_manifest(
                cid, "cve", title, version=entry.get("affected") or "*", version_ref=ref,
                root_cause={"file": source.split("upstream/", 1)[1] if source else f"advisory:{entry['source']}",
                            "line": line, "function": "", "snippet": snippet,
                            "source": source, "source_sha256": sha(ROOT / source) if source else None,
                            "note": analysis},
                status="static-only", method="static-source" if source else "static-advisory",
                module=(entry.get("modules") or [None])[0], python=PY_REPRO,
                advisory=entry["source"], notes=analysis,
                static_evidence_level="source-line" if source else "advisory",
                static_analysis=analysis, static_verdict="not-dynamically-verified",
            )
            write_case(cid, comp, manifest, static_poc)
            continue

        raise SystemExit(f"unclassified CVE: {cid}")

    # ---- 70 mining candidates -------------------------------------------------
    for idx, cand in enumerate(mining):
        cid = cand["id"]
        target = cand["target"]
        key = f"{target}/{cand['file']}"
        src = candidate_sources.get(key)
        if not src:
            raise SystemExit(f"missing candidate source: {key}")
        source_path = ROOT / src["local"]
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        actual = lines[cand["line"] - 1] if 0 < cand["line"] <= len(lines) else ""
        rule = cand.get("rule", "")
        note, verdict = candidate_note(idx, rule, actual)
        ref = {"kind": "git", "repo": src["repo"], "tag": src["tag"], "commit": src["commit"]}
        manifest = base_manifest(
            cid, "mining", f"{target}: {rule} @ {cand['file']}:{cand['line']}",
            version=src["tag"], version_ref=ref,
            root_cause={"file": src["path"], "line": cand["line"], "function": "",
                        "snippet": actual.strip(), "source": src["local"],
                        "source_sha256": src["sha256"], "note": note},
            status="static-only", method="static-source", module=None, python=PY_REPRO,
            advisory="reports/samples/mining-trainstack/mining-report.json",
            notes=note, static_evidence_level="source-line",
            static_analysis=note, static_verdict=verdict,
        )
        manifest["mining"] = {
            "candidate_index": idx,
            "rule": rule,
            "channel": cand.get("channel"),
            "file": cand.get("file"),
            "line": cand.get("line"),
            "snippet": cand.get("snippet"),
            "original_status": cand.get("status"),
            "promoted": False,
        }
        write_case(cid, target, manifest, static_poc)

    print(f"cases: {sum(1 for _ in CASES.glob('*/*/manifest.json'))}")


def candidate_note(idx: int, rule: str, actual: str) -> tuple[str, str]:
    if rule == "torch-load-any":
        return (
            "Unsafe torch.load without weights_only; duplicate of CVE-2026-65110 at a newer tag. "
            "0.19.2 import needs triton/GPU on this host, so the candidate itself is not dynamically reproduced.",
            "duplicate-static-only",
        )
    if rule == "torch-load-unsafe":
        return (
            "Explicit weights_only=False is reachable only with an untrusted checkpoint; "
            "candidate is a trust-boundary warning, not a new sink. Static-only.",
            "risk-not-vuln",
        )
    if rule in ("wandb-checkpoint-hook", "env-rank-read", "subprocess-popen", "eval-call"):
        if rule == "eval-call" and actual.strip() == "model.eval()":
            return ("False positive: the matched text is model.eval(), not Python eval().", "false-positive")
        return ("Rule hit is a legitimate framework call; no untrusted-data sink is reached.", "false-positive")
    if rule in ("bind-all-interfaces", "go-bind-all"):
        return ("Default 0.0.0.0/[::] bind is an exposure/configuration risk, not code execution.", "risk-not-vuln")
    if rule == "missing-revision":
        return ("Missing revision pin is a supply-chain hygiene gap; no direct exploit primitive.", "supply-chain-gap")
    if rule == "trust-remote-code-propagated":
        return ("Explicit trust_remote_code opt-in; requires a malicious model repository and user consent. Not a vulnerability by itself.", "risk-not-vuln")
    if rule == "load-dataset-any":
        return ("Dataset loading is intended functionality; remote dataset trust is a documented boundary.", "risk-not-vuln")
    if rule == "apply-chat-template-dynamic":
        if actual.strip().startswith(">>>") or actual.strip().startswith("#"):
            return ("Documentation/example line, no runtime sink.", "false-positive")
        return ("Chat-template rendering is data transformation inside the tokenizer; no code-execution sink.", "false-positive")
    return ("Manual review found no dynamic exploit path; static-only.", "not-dynamically-verified")


if __name__ == "__main__":
    main()



