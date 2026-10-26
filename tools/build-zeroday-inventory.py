# -*- coding: utf-8 -*-
"""Build corpus/zeroday/inventory.json from the audit history, upstream mining
registry, legacy candidate files and the new-discovery cases.

The inventory is deliberately explicit about *why* an entry is verified and
what was actually executed.  Source documents are mapped one-by-one in
``source_index`` so no historical finding disappears into a duplicate bucket.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
OUT = ROOT / "corpus" / "zeroday" / "inventory.json"

COMPONENT_META = {
    "vllm": dict(pkg="vllm", eco="PyPI", gh="pip", repo="vllm-project/vllm"),
    "vllm-jev": dict(pkg="vllm", eco="PyPI", gh="pip", repo="mode-io/vllm-jev"),
    "djev": dict(pkg="djev", eco="PyPI", gh="pip", repo="mmastrac/djev"),
    "sglang": dict(pkg="sglang", eco="PyPI", gh="pip", repo="sgl-project/sglang"),
    "slime": dict(pkg="slime", eco="PyPI", gh="pip", repo="THUDM/slime"),
    "sglang-omni": dict(pkg="sglang-omni", eco="PyPI", gh="pip", repo="sgl-project/sglang-omni"),
    "openjev-sglang": dict(pkg="openjev-sglang", eco="PyPI", gh="pip", repo="ekzhang/openjev-sglang"),
    "skyrl": dict(pkg="skyrl", eco="PyPI", gh="pip", repo="NovaSky-AI/SkyRL"),
    "trl": dict(pkg="trl", eco="PyPI", gh="pip", repo="huggingface/trl"),
    "areal": dict(pkg="areal", eco="PyPI", gh="pip", repo="inclusionAI/AReaL"),
    "openrlhf": dict(pkg="openrlhf", eco="PyPI", gh="pip", repo="OpenRLHF/OpenRLHF"),
    "llamafactory": dict(pkg="llamafactory", eco="PyPI", gh="pip", repo="hiyouga/LLaMA-Factory"),
    "msswift": dict(pkg="ms-swift", eco="PyPI", gh="pip", repo="modelscope/ms-swift"),
    "verl": dict(pkg="verl", eco="PyPI", gh="pip", repo="volcengine/verl"),
    "ray": dict(pkg="ray", eco="PyPI", gh="pip", repo="ray-project/ray"),
    "vllm-omni": dict(pkg="vllm-omni", eco="PyPI", gh="pip", repo="vllm-project/vllm-omni"),
    "openjev": dict(pkg="openjev", eco="PyPI", gh="pip", repo="razorback16/openjev"),
    "onejev": dict(pkg="onejev", eco="PyPI", gh="pip", repo="OmniJev/OneJev"),
    "llm2jev": dict(pkg="llm2jev", eco="PyPI", gh="pip", repo="Yinsongxu/LLM2Jev"),
    "siliconlab": dict(pkg="openjev-siliconlabai", eco="PyPI", gh="pip", repo="SiliconLabAI/OpenJev"),
    "wald-4b": dict(pkg="wald-4b", eco="PyPI", gh="pip", repo="org2AI/wald-4b"),
    "von": dict(pkg="von", eco="PyPI", gh="pip", repo="wfzyx/von"),
    "simple-jev": dict(pkg="simple-jev", eco="PyPI", gh="pip", repo="featherless-ai/simple-jev"),
    "jev-compatible": dict(pkg="jev-compatible", eco="PyPI", gh="pip", repo="David-Lolly/Jev-Compatible"),
    "diffusion-jev": dict(pkg="diffusion-jev", eco="PyPI", gh="pip", repo="Hangzhi/diffusion-jev-sglang"),
    "dify": dict(pkg="dify", eco="PyPI", gh="pip", repo="langgenius/dify"),
    "open-webui": dict(pkg="open-webui", eco="PyPI", gh="pip", repo="open-webui/open-webui"),
    "deepspeed": dict(pkg="deepspeed", eco="PyPI", gh="pip", repo="deepspeedai/DeepSpeed"),
    "cephcsi": dict(pkg="cephcsi", eco="Go", gh="go", repo="ceph/ceph-csi"),
    "hami": dict(pkg="hami", eco="Go", gh="go", repo="Project-HAMi/HAMi"),
    "litellm": dict(pkg="litellm", eco="PyPI", gh="pip", repo="BerriAI/litellm"),
    "kuberay": dict(pkg="kuberay", eco="Go", gh="go", repo="ray-project/kuberay"),
    "lws": dict(pkg="lws", eco="Go", gh="go", repo="kubernetes-sigs/lws"),
    "transformers": dict(pkg="transformers", eco="PyPI", gh="pip", repo="huggingface/transformers"),
    "megatron": dict(pkg="megatron-core", eco="PyPI", gh="pip", repo="NVIDIA/Megatron-LM"),
}


def osv_version(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if re.search(r"HEAD|commit|^[0-9a-f]{7,40}$", text, re.I):
        return None
    m = re.search(r"(?<![\w.])v?(\d+(?:\.\d+){1,3})(?![\w.])", text)
    return m.group(1) if m else None


COMMITS = {
    "vllm-jev": "57226d4e5b8e164f07288acd4f6b7ccca3340218",
    "djev": "e5841cf41e9211608e698492658685c36e24e77a",
    "sglang-omni": "204ba29a5303c25ca74238cc7f1e1356b494dd24",
    "openjev-sglang": "bf6a53bbb1f75040b06de39abff1230524553ab5",
    "openjev": "b4339c640f5331ef75098637d1be2c787715ee88",
    "vllm-omni": "b463516ff4cfe6d3c3e46aaad07f58e6ce63ac40",
    "onejev": "6122519058af23504a33d944f0e63b2d868c8a4b",
    "llm2jev": "f2bdad648e7a34bfce64401fb0f7c44bc13209ae",
    "siliconlab": "a08e969c37b2e4a37f95b3426f983bd94303590c",
    "wald-4b": "5d26d95e9292230d3a7e20bf9d1b0152751cfbbc",
    "von": "9319ced779f8232ab1d8d3e9c69cdc52ddce77ec",
    "simple-jev": "31c8d7a55a48e82d21a481799f3044eb45d81c75",
    "jev-compatible": "e52e963d85392fbf7a4490f2c58152eed4af4f45",
    "diffusion-jev": "a6dce88a2fc9c11b1df44d03033f1ebafd75c504",
    "skyrl": "a1e34dbf21003f66bd7921487fd47db6c154aba2",
    "areal": "448de5235341482465362e8b831097685d8e305d",
    "verl": "76e837e0bfcb18b380a66c0ba56ef9f0ac840f09",
}

NVD_KEYS = {
    "msswift": "ms-swift",
    "llamafactory": "llama-factory",
    "open-webui": "open webui",
    "vllm-jev": "vllm-jev",
    "sglang-omni": "sglang-omni",
    "openjev-sglang": "openjev",
    "jev-compatible": "jev",
    "siliconlab": "openjev",
    "llm2jev": "llm2jev",
    "onejev": "onejev",
    "wald-4b": "wald-4b",
    "diffusion-jev": "diffusion-jev",
    "simple-jev": "simple-jev",
}


def novelty_for(component: str, version: str | None, function: str | None,
                file: str | None, *, strong: list[str] | None = None,
                weak: list[str] | None = None, repo: str | None = None,
                local_source: str | None = None) -> dict:
    meta = dict(COMPONENT_META.get(component, {}))
    strong_terms = [t for t in ([function] if function else []) + (strong or []) if t]
    if file:
        strong_terms.append(Path(file).name)
    keywords = [t for t in ([component] + (weak or [])) if t]
    return {
        "osv_package": meta.get("pkg", component),
        "osv_ecosystem": meta.get("eco", "PyPI"),
        "osv_version": osv_version(version),
        "osv_commit": COMMITS.get(component),
        "ghsa_package": meta.get("pkg", component),
        "ghsa_ecosystem": meta.get("gh", "pip"),
        "repo": repo or meta.get("repo"),
        "nvd_keywords": [NVD_KEYS.get(component, component)],
        "strong_terms": strong_terms,
        "keywords": keywords,
        "local_source": local_source,
    }


def E(eid, source, component, title, module, version, file, line, function,
      preconditions, exploit, evidence_path, *, status="verified", dynamic=True,
      method="dynamic-function", reachability="", disclosure=None,
      strong=None, weak=None, repo=None, local_source=None, notes="") -> dict:
    meta = COMPONENT_META.get(component, {})
    return {
        "id": eid,
        "source": source,
        "component": component,
        "product": meta.get("repo") or component,
        "title": title,
        "module": module,
        "version": version,
        "root_cause": {"file": file, "line": line, "function": function or "", "snippet": notes[:240]},
        "preconditions": preconditions,
        "exploit": exploit,
        "evidence": {"path": evidence_path, "mode": "evidence-reused" if status == "verified" else "static",
                     "kind": "dynamic" if dynamic else "static"},
        "verification": {"status": status, "dynamic": dynamic, "method": method,
                         "reason": "" if status == "verified" else notes or "not dynamically reproduced"},
        "reachability": reachability,
        "novelty": novelty_for(component, version, function, file, strong=strong, weak=weak, repo=repo,
                               local_source=local_source),
        "disclosure": disclosure or {"status": "undisclosed", "channel": "vendor security policy"},
        "notes": notes,
    }


def evidence(rel: str) -> str:
    return rel


AUDIT: list[dict] = [
    E("vllm-jev-plugin-auth-bypass", "audit-history", "vllm-jev",
      "vLLM --api-key does not guard /plugins/vllm-jev/* (auth bypass)",
      "vllm-plugin-auth-bypass", "v0.31.0 + vllm-jev 57226d4",
      "vllm_jev/endpoint.py", 530, "choice",
      ["vLLM started with --api-key", "vllm-jev endpoint plugin registered", "service port reachable"],
      "POST /plugins/vllm-jev/choice without Authorization -> 200; /v1/systemone -> 401",
      evidence("projects/repro-2026-10/P1-vllm-jev-plugin-auth-bypass/LATEST-RESULT.md"),
      reachability="HTTP request -> vLLM AuthenticationMiddleware (GUARDED_PREFIX only /v1,/v2,/inference,/cohere) -> plugin route /plugins/vllm-jev/choice -> decision handler; no token check in endpoint.py.",
      strong=["GUARDED_PREFIX", "plugins/vllm-jev"], weak=["vllm-jev", "plugin", "api-key"]),
    E("djev-open-proxy", "audit-history", "djev",
      "djev default-open proxy: no key + /v1/* relay + GET bypass when key configured",
      "djev-open-proxy", "e5841cf",
      "djev/structured_server.py", 1990, "do_POST",
      ["djev exposed on 0.0.0.0:8011", "API_KEY unset or attacker uses GET"],
      "unauthenticated POST /v1/* relayed to upstream vLLM; GET management routes remain unauthenticated with key set",
      evidence("projects/repro-2026-10/P2-djev-open-proxy/LATEST-RESULT.md"),
      reachability="HTTP request -> structured_server.do_POST/do_GET -> httpx relay -> upstream vLLM /v1 management surface; key check is optional and absent on GET.",
      strong=["structured_server", "do_GET"], weak=["djev", "relay", "open proxy"]),
    E("sglang-admin-optional-failopen", "audit-history", "sglang",
      "SGLang ADMIN_OPTIONAL routes fail open when no key is configured",
      "sglang-admin-failopen", "v0.5.21",
      "python/sglang/srt/entrypoints/http_server.py", 1242, "update_weights_from_disk",
      ["SGLang server without api_key/admin_api_key", "management port reachable"],
      "POST /update_weights_from_disk without token -> 200; with wrong token -> 401; 41 admin routes",
      evidence("projects/repro-2026-10/PR3-slime-pull-weights/LATEST-RESULT.md"),
      reachability="HTTP request -> add_api_key_middleware -> decide_request_auth: ADMIN_OPTIONAL with no configured key returns allowed=True -> update_weights_from_disk / pause_generation / profiler routes.",
      strong=["decide_request_auth", "update_weights_from_disk"], weak=["sglang", "admin", "fail-open"]),
    E("slime-pull-weights", "audit-history", "slime",
      "slime private /pull_weights patch: ADMIN_OPTIONAL + request-controlled source_dir/local_checkpoint_dir",
      "slime-weight-pull-poison", "slime 05e3b01 / SGLang v0.5.15.post1",
      "docker/patch/latest/sglang-pull_weights.patch", 17, "pull_weights",
      ["slime patch stack deployed", "shared PVC/NFS writable by attacker", "port reachable"],
      "unauthenticated /pull_weights with source_dir/local_checkpoint_dir -> cross-tenant weight write/read",
      evidence("projects/repro-2026-10/PR3-slime-pull-weights/LATEST-RESULT.md"),
      reachability="HTTP request -> patched SGLang route /pull_weights -> io_struct PullWeightsReqInput -> weight_sync local_checkpoint path join -> shared volume write.",
      strong=["pull_weights", "local_checkpoint_dir"], weak=["slime", "weight", "patch"]),
    E("sglang-omni-admin-failopen", "omni-jev", "sglang-omni",
      "sglang-omni admin dependency is a no-op without SGLANG_OMNI_ADMIN_KEY; profiler event_dir is request-controlled",
      "sglang-omni-profiler-write", "HEAD 204ba29",
      "sglang_omni/http/admin_auth.py", 28, "make_admin_auth_dependency",
      ["no SGLANG_OMNI_ADMIN_KEY", "admin/profiler port reachable"],
      "POST /start_profile with event_dir=attacker path -> 200; /pause_generation and /update_weights_from_disk -> 200",
      evidence("projects/repro-2026-10/P3-sglang-omni-admin-failopen/LATEST-RESULT.md"),
      reachability="HTTP request -> FastAPI admin dependency (None -> _no_auth) -> start_profile -> RequestEventRecorder.start(event_dir) -> mkdir/write JSONL under attacker-chosen directory.",
      strong=["make_admin_auth_dependency", "event_dir"], weak=["sglang-omni", "profiler", "admin"]),
    E("openjev-sglang-unauth", "omni-jev", "openjev-sglang",
      "openjev-sglang compatibility endpoints default unauthenticated (archived snapshot)",
      "openjev-unauth", "bf6a53b (archived)",
      "openjev_sglang", 0, "unauthenticated",
      ["compatible deployment of archived openjev-sglang", "port reachable"],
      "unauthenticated decision endpoints -> model control / data exposure",
      evidence("projects/repro-2026-10/LV2-openjev-sglang-archived/LATEST-RESULT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP request -> openjev-sglang route with unauthenticated=True -> decision handler; archived snapshot, no live endpoint retest.",
      strong=["unauthenticated"], weak=["openjev-sglang"]),
    E("skyrl-vllm-devmode", "audit-history", "skyrl",
      "SkyRL forces vLLM 0.0.0.0 + dev-mode + insecure serialization + unauthenticated /fetch_weights",
      "skyrl-dev-pickle-rce", "a1e34db",
      "skyrl_train/workers/vllm_server_actor.py", 216, "start",
      ["SkyRL training recipe deployed", "vLLM worker port reachable"],
      "unauthenticated /update_weights -> pickle decode -> marker; dev endpoints exposed on 0.0.0.0",
      evidence("projects/repro-2026-10/skyrl-vllm-devmode/LATEST-RESULT.md"),
      reachability="HTTP request -> vLLM dev routes (VLLM_SERVER_DEV_MODE=1 forced by SkyRL) -> /update_weights -> insecure serialization -> pickle.loads -> RCE.",
      strong=["VLLM_SERVER_DEV_MODE", "fetch_weights"], weak=["skyrl", "vllm", "dev-mode"]),
    E("skyrl-tinker-api", "audit-history", "skyrl",
      "SkyRL Tinker API binds 0.0.0.0:8000 and has no authentication on 8 endpoints",
      "skyrl-tinker-hijack", "a1e34db",
      "skyrl/tinker/api.py", 0, "api",
      ["Tinker API started", "port 8000 reachable"],
      "unauthenticated create/sample/delete model control plane -> checkpoint manipulation",
      evidence("projects/repro-2026-10/skyrl-tinker-api/LATEST-RESULT.md"),
      reachability="HTTP request -> FastAPI Tinker routes (no auth dependency, default 0.0.0.0:8000) -> training control operations.",
      strong=["tinker/api"], weak=["skyrl", "tinker", "api"]),
    E("trl-vllm-serve-devmode", "audit-history", "trl",
      "trl vllm-serve defaults to 0.0.0.0 + VLLM_SERVER_DEV_MODE=1 + no api-key",
      "trl-serve-dev-mode", "1.15.0",
      "trl/scripts/vllm_serve.py", 103, "main",
      ["trl vllm-serve used", "port reachable"],
      "dev endpoints (weight/cache control) reachable without token",
      evidence("projects/repro-2026-10/PR5-trl-vllm-serve/LATEST-RESULT.md"),
      reachability="CLI -> trl vllm-serve -> vLLM dev mode + host 0.0.0.0 -> unauthenticated dev endpoints.",
      strong=["VLLM_SERVER_DEV_MODE", "vllm_serve"], weak=["trl", "dev-mode"]),
    E("areal-unauth-engine-control", "audit-history", "areal",
      "AReaL proxy rollout control plane: unauthenticated /set_env + /create_engine + /call",
      "areal-setenv-engine-rce", "448de52",
      "areal/experimental/proxy_rollout_server.py", 445, "set_env",
      ["AReaL proxy rollout server exposed", "port reachable"],
      "POST /set_env + /create_engine + /call -> arbitrary module import/class/method -> marker RCE",
      evidence("projects/repro-2026-10/PR1-areal-unauth-engine-control/RESULT.md"),
      reachability="HTTP request -> /set_env (os.environ) -> /create_engine (importlib + getattr) -> /call -> arbitrary method execution.",
      strong=["proxy_rollout_server", "set_env"], weak=["areal", "engine", "control"]),
    E("areal-dataservice-pickle", "audit-history", "areal",
      "AReaL data-service worker /run accepts pickle.load without auth",
      "areal-load-pickle", "448de52",
      "areal/infra/data_service/worker/app.py", 268, "run",
      ["data-service worker exposed", "port reachable", "attacker can POST job"],
      "pickle.load on request body -> marker RCE",
      evidence("projects/repro-2026-10/areal-dataservice-pickle/LATEST-RESULT.md"),
      reachability="HTTP request -> /run -> pickle.load(request body) -> object reconstruction -> RCE.",
      strong=["data_service/worker", "pickle.load"], weak=["areal", "worker", "pickle"]),
    E("openrlhf-serve-rm", "audit-history", "openrlhf",
      "OpenRLHF serve_rm binds 0.0.0.0:5000 without authentication",
      "openrlhf-serve-rm", "0.11.2 / dc2a7ad",
      "openrlhf/cli/serve_rm.py", 0, "serve_rm",
      ["serve_rm started", "port 5000 reachable"],
      "unauthenticated reward scoring -> forged training signal",
      evidence("projects/repro-2026-10/openrlhf-serve-rm/RESULT.md"),
      reachability="HTTP request -> reward model Flask routes (no auth dependency, default 0.0.0.0:5000) -> scoring.",
      strong=["serve_rm"], weak=["openrlhf", "reward"]),
    E("llamafactory-webui-rce", "audit-history", "llamafactory",
      "LLaMA-Factory WebUI no auth + trust_remote_code=True + attacker model path -> RCE",
      "llamafactory-checkpoint-rce", "0.9.5 / 1fded91",
      "src/llamafactory/webui/chatter.py", 139, "load_model",
      ["WebUI reachable (default 0.0.0.0)", "attacker controls model_path"],
      "malicious HF model auto_map executes during load -> marker inside service process",
      evidence("projects/repro-2026-10/LFA-1-llamafactory-webui-rce/LATEST-RESULT.md"),
      reachability="HTTP WebUI -> model load form -> trust_remote_code=True -> transformers dynamic module import -> Python execution.",
      strong=["trust_remote_code", "chatter"], weak=["llamafactory", "webui"]),
    E("msswift-trust-remote-code", "audit-history", "msswift",
      "ms-swift default_trust_remote_code=True + WebUI/deploy fail-open -> malicious model RCE",
      "msswift-trust-remote-code", "4.5.3 / fbc61cf",
      "swift/model/loader.py", 0, "ModelLoader",
      ["ms-swift WebUI or swift deploy reachable", "attacker controls model id/path"],
      "malicious model auto_map executes in service process; PyPI 4.5.3 binds 0.0.0.0",
      evidence("projects/repro-2026-10/MSW-1-msswift-trust-remote-code/LATEST-RESULT.md"),
      reachability="HTTP WebUI/deploy -> model load -> default trust_remote_code=True -> transformers dynamic module import -> execution.",
      strong=["trust_remote_code", "default_trust_remote_code"], weak=["ms-swift", "webui", "deploy"]),
    E("verl-prime-math-eval", "audit-history", "verl",
      "verl prime_math reward grader eval() on model output (\\pi branch)",
      "verl-prime-math-eval", "76e837e",
      "verl/utils/reward_score/prime_math/grader.py", 169, "grade_answer",
      ["training job uses prime_math reward", "model output controlled by attacker/data"],
      "crafted model answer reaches eval() -> marker / host code execution",
      evidence("projects/repro-2026-10/PR4-verl-prime-math-eval/RESULT.md"),
      reachability="training rollout -> reward_score prime_math -> grader.eval() on model answer -> Python execution in training process.",
      strong=["prime_math", "grader"], weak=["verl", "reward", "eval"]),
    E("verl-prime-code-exec", "audit-history", "verl",
      "verl prime_code executes model-generated code with exec() and no sandbox",
      "verl-prime-code-exec", "76e837e",
      "verl/utils/reward_score/prime_code/testing_util.py", 616, "reward",
      ["training job uses prime_code reward", "model output is untrusted"],
      "generated code exec() -> marker on training host",
      evidence("projects/repro-2026-10/verl-prime-code-exec/LATEST-RESULT.md"),
      reachability="training rollout -> prime_code reward -> exec(generated code) in fallback path -> host execution.",
      strong=["prime_code", "testing_util"], weak=["verl", "exec", "reward"]),
    E("verl-checkpoint-pickle", "audit-history", "verl",
      "verl checkpoint engine recv_pyobj: pickle over TCP/ZMQ without auth",
      "verl-checkpoint-pickle", "76e837e",
      "verl/checkpoint_engine", 0, "recv_pyobj",
      ["checkpoint engine binds a reachable tcp://ip:port", "flat network"],
      "connect to checkpoint channel -> send pickle -> RCE",
      evidence("projects/repro-2026-10/verl-checkpoint-engine-pickle/LATEST-RESULT.md"),
      reachability="TCP/ZMQ peer -> recv_pyobj -> pickle.loads -> RCE; no authentication on the checkpoint channel.",
      strong=["recv_pyobj", "checkpoint_engine"], weak=["verl", "pickle", "zmq"]),
    E("skyrl-fetch-weights", "audit-history", "skyrl",
      "SkyRL /fetch_weights payload_files path traversal write + weight poisoning",
      "skyrl-fetch-weights-traversal", "a1e34db",
      "skyrl/weight_sync/delta/checkpoint.py", 257, "fetch_weights",
      ["/fetch_weights reachable", "shared cache dir writable"],
      "payload_files=../../... -> write outside cache_dir -> control next loaded weights",
      evidence("projects/repro-2026-10/PR2-skyrl-fetch-weights-traversal/RESULT.md"),
      reachability="HTTP request -> /fetch_weights -> cache_dir / payload_file join (no normalization) -> arbitrary write.",
      strong=["fetch_weights", "payload_files"], weak=["skyrl", "weight", "traversal"]),
    E("openrlhf-vllm-insecure", "audit-history", "openrlhf",
      "OpenRLHF unconditionally sets VLLM_ALLOW_INSECURE_SERIALIZATION=1",
      "openrlhf-vllm-env-force", "0.11.2 / dc2a7ad",
      "openrlhf/trainer/ray/vllm_engine.py", 95, "vllm_engine",
      ["OpenRLHF rollout with vLLM", "network peer can reach IPC/dev surface"],
      "insecure serialization re-enables pickle IPC -> RCE on flat network",
      evidence("projects/repro-2026-10/openrlhf-vllm-env-force/RESULT.md"),
      reachability="OpenRLHF trainer -> vLLM engine env -> VLLM_ALLOW_INSECURE_SERIALIZATION=1 -> pickle IPC surface exposed.",
      strong=["VLLM_ALLOW_INSECURE_SERIALIZATION"], weak=["openrlhf", "vllm", "serialization"]),
    E("areal-v2-worker", "audit-history", "areal",
      "AReaL v2 worker /load -> torch.load(weights_only=False) without auth (+/save, /data, /awex)",
      "areal-load-pickle", "448de52",
      "areal/v2/engine/fsdp_engine.py", 1965, "load",
      ["v2 worker reachable", "attacker can supply .pt"],
      "malicious .pt -> torch.load(weights_only=False) -> marker RCE",
      evidence("projects/repro-2026-10/areal-v2-worker/LATEST-RESULT.md"),
      reachability="HTTP request -> /load -> torch.load(weights_only=False) -> pickle reduce -> RCE.",
      strong=["fsdp_engine", "weights_only"], weak=["areal", "worker", "torch.load"]),
    E("slime-torch-load", "audit-history", "slime",
      "slime debug/resume data torch.load(weights_only=False) in multiple sinks",
      "slime-weight-pull-poison", "05e3b01",
      "slime/backends/sglang_utils/load_debug_rollout_data.py", 0, "load_debug_rollout_data",
      ["shared NFS/JuiceFS writable by attacker", "victim loads debug/resume data"],
      "malicious .pt -> torch.load(weights_only=False) -> RCE",
      evidence("projects/repro-2026-10/slime-torch-load/RESULT.md"),
      reachability="shared checkpoint file -> torch.load(weights_only=False) -> pickle execution in training process.",
      strong=["load_debug_rollout_data", "weights_only"], weak=["slime", "torch.load"]),
    E("openjev-clef-release-module", "omni-jev", "openjev",
      "OpenJev Clef release_module() executes model-directory joint_schema_model.py; revision missing",
      "openjev-clef-release-module", "b4339c6",
      "openjev/clef_vllm.py", 40, "release_module",
      ["attacker can write shared model cache/PVC", "victim loads model"],
      "joint_schema_model.py in model dir -> exec_module -> Python execution",
      evidence("projects/repro-2026-10/P4-openjev-clef-release-module/LATEST-RESULT.md"),
      reachability="model load -> release_module -> importlib exec_module on model-provided joint_schema_model.py -> RCE.",
      strong=["release_module", "joint_schema_model"], weak=["openjev", "clef", "model"]),
    E("msswift-eval-escape", "audit-history", "msswift",
      "ms-swift --device_groups ranks restricted eval() escape; WebUI more_params reachable",
      "msswift-eval-escape", "4.5.3 / fbc61cf",
      "swift/ray_utils/resource_manager.py", 48, "parse_ranks",
      ["WebUI reachable", "attacker controls more_params/device_groups"],
      "ranks expression escapes {'__builtins__':{'list','range'}} -> marker code execution",
      evidence("projects/repro-2026-10/MSW-2-msswift-eval-escape/LATEST-RESULT.md"),
      reachability="HTTP WebUI -> more_params -> --device_groups -> eval(ranks) -> builtins escape -> execution.",
      strong=["resource_manager", "device_groups"], weak=["ms-swift", "eval"]),
    E("areal-awex", "audit-history", "areal",
      "AReaL SGLang /awex/* unauthenticated: arbitrary torch.save + join arbitrary NCCL group",
      "areal-awex-nccl-injection", "448de52",
      "areal/sglang/awex", 0, "awex",
      ["AReaL SGLang /awex endpoint reachable", "flat network"],
      "arbitrary path torch.save + NCCL join with attacker master_addr/port -> weight/gradient injection",
      evidence("projects/repro-2026-10/areal-awex-sglang/LATEST-RESULT.md"),
      reachability="HTTP request -> /awex -> torch.save(path) + NCCL group join(master_addr/port) -> weight/gradient injection.",
      strong=["awex", "master_addr"], weak=["areal", "nccl"]),
    E("vllm-omni-media-ssrf", "omni-jev", "vllm-omni",
      "vllm-omni media URL direct download: SSRF / metadata / unbounded response",
      "vllm-omni-ssrf", "b463516",
      "vllm_omni/entrypoints/openai/video_api_utils.py", 234, "download",
      ["vllm-omni OpenAI API reachable", "request can carry media URL"],
      "image_url/video URL -> httpx GET internal/metadata -> response returned",
      evidence("projects/repro-2026-10/P5-vllm-omni-media-ssrf/LATEST-RESULT.md"),
      reachability="HTTP request -> /v1/videos or /v1/images/edits -> video_api_utils URL fetch (httpx, no policy) -> internal service/metadata.",
      strong=["video_api_utils", "image_url"], weak=["vllm-omni", "ssrf"]),
    E("onejev-media-ssrf", "omni-jev", "onejev",
      "OneJev qev/media.py urlopen without policy -> SSRF",
      "onejev-ssrf", "6122519",
      "qev/media.py", 101, "fetch",
      ["OneJev endpoint reachable", "request can carry media URL"],
      "media URL -> urllib urlopen -> internal service; UA=qev marker",
      evidence("projects/repro-2026-10/P7-onejev-media-ssrf/LATEST-RESULT.md"),
      reachability="HTTP request -> /v1/systemone media URL -> urlopen(url) -> internal network.",
      strong=["qev/media", "urlopen"], weak=["onejev", "ssrf"]),
    E("llm2jev-image-file", "omni-jev", "llm2jev",
      "LLM2Jev image_url accepts file://, local paths and arbitrary http(s) -> local file read + SSRF",
      "llm2jev-file-read", "f2bdad6",
      "image_inputs.py", 40, "load_image",
      ["LLM2Jev endpoint reachable", "request carries image_url"],
      "image_url=file:///etc/passwd / local path -> read and parse image; http(s) -> SSRF",
      evidence("projects/repro-2026-10/P6-llm2jev-image-file-ssrf/LATEST-RESULT.md"),
      reachability="HTTP request -> image_inputs -> core/multimodal -> file:// or local path open / http fetch -> data returned.",
      strong=["image_inputs", "image_url"], weak=["llm2jev", "file"]),
    E("siliconlab-credential-exfil", "omni-jev", "siliconlab",
      "OpenJev-SiliconLabAI request-controlled base_url/decider_url + server-side API key leakage",
      "siliconlab-credential-exfil", "a08e969",
      "server/index.ts", 40, "evaluate",
      ["OpenJev-SiliconLabAI service reachable", "server env has provider key"],
      "base_url/decider_url -> attacker server -> server sends API key / evaluation payload",
      evidence("projects/repro-2026-10/P8-siliconlab-openjev-ssrf/LATEST-RESULT.md"),
      reachability="HTTP request -> server/index.ts base_url/decider_url -> src/lib/evaluate.ts outbound call with server key -> credential exfiltration.",
      strong=["base_url", "decider_url"], weak=["siliconlab", "credential", "ssrf"]),
    E("llamafactory-ssrf-redirect", "audit-history", "llamafactory",
      "LLaMA-Factory SSRF guard bypass via 302 redirect (check-then-fetch)",
      "llamafactory-ssrf-redirect", "0.9.5 / 1fded91",
      "src/llamafactory/api/common.py", 52, "check_url",
      ["LLaMA-Factory API reachable", "request-controlled URL"],
      "public URL 302 -> internal/metadata; guard only checks first URL",
      evidence("projects/repro-2026-10/LFA-2-llamafactory-ssrf-redirect/LATEST-RESULT.md"),
      reachability="HTTP request -> api/chat.py -> common.check_url(first URL) -> requests.get(follow redirects) -> internal/metadata.",
      strong=["check_url", "requests.get"], weak=["llamafactory", "ssrf", "redirect"]),
    E("verl-hdfs-command-injection", "audit-history", "verl",
      "verl HDFS path is interpolated into os.system (command injection)",
      "verl-hdfs-command-injection", "76e837e",
      "verl/utils/checkpoint/checkpoint_handler.py", 136, "copy",
      ["HDFS checkpoint path attacker-influenced", "training job runs"],
      "path with ;/$(...) -> os.system -> marker command execution",
      evidence("projects/repro-2026-10/verl-hdfs-command-injection/RESULT.md"),
      reachability="checkpoint path -> fs.py os.system('hdfs dfs ... ' + path) -> shell metacharacters -> command execution.",
      strong=["checkpoint_handler", "os.system"], weak=["verl", "hdfs"]),
    E("ray-dashboard-unauth", "audit-history", "ray",
      "Ray Dashboard/Jobs unauthenticated under the audited deployment (RAY_AUTH_MODE disabled)",
      "ray-dashboard-job", "2.59.0 / slime/AReaL recipes",
      "ray/dashboard", 0, "jobs",
      ["Ray head exposed", "RAY_AUTH_MODE=disabled (training recipes do not manage token)"],
      "unauthenticated POST /api/jobs/ -> JobSupervisor -> arbitrary command on head",
      evidence("projects/repro-2026-10/ray-dashboard-unauth/LATEST-RESULT.md"),
      reachability="HTTP request -> Ray dashboard /api/jobs/ (no token in audited deployment) -> JobSupervisor entrypoint -> command execution on head.",
      strong=["/api/jobs", "RAY_AUTH_MODE"], weak=["ray", "dashboard"]),
    E("ray-version-drift", "audit-history", "ray",
      "Ray version drift in framework locks: known CVEs below fixed versions",
      "ray-dashboard-job", "verl 2.55.1 / OpenRLHF 2.55.0 / SkyRL-agent 2.51.1",
      "verl/uv.lock", 1, "lock",
      ["deployed lock uses vulnerable Ray", "data pipeline enabled"],
      "known Ray CVEs (e.g. CVE-2026-57516 family) reachable via webdataset/Arrow",
      evidence("projects/repro-2026-10/LATEST-VERIFICATION.md"),
      status="static-only", dynamic=False,
      reachability="dependency lock -> Ray version < fixed -> known CVE surface; not a new unpublished finding.",
      strong=["CVE-2026-57516"], weak=["ray", "version", "lock"]),
    E("cache-cross-tenant", "audit-history", "vllm-jev",
      "Shared prefix/KV cache cross-tenant side channels (salt optional, cached_tokens oracle)",
      "prefix-cache-cross-tenant-leak", "vllm-jev / cache-sim",
      "vllm_jev/endpoint.py", 49, "cache_salt",
      ["multi-tenant shared engine", "cache_salt not enforced"],
      "cross-tenant prefix membership/timing oracle; simulated, not a confirmed production exploit",
      evidence("reports/samples/cache-security/effects.json"),
      status="static-only", dynamic=False,
      reachability="request -> shared prefix cache -> cached_tokens/timing oracle; lab simulation only, not counted as verified.",
      strong=["cache_salt", "cached_tokens"], weak=["prefix cache", "tenant"]),
    E("lora-adapter-injection", "audit-history", "skyrl",
      "SkyRL /skyrl/v1/load_lora_adapter request-controlled lora_path + vLLM runtime LoRA update",
      "lora-adapter-injection", "a1e34db",
      "skyrl/serve/load_lora_adapter.py", 0, "load_lora_adapter",
      ["runtime LoRA updating enabled", "attacker controls lora_path"],
      "load attacker adapter from shared path -> model behavior hijack",
      evidence("projects/repro-2026-10/LATEST-VERIFICATION.md"),
      status="static-only", dynamic=False,
      reachability="HTTP request -> /skyrl/v1/load_lora_adapter -> lora_path -> vLLM runtime adapter load; static evidence only.",
      strong=["load_lora_adapter", "lora_path"], weak=["skyrl", "lora"]),
]

OMNI_EXTRA = [
    E("vllm-omni-trust-remote-code", "omni-jev", "vllm-omni",
      "vllm-omni hardcodes trust_remote_code=True in 12 places (operator False is overridden)",
      "vllm-omni-trust-remote-code", "b463516",
      "vllm_omni/entrypoints/openai/api_server.py", 654, "AutoConfig.from_pretrained",
      ["vllm-omni service reachable", "attacker controls model path/repo"],
      "malicious auto_map model -> dynamic module import -> marker in service process",
      evidence("projects/repro-2026-10/PR6-webui-trust-remote-code/RESULT.md"),
      reachability="model load -> AutoConfig.from_pretrained(..., trust_remote_code=True) -> transformers dynamic module -> Python execution.",
      strong=["trust_remote_code", "serving_speech"], weak=["vllm-omni", "tts"]),
    E("sglang-omni-media-ssrf", "omni-jev", "sglang-omni",
      "sglang-omni media connector allows remote media without domain allowlist / unsafe addresses",
      "sglang-omni-profiler-write", "204ba29",
      "sglang_omni/connectors/resource_connector.py", 315, "fetch",
      ["sglang-omni service reachable", "request carries media URL"],
      "allow_remote_media_without_domains=True + reject_unsafe_remote_addresses=False -> SSRF/local file",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP request -> resource_connector -> requests/urlopen without private-address rejection; static evidence only.",
      strong=["resource_connector", "allow_remote_media_without_domains"], weak=["sglang-omni", "ssrf"]),
    E("wald-4b-unauth", "omni-jev", "wald-4b",
      "wald-4b inference service binds 0.0.0.0 without authentication",
      "unlimited-query-distillation", "5d26d95",
      "wald_4b/server.py", 0, "serve",
      ["wald-4b service exposed"],
      "unauthenticated inference / model extraction",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP inference port -> no auth -> unlimited queries; static evidence only.",
      strong=["wald_4b"], weak=["wald-4b", "inference"]),
    E("von-unauth", "omni-jev", "von",
      "von binds 0.0.0.0 with optional VON_API_KEY and wildcard CORS",
      "unlimited-query-distillation", "9319ced",
      "von/server.py", 0, "serve",
      ["von service exposed"],
      "unauthenticated inference / CORS drive-by",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP inference port -> optional key -> open access; static evidence only.",
      strong=["VON_API_KEY"], weak=["von", "cors"]),
    E("simple-jev-unauth", "omni-jev", "simple-jev",
      "simple-jev provider forwarding without auth and 0.0.0.0 bind",
      "unlimited-query-distillation", "31c8d7a",
      "simple_jev/server.py", 0, "serve",
      ["simple-jev service exposed"],
      "unauthenticated provider proxy / key abuse",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP port -> provider forwarding -> upstream key abuse; static evidence only.",
      strong=["simple_jev"], weak=["simple-jev", "provider"]),
    E("jev-compatible-auth", "omni-jev", "jev-compatible",
      "Jev-Compatible decision endpoints omit API key checks",
      "unlimited-query-distillation", "e52e963",
      "Jev-Compatible/server.py", 0, "serve",
      ["Jev-Compatible service exposed"],
      "unauthenticated decision API",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="HTTP decision route -> no API key -> open access; static evidence only.",
      strong=["Jev-Compatible"], weak=["jev", "api key"]),
    E("diffusion-jev-trust", "omni-jev", "diffusion-jev",
      "diffusion-jev-sglang hardcodes trust_remote_code=True + --trust-remote-code",
      "lora-adapter-injection", "a6dce88",
      "diffusion_jev_sglang/cli.py", 77, "main",
      ["service loads attacker model"],
      "malicious model -> dynamic module execution",
      evidence("projects/jev-omni-2026-10/AUDIT-REPORT.md"),
      status="static-only", dynamic=False,
      reachability="model load -> trust_remote_code=True -> dynamic module import; static evidence only.",
      strong=["trust_remote_code"], weak=["diffusion-jev", "sglang"]),
]

AGENT = [
    E("dify-shellctl-unauth-rce", "agent-platform", "dify",
      "Dify 1.17.1 shellctl sandbox daemon: no auth -> zero-precondition host RCE + all tenant homes",
      "dify-local-sandbox-unauth-rce", "v1.17.1",
      "dify-agent/docker/docker-compose.yaml", 559, "shellctl",
      ["dify-agent-local-sandbox:1.17.1 running", "port 5004 reachable"],
      "POST /v1/jobs/run without token -> arbitrary command; cwd=/home/dify/victim -> read secrets",
      evidence("projects/agent-2026-10/results/repro-dify/RESULT.md"),
      reachability="HTTP request -> shellctl 0.0.0.0:5004 (no token) -> job run/cwd -> host command execution and tenant home read.",
      strong=["shellctl", "SHELLCTL_AUTH_TOKEN"], weak=["dify", "sandbox"]),
    E("dify-agent-auth-failopen", "agent-platform", "dify",
      "dify-agent backend auth fail-open (token None -> allow all) + public dev token in compose",
      "dify-control-plane-failopen", "v1.17.1 / bbfac7a",
      "dify-agent/src/dify_agent/server/auth.py", 17, "require_token",
      ["dify-agent-backend reachable", "token unset/default"],
      "no Bearer -> 201 create binding; wrong Bearer -> 201; host mkdir/rm -rf",
      evidence("projects/agent-2026-10/results/repro-dify/RESULT.md"),
      reachability="HTTP request -> auth.py token None -> allow -> execution_bindings -> host mkdir/rm -rf.",
      strong=["require_token", "dify-agent"], weak=["dify", "auth"]),
    E("dify-stub-jwe-default-key", "agent-platform", "dify",
      "Dify Agent Stub JWE root key hardcoded public default -> offline token forgery",
      "dify-stub-token-forgery", "v1.17.1",
      "dify/docker/docker-compose.yaml", 689, "AGENT_STUB_SECRET",
      ["stub control plane reachable", "default secret unchanged"],
      "derive JWE offline -> access /agent-stub/* files/config -> 200",
      evidence("projects/agent-2026-10/results/repro-dify/RESULT.md"),
      reachability="offline JWE mint (public default key) -> HTTP /agent-stub/* -> files/config control plane.",
      strong=["agent_stub", "AGENT_STUB_SECRET"], weak=["dify", "jwe"]),
    E("dify-home-snapshot-cross-tenant", "agent-platform", "dify",
      "Dify local runtime: snapshot/control-lease root is common ancestor -> cross-tenant home snapshot theft",
      "dify-snapshot-cross-tenant-theft", "v1.17.1",
      "dify-agent/src/dify_agent/runtime_backend/local.py", 240, "snapshot",
      ["runtime_backend=local (default)", "victim binding ref known"],
      "snapshot victim home -> materialize into attacker binding -> read VICTIM-SECRET",
      evidence("projects/agent-2026-10/results/repro-dify/RESULT.md"),
      reachability="HTTP request -> home_snapshots -> local.py control-lease root -> cp -a victim home -> attacker-readable snapshot.",
      strong=["home_snapshot", "runtime_backend/local"], weak=["dify", "tenant", "snapshot"]),
    E("openwebui-code-execute", "agent-platform", "open-webui",
      "Open WebUI /api/v1/utils/code/execute lets any verified user run arbitrary Python in shared Jupyter",
      "open-webui-code-execute-rce", "v0.12.3 / 91ea4e3",
      "backend/open_webui/routers/utils.py", 41, "execute_code",
      ["code_execution.engine=jupyter", "any verified user"],
      "POST code -> Jupyter execute -> uid=1000 host shell; cross-user residue read",
      evidence("projects/agent-2026-10/results/repro-owui/RESULT.md"),
      reachability="HTTP request -> get_verified_user -> code execute -> shared Jupyter kernel -> host command execution.",
      strong=["/api/v1/utils/code/execute", "execute_code"], weak=["open-webui", "jupyter"]),
    E("openwebui-code-interpreter-bypass", "agent-platform", "open-webui",
      "Open WebUI code_interpreter guard: BLOCKED_MODULES empty + __import__ patch only top-level __main__",
      "open-webui-indirect-injection-exec", "v0.12.3 / 91ea4e3",
      "backend/open_webui/utils/middleware.py", 6111, "execute_code_block",
      ["features.code_interpreter enabled", "indirect prompt injection reaches model output"],
      "importlib.import_module('subprocess') bypasses __import__ patch -> BYPASS-OK uid=1000",
      evidence("projects/agent-2026-10/results/repro-owui/RESULT.md"),
      reachability="chat/RAG injection -> model emits <code_interpreter> -> server Jupyter -> importlib bypass -> host execution.",
      strong=["BLOCKED_MODULES", "__import__"], weak=["open-webui", "code_interpreter"]),
]

NEW = [
    E("vllm-rl-dev-auth-bypass", "new-discovery", "vllm",
      "vLLM 0.32.0 RL control router is mounted at / and bypasses --api-key",
      "vllm-plugin-auth-bypass", "v0.32.0",
      "vllm/entrypoints/rl/online/api_router.py", 31, "pause_generation",
      ["VLLM_SERVER_DEV_MODE=1 (SkyRL/TRL recipes)", "vLLM --api-key configured", "port reachable"],
      "POST /pause, /resume, /abort_requests, /update_weights, /weight_checker without Authorization -> 200; /v1/* -> 401",
      evidence("lab/zeroday_reserve/cases/vllm-rl-dev-auth-bypass/result.json"),
      method="dynamic-http", reachability="HTTP request -> real vLLM AuthenticationMiddleware (GUARDED_PREFIX excludes /) -> real RL router /pause or /weight_checker -> engine control; --api-key only guards /v1,/v2,/inference,/cohere.",
      strong=["/weight_checker", "pause_generation", "GUARDED_PREFIX"], weak=["vllm", "rl", "dev"]),
    E("sglang-legacy-tar-weights-rce", "new-discovery", "sglang",
      "SGLang pt loader falls back to torch.load(weights_only=False) for legacy tar model shards",
      "sglang-admin-failopen", "v0.5.22",
      "python/sglang/srt/model_loader/weight_utils.py", 1414, "_load_pt_file",
      ["victim loads a model directory containing an attacker-controlled .bin/.pt shard", "shard is legacy tar format"],
      "crafted legacy-tar .bin -> weights_only=True raises -> fallback weights_only=False -> pickle -> marker",
      evidence("lab/zeroday_reserve/cases/sglang-legacy-tar-weights-rce/result.json"),
      method="dynamic-function", reachability="model load -> pt_weights_iterator -> _load_pt_file -> weights_only=True RuntimeError('legacy .tar format') -> weights_only=False -> pickle reduce -> RCE.",
      strong=["_load_pt_file", "legacy .tar format", "weights_only=False"], weak=["sglang", "model loader"]),
    E("deepspeed-autoep-unsafe-load", "new-discovery", "deepspeed",
      "DeepSpeed 0.19.8 AutoEP universal conversion loads expert shards with weights_only=False",
      "deepspeed-checkpoint-rce", "v0.19.8",
      "deepspeed/checkpoint/autoep_universal.py", 459, "consolidate_autoep_expert_files",
      ["attacker can write an AutoEP checkpoint directory", "victim runs ds_to_universal conversion"],
      "malicious layer_<n>_expert_<e>_mp_rank_0_model_states.pt -> torch.load(weights_only=False) -> marker",
      evidence("lab/zeroday_reserve/cases/deepspeed-autoep-unsafe-load/result.json"),
      method="dynamic-function", reachability="checkpoint dir -> consolidate_autoep_expert_files -> resolve_expert_ckpt_path/torch.load(weights_only=False) -> pickle reduce -> RCE in conversion process.",
      strong=["autoep_universal", "consolidate_autoep_expert_files", "weights_only=False"], weak=["deepspeed", "autoep", "checkpoint"]),
    E("msswift-media-local-read", "new-discovery", "msswift",
      "ms-swift 4.6.0 deploy media path reads arbitrary host files by default",
      "msswift-trust-remote-code", "v4.6.0",
      "swift/infer_engine/protocol.py", 275, "MultiModalRequestMixin.to_base64",
      ["swift deploy reachable", "SWIFT_MEDIA_ALLOWED_DIRS unset (default)", "request carries a local media path"],
      "image/audio/video local path -> SafeMediaPath default allow-all -> open(path).read() -> base64 returned",
      evidence("lab/zeroday_reserve/cases/msswift-media-local-read/result.json"),
      method="dynamic-function", reachability="HTTP chat/completion request -> MultiModalRequestMixin.to_base64 -> SafeMediaPath.check (env unset -> allow) -> open(mm_data,'rb') -> base64 in request.",
      strong=["SafeMediaPath", "SWIFT_MEDIA_ALLOWED_DIRS", "to_base64"], weak=["ms-swift", "media", "deploy"]),
]


def load_mining() -> list[dict]:
    registry = json.loads((ROOT / "trident" / "core" / "exploit-registry.json").read_text(encoding="utf-8"))
    cases = {
        json.loads(p.read_text(encoding="utf-8")).get("id"): p
        for p in (ROOT / "lab" / "upstream_verify" / "cases").glob("*/*/manifest.json")
    }
    out = []
    for item in registry.get("entries", []):
        if item.get("source") != "mining":
            continue
        manifest_path = cases.get(item["id"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path else {}
        rc = manifest.get("root_cause") or item.get("root_cause") or {}
        status = item.get("status", "static-only")
        component = item.get("component") or manifest.get("component") or "unknown"
        version = item.get("version") or manifest.get("version") or ""
        function = rc.get("function") or manifest.get("mining", {}).get("rule") or ""
        file = rc.get("file") or manifest.get("mining", {}).get("file") or ""
        line = rc.get("line") or manifest.get("mining", {}).get("line") or 0
        title = item.get("title") or manifest.get("title") or item["id"]
        module = item.get("module") or manifest.get("module") or "unassigned"
        evidence_path = item.get("evidence") or str(manifest_path.parent / "result.json") if manifest_path else ""
        if evidence_path and not str(evidence_path).startswith("lab/"):
            evidence_path = str(Path(evidence_path).relative_to(ROOT)).replace("\\", "/") if Path(evidence_path).is_absolute() and str(evidence_path).startswith(str(ROOT)) else evidence_path
        notes = item.get("notes") or manifest.get("notes") or ""
        out.append(E(
            item["id"], "mining", component, title, module, version, file, int(line or 0), function,
            manifest.get("preconditions") or ["see manifest"],
            (notes or title)[:300],
            evidence_path,
            status="verified" if status == "verified" else ("unsupported" if status == "unsupported" else "static-only"),
            dynamic=status == "verified",
            method=manifest.get("method") or ("dynamic-function" if status == "verified" else "static"),
            reachability=(manifest.get("root_cause") or {}).get("note") or notes,
            strong=[function] if function else None,
            local_source=(str((manifest_path.parent / "poc.py").relative_to(ROOT)).replace("\\", "/")
                          if manifest_path else None),
        ))
    return out


def load_legacy() -> list[dict]:
    base = ROOT / "reports" / "samples" / "mining" / "zeroday" / "registry" / "candidates"
    out = []
    for path in sorted(base.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        target = data.get("target") or "unknown"
        repo = data.get("repo")
        version = data.get("tag") or ""
        eid = data["id"]
        out.append({
            "id": eid,
            "source": "legacy-candidate",
            "component": target,
            "product": repo or target,
            "title": f"{target}: {data.get('rule')} @ {data.get('file')}:{data.get('line')}",
            "module": "unassigned",
            "version": version,
            "root_cause": {"file": data.get("file"), "line": data.get("line"), "function": data.get("rule"),
                           "snippet": data.get("snippet", "")[:240]},
            "preconditions": ["source-level rule hit only; no dynamic reproduction"],
            "exploit": "not reproduced; static candidate retained for triage",
            "evidence": {"path": str(path.relative_to(ROOT)).replace("\\", "/"), "mode": "static", "kind": "static"},
            "verification": {"status": "static-only", "dynamic": False, "method": "static",
                             "reason": data.get("note") or "pending manual review"},
            "reachability": {
                "hami": "metrics/pprof HTTP listener -> /debug/pprof -> profile/heap data exposure; static rule hit, not dynamically reproduced",
                "litellm": "HTTP proxy request -> proxy_server auth/import path -> sink; static rule hit, not dynamically reproduced",
                "transformers": "model load -> dynamic module import / trust_remote_code path; static rule hit, not dynamically reproduced",
                "sglang": "HTTP admin route -> auth decision path; static rule hit, not dynamically reproduced",
            }.get(target, "static rule hit; no taint path proven, not counted as exploitable"),
            "novelty": novelty_for(target, version, data.get("rule"), data.get("file"),
                                   strong=[data.get("rule"), Path(str(data.get("file") or "")).name],
                                   weak=[target, data.get("rule")],
                                   repo=repo),
            "disclosure": {"status": "undisclosed", "channel": "vendor security policy"},
            "notes": data.get("note") or "",
        })
    return out


def build_source_index(entries: list[dict], legacy_alias: dict[str, str] | None = None) -> dict:
    ids = {e["id"] for e in entries}
    master = {
        "§1.1": ["vllm-jev-plugin-auth-bypass"],
        "§1.2": ["djev-open-proxy"],
        "§1.3": ["sglang-admin-optional-failopen"],
        "§1.4": ["slime-pull-weights"],
        "§1.5": ["sglang-omni-admin-failopen"],
        "§1.6": ["openjev-sglang-unauth"],
        "§1.7": ["skyrl-vllm-devmode"],
        "§1.8": ["skyrl-tinker-api"],
        "§1.9": ["trl-vllm-serve-devmode"],
        "§1.10": ["areal-unauth-engine-control"],
        "§1.11": ["areal-dataservice-pickle"],
        "§1.12": ["openrlhf-serve-rm"],
        "§1.13": ["llamafactory-webui-rce", "msswift-trust-remote-code"],
        "§2.1": ["verl-prime-math-eval"],
        "§2.2": ["verl-prime-code-exec"],
        "§2.3": ["verl-checkpoint-pickle"],
        "§2.4": ["skyrl-fetch-weights"],
        "§2.5": ["openrlhf-vllm-insecure"],
        "§2.6": ["areal-v2-worker"],
        "§2.7": ["slime-torch-load"],
        "§2.8": ["openjev-clef-release-module"],
        "§2.9": ["msswift-eval-escape"],
        "§2.10": ["areal-awex"],
        "§3.1": ["vllm-omni-trust-remote-code", "llamafactory-webui-rce", "msswift-trust-remote-code",
                 "openrlhf-vllm-insecure", "skyrl-vllm-devmode"],
        "§3.2": ["llamafactory-webui-rce", "msswift-trust-remote-code"],
        "§3.3": ["llamafactory-webui-rce", "msswift-trust-remote-code"],
        "§3.4": ["lora-adapter-injection"],
        "§4.1": ["vllm-omni-media-ssrf"],
        "§4.2": ["onejev-media-ssrf"],
        "§4.3": ["llm2jev-image-file"],
        "§4.4": ["siliconlab-credential-exfil"],
        "§4.5": ["llamafactory-ssrf-redirect"],
        "§4.6": ["verl-hdfs-command-injection"],
        "§4.7": ["sglang-omni-admin-failopen", "skyrl-fetch-weights"],
        "§5.1": ["ray-dashboard-unauth"],
        "§5.2": ["ray-version-drift"],
        "§5.3": ["areal-awex"],
        "§5.4": ["cache-cross-tenant"],
        "§6.1": ["vllm-jev-plugin-auth-bypass", "djev-open-proxy", "trl-vllm-serve-devmode"],
        "§6.2": ["vllm-jev-plugin-auth-bypass"],
        "§6.3": ["llm2jev-image-file", "skyrl-fetch-weights"],
        "§6.4": ["siliconlab-credential-exfil", "vllm-omni-media-ssrf", "llamafactory-ssrf-redirect"],
    }
    omni = {
        "G3-1 sglang-omni admin fail-open": ["sglang-omni-admin-failopen"],
        "G3-2 vllm-omni media SSRF": ["vllm-omni-media-ssrf"],
        "G3-3 vllm-omni trust_remote_code": ["vllm-omni-trust-remote-code"],
        "G1-1 vllm-jev plugin auth bypass": ["vllm-jev-plugin-auth-bypass"],
        "G1-2 djev open proxy": ["djev-open-proxy"],
        "G2-1 openjev clef release_module": ["openjev-clef-release-module"],
        "G4-1 OpenJev-SiliconLabAI credential exfil": ["siliconlab-credential-exfil"],
        "G5-1 LLM2Jev image file read": ["llm2jev-image-file"],
        "G5-2 OneJev media SSRF": ["onejev-media-ssrf"],
        "G5-3 wald-4b unauth": ["wald-4b-unauth"],
        "G5-4 von unauth": ["von-unauth"],
        "G5-5 simple-jev unauth": ["simple-jev-unauth"],
        "G4-2 Jev-Compatible auth gap": ["jev-compatible-auth"],
        "G3-4 sglang-omni remote media": ["sglang-omni-media-ssrf"],
        "G2-4 diffusion-jev trust_remote_code": ["diffusion-jev-trust"],
    }
    agent = {
        "D-4 shellctl unauth RCE": ["dify-shellctl-unauth-rce"],
        "D-1 dify-agent auth fail-open": ["dify-agent-auth-failopen"],
        "D-2 Agent Stub JWE default key": ["dify-stub-jwe-default-key"],
        "D-3 home snapshot cross-tenant": ["dify-home-snapshot-cross-tenant"],
        "O-1 Open WebUI code execute": ["openwebui-code-execute"],
        "O-2 Open WebUI code_interpreter bypass": ["openwebui-code-interpreter-bypass"],
    }
    latest = {
        "vLLM vllm-jev plugin auth bypass": ["vllm-jev-plugin-auth-bypass"],
        "djev open proxy": ["djev-open-proxy"],
        "SGLang admin fail-open": ["sglang-admin-optional-failopen"],
        "slime pull_weights": ["slime-pull-weights"],
        "slime torch.load": ["slime-torch-load"],
        "sglang-omni admin/profiler": ["sglang-omni-admin-failopen"],
        "openjev-sglang unauth": ["openjev-sglang-unauth"],
        "vllm-omni media SSRF": ["vllm-omni-media-ssrf"],
        "openjev clef release_module": ["openjev-clef-release-module"],
        "OneJev media SSRF": ["onejev-media-ssrf"],
        "LLM2Jev image file": ["llm2jev-image-file"],
        "OpenJev-SiliconLabAI SSRF/key": ["siliconlab-credential-exfil"],
        "verl prime_math eval": ["verl-prime-math-eval"],
        "verl prime_code exec": ["verl-prime-code-exec"],
        "verl rollout HTTP no auth": ["sglang-admin-optional-failopen"],
        "verl checkpoint recv_pyobj": ["verl-checkpoint-pickle"],
        "verl HDFS command injection": ["verl-hdfs-command-injection"],
        "SkyRL vLLM dev-mode": ["skyrl-vllm-devmode"],
        "SkyRL Tinker API": ["skyrl-tinker-api"],
        "SkyRL fetch_weights": ["skyrl-fetch-weights"],
        "SkyRL agent code exec": ["skyrl-vllm-devmode"],
        "TRL vllm-serve": ["trl-vllm-serve-devmode"],
        "OpenRLHF insecure serialization": ["openrlhf-vllm-insecure"],
        "OpenRLHF RM SSRF": ["openrlhf-serve-rm"],
        "OpenRLHF serve_rm": ["openrlhf-serve-rm"],
        "AReaL engine control": ["areal-unauth-engine-control"],
        "AReaL v2 worker": ["areal-v2-worker"],
        "AReaL data pickle": ["areal-dataservice-pickle"],
        "AReaL awex": ["areal-awex"],
        "AReaL agent worker": ["areal-dataservice-pickle"],
        "LLaMA-Factory WebUI RCE": ["llamafactory-webui-rce"],
        "LLaMA-Factory SSRF": ["llamafactory-ssrf-redirect"],
        "ms-swift trust_remote_code": ["msswift-trust-remote-code"],
        "ms-swift eval escape": ["msswift-eval-escape"],
        "Ray dashboard unauth": ["ray-dashboard-unauth"],
    }
    def map_items(mapping):
        return [{"ref": k, "entry_ids": [i for i in v if i in ids]} for k, v in mapping.items()]
    return {
        "master": map_items(master),
        "omni": map_items(omni),
        "agent": map_items(agent),
        "latest": map_items(latest),
        "mining": [{"ref": e["id"], "entry_ids": [e["id"]]} for e in entries if e["source"] == "mining"],
        "legacy": [{"ref": Path(e["evidence"]["path"]).name, "entry_ids": [e["id"]]}
                   for e in entries if e["source"] == "legacy-candidate"]
        + [{"ref": name, "entry_ids": [eid]} for name, eid in (legacy_alias or {}).items()],
        "new": [{"ref": e["id"], "entry_ids": [e["id"]]} for e in entries if e["source"] == "new-discovery"],
    }


def main() -> None:
    entries = AUDIT + OMNI_EXTRA + AGENT + NEW + load_mining()
    by_id = {}
    for e in entries:
        if e["id"] in by_id:
            raise SystemExit(f"duplicate id: {e['id']}")
        by_id[e["id"]] = e
    # Cross-listed inventory sources: the primary bucket drives counts, while
    # source_tags lets the OMNI/JEV section show Jev components that were first
    # catalogued under the core framework audit.
    for e in entries:
        if e["id"] in {"djev-open-proxy", "vllm-jev-plugin-auth-bypass", "slime-pull-weights"}:
            e.setdefault("source_tags", [])
            if "omni-jev" not in e["source_tags"]:
                e["source_tags"].append("omni-jev")
    # Public references already cited by the source audit documents.  These are
    # authoritative downgrades even when a keyword search cannot see the exact
    # function name (e.g. CERT/CC VU#281278 describes the SGLang behaviour but
    # not `decide_request_auth`).
    known_public = {
        "sglang-admin-optional-failopen": ["CVE-2026-15978", "VU#281278",
                                            "GHSA-2wvm-gjg7-5jfm", "GHSA-h6rf-77vv-9mvj"],
        "llamafactory-webui-rce": ["CVE-2026-58116"],
        "llamafactory-ssrf-redirect": ["CVE-2025-61784", "CVE-2026-85673"],
        "verl-prime-math-eval": ["CVE-2026-6878"],
        "ray-version-drift": ["CVE-2026-57516"],
        "ray-dashboard-unauth": ["CVE-2023-48022", "CVE-2023-48023"],
        "vllm-omni-media-ssrf": ["CVE-2026-24779", "CVE-2026-73560", "CVE-2026-34753"],
        "vllm-omni-trust-remote-code": ["CVE-2026-27893", "CVE-2026-22807", "CVE-2026-90553"],
    }
    for e in entries:
        if e["id"] in known_public:
            e["known_public"] = known_public[e["id"]]
    # Exposure/hardening observations are kept in the inventory but are not
    # counted as 0day vulnerabilities even when dynamically reproducible.
    for e in entries:
        if e["id"] == "cephcsi-httpserver-go-pprof-exposed-l37-regex":
            e["reserve_eligible"] = False
            e["notes"] = (e.get("notes") or "") + " [exposure-only: pprof endpoint reachable; hardening observation, not a novel 0day]"
    legacy_alias: dict[str, str] = {}
    for e in load_legacy():
        name = Path(e["evidence"]["path"]).name
        if e["id"] in by_id:
            # The same rule hit was promoted into the upstream-verification
            # registry; keep the legacy file as a source alias, not a second
            # mutable entry with independent counts.
            legacy_alias[name] = e["id"]
            continue
        by_id[e["id"]] = e
        entries.append(e)
    missing = []
    for e in entries:
        p = e.get("evidence", {}).get("path")
        if p and not (Path(p).is_absolute() or (ROOT / p).exists() or (WORKSPACE / p).exists()):
            missing.append((e["id"], p))
    inventory = {
        "schema": "trident-zeroday-inventory-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generated_by": "tools/build-zeroday-inventory.py",
        "sources": {
            "master": "internal vulnerability master (§1–§6, §10)",
            "omni": "projects/jev-omni-2026-10/AUDIT-REPORT.md + projects/repro-2026-10",
            "agent": "projects/agent-2026-10/results/0DAY-REGISTRY.md",
            "latest": "projects/repro-2026-10/LATEST-VERIFICATION.md",
            "mining": "trident/core/exploit-registry.json (source=mining)",
            "legacy": "reports/samples/mining/zeroday/registry/candidates/*.json",
            "new": "tools/build-zeroday-inventory.py curated new-discovery cases",
        },
        "source_index": build_source_index(entries, legacy_alias),
        "missing_evidence": missing,
        "entries": entries,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(inventory, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"entries": len(entries), "missing_evidence": len(missing),
                      "by_source": {s: sum(1 for e in entries if e["source"] == s)
                                    for s in ("audit-history", "omni-jev", "agent-platform",
                                              "mining", "new-discovery", "legacy-candidate")}},
                     ensure_ascii=False, indent=2))
    if missing:
        print("MISSING EVIDENCE:")
        for eid, p in missing:
            print(f"  {eid}: {p}")


if __name__ == "__main__":
    main()
