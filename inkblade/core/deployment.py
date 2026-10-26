# -*- coding: utf-8 -*-
"""Deployment-requirement classification for every exploit-registry entry.

The registry answers "was the sink reproduced?".  It does not answer the first
question of an engagement: *is the path reachable on the vendor's default
install?*  This module adds that second axis:

``default-exposed``
    Reachable with the vendor's default bind address/config: a listener on
    ``0.0.0.0``/``::``, no authentication dependency, a feature that is on by
    default, or a default path.  Reachability is not the same as RCE - a
    ``default-exposed`` metrics/pprof listener is still only an exposure
    finding until an exploit primitive is verified.

``needs-config``
    Requires a non-default flag/environment variable, an admin/tenant
    credential, an extra service (database/model server/sandbox), or a
    deployment-specific feature.

``function-level``
    The sink is a library/CLI call reached by the local operator (checkpoint
    loader, training launcher, packaging helper).  No network service exposure
    is claimed.

``hardware-only``
    The path lives in BMC/switch/DPU/NIC/GPU-fabric firmware or a host kernel /
    container runtime that cannot be reached from a tenanted workload API.

Every verdict carries an ``evidence`` string naming the concrete reason:
``file:line`` + snippet, the bind address, the missing flag/env, the required
GPU/model runtime, or the vendor-firmware prerequisite.  Empty or generic
evidence is rejected by :func:`validate_evidence` and by
``tools/verify-exploits.py``.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED = ("default-exposed", "needs-config", "function-level", "hardware-only")

# Components whose vulnerable path is firmware / host kernel / fabric hardware.
HARDWARE_COMPONENTS = {
    "bmc", "sonic", "sonicrestapi", "cumulus", "nvidia", "cgpu", "nccl",
    "ucx", "ucxpy", "runc", "containerd", "linux-kernel", "dpu",
    "nvswitch", "cxl", "spdm", "tpm", "secureboot", "iommu",
}

# Verified dynamic-function cases whose only trigger is a GPU/model runtime.
GPU_RUNTIME_IDS = {
    "CVE-2025-59425",   # vLLM timing oracle needs a live GPU model server
    "CVE-2026-15978",   # SGLang weight exfil needs a loaded GPU model
}

# ---------------------------------------------------------------------------
# Explicit verdicts.  These override the generic rules below and are the
# audited, human-reviewed statements rendered into WEAPON-READINESS.md.
# ---------------------------------------------------------------------------
OVERRIDES: dict[str, tuple[str, str]] = {
    # ---- default-exposed: verified service paths -------------------------
    "CVE-2026-92972": (
        "default-exposed",
        "sglang/srt/disaggregation/common/conn.py:738 registers PUT /route, "
        "/register_dp_rank and /query_dp_ranks on the PD bootstrap aiohttp app with no "
        "auth dependency (TCPSite host=self.host); a live unauthenticated PUT /route "
        "returned 200 and rewrote prefill_port_table (KV peer redirection).",
    ),
    "cephcsi-httpserver-go-pprof-exposed-l37-regex": (
        "default-exposed",
        "internal/util/httpserver.go:37 registers net/http/pprof on the CSI metrics mux; "
        "cmd/cephcsi.go:255 defaults MetricsIP to 0.0.0.0 and the mux has no auth - live "
        "GET /debug/pprof/ and /metrics returned 200 without Authorization.",
    ),
    "cephcsi-cephcsi-go-bind-all-l255-regex": (
        "default-exposed",
        "cmd/cephcsi.go:255 sets conf.MetricsIP = \"0.0.0.0\" for the default CSI "
        "metrics/pprof mux; no auth middleware is installed on that listener.",
    ),
    "kueue-server-go-pprof-exposed-l30-regex": (
        "default-exposed",
        "cmd/kueueviz/backend/config/server.go:30 imports net/http/pprof; KUEUEVIZ_AUTH_MODE "
        "unset defaults to Disabled and the listener is :::18080 - unauthenticated "
        "GET /api/pod/<name> returned 200 with the canary env value.",
    ),
    "juicefscsi-controller-manager-go-go-bind-all-l71-regex": (
        "default-exposed",
        "cmd/app/controller_manager.go:71 BindAddress: \"0.0.0.0:8084\" and controller-runtime "
        "logs secure=false; unauthenticated GET /metrics returned 200 on eth0.",
    ),
    # ---- default-exposed: source-line exposure (no RCE claimed) ----------
    "llamafactory-app-py-bind-all-interfaces-l130-regex": (
        "default-exposed",
        "src/llamafactory/api/app.py:130 api_host = os.getenv(\"API_HOST\", \"0.0.0.0\"); "
        "the FastAPI app installs no authentication dependency, so the default launch is "
        "reachable from every interface.",
    ),
    "llamafactory-app-py-go-bind-all-l130-regex": (
        "default-exposed",
        "src/llamafactory/api/app.py:130 api_host = os.getenv(\"API_HOST\", \"0.0.0.0\"); "
        "default run binds 0.0.0.0 with no auth dependency.",
    ),
    "llamafactory-interface-py-bind-all-interfaces-l103-regex": (
        "default-exposed",
        "src/llamafactory/webui/interface.py:103 server_name = "
        "os.getenv(\"GRADIO_SERVER_NAME\", \"0.0.0.0\"); gradio launch() has no auth by default.",
    ),
    "llamafactory-interface-py-bind-all-interfaces-l94-regex": (
        "default-exposed",
        "src/llamafactory/webui/interface.py:94 server_name = "
        "os.getenv(\"GRADIO_SERVER_NAME\", \"0.0.0.0\"); gradio launch() has no auth by default.",
    ),
    "llamafactory-interface-py-go-bind-all-l103-regex": (
        "default-exposed",
        "src/llamafactory/webui/interface.py:103 binds the web UI to 0.0.0.0 when "
        "GRADIO_SERVER_NAME is unset (the vendor default).",
    ),
    "llamafactory-interface-py-go-bind-all-l94-regex": (
        "default-exposed",
        "src/llamafactory/webui/interface.py:94 binds the web UI to 0.0.0.0 when "
        "GRADIO_SERVER_NAME is unset (the vendor default).",
    ),
    # ---- needs-config: verified but gated ---------------------------------
    "CVE-2023-48022": (
        "needs-config",
        "ray/dashboard/modules/job/job_head.py:273 @routes.post(\"/api/jobs/\") has no token "
        "check, but the dashboard binds 127.0.0.1 by default (--dashboard-host is required "
        "to expose it); a reachable dashboard is a deployment setting.",
    ),
    "CVE-2023-48023": (
        "needs-config",
        "ray/dashboard/modules/log/log_head.py:66 proxies ?url= to a 127.0.0.1-only log "
        "service; requires the dashboard to be exposed with --dashboard-host first.",
    ),
    "CVE-2026-40217": (
        "needs-config",
        "litellm/proxy/guardrails/guardrail_endpoints.py:1528 exec(compile(custom_code)) is "
        "only reachable through the admin guardrail endpoint (user_api_key_auth + admin "
        "check); a non-admin request is rejected.",
    ),
    "CVE-2026-42203": (
        "needs-config",
        "litellm/integrations/dotprompt/prompt_manager.py:62 uses a plain jinja2 Environment; "
        "the dotprompt write/read path requires a valid virtual key (Authorization: Bearer).",
    ),
    "volcano-scheduler-server-go-pprof-exposed-l162-regex": (
        "needs-config",
        "cmd/scheduler/app/server.go:162 installs /debug/pprof/ only when the scheduler is "
        "started with --enable-pprof; the default scheduler does not register the handler.",
    ),
    # ---- needs-config: full stack / k8s / advisory ------------------------
    "CVE-2025-3466": (
        "needs-config",
        "Dify 1.1.0-1.1.2 code node: exploiting the parseInt override requires the Dify API, "
        "workflow engine and dify-sandbox Node runtime; a bare API request has no code node.",
    ),
    "CVE-2025-56520": (
        "needs-config",
        "Same Dify code-node prerequisite: the sandbox service, a workflow app and a code "
        "node must all be deployed before the parseInt escape is reachable.",
    ),
    "CVE-2025-63387": (
        "needs-config",
        "Same Dify code-node prerequisite: dify-sandbox plus a workflow code node; no "
        "default HTTP route reaches the vulnerable JS runner.",
    ),
    "CVE-2025-23354": (
        "needs-config",
        "Megatron ensemble_classifier advisory has no resolved file:line sink; reproduction "
        "needs a full Megatron training/checkpoint configuration (torch + model shards).",
    ),
    "CVE-2025-33247": (
        "needs-config",
        "Same Megatron ensemble_classifier prerequisite: a training stack and checkpoint "
        "load path; the advisory does not identify a standalone function sink.",
    ),
    "CVE-2025-64496": (
        "needs-config",
        "Open WebUI Direct Connections SSE path needs the FastAPI server, built frontend, "
        "database and an authenticated session; no default unauthenticated route.",
    ),
    "CVE-2026-28786": (
        "needs-config",
        "Open WebUI file overwrite needs the full server + DB and an authenticated user "
        "session before the write handler is reachable.",
    ),
    "CVE-2026-28788": (
        "needs-config",
        "Open WebUI file overwrite needs the full server + DB and an authenticated user "
        "session before the write handler is reachable.",
    ),
    "CVE-2026-35029": (
        "needs-config",
        "litellm/proxy/proxy_server.py:11416 /config/update is guarded by user_api_key_auth; "
        "reaching it needs a DB-backed virtual key (Postgres/Prisma user row) on a running "
        "litellm 1.82.0 proxy.",
    ),
    "CVE-2026-47102": (
        "needs-config",
        "Same litellm /config/update prerequisite: a Postgres-backed proxy and an "
        "authenticated non-admin virtual key are required.",
    ),
    "CVE-2024-10220": (
        "needs-config",
        "Kubelet gitRepo volume hostPath traversal affects kubelet <=1.30 and still needs "
        "pod-create permission (namespace RBAC) plus the gitRepo volume plugin enabled.",
    ),
    "CVE-2024-3177": (
        "needs-config",
        "Kubernetes mountable-secrets bypass needs pod-create permission and an existing "
        "service-account secret; kubelet/apiserver version pin <1.29.",
    ),
    "KUBERAY-ADV-2026-01": (
        "needs-config",
        "Requires a Kubernetes cluster with the KubeRay operator and a RayCluster CR; the "
        "operator's default RBAC is the vulnerable boundary (no standalone HTTP path).",
    ),
    "LWS-ADV-2026-01": (
        "needs-config",
        "Requires a Kubernetes cluster with LeaderWorkerSet CRDs and a created "
        "LeaderWorkerSet; the leader endpoint is only reachable inside that deployment.",
    ),
    "gpuoperator-0500-daemonset-yaml-elevated-pod-spec-l108-regex": (
        "needs-config",
        "manifests/state-driver/0500_daemonset.yaml:108 hostNetwork: true runs only after the "
        "GPU Operator is installed on a GPU node; it is an operator-owned DaemonSet, not a "
        "tenant API.",
    ),
    "CVE-2026-32981": (
        "needs-config",
        "Ray dashboard static traversal was refuted on 2.8.0 (path_clean_middleware returns "
        "403 for raw/encoded /static and /logs); only an explicitly exposed dashboard is "
        "relevant, and the claim did not reproduce.",
    ),
    "CVE-2026-7301": (
        "needs-config",
        "sglang multimodal scheduler_client.py:20 binds the ZMQ broker to 127.0.0.1, not "
        "0.0.0.0; the pickle sink is real but has no default remote exposure.",
    ),
    "CVE-2026-7302": (
        "needs-config",
        "The cited line is the profiler trace export path (output_dir + profile_prefix), not "
        "the multimodal upload handler; no remote attacker file-content path exists.",
    ),
    "CVE-2026-42208": (
        "needs-config",
        "The LiteLLM SQL-injection claim was not resolved to a concrete unparameterized "
        "query in 1.82.0; there is no reachable sink to classify beyond the proxy surface.",
    ),
    "LITELLM-DEFAULT-KEY": (
        "needs-config",
        "1.82.0 ships no default master key; the proxy runs open only when the operator "
        "omits LITELLM_MASTER_KEY (deployment misconfiguration, not a version-bounded flaw).",
    ),
    "CVE-2024-37061": (
        "function-level",
        "MLflow 2.8.1 MLproject execution is the documented project-runner trust model; the "
        "call is operator-invoked (mlflow run) with no attacker-controlled service boundary.",
    ),
    "CVE-2026-4993": (
        "function-level",
        "Catalog metadata is inconsistent (LITELLM_MASTER_KEY recorded under wandb); there is "
        "no wandb source/sink to reach, so no deployment surface can be classified.",
    ),
    "megatron-checkpointing-py-torch-load-any-l2796-regex": (
        "function-level",
        "checkpointing.py:2796 torch.load is only called by load_biencoder_checkpoint with an "
        "operator-supplied checkpoint directory; the caller path is unreachable from a "
        "service request (the registry records it as unsupported).",
    ),
    # ---- hardware-only: GPU/model runtime ---------------------------------
    "CVE-2025-59425": (
        "hardware-only",
        "vllm/entrypoints/openai/api_server.py:848 auth-header comparison is a timing oracle "
        "that needs a live GPU-backed vLLM model server and network-level timing measurement; "
        "a CPU-only lab cannot serve the model.",
    ),
    "CVE-2026-15978": (
        "hardware-only",
        "sglang/srt/entrypoints/http_server.py:225 api_key is None by default, but weight "
        "exfiltration needs a GPU-loaded SGLang model server and the model weight endpoints; "
        "no CPU-only path serves real weights.",
    ),
}

# Library components whose static findings are local function/CLI calls.
LIBRARY_COMPONENTS = {
    "deepspeed", "llamafactory", "msswift", "trl", "transformers", "megatron",
    "pytorch", "ucxpy", "mlflow", "vllm", "sglang", "slime", "skyrl", "areal",
    "verl", "openrlhf", "dify", "open-webui", "litellm", "ray",
}

# Static-only blockers that describe a local library sink rather than a
# deployment-specific service configuration.
FUNCTION_LEVEL_BLOCKERS = {
    "hygiene-not-exploitable", "pattern-false-positive", "dependency-default-blocks",
    "by-design", "catalog-data-error",
}

# Blockers that mean "a whole service stack is missing".
STACK_BLOCKERS = {"requires-full-stack", "requires-k8s"}

_ANCHOR_RE = re.compile(
    r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::|0\.0\.0\.0|127\.0\.0\.1|"
    r"\.(?:py|go|yaml|yml|js|ts):\d+|--[a-z][a-z0-9-]+|"
    r"[A-Z][A-Z0-9_]{3,}|:\d{2,5}|unauthenticated|no auth|default|requires|GPU|"
    r"model|checkpoint|firmware|BMC|kubelet|namespace|pod|sandbox|ZMQ|pickle|"
    r"torch\.load|admin|token|key|flag|env)",
    re.IGNORECASE,
)


def validate_evidence(evidence: str) -> list[str]:
    """Return the reasons a deployment-evidence string is not specific enough."""
    problems: list[str] = []
    text = " ".join(str(evidence or "").split())
    if len(text) < 30:
        problems.append("evidence shorter than 30 characters")
    if not _ANCHOR_RE.search(text):
        problems.append("evidence has no concrete anchor (address/flag/env/file:line/GPU/BMC)")
    return problems


def _blocker(manifest: dict | None) -> tuple[str, str]:
    block = (manifest or {}).get("static_blocker") or {}
    return str(block.get("category") or ""), str(block.get("reason") or "")


def _root_cause(manifest: dict | None) -> str:
    rc = (manifest or {}).get("root_cause") or {}
    file = str(rc.get("file") or "")
    line = rc.get("line") or 0
    snippet = " ".join(str(rc.get("snippet") or "").split())
    if not file:
        return ""
    loc = f"{file}:{line}" if line else file
    return f"{loc} `{snippet}`" if snippet else loc


def _component(entry: dict) -> str:
    return str(entry.get("component") or "").lower()


def classify(entry: dict, manifest: dict | None = None) -> dict[str, str]:
    """Return ``{requirement, evidence, basis}`` for one registry entry."""
    eid = str(entry.get("id") or "")
    if eid in OVERRIDES:
        requirement, evidence = OVERRIDES[eid]
        return {"requirement": requirement, "evidence": evidence,
                "basis": "runtime" if entry.get("status") == "verified" else "source-line"}

    status = str(entry.get("status") or "")
    method = str(entry.get("method") or "")
    component = _component(entry)
    category, reason = _blocker(manifest)
    root = _root_cause(manifest)

    if eid in GPU_RUNTIME_IDS:
        return {"requirement": "hardware-only", "evidence": reason or root,
                "basis": "runtime"}

    if status == "unsupported":
        unsupported = (manifest or {}).get("unsupported") or {}
        requires = ", ".join(str(x) for x in unsupported.get("requires") or [])
        base_reason = str(unsupported.get("reason") or reason or root
                          or "vendor firmware / host kernel path")
        evidence = base_reason
        if requires:
            evidence = f"{evidence}; requires {requires}"
        hardware = component in HARDWARE_COMPONENTS or "firmware" in evidence.lower()
        return {"requirement": "hardware-only" if hardware else "function-level",
                "evidence": evidence, "basis": "advisory"}

    if status == "verified":
        if method in {"dynamic-function"}:
            evidence = (f"{root}; the sink is reached by a library/CLI caller, not by a "
                        "network service") if root else (
                        f"local library/CLI sink in {component}; no service exposure claimed")
            return {"requirement": "function-level", "evidence": evidence, "basis": "runtime"}
        if method in {"dynamic-http", "dynamic-service"}:
            evidence = (f"{root}; dynamically reproduced service path in {component}; "
                        "reaching it needs the deployment-specific endpoint/credential")
            if not root:
                evidence = (f"dynamically reproduced {method} path in {component}; the "
                            "service must be deployed with the documented endpoint")
            return {"requirement": "needs-config", "evidence": evidence, "basis": "runtime"}
        evidence = root or f"verified {method} path in {component}"
        return {"requirement": "function-level", "evidence": evidence, "basis": "runtime"}

    # ---- static-only -------------------------------------------------------
    if category == "exposure-only":
        evidence = (f"{root}; the bind/launch default is reachable without a non-default "
                    "setting (exposure finding, no RCE primitive verified)") if root else reason
        return {"requirement": "default-exposed", "evidence": evidence, "basis": "source-line"}

    if category == "host-toolchain-missing":
        if component == "sonicrestapi":
            return {"requirement": "hardware-only", "evidence": reason, "basis": "source-line"}
        if "bind" in reason.lower() or "0.0.0.0" in reason or "metrics" in reason.lower():
            return {"requirement": "default-exposed", "evidence": f"{root}; {reason}",
                    "basis": "source-line"}
        return {"requirement": "needs-config", "evidence": f"{root}; {reason}",
                "basis": "source-line"}

    if category == "requires-full-stack":
        if eid in GPU_RUNTIME_IDS or "GPU" in reason or "model runtime" in reason:
            return {"requirement": "hardware-only", "evidence": f"{root}; {reason}",
                    "basis": "advisory"}
        return {"requirement": "needs-config", "evidence": f"{root}; {reason}",
                "basis": "source-line" if root else "advisory"}

    if category == "requires-k8s":
        return {"requirement": "needs-config", "evidence": f"{root}; {reason}",
                "basis": "advisory"}

    if category in FUNCTION_LEVEL_BLOCKERS and component in LIBRARY_COMPONENTS:
        evidence = (f"{root}; {reason}") if root else reason
        return {"requirement": "function-level", "evidence": evidence, "basis": "source-line"}

    if category in {"claim-refuted", "advisory-unresolved", "deployment-misconfig"}:
        return {"requirement": "needs-config", "evidence": f"{root}; {reason}",
                "basis": "advisory"}

    # Conservative fallback: a static finding without a verified primitive needs
    # a deployment-specific configuration before it is reachable.
    evidence = (f"{root}; {reason}") if root else (
        reason or f"static finding in {component}; no default-exposed path established")
    return {"requirement": "needs-config", "evidence": evidence, "basis": "source-line"}


# ---------------------------------------------------------------------------

    if eid in _RESERVE_PICKLE_IDS:
        rc = entry.get("root_cause") or {}
        loc = f"{rc.get('file')}:{rc.get('line')}" if rc.get("file") else "checkpoint loader"
        return {
            "requirement": "function-level",
            "evidence": f"{loc} deserialises a checkpoint/cache file controlled by the "
                        "operator or a tenant with write access; no default service route.",
            "basis": "runtime",
        }

    text = " ".join(str(x) for x in (entry.get("preconditions") or []))
    surface = str(entry.get("surface") or "")
    if not surface:
        rc = entry.get("root_cause") or {}
        file = str(rc.get("file") or "")
        if file.endswith((".py", ".pt", ".pth")) or "model" in str(entry.get("reachability") or "").lower():
            requirement = "function-level"
        else:
            requirement = "needs-config"
    elif "0.0.0.0" in text or "no token" in text.lower() or "no auth" in text.lower():
        requirement = "default-exposed"
    else:
        requirement = "needs-config"
    evidence = (entry.get("exploit") or "") + "; preconditions: " + (text or "none recorded")
    return {"requirement": requirement, "evidence": evidence, "basis": "runtime"}


def summarize(entries: list[dict]) -> dict[str, int]:
    counts = {key: 0 for key in ALLOWED}
    for entry in entries:
        requirement = entry.get("deployment_requirement")
        if requirement in counts:
            counts[requirement] += 1
    return counts
