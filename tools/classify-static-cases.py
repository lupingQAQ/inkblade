"""Classify every static-only case with a precise blocker category + reason.

The category is written to ``manifest.json:static_blocker`` and rendered by
``tools/render_exploit_verification.py``; ``tools/verify-exploits.py`` rejects
static-only cases without a known category.

Usage::

    python tools/classify-static-cases.py            # dry run (counts only)
    python tools/classify-static-cases.py --write    # write manifests
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "lab" / "upstream_verify" / "cases"

# (component, rule or id substring) -> (category, reason)
GROUPS = {
    # --- Go services: no Go toolchain / container runtime on this host ------
    "go-toolchain": (
        "host-toolchain-missing",
        "Go toolchain and container runtime are absent on this Windows host; the pinned "
        "service/binary cannot be built or started, so the sink cannot be driven "
        "dynamically. Source-line root cause and pin remain recorded.",
    ),
    # --- Kubernetes control plane / kubelet ---------------------------------
    "k8s": (
        "requires-k8s",
        "Requires a live Kubernetes API server/kubelet (Linux node, admission plugins, "
        "CRDs); no cluster is available in this lab, so the cross-component path cannot "
        "be executed end-to-end.",
    ),
    # --- Full service stack (DB/GPU/model runtime) --------------------------
    "full-stack": (
        "requires-full-stack",
        "Requires the complete upstream service stack (database/GPU/model runtime) that "
        "cannot be started in this lab; no function-level path reproduces the claimed "
        "impact on its own.",
    ),
    # --- Pattern matched, but not a sink -----------------------------------
    "false-positive": (
        "pattern-false-positive",
        "The matched line is not an attacker-reachable sink (method definition, "
        "docstring/example, or a benign call with the rule's keyword); no vulnerable "
        "data flow exists at this location.",
    ),
    # --- Trust-boundary / hygiene finding ----------------------------------
    "hygiene": (
        "hygiene-not-exploitable",
        "No attacker-controlled value crosses into the matched call: it is driven by "
        "the local operator's CLI/config or is a supply-chain hygiene gap. This is a "
        "hardening recommendation, not a reproducible exploit.",
    ),
}


def classify(manifest: dict) -> tuple[str, str]:
    cid = manifest["id"]
    component = str(manifest.get("component") or "")
    rule = str((manifest.get("mining") or {}).get("rule") or "")

    if cid == "CVE-2026-32981":
        return ("claim-refuted",
                "Live probe on the pinned Ray 2.8.0 dashboard: path_clean_middleware "
                "answers all raw/encoded /static and /logs traversal attempts with 403.")
    if cid == "CVE-2026-7301":
        return ("claim-refuted",
                "Pinned scheduler_client.py:20 binds the ZMQ broker to 127.0.0.1, not "
                "0.0.0.0; the pickle sink is real but has no remote exposure path as "
                "claimed. Left static rather than promoting a weaker claim.")
    if cid == "CVE-2026-7302":
        return ("claim-refuted",
                "The cited line is the profiler trace export path (output_dir + "
                "profile_prefix), not the multimodal upload handler; no attacker file "
                "content/write is shown. Claim is misattributed in the advisory mapping.")
    if cid == "CVE-2026-4993":
        return ("catalog-data-error",
                "Catalog metadata is inconsistent (LITELLM_MASTER_KEY recorded under "
                "wandb); no wandb source/sink exists for this record. Catalog fix needed, "
                "not an exploit.")
    if cid == "CVE-2026-42208":
        return ("advisory-unresolved",
                "The SQL-injection claim was never resolved to a concrete unparameterized "
                "query in 1.82.0; without a sink there is nothing to execute.")
    if cid == "LITELLM-DEFAULT-KEY":
        return ("deployment-misconfig",
                "1.82.0 ships no default master key; the proxy runs open only when the "
                "operator omits LITELLM_MASTER_KEY, and DB-less management calls still "
                "fail. Deployment guidance, not a version-bounded vulnerability.")
    if cid == "CVE-2024-37061":
        return ("by-design",
                "MLproject execution is the documented project-runner trust model; no "
                "safe-vs-vulnerable boundary exists in 2.8.1 to reproduce.")
    if cid.startswith("msswift-loader-py-load-dataset-any-l338") or cid.startswith(
            "msswift-loader-py-load-dataset-any-l341"):
        return ("pattern-false-positive",
                "The matched line is a docstring example (>>> load_dataset(...)), not "
                "executable code.")
    if cid in {
        "trl-data-utils-py-apply-chat-template-dynamic-l167-regex",
        "trl-data-utils-py-apply-chat-template-dynamic-l303-regex",
        "trl-data-utils-py-apply-chat-template-dynamic-l357-regex",
        "trl-data-utils-py-apply-chat-template-dynamic-l362-regex",
        "trl-data-utils-py-missing-revision-l352-regex",
        "trl-sft-trainer-py-missing-revision-l310-regex",
        "trl-sft-trainer-py-load-dataset-any-l527-regex",
        "trl-utils-py-missing-revision-l1431-regex",
    }:
        return ("pattern-false-positive",
                "The matched line is a function definition, a wrapper return, or a "
                "docstring example; the rule matched the API name, not an execution sink.")
    if cid.startswith("msswift-loader-py-load-dataset-any"):
        return ("hygiene-not-exploitable",
                "load_dataset() is driven by the operator's dataset id/local file "
                "argument; no attacker-controlled path reaches it.")
    if cid == "llamafactory-fsdp2-py-torch-load-any-l517-regex":
        return ("dependency-default-blocks",
                "Upstream omits weights_only, but the pinned torch (2.14.1) defaults to "
                "weights_only=True, so a reducing payload is refused before any object is "
                "constructed. Not exploitable with this dependency pairing.")
    if cid == "deepspeed-stage3-py-torch-load-any-l3616-regex":
        return ("pattern-false-positive",
                "Line 3616 is inside the class docstring example; it is never executed.")
    if rule in {"eval-call"}:
        return ("pattern-false-positive",
                "The rule matched `<module>.eval()` (torch train/eval mode) or a `def "
                "eval` method, not Python's builtin eval; there is no code evaluation.")
    if rule == "apply-chat-template-dynamic":
        return ("dependency-default-blocks",
                "The template is Jinja-compiled inside transformers' "
                "ImmutableSandboxedEnvironment; the hit is template/data manipulation, "
                "not code execution, and the sandbox blocks attribute escapes.")
    if rule == "missing-revision":
        return ("hygiene-not-exploitable",
                "from_pretrained()/load_dataset() without a revision is a supply-chain "
                "reproducibility gap; exploiting it requires control of the upstream Hub "
                "repository (TOCTOU), which is not a local attacker path.")
    if rule == "trust-remote-code-propagated":
        return ("hygiene-not-exploitable",
                "trust_remote_code propagation is an explicit operator opt-in; a "
                "malicious model repository is required, and the flag's execution "
                "primitive is already verified in the transformers cases.")
    if component in {"sonicrestapi", "dradriver"} or cid.startswith("gpuoperator-main-go"):
        return GROUPS["go-toolchain"]
    if cid.startswith(("cephcsi-", "juicefscsi-")) or component in {"kueue", "volcano"}:
        return GROUPS["go-toolchain"]
    if rule == "subprocess-popen" or rule == "exec-command-go":
        return ("hygiene-not-exploitable",
                "The command and argv come from the local launcher/daemon configuration "
                "(operator CLI), not from a tenant/network input; no privilege boundary "
                "is crossed.")
    if rule == "env-rank-read":
        return ("hygiene-not-exploitable",
                "Reading LOCAL_RANK/RANK from the environment is normal distributed "
                "startup behaviour; the value is not attacker-controlled.")
    if rule == "wandb-checkpoint-hook":
        return ("pattern-false-positive",
                "The matched line calls a wandb bookkeeping hook; it is not a sink and "
                "takes no attacker-controlled input.")
    if rule == "pickle-loads" and component == "ucxpy":
        return ("pattern-false-positive",
                "The cloudpickle payload is the local `func` argument passed by the test "
                "harness (start_process), not bytes received from the network; the debug "
                "server also needs UCX/GPU.")
    if rule == "bind-all-interfaces" or rule == "go-bind-all":
        return ("exposure-only",
                "Default 0.0.0.0 binding is an exposure posture, not an exploit: no "
                "authentication bypass, write or code execution is demonstrated.")
    if rule == "pprof-exposed":
        return GROUPS["go-toolchain"]
    if rule == "elevated-pod-spec":
        return ("requires-k8s",
                "Privileged/hostNetwork DaemonSet posture in a Helm manifest; evaluating "
                "it needs a live cluster and GPU nodes.")
    for prefix in ("cephcsi-", "juicefscsi-", "kueue-", "volcano-", "dradriver-",
                   "sonicrestapi-", "gpuoperator-main-go"):
        if cid.startswith(prefix):
            return GROUPS["go-toolchain"]
    if component == "gpuoperator":
        return GROUPS["k8s"]
    if component in {"kubernetes", "lws", "kuberay"}:
        return GROUPS["k8s"]
    if component == "dify" or component == "open-webui":
        return GROUPS["full-stack"]
    if component == "megatron":
        return GROUPS["full-stack"]
    if component == "sglang":
        return GROUPS["full-stack"]
    if cid == "CVE-2025-59425":
        return ("requires-full-stack",
                "Timing side channel in the vLLM OpenAI auth middleware needs a live "
                "GPU/model server plus a network-level timing measurement; an in-process "
                "comparison cannot establish the claimed attack.")
    if component == "vllm":
        return GROUPS["full-stack"]
    if component == "litellm":
        return ("requires-full-stack",
                "The path needs a DB-backed virtual key/user (Prisma/Postgres); without "
                "it the vulnerable handler cannot be reached with a non-admin principal.")
    if rule == "load-dataset-any":
        return ("hygiene-not-exploitable",
                "load_dataset() takes the operator's dataset argument (or is a "
                "docstring); no attacker-controlled path reaches it.")
    if rule == "torch-load-any":
        return ("dependency-default-blocks",
                "torch.load() without weights_only is neutralised by the pinned torch "
                "default (weights_only=True).")
    if rule == "eval-call":
        return GROUPS["false-positive"]
    raise SystemExit(f"unclassified static-only case: {cid} ({component}/{rule})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the manifests (default: dry run)")
    args = parser.parse_args()

    counts: dict[str, int] = {}
    total = 0
    for path in sorted(CASES.glob("*/*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("status") != "static-only":
            continue
        category, reason = classify(manifest)
        if args.write:
            manifest["static_blocker"] = {"category": category, "reason": reason}
            path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        counts[category] = counts.get(category, 0) + 1
        total += 1
    print("classified", total, "(written)" if args.write else "(dry run)")
    for key, value in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {key:28} {value}")


if __name__ == "__main__":
    main()
