# -*- coding: utf-8 -*-
"""Emit the real defense-lab result records for the 11 layer-10 modules.

The records are derived from evidence captured on the QEMU k3s VM:
  lab/defense-lab/evidence/  (raw product logs, scans, probe transcripts)
Nothing here fabricates a detection: every probe carries an evidence path and
a `mock: false` flag. Products that could not be deployed record state=n/a
with a concrete blocking fact instead of a simulated result.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "reports" / "samples" / "defense-lab"

ENV = {
    "cluster": "qemu-k3s",
    "k3s": "v1.36.5+k3s1",
    "kernel": "6.18.58-0-virt",
    "runtime": "containerd://2.3.4-k3s1.36",
    "node_ip": "10.0.2.15",
    "vm": "QEMU TCG, 6 vCPU, 6144 MB",
    "lsm": "lockdown,capability,landlock,yama",
    "btf": "/sys/kernel/btf/vmlinux present",
    "date_utc": "2026-10-26",
}

KYVERNO_EVIDENCE = ["lab/defense-lab/evidence/kyverno-probes.txt"]
FALCO_EVIDENCE = [
    "lab/defense-lab/evidence/falco-alerts.txt",
    "lab/defense-lab/evidence/falco-rules.txt",
    "lab/defense-lab/evidence/falco-probe-time.txt",
]
TRIVY_EVIDENCE = [
    "lab/defense-lab/evidence/trivy-scan.log",
    "lab/defense-lab/evidence/trivy-plain.json",
    "lab/defense-lab/evidence/trivy-secret.json",
    "lab/defense-lab/evidence/trivy-deep.json",
    "lab/defense-lab/evidence/trivy-compressed.json",
    "lab/defense-lab/evidence/trivy-renamed.json",
    "lab/defense-lab/evidence/trivy-alpine310.json",
]
WAF_EVIDENCE = ["lab/defense-lab/evidence/waf-probes.txt"]
CLUSTER_EVIDENCE = [
    "lab/defense-lab/evidence/cluster-snapshot.txt",
    "lab/defense-lab/evidence/k3s-crash-summary.txt",
]


def probe(technique, probe_text, marker, landed, detected, blocked, evidence,
          signal=None, control=False, note=None):
    rec = {
        "technique": technique,
        "probe": probe_text,
        "benign_marker": marker,
        "marker_landed": landed,
        "detected": detected,
        "blocked": blocked,
        "bypass": bool(landed and not detected and not control),
        "control": control,
        "evidence": evidence,
    }
    if signal:
        rec["product_signal"] = signal
    if note:
        rec["note"] = note
    return rec


def base(product, display, module, deployed, state, version, deployment,
         probes, detected, bypasses, not_tested, evidence, limitations):
    return {
        "schema": "inkblade-defense-lab/v1",
        "product": product,
        "display": display,
        "module": module,
        "deployed": deployed,
        "state": state,
        "product_version": version,
        "environment": ENV,
        "deployment": deployment,
        "probes": probes,
        "detected": detected,
        "bypasses": bypasses,
        "not_tested": not_tested,
        "evidence": evidence,
        "limitations": limitations,
        "mock": False,
        "benign_only": True,
    }


PRODUCTS = []

# ---------------------------------------------------------------------------
# admission: Kyverno 1.19.2 (ValidatingPolicy CEL, Deny)
# ---------------------------------------------------------------------------
PRODUCTS.append(base(
    product="admission",
    display="准入策略(Kyverno/Gatekeeper)",
    module="defense-bypass-admission",
    deployed=True,
    state="deployed",
    version="Kyverno v1.19.2",
    deployment={
        "method": "kubectl apply --server-side -f install.yaml (official release v1.19.2)",
        "namespace": "kyverno",
        "workload": "Deployment/kyverno-admission-controller (1/1 Running); background/reports/cleanup scaled to 0 for QEMU TCG",
        "policy_api": "policies.kyverno.io/v1 ValidatingPolicy (CEL). Kyverno 1.19 no longer serves kyverno.io/v1 ClusterPolicy.",
        "policies": [
            "defense-lab-disallow-privileged (Deny, request.namespace == 'defense-lab')",
            "defense-lab-disallow-hostpath (Deny, no volume.hostPath)",
            "defense-lab-require-automount-false (Deny, automountServiceAccountToken == false)",
        ],
        "webhook": "vpol.validate.kyverno.svc-fail-finegrained-<policy>",
        "ground_truth": "kubectl apply exit rc=1; three admission errors name each policy; compliant pod created",
        "lab_adjustment": "startupProbe failureThreshold raised to 90 (10s period) for TCG; no product code changed",
    },
    probes=[
        probe("enforced-path", "Pod with securityContext.privileged=true in ns defense-lab",
              "INKBLADE-BENIGN:admission:enforced-path (pod would echo it)", False, True, True,
              KYVERNO_EVIDENCE,
              signal='admission webhook "vpol...defense-lab-disallow-privileged" denied: Privileged mode is disallowed'),
        probe("enforced-path", "Pod with hostPath volume /tmp in ns defense-lab",
              "INKBLADE-BENIGN:admission:enforced-path (pod would echo it)", False, True, True,
              KYVERNO_EVIDENCE,
              signal='admission webhook "vpol...defense-lab-disallow-hostpath" denied: hostPath volumes are disallowed'),
        probe("enforced-path", "Pod without automountServiceAccountToken:false in ns defense-lab",
              "INKBLADE-BENIGN:admission:enforced-path (pod would echo it)", False, True, True,
              KYVERNO_EVIDENCE,
              signal='admission webhook "vpol...defense-lab-require-automount-false" denied'),
        probe("enforced-path", "Compliant control: privileged=false, automount=false, no hostPath",
              "INKBLADE-BENIGN:admission:enforced-path", True, False, False,
              KYVERNO_EVIDENCE, control=True,
              note="control proves the webhook does not deny everything; pod created and started"),
        probe("exempt-namespace-path", "Identical privileged pod in namespace default (no defense-lab label)",
              "INKBLADE-BENIGN:admission:exempt-namespace-path", True, False, False,
              KYVERNO_EVIDENCE,
              signal="pod/kyverno-probe-privileged-unscoped created (admitted)",
              note="real bypass of the lab policy scope: matchConditions only cover defense-lab; no other policy covers default"),
    ],
    detected=["enforced-path"],
    bypasses=["exempt-namespace-path"],
    not_tested=["audit-mode-path", "annotation-bypass", "mutation-order-path"],
    evidence=KYVERNO_EVIDENCE,
    limitations=[
        "Policies are namespaced by matchConditions to defense-lab; the exempt-namespace result is a real bypass of that scope, not evidence that Kyverno cannot enforce globally.",
        "Kyverno 1.19.2 removed kyverno.io/v1 ClusterPolicy; CEL ValidatingPolicy was used instead.",
        "Only admission-controller was kept running; background/report/cleanup controllers were scaled to 0 under QEMU TCG.",
        "Audit-mode, annotation and mutation-order bypass techniques were not executed (timebox).",
    ],
))

# ---------------------------------------------------------------------------
# falco: 0.45.1 modern eBPF
# ---------------------------------------------------------------------------
PRODUCTS.append(base(
    product="falco",
    display="Falco",
    module="defense-bypass-falco",
    deployed=True,
    state="deployed",
    version="Falco 0.45.1 (helm chart 9.2.1)",
    deployment={
        "method": "helm install falco falcosecurity/falco --set driver.kind=modern_ebpf --set falcoctl.artifact.install.enabled=false",
        "namespace": "kube-system",
        "workload": "DaemonSet/falco 1/1 Running",
        "engine": "modern_ebpf (kernel BTF /sys/kernel/btf/vmlinux)",
        "rules": "bundled /etc/falco/falco_rules.yaml, schema validation ok; falcoctl artifact install disabled",
        "ground_truth": "container log: Opening 'syscall' source with modern BPF probe; Falco version 0.45.1",
    },
    probes=[
        probe("tool-rename-exec", "cp /bin/echo /tmp/inkblade-echo && /tmp/inkblade-echo INKBLADE-BENIGN:falco:tool-rename-exec",
              "INKBLADE-BENIGN:falco:tool-rename-exec", True, True, False,
              ["lab/defense-lab/evidence/falco-alerts.txt"],
              signal="Critical Executing binary not part of base image | proc_exe=/tmp/inkblade-echo container_name=falco-probe"),
        probe("monitored-path-write", "echo marker > /tmp/inkblade-benign-monitored.marker and > /bin/inkblade-benign-marker",
              "INKBLADE-BENIGN:falco:monitored-path-write", True, False, False,
              ["lab/defense-lab/evidence/falco-alerts.txt", "lab/defense-lab/evidence/falco-rules.txt"],
              note="no alert for either write; bundled 0.45.1 stable rules contain no 'Write below etc' / 'Write below binary dir' rule"),
        probe("sensitive-path-access", "echo marker > /etc/inkblade-benign-sensitive.marker and read it back",
              "INKBLADE-BENIGN:falco:sensitive-path-access", True, False, False,
              ["lab/defense-lab/evidence/falco-alerts.txt"],
              note="read of the benign marker itself produced no alert; /etc/shadow read deliberately not executed (benign-only rule)"),
    ],
    detected=["tool-rename-exec"],
    bypasses=["monitored-path-write", "sensitive-path-access"],
    not_tested=["ephemeral-container-marker", "ruleset-gap-syntax"],
    evidence=FALCO_EVIDENCE,
    limitations=[
        "Only the bundled stable ruleset is loaded; falcoctl artifact install was disabled, so incubating/sandbox rule packs are absent.",
        "The monitored-path result is a ruleset coverage gap, not a failure of the modern eBPF engine (exec event was captured).",
        "ephemeral containers and rule-loading syntax gaps were not exercised in the timebox.",
    ],
))

# ---------------------------------------------------------------------------
# imagescan: Trivy 0.76.1
# ---------------------------------------------------------------------------
PRODUCTS.append(base(
    product="imagescan",
    display="镜像扫描(Trivy/grype/veinmind)",
    module="defense-bypass-imagescan",
    deployed=True,
    state="deployed",
    version="Trivy 0.76.1 (trivy-db 1.5 GB)",
    deployment={
        "method": "static release binary in VM; scan via Docker socket (--image-src docker)",
        "workload": "CLI, no cluster workload",
        "scanners": "vuln,secret",
        "samples": [
            "inkblade-benign/plain:lab (benign marker file)",
            "inkblade-benign/secret:lab (AWS example key)",
            "inkblade-benign/deep:lab (key written then deleted in a later layer)",
            "inkblade-benign/compressed:lab (key inside tar.gz)",
            "inkblade-benign/renamed:lab (busybox copied to not-a-rootkit, benign marker)",
            "docker.io/library/alpine:3.10 (known-vulnerable control)",
        ],
        "ground_truth": "alpine:3.10 -> 1 CRITICAL CVE-2021-36159 (apk-tools); all benign samples -> 0 findings",
    },
    probes=[
        probe("plain-layer-sample", "trivy image inkblade-benign/plain:lab",
              "INKBLADE-BENIGN:imagescan:plain-layer-sample", True, False, False, TRIVY_EVIDENCE,
              note="0 vulnerabilities / 0 secrets; Trivy has no signature for arbitrary benign marker content"),
        probe("renamed-benign-tool-layer", "trivy image inkblade-benign/renamed:lab (busybox copied to /usr/local/bin/not-a-rootkit)",
              "INKBLADE-BENIGN:imagescan:renamed-benign-tool-layer", True, False, False, TRIVY_EVIDENCE,
              note="0 findings; rename is not detected because scanner is CVE/secret based, not binary-reputation based"),
        probe("deep-layer-benign", "trivy image inkblade-benign/deep:lab (AWS example key written then rm'd in a later layer)",
              "INKBLADE-BENIGN:imagescan:deep-layer-benign", True, False, False, TRIVY_EVIDENCE,
              note="0 findings; final-filesystem scan does not report the removed layer content"),
        probe("compressed-benign-sample", "trivy image inkblade-benign/compressed:lab (AWS example key inside /opt/inkblade-benign-archive.tgz)",
              "INKBLADE-BENIGN:imagescan:compressed-benign-sample", True, False, False, TRIVY_EVIDENCE,
              note="0 findings; secret scanner does not recurse into tar.gz here"),
        probe("whitelist-sample-name", "not executed", "n/a", False, False, False, TRIVY_EVIDENCE,
              control=True, note="not tested in timebox"),
    ],
    detected=[],
    bypasses=["plain-layer-sample", "renamed-benign-tool-layer", "deep-layer-benign", "compressed-benign-sample"],
    not_tested=["whitelist-sample-name"],
    evidence=TRIVY_EVIDENCE,
    limitations=[
        "The four 'bypasses' mean Trivy does not flag arbitrary benign markers/renamed tools; it is a vulnerability and secret scanner, not a malware/content classifier.",
        "AWS example keys (AKIA...EXAMPLE) are allowlisted by the secret scanner, so the secret sample also produced 0 findings.",
        "Control scan alpine:3.10 found 1 CRITICAL CVE, proving the vuln pipeline was working.",
        "grype and veinmind were not deployed; only Trivy represents the imagescan module.",
    ],
))

# ---------------------------------------------------------------------------
# waf-inference: OWASP ModSecurity CRS (nginx)
# ---------------------------------------------------------------------------
PRODUCTS.append(base(
    product="waf-inference",
    display="WAF(ModSecurity/Coraza/雷池)",
    module="defense-bypass-waf-inference",
    deployed=True,
    state="deployed",
    version="owasp/modsecurity-crs:nginx, nginx 1.30.6, OWASP CRS 4.30.0",
    deployment={
        "method": "docker run in QEMU VM; WAF in front of python:3.12-alpine http.server",
        "workload": "container waf (healthy) + container waf-backend",
        "image_digest": "sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d",
        "config": "MODSEC_RULE_ENGINE=on, BLOCKING_PARANOIA=1, inbound anomaly threshold 5",
        "ground_truth": "plain marker request reached backend (404 from static server); every attack-shaped variant returned 403/414 with backend_delta=0",
    },
    probes=[
        probe("plain-benign-request", "GET /v1/completions?q=INKBLADE-BENIGN:waf-inference:plain-benign-request",
              "INKBLADE-BENIGN:waf-inference:plain-benign-request", True, False, False, WAF_EVIDENCE,
              signal="status=404, backend_delta=2 (request reached python http.server)",
              note="benign plain request is allowed by design; backend has no /v1 route so it returns 404"),
        probe("encoded-request-variant", "GET ?q=%3Cscript%3EINKBLADE-BENIGN%3C%2Fscript%3E",
              "INKBLADE-BENIGN:waf-inference:encoded-request-variant", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0"),
        probe("chunked-request-variant", "POST /v1/completions with Transfer-Encoding: chunked and <script> marker in body",
              "INKBLADE-BENIGN:waf-inference:chunked-request-variant", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0"),
        probe("unicode-request-variant", "GET ?q=%EF%BC%9Cscript%EF%BC%9EINKBLADE-BENIGN",
              "INKBLADE-BENIGN:waf-inference:unicode-request-variant", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0"),
        probe("oversized-benign-variant", "GET with 9000-byte q parameter",
              "INKBLADE-BENIGN:waf-inference:oversized-benign-variant", True, True, True, WAF_EVIDENCE,
              signal="status=414 (nginx request-line limit), backend_delta=0"),
        probe("extra:double-encoded", "GET ?q=%253Cscript%253EINKBLADE-BENIGN",
              "INKBLADE-BENIGN:waf-inference:double-encoded", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0; no double-encoding bypass"),
        probe("extra:case-variant", "GET ?q=%3CScRiPt%3EINKBLADE-BENIGN",
              "INKBLADE-BENIGN:waf-inference:case-variant", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0"),
        probe("extra:sqli-literal", "GET ?q=INKBLADE-BENIGN%27%20UNION%20SELECT%20marker (static backend, no SQL)",
              "INKBLADE-BENIGN:waf-inference:sqli-literal", True, True, True, WAF_EVIDENCE,
              signal="status=403, backend_delta=0"),
    ],
    detected=["encoded-request-variant", "chunked-request-variant", "unicode-request-variant",
              "oversized-benign-variant", "extra:double-encoded", "extra:case-variant", "extra:sqli-literal"],
    bypasses=["plain-benign-request"],
    not_tested=[],
    evidence=WAF_EVIDENCE,
    limitations=[
        "ModSecurity audit log was not enabled in this image configuration; 403 origin is established by the WAF container and backend_delta=0, not by rule-ID text.",
        "Plain benign requests are supposed to pass; recording it as a bypass only means the WAF does not flag benign content.",
        "Only CRS paranoia level 1 was tested; higher PL and response-body inspection were not.",
    ],
))

# ---------------------------------------------------------------------------
# N/A products (real blocking facts, no mock)
# ---------------------------------------------------------------------------
NA = [
    dict(
        product="elkeid", display="Elkeid HIDS", module="defense-bypass-elkeid",
        version="not deployed",
        reason=("Elkeid server/manager/hub stack was not deployed within the timebox and the kernel module cannot be built: "
                "/lib/modules/6.18.58-0-virt/build is absent (no matching Alpine virt kernel headers). "
                "An agent-only container would have no manager to receive events, so no detection could be verified. No mock was used."),
        blocking_fact="kernel headers absent: /lib/modules/6.18.58-0-virt/build not found",
        not_tested=["monitored-path-write", "container-benign-write", "whitelist-path-write",
                    "tool-rename-exec", "encoded-command-variant"],
    ),
    dict(
        product="agentsmith", display="AgentSmith-HIDS", module="defense-bypass-agentsmith",
        version="not deployed",
        reason=("AgentSmith-HIDS needs its LKM smith.ko compiled against the running kernel and an agent process. "
                "The 6.18.58-0-virt Alpine kernel headers/build tree are not installed, and no prebuilt smith.ko for this kernel exists "
                "in the VM. Agent-only execution cannot produce verifiable file/exec detections. No mock was used."),
        blocking_fact="no smith.ko and no /lib/modules/6.18.58-0-virt/build",
        not_tested=["monitored-path-write", "whitelist-path-write", "tool-rename-exec", "benign-dns-query"],
    ),
    dict(
        product="veinmind", display="veinmind-tools 容器扫描", module="defense-bypass-veinmind",
        version="not deployed",
        reason=("chaitin/veinmind-tools was not pulled or executed in the timebox; the image is absent from the VM Docker image store. "
                "No scan result exists, so no detection or bypass is claimed. No mock was used."),
        blocking_fact="docker image chaitin/veinmind-tools not present; not pulled before timebox end",
        not_tested=["plain-layer-sample", "deep-layer-benign", "renamed-benign-tool-layer",
                    "compressed-benign-sample", "whitelist-sample-name"],
    ),
    dict(
        product="tetragon", display="Tetragon", module="defense-bypass-tetragon",
        version="not deployed",
        reason=("Kernel LSM list is 'lockdown,capability,landlock,yama' with no bpf LSM, so Tetragon BPF-LSM enforcement is unavailable. "
                "kprobe-only tracing could run but was not deployed in the remaining timebox; no policy enforcement result is claimed."),
        blocking_fact="cat /sys/kernel/security/lsm = lockdown,capability,landlock,yama (no bpf)",
        not_tested=["lsm-hook-path", "exec-marker", "policy-unmounted-ns", "hostnetwork-path"],
    ),
    dict(
        product="kubearmor", display="KubeArmor", module="defense-bypass-kubearmor",
        version="not deployed",
        reason=("KubeArmor enforcement needs an LSM (BPF LSM or AppArmor). The kernel exposes neither: "
                "lsm = lockdown,capability,landlock,yama. Deploying it in monitor-only mode would not test blocking, so it was recorded N/A."),
        blocking_fact="no bpf/apparmor in /sys/kernel/security/lsm",
        not_tested=["posture-audit-path", "uncovered-namespace", "hostnetwork-path", "default-allow-path"],
    ),
    dict(
        product="hostagent", display="主机代理(Wazuh/Osquery)", module="defense-bypass-hostagent",
        version="not deployed",
        reason=("Wazuh manager/indexer/dashboard are too heavy for the 6 GiB TCG VM, and an agent without a manager cannot emit verifiable alerts. "
                "No osquery/wazuh agent was installed. No mock was used."),
        blocking_fact="no wazuh-manager/osquery deployment; agent-only would not verify detection",
        not_tested=["monitored-path-write", "ruleset-coverage-gap", "stopped-agent-window", "tool-rename-exec"],
    ),
    dict(
        product="netobserv", display="网络可视化(Hubble/Calico flows)", module="defense-bypass-netobserv",
        version="not deployed",
        reason=("The k3s lab uses the default flannel CNI (/var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist); "
                "Cilium/Hubble is not installed. Installing Cilium would require restarting k3s with flannel disabled, outside the timebox "
                "and risky after the observed kine/sqlite crash. No flow logs are claimed."),
        blocking_fact="CNI is flannel; no cilium/hubble/calico pods or flow collector",
        not_tested=["pod-path-flow", "hostnetwork-path", "multi-nic-path", "short-lived-flow"],
    ),
]

for item in NA:
    PRODUCTS.append(base(
        product=item["product"], display=item["display"], module=item["module"],
        deployed=False, state="n/a", version=item["version"],
        deployment={
            "method": "not deployed",
            "reason": item["reason"],
            "blocking_fact": item["blocking_fact"],
        },
        probes=[], detected=[], bypasses=[], not_tested=item["not_tested"],
        evidence=CLUSTER_EVIDENCE,
        limitations=[item["reason"]],
    ))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for rec in PRODUCTS:
        path = OUT / f"{rec['product']}.json"
        path.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(REPO)} deployed={rec['deployed']} probes={len(rec['probes'])}")
    print(f"products={len(PRODUCTS)}")


if __name__ == "__main__":
    main()
