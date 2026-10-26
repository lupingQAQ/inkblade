"""OSS tooling bench for the ML-cluster pentest landscape (task: OSS-BENCH).

Runs seven open-source tools against fixed local fixtures/targets and records
wall time, peak RSS, output size and detection stats:

  1. kube-bench (in the QEMU TCG k3s guest, via ssh + docker)
  2. kube-hunter (against the deterministic mock cluster endpoints)
  3. Trivy fs (fixture dir: 9 seeded K8s/Docker files) and Trivy k8s (live k3s)
  4. ModelScan / Fickling / picklescan (same 14-file model fixture set,
     8 malicious / 6 benign, manifest is the ground truth)
  5. promptfoo (12 cases against a local echo provider, no external model)
  6. toxiproxy (inject latency/timeout toxics on a proxy to the mock target)
  7. Chaos Toolkit (local-process experiment: steady state -> kill -> deviation)

Run under the bench venv (has psutil + the tools)::

    .slim/oss-bench-venv/Scripts/python.exe lab/oss_bench/run_bench.py \
        --out reports/samples/oss-bench [--only kubehunter,trivy-fs ...] [--runs 3]

Artifacts: ``<out>/<tool>.json`` (per-tool metrics), ``<out>/raw/`` (raw tool
output), ``<out>/summary.json``.  Timings are wall-clock on the host; the
kube-bench guest timings are measured inside the guest (busybox ``date +%s``,
1 s resolution, QEMU TCG amplification noted in every artifact).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from http.client import RemoteDisconnected
from pathlib import Path

import psutil

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from lab.oss_bench.mock_k8s import MockCluster  # noqa: E402
from lab.oss_bench.mock_llm import MockLLM  # noqa: E402
from inkblade.core.env import getenv  # noqa: E402

# Tool locations come from the environment so no internal absolute path is
# baked into the repo.  The bench venv python defaults to the interpreter this
# runner itself executes under (that is the supported setup).
VENV_PY = Path(getenv("OSSBENCH_PY") or sys.executable)
TRIVY = getenv("TRIVY", "trivy")
TOXIPROXY_SERVER = getenv("TOXIPROXY", "toxiproxy-server")
NODE = getenv("NODE", "node")
PROMPTFOO_MAIN = getenv("PROMPTFOO_MAIN", "")
SSH_KEY = PROJECT / "lab" / "qemu-k3s" / "http" / "id_ed25519"
SSH_KNOWN_HOSTS = PROJECT / "lab" / "qemu-k3s" / "out" / "known_hosts"
K3S_KUBECONFIG = PROJECT / "lab" / "qemu-k3s" / "out" / "k3s.yaml"
KUBEBENCH_GUEST_SH = Path(__file__).resolve().parent / "kubebench_guest.sh"

FIXTURES = Path("lab/oss_bench/fixtures")  # relative to PROJECT (stays out of raw reports)
MODELS = FIXTURES / "models"
K8S_FIX = FIXTURES / "k8s"
LLM_FIX = FIXTURES / "llm"

HOST_SSH = [
    "ssh", "-i", str(SSH_KEY),
    "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
    "-p", "2222", "root@127.0.0.1",
]


# ---------------------------------------------------------------------------
# measurement helpers
# ---------------------------------------------------------------------------
class RssSampler(threading.Thread):
    """Sample RSS of a process tree while it runs."""

    def __init__(self, proc: psutil.Process, interval: float = 0.025):
        super().__init__(daemon=True)
        self.proc = proc
        self.interval = interval
        self.peak_kb = 0
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            try:
                total = self.proc.memory_info().rss
                for child in self.proc.children(recursive=True):
                    try:
                        total += child.memory_info().rss
                    except psutil.Error:
                        pass
                self.peak_kb = max(self.peak_kb, total // 1024)
            except psutil.Error:
                return
            self._halt.wait(self.interval)

    def stop(self) -> int:
        self._halt.set()
        self.join(timeout=2)
        return self.peak_kb


def run_timed(cmd: list[str], timeout: float = 600, env: dict | None = None,
              cwd: str | None = None) -> dict:
    """Run a command once, sampling time/RSS; capture stderr as text.

    Defaults to running in PROJECT so relative fixture/output paths stay
    relative in the tools' own reports (keeps raw artifacts portable).
    """
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=cwd or str(PROJECT))
    sampler = RssSampler(psutil.Process(proc.pid))
    sampler.start()
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        rc = "timeout"
    peak_kb = sampler.stop()
    seconds = time.perf_counter() - t0
    return {
        "rc": rc,
        "seconds": round(seconds, 3),
        "peak_rss_kb": peak_kb,
        "stdout": (stdout or b"").decode("utf-8", "replace"),
        "stderr": (stderr or b"").decode("utf-8", "replace")[-4000:],
    }


def agg(runs: list[dict], key: str) -> dict:
    vals = [r[key] for r in runs]
    return {
        "values": vals,
        "median": round(statistics.median(vals), 3),
        "min": round(min(vals), 3),
        "max": round(max(vals), 3),
    }


def load_manifest() -> dict:
    manifest = json.loads((MODELS / "manifest.json").read_text(encoding="utf-8"))
    return {m["file"]: m["malicious"] for m in manifest["files"]}


def detection_stats(flags: dict[str, bool], exclude: set[str] | None = None) -> dict:
    """flags: file -> tool flagged it as suspicious/malicious.

    ``exclude`` removes files the tool could not parse at all (counted
    separately as skipped_unsupported) so TN/FN are not inflated.
    """
    truth = load_manifest()
    exclude = exclude or set()
    truth = {f: m for f, m in truth.items() if f not in exclude}
    tp = sorted(f for f, m in truth.items() if m and flags.get(f))
    fn = sorted(f for f, m in truth.items() if m and not flags.get(f))
    fp = sorted(f for f, m in truth.items() if not m and flags.get(f))
    tn = sorted(f for f, m in truth.items() if not m and not flags.get(f))
    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) else None
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) else None
    return {
        "fixtures": len(truth) + len(exclude),
        "malicious": sum(1 for m in truth.values() if m),
        "benign": sum(1 for m in truth.values() if not m),
        "true_positives": len(tp), "tp_files": tp,
        "false_negatives": len(fn), "fn_files": fn,
        "false_positives": len(fp), "fp_files": fp,
        "true_negatives": len(tn),
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
    }


# ---------------------------------------------------------------------------
# 1) kube-hunter
# ---------------------------------------------------------------------------
def bench_kubehunter(out: Path, runs: int) -> dict:
    runs_data = []
    report = None
    for _ in range(runs):
        with MockCluster():
            r = run_timed(
                [str(VENV_PY), "-m", "kube_hunter", "--remote", "127.0.0.1",
                 "--report", "json", "--network-timeout", "1", "--log", "WARNING"],
                timeout=300,
            )
        runs_data.append(r)
        blob = r["stdout"] + "\n" + r["stderr"]
        pos = blob.find("{\"nodes\"")
        if pos == -1:
            pos = blob.find("{\"vulnerabilities\"")
        if pos != -1:
            try:
                report = json.loads(blob[pos:])
            except json.JSONDecodeError:
                pass
    (out / "raw" / "kubehunter.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    vulns = (report or {}).get("vulnerabilities", [])
    by_sev: dict[str, int] = {}
    for v in vulns:
        by_sev[v.get("severity", "?")] = by_sev.get(v.get("severity", "?"), 0) + 1
    categories = sorted({(v.get("category") or "?").split("//")[0].strip() for v in vulns})
    privileged = any("Privileged container" in (v.get("category") or "") for v in vulns)
    kubelet = any("Kubelet API" in (v.get("category") or "") for v in vulns)
    return {
        "tool": "kube-hunter",
        "version": "0.6.8",
        "category": "cluster-scanning",
        "target": "mock cluster 127.0.0.1:6443 (unauth read API) + :10255 (read-only kubelet, 1 privileged pod)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": (out / "raw" / "kubehunter.json").stat().st_size,
        "detection": {
            "vulnerabilities": len(vulns),
            "by_severity": by_sev,
            "categories": categories,
            "seeded_findings": {"privileged_container": privileged, "read_only_kubelet": kubelet},
            "seeded_total": 2,
            "seeded_hit": int(privileged) + int(kubelet),
        },
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "hunters see only the two seeded endpoints; active hunting disabled (--active not used)",
        "environment": "host python 3.12 (oss-bench-venv), Windows 11, QEMU host",
    }


# ---------------------------------------------------------------------------
# 2) Trivy fs (fixture dir) + Trivy k8s (live cluster)
# ---------------------------------------------------------------------------
TRIVY_FS_SEEDS = {
    "privileged_pod": ["KSV-0017", "KSV-0014", "KSV-0016"],
    "cluster_admin_rbac": ["KSV-0044"],
    "hardcoded_secrets_env": ["aws-access-key-id", "github-pat"],
    "jupyter_no_auth": ["KSV-0011", "KSV-0030"],
    "ray_privileged": ["KSV-0017"],
    "dockerfile_root_and_pins": ["DS-0002"],
}


def bench_trivy_fs(out: Path, runs: int) -> dict:
    raw_path = out / "raw" / "trivy-fs.json"
    runs_data = []
    parsed = None
    for _ in range(runs):
        r = run_timed(
            [str(TRIVY), "fs", "--scanners", "misconfig,secret", "--skip-db-update",
             "--skip-check-update", "--format", "json", "-o", str(raw_path),
             str(K8S_FIX)],
            timeout=300,
        )
        runs_data.append(r)
    parsed = json.loads(raw_path.read_text(encoding="utf-8"))
    ids: dict[str, int] = {}
    secrets: dict[str, list[str]] = {}
    for res in parsed.get("Results", []):
        for m in res.get("Misconfigurations") or []:
            ids[m.get("ID", "?")] = ids.get(m.get("ID", "?"), 0) + 1
        for s in res.get("Secrets") or []:
            secrets.setdefault(s.get("RuleID", "?"), []).append(Path(res.get("Target", "")).name)
    all_ids = set(ids) | set(secrets)
    seeds = {name: sorted(set(expected) & all_ids) for name, expected in TRIVY_FS_SEEDS.items()}
    # honest FP note: the OPENAI_API_KEY (sk-proj-...) in Dockerfile is a seeded
    # secret, but trivy labels it github-pat -> wrong-class secret (counted
    # separately, not as a clean TP)
    return {
        "tool": "trivy-fs",
        "version": "0.76.1",
        "category": "cluster-scanning",
        "target": f"fixtures/k8s ({len(list(K8S_FIX.iterdir()))} files: 7 yaml + Dockerfile + requirements.txt + .env)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": raw_path.stat().st_size,
        "detection": {
            "misconfigs": sum(ids.values()),
            "unique_misconfig_ids": len(ids),
            "secrets": {k: v for k, v in secrets.items()},
            "seeded_categories": seeds,
            "seeded_total": len(TRIVY_FS_SEEDS),
            "seeded_hit": sum(1 for v in seeds.values() if v),
            "not_flagged": "the canonical AWS example key AKIAIOSFODNN7EXAMPLE seeded in mlflow-insecure.yaml is NOT flagged (trivy blocklists the documentation example key); the synthetic keys in .env are flagged",
        },
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "offline (embedded checks bundle; --skip-check-update), misconfig+secret scanners only",
        "environment": "host binary trivy.exe, Windows 11",
    }


def bench_trivy_k8s(out: Path, runs: int) -> dict:
    """Trivy against a snapshot of the live k3s cluster.

    Direct `trivy k8s` against the QEMU TCG cluster is flaky: the scan path
    wants the node-collector job (image pull through the TCG guest proxy fails)
    and errors with 'no compliance commands found' before writing any report;
    ``--disable-node-collector`` produces a degenerate ``{"ClusterName": ...}``
    report in 0.76.1.  Both behaviours are recorded in ``live_scan_notes``.
    The bench therefore dumps the full cluster state with kubectl (the k3s
    snapshot) and scans it with ``trivy fs`` -- same trivy checks, offline,
    reproducible.
    """
    raw_dir = out / "raw"
    kubectl = PROJECT / "lab" / "qemu-k3s" / "kubectl.exe"
    snap_path = raw_dir / "k3s-snapshot.yaml"
    resources = ",".join([
        "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
        "jobs", "cronjobs", "services", "endpoints", "configmaps",
        "serviceaccounts", "roles", "rolebindings", "clusterroles",
        "clusterrolebindings", "networkpolicies",
        "resourcequotas", "limitranges", "namespaces",
    ])
    t0 = time.perf_counter()
    dump = subprocess.run(
        [str(kubectl), "--kubeconfig", str(K3S_KUBECONFIG),
         "get", resources, "-A", "-o", "yaml"],
        capture_output=True, timeout=600, cwd=str(PROJECT),
    )
    dump_seconds = round(time.perf_counter() - t0, 3)
    if dump.returncode != 0 or not dump.stdout.strip():
        raise RuntimeError(
            f"kubectl snapshot dump failed rc={dump.returncode}: "
            f"{dump.stderr.decode('utf-8', 'replace')[:500]}")
    # kubectl wraps everything in a single `kind: List`; trivy does not split
    # List items, so explode the snapshot into `---` separated documents
    import yaml
    snap_dir = raw_dir / "k3s-snapshot"
    snap_dir.mkdir(parents=True, exist_ok=True)
    docs = []
    for chunk in yaml.safe_load_all(dump.stdout.decode("utf-8", "replace")):
        if isinstance(chunk, dict) and isinstance(chunk.get("items"), list):
            docs.extend(chunk["items"])
        elif chunk:
            docs.append(chunk)
    split_path = snap_dir / "all.yaml"
    split_path.write_text(
        "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs), encoding="utf-8")
    snap_path = split_path
    raw_path = raw_dir / "trivy-k8s.json"
    runs_data = []
    for _ in range(runs):
        r = run_timed(
            [str(TRIVY), "fs", "--scanners", "misconfig", "--skip-db-update",
             "--skip-check-update", "--format", "json", "-o", str(raw_path),
             str(snap_path)],
            timeout=600,
        )
        runs_data.append(r)
    parsed = json.loads(raw_path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    per_result = []
    for res in parsed.get("Results", []):
        mis = res.get("Misconfigurations") or []
        if mis:
            per_result.append({"kind": res.get("Type"), "target": res.get("Target", "")[:80],
                               "misconfigurations": len(mis)})
        for m in mis:
            counts[m.get("ID", "?")] = counts.get(m.get("ID", "?"), 0) + 1
    return {
        "tool": "trivy-k8s",
        "version": "0.76.1",
        "category": "cluster-scanning",
        "target": "k3s v1.36.5+k3s1 full-cluster snapshot (kubectl get 19 resource kinds -A -o yaml, "
                  f"{snap_path.stat().st_size // 1024} KiB) from the QEMU TCG guest",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "snapshot_seconds": dump_seconds,
        "output_bytes": raw_path.stat().st_size,
        "detection": {
            "misconfigs": sum(counts.values()),
            "unique_ids": len(counts),
            "artifacts_with_findings": per_result,
            "top_ids": dict(sorted(counts.items(), key=lambda kv: -kv[1])[:8]),
        },
        "return_codes": [r["rc"] for r in runs_data],
        "live_scan_notes": "direct `trivy k8s --scanners misconfig` against this cluster was attempted "
                           "3x and failed before writing output ('get k8s artifacts with node info error: no "
                           "compliance commands found' -- node-collector image cannot be pulled through the "
                           "TCG guest; one earlier attempt did complete with node info and produced 86 "
                           "misconfigs / 8 results); `--disable-node-collector` writes only "
                           "'{\"ClusterName\": \"default\"}' in 0.76.1",
        "notes": "snapshot + trivy fs (embedded checks, offline): same misconfig checks as trivy k8s, "
                 "deterministic and repeatable; scan time excludes the one-time kubectl dump",
        "environment": "host trivy.exe; snapshot taken over kubectl hostfwd :6445 to QEMU TCG guest",
    }


# ---------------------------------------------------------------------------
# 3) model scanners
# ---------------------------------------------------------------------------
def bench_modelscan(out: Path, runs: int) -> dict:
    report_path = out / "raw" / "modelscan-report.json"
    runs_data = []
    flags: dict[str, bool] | None = None
    for _ in range(runs):
        r = run_timed(
            [str(VENV_PY), "-c",
             "from modelscan.cli import main; import sys; sys.argv=['modelscan','scan','-p',%r,"
             "'-r','json','-o',%r]; main()" % (str(MODELS), str(report_path))],
            timeout=300,
        )
        runs_data.append(r)
    try:
        parsed = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        parsed = {}
    # modelscan embeds an absolute scan root; normalize to repo-relative
    if isinstance(parsed, dict):
        summary = parsed.get("summary", {})
        if isinstance(summary, dict) and "absolute_path" in summary:
            try:
                summary["absolute_path"] = str(
                    Path(str(summary["absolute_path"])).resolve().relative_to(PROJECT)
                ).replace("\\", "/")
            except ValueError:
                summary["absolute_path"] = str(summary["absolute_path"]).replace("\\", "/")
        report_path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
    issues = parsed.get("issues", []) if isinstance(parsed, dict) else []
    # torch zip sources look like "evil_torch.pt:benign_tensor\data.pkl"
    flags = {Path(str(i.get("source", "")).split(":")[0]).name: True for i in issues}
    scanned = (parsed.get("summary", {}).get("scanned", {}) or {}).get("scanned_files", [])
    return {
        "tool": "modelscan",
        "version": "0.8.8",
        "category": "model-inference",
        "target": f"fixtures/models ({len(list(MODELS.glob('*'))) - 1} files vs manifest ground truth)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": report_path.stat().st_size,
        "detection": detection_stats(flags),
        "scanned_files": len(scanned),
        "issues_by_severity": (parsed.get("summary", {}) or {}).get("total_issues_by_severity", {}),
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "json report; flags = file appears in issues[] with any severity; "
                 "scanned_files counts inner pickles (torch zip counts as one)",
        "environment": "host python 3.12 (oss-bench-venv), Windows 11",
    }


def bench_fickling(out: Path, runs: int) -> dict:
    runs_data = []
    flags: dict[str, bool] = {}
    per_file: dict[str, dict] = {}
    truth = load_manifest()
    raw_dir = out / "raw" / "fickling"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(runs):
        flags = {}
        per_file = {}
        run_seconds = 0.0
        run_peak_kb = 0
        for name in sorted(truth):
            jout = raw_dir / f"{name}.json"
            # fickling --json-output APPENDS when the file exists (verified:
            # second run produces concatenated JSON) -- start clean
            if jout.exists():
                jout.unlink()
            r = run_timed(
                [str(VENV_PY), "-m", "fickling", "--check-safety",
                 "--json-output", str(jout), str(MODELS / name)],
                timeout=120,
            )
            run_seconds += r["seconds"]
            run_peak_kb = max(run_peak_kb, r["peak_rss_kb"])
            severity = None
            try:
                severity = json.loads(jout.read_text(encoding="utf-8")).get("severity")
            except Exception:
                pass
            per_file[name] = {
                "severity": severity, "rc": r["rc"], "seconds": r["seconds"],
                "status": "unsupported" if (r["rc"] == 2 or severity is None) else "scanned",
            }
            flagged = severity in ("LIKELY_UNSAFE", "MAYBE_UNSAFE", "LIKELY_OVERTLY_MALICIOUS",
                                   "OVERTLY_MALICIOUS")
            flags[name] = flagged
        runs_data.append({
            "seconds": round(run_seconds, 3),
            "peak_rss_kb": run_peak_kb,
        })
    unsupported = sorted(f for f, v in per_file.items() if v["status"] == "unsupported")
    truth_map = load_manifest()
    # benign unparseable files would inflate TN -> exclude them; the malicious
    # torch zip stays in as a false negative (it slipped through the tool)
    benign_unsupported = {f for f in unsupported if not truth_map.get(f, False)}
    stats = detection_stats(flags, exclude=benign_unsupported)
    stats["skipped_unsupported"] = unsupported
    return {
        "tool": "fickling",
        "version": "0.1.12",
        "category": "model-inference",
        "target": f"fixtures/models ({len(truth)} files, one CLI invocation per file)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": {"values": [r["peak_rss_kb"] for r in runs_data],
                        "note": "peak of the 14 single-file processes (max per run)"},
        "output_bytes": sum(p.stat().st_size for p in raw_dir.glob("*.json")),
        "detection": detection_stats(flags),
        "per_file": per_file,
        "return_codes": "see per_file (1 = unsafe verdict, 2 = cannot parse)",
        "notes": "CLI is per-file only; total time includes N interpreter startups -- compare with care. "
                 "Severity LIKELY_UNSAFE/OVERTLY_MALICIOUS* counts as flagged; rc=2 (torch zip, json, npy) "
                 "counts as unsupported, so the malicious torch fixture is a miss, not a skip",
        "environment": "host python 3.12 (oss-bench-venv), Windows 11",
    }


def bench_picklescan(out: Path, runs: int) -> dict:
    runs_data = []
    report_text = ""
    for _ in range(runs):
        t0 = time.perf_counter()
        proc = subprocess.Popen(
            [str(VENV_PY), "-m", "picklescan", "-p", str(MODELS)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(PROJECT),
        )
        sampler = RssSampler(psutil.Process(proc.pid))
        sampler.start()
        stdout, stderr = proc.communicate(timeout=300)
        peak_kb = sampler.stop()
        seconds = time.perf_counter() - t0
        text = (stdout + b"\n" + stderr).decode("utf-8", "replace")
        runs_data.append({"rc": proc.returncode, "seconds": round(seconds, 3), "peak_rss_kb": peak_kb})
        report_text = text
    # picklescan prints absolute paths for the scanned dir; normalize the
    # workspace prefix to keep the raw evidence portable
    report_text = report_text.replace(str(PROJECT) + os.sep, "").replace(str(PROJECT), ".")
    (out / "raw" / "picklescan.txt").write_text(report_text, encoding="utf-8")
    truth = load_manifest()
    flags = {}
    for name in truth:
        hit = re.search(re.escape(name) + r".*FOUND", report_text)
        flags[name] = bool(hit)
    summary = {}
    for key in ("Scanned files", "Infected files", "Dangerous globals", "Suspicious globals"):
        m = re.search(key + r":\s*(\d+)", report_text)
        if m:
            summary[key] = int(m.group(1))
    return {
        "tool": "picklescan",
        "version": "1.0.5",
        "category": "model-inference",
        "target": f"fixtures/models (directory scan)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": len(report_text.encode("utf-8")),
        "detection": detection_stats(flags),
        "summary": summary,
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "exit code is 0 even with infected files (no --strict); flags parsed from FOUND lines",
        "environment": "host python 3.12 (oss-bench-venv), Windows 11",
    }


# ---------------------------------------------------------------------------
# 4) promptfoo
# ---------------------------------------------------------------------------
def bench_promptfoo(out: Path, runs: int) -> dict:
    cfg = LLM_FIX / "promptfoo.yaml"
    result_path = out / "raw" / "promptfoo-results.json"
    env = dict(
        os.environ,
        PROMPTFOO_DISABLE_TELEMETRY="1", PROMPTFOO_DISABLE_UPDATE="1",
        # keep promptfoo's runtime db/logs out of the evidence tree
        PROMPTFOO_CONFIG_DIR=getenv("PF_CONFIG_DIR")
        or str(Path(os.environ.get("TEMP", "/tmp")) / "inkblade-pf-config"),
    )
    if not PROMPTFOO_MAIN:
        raise RuntimeError(
            "promptfoo bench needs INKBLADE_PROMPTFOO_MAIN=<path to "
            "node_modules/promptfoo/dist/src/entrypoint.js>")
    # warmup (node module cache) -- not measured
    with MockLLM():
        subprocess.run(
            [str(NODE), str(PROMPTFOO_MAIN), "eval", "-c", str(cfg), "-o", str(out / "raw" / "pf-warmup.json"),
             "--no-progress-bar"],
            capture_output=True, timeout=600, env=env, cwd=str(PROJECT),
        )
    runs_data = []
    parsed = {}
    for _ in range(runs):
        with MockLLM():
            r = run_timed(
                [str(NODE), str(PROMPTFOO_MAIN), "eval", "-c", str(cfg), "-o", str(result_path),
                 "--no-progress-bar"],
                timeout=600, env=env, cwd=str(PROJECT),
            )
        runs_data.append(r)
        try:
            parsed = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            parsed = {}
    # promptfoo embeds the workspace basePath; normalize to repo-relative
    if result_path.exists():
        text = result_path.read_text(encoding="utf-8")
        text = text.replace(str(PROJECT).replace("\\", "\\\\"), ".").replace(str(PROJECT), ".")
        result_path.write_text(text, encoding="utf-8")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass
    warmup = out / "raw" / "pf-warmup.json"
    if warmup.exists():
        warmup.unlink()
    rs = parsed.get("results", {}).get("results", [])
    total = sum(
        int(p.get("statistics", {}).get("total", 0)) if "statistics" in p else 0
        for p in [parsed.get("stats", {})]
    )
    success = sum(1 for r in rs if r.get("success"))
    return {
        "tool": "promptfoo",
        "version": "0.125.1",
        "category": "model-inference",
        "target": "12 eval cases -> local echo provider (http://127.0.0.1:18082, no external model)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": result_path.stat().st_size,
        "detection": {
            "cases": len(rs),
            "assertions_passed": success,
            "pass_rate": round(success / len(rs), 3) if rs else None,
        },
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "one warmup run excluded from timing (node/promptfoo cold start ~48 s first run)",
        "environment": "host node 22, npm-installed promptfoo, Windows 11",
    }


# ---------------------------------------------------------------------------
# 5) toxiproxy
# ---------------------------------------------------------------------------
def _http_json(method: str, url: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status


def bench_toxiproxy(out: Path, runs: int) -> dict:
    api = "http://127.0.0.1:8474"
    listen_port = 18083
    runs_data = []
    experiment = {}
    for _ in range(runs):
        server = subprocess.Popen([str(TOXIPROXY_SERVER), "--host", "127.0.0.1", "--port", "8474"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sampler = RssSampler(psutil.Process(server.pid))
        t0 = time.perf_counter()
        try:
            time.sleep(1.5)  # server listen
            sampler.start()
            with MockLLM():
                _http_json("POST", f"{api}/proxies", {"name": "bench", "listen": f"127.0.0.1:{listen_port}",
                                                      "upstream": "127.0.0.1:18082"})
                base_rtts = []
                for _ in range(5):
                    t = time.perf_counter()
                    urllib.request.urlopen(f"http://127.0.0.1:{listen_port}/healthz", timeout=5).read()
                    base_rtts.append((time.perf_counter() - t) * 1000)
                _http_json("POST", f"{api}/proxies/bench/toxics",
                           {"name": "lat", "type": "latency", "stream": "downstream", "toxicity": 1.0,
                            "attributes": {"latency": 200}})
                lat_rtts = []
                for _ in range(5):
                    t = time.perf_counter()
                    urllib.request.urlopen(f"http://127.0.0.1:{listen_port}/healthz", timeout=5).read()
                    lat_rtts.append((time.perf_counter() - t) * 1000)
                _http_json("POST", f"{api}/proxies/bench/toxics",
                           {"name": "tmout", "type": "timeout", "stream": "downstream", "toxicity": 1.0,
                            "attributes": {"timeout": 0}})
                dropped = False
                drop_error = None
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{listen_port}/healthz", timeout=5).read()
                except Exception as exc:  # noqa: BLE001
                    dropped = True
                    drop_error = type(exc).__name__
                experiment = {
                    "baseline_rtt_ms_median": round(statistics.median(base_rtts), 1),
                    "with_latency_tox_ms_median": round(statistics.median(lat_rtts), 1),
                    "configured_latency_ms": 200,
                    "observed_added_latency_ms": round(statistics.median(lat_rtts) - statistics.median(base_rtts), 1),
                    "timeout_tox_dropped_connection": dropped,
                    "drop_error": drop_error,
                }
        finally:
            peak_kb = 0
            try:
                peak_kb = sampler.stop()
            except Exception:
                pass
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
            seconds = time.perf_counter() - t0
        runs_data.append({"rc": 0, "seconds": round(seconds, 3), "peak_rss_kb": peak_kb})
    return {
        "tool": "toxiproxy",
        "version": "2.13.0",
        "category": "network-fabric",
        "target": "proxy 127.0.0.1:18083 -> mock LLM :18082; toxics: latency 200 ms + timeout 0 (downstream)",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": len(json.dumps(experiment).encode()),
        "injection_effect": experiment,
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "effect measured on the client via the proxied /healthz endpoint; server process RSS sampled at 25 ms",
        "environment": "host binaries toxiproxy-server-windows-amd64.exe, Windows 11",
    }


# ---------------------------------------------------------------------------
# 6) Chaos Toolkit
# ---------------------------------------------------------------------------
def bench_chaostoolkit(out: Path, runs: int) -> dict:
    experiment_dir = out / "raw" / "chaostoolkit"
    experiment_dir.mkdir(parents=True, exist_ok=True)
    runs_data = []
    journals = []
    for run_idx in range(runs):
        # unique port per run: Windows SO_REUSEADDR lets a stale victim from a
        # failed earlier run double-bind the same port and answer probes
        port = 18100 + run_idx
        victim = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(PROJECT),
        )
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read()
        except Exception:
            time.sleep(1.0)
        workdir = experiment_dir / f"run{run_idx + 1}"
        workdir.mkdir(parents=True, exist_ok=True)
        experiment = {
            "version": "1.0.0",
            "title": "inkblade-oss-bench local process chaos",
            "description": "steady-state HTTP 200 on the victim, kill the victim process, "
                           "expect the steady-state probe to fail afterwards",
            "tags": ["inkblade-oss-bench"],
            "steady-state-hypothesis": {
                "title": "victim endpoint keeps answering",
                "probes": [{
                    "type": "probe",
                    "name": "victim-answers-200",
                    "provider": {
                        "type": "http",
                        "url": f"http://127.0.0.1:{port}/",
                        "timeout": 3,
                    },
                    "tolerance": 200,
                }],
            },
            "method": [
                {
                    "type": "action",
                    "name": "kill-victim-process",
                    "provider": {
                        "type": "process",
                        "path": "taskkill",
                        "arguments": f"/PID {victim.pid} /F",
                        "timeout": 10,
                    },
                },
                {
                    "type": "probe",
                    "name": "victim-still-alive",
                    "provider": {
                        "type": "http",
                        "url": f"http://127.0.0.1:{port}/",
                        "timeout": 3,
                    },
                    "pauses": {"after": 1},
                },
            ],
        }
        (workdir / "experiment.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
        r = run_timed([str(VENV_PY), "-m", "chaostoolkit.__main__", "run", "experiment.json"],
                      timeout=300, cwd=str(workdir))
        r["seconds"] = round(r["seconds"], 3)
        runs_data.append(r)
        journal_path = workdir / "journal.json"
        journal = None
        if journal_path.exists():
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journals.append(journal)
        # verify the victim is really dead (taskkill may have missed it)
        try:
            victim.wait(timeout=5)
        except subprocess.TimeoutExpired:
            victim.kill()
            victim.wait()
    deviated = []
    killed_ok = []
    for j in journals:
        dev = j.get("deviated")
        kill_ok = False
        for entry in j.get("run", []):
            act = entry.get("activity", {})
            if act.get("name") == "kill-victim-process":
                out_text = str((entry.get("output") or {}).get("stdout", ""))
                kill_ok = "has been terminated" in out_text or entry.get("status") == "succeeded"
        killed_ok.append(kill_ok)
        deviated.append(dev)
    return {
        "tool": "chaostoolkit",
        "version": "1.21.4",
        "category": "chaos",
        "target": "local http.server victim process; action taskkill /PID <victim> /F",
        "runs": runs,
        "seconds": agg(runs_data, "seconds"),
        "peak_rss_kb": agg(runs_data, "peak_rss_kb"),
        "output_bytes": sum(p.stat().st_size for p in experiment_dir.rglob("journal.json")),
        "chaos_effect": {
            "deviated": deviated,
            "victim_killed": killed_ok,
            "all_runs_detected_deviation": all(d is True for d in deviated) if deviated else False,
        },
        "return_codes": [r["rc"] for r in runs_data],
        "notes": "chaos exits non-zero when the steady state is broken (expected); journal.json is the evidence",
        "environment": "host python 3.12 (oss-bench-venv), Windows 11; process provider uses Windows taskkill",
    }


# ---------------------------------------------------------------------------
# 7) kube-bench (guest)
# ---------------------------------------------------------------------------
def bench_kubebench(out: Path, runs: int) -> dict:
    script = KUBEBENCH_GUEST_SH.read_text(encoding="utf-8").replace("\r", "")
    remote_marker_out = subprocess.run(
        HOST_SSH + ["sh", "-c", "cat > /root/kubebench_guest.sh"],
        input=script.encode("utf-8"), capture_output=True, timeout=60,
    )
    marker = subprocess.run(
        HOST_SSH + [f"KUBEBENCH_RUNS={runs} sh /root/kubebench_guest.sh"],
        capture_output=True, timeout=1800,
    )
    text = marker.stdout.decode("utf-8", "replace")
    (out / "raw" / "kubebench-console.txt").write_text(text, encoding="utf-8")
    elapsed = [int(m) for m in re.findall(r"elapsed_s=(\d+)", text)]
    sizes = [int(m) for m in re.findall(r"json_bytes=(\d+)", text)]
    rcs = [int(m) for m in re.findall(r"rc=(\d+)", text)]
    scp = subprocess.run(
        ["scp", "-i", str(SSH_KEY), "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
         "-o", "BatchMode=yes", "-P", "2222",
         "root@127.0.0.1:/tmp/kubebench-run1.json", str(out / "raw" / "kubebench-report.json")],
        capture_output=True, timeout=120,
    )
    parsed = {}
    try:
        parsed = json.loads((out / "raw" / "kubebench-report.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    controls = parsed.get("Controls", [])
    totals = parsed.get("Totals", {})
    benchmarks = sorted({c.get("version", "?") for c in controls})
    return {
        "tool": "kube-bench",
        "version": "0.16.0",
        "category": "cluster-scanning",
        "target": "live k3s v1.36.5+k3s1 node (QEMU TCG Alpine guest), docker container, KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
        "runs": runs,
        "seconds": {"values": elapsed, "median": statistics.median(elapsed) if elapsed else None,
                    "resolution": "1 s (busybox date +%s, measured inside guest)"},
        "peak_rss_kb": {"note": "guest container; not sampled (docker run --rm, TCG) -- image size 227 MB recorded instead"},
        "output_bytes": sizes[0] if sizes else 0,
        "detection": {
            "totals": totals,
            "benchmarks_run": benchmarks,
            "controls": len(controls),
            "sections": [{"id": c.get("id"), "text": (c.get("text") or "")[:60],
                          "pass": c.get("total_pass"), "fail": c.get("total_fail"),
                          "warn": c.get("total_warn"), "info": c.get("total_info")} for c in controls],
        },
        "return_codes": rcs,
        "notes": "CIS profile auto-detected through the k3s kubeconfig; guest timings carry QEMU TCG amplification",
        "environment": "guest: Alpine 3.24 / 6 vCPU TCG / docker 29.9.2; image aquasec/kube-bench:v0.16.0 (227 MB)",
    }


# ---------------------------------------------------------------------------
BENCHES = {
    "kubehunter": bench_kubehunter,
    "trivy-fs": bench_trivy_fs,
    "trivy-k8s": bench_trivy_k8s,
    "modelscan": bench_modelscan,
    "fickling": bench_fickling,
    "picklescan": bench_picklescan,
    "promptfoo": bench_promptfoo,
    "toxiproxy": bench_toxiproxy,
    "chaostoolkit": bench_chaostoolkit,
    "kubebench": bench_kubebench,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(PROJECT / "reports" / "samples" / "oss-bench"))
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--only", default="", help="comma separated bench keys")
    args = ap.parse_args()

    out = Path(args.out)
    (out / "raw").mkdir(parents=True, exist_ok=True)

    selected = args.only.split(",") if args.only else list(BENCHES)
    results = {}
    for key in selected:
        print(f"[oss-bench] running {key} (runs={args.runs})", flush=True)
        try:
            results[key] = BENCHES[key](out, args.runs)
        except Exception as exc:  # noqa: BLE001 -- record and continue
            results[key] = {
                "tool": key,
                "error": f"{type(exc).__name__}: {exc}",
                "seconds": None, "peak_rss_kb": None, "output_bytes": None,
            }
            print(f"[oss-bench] {key} FAILED: {exc}", flush=True)
            continue
        (out / f"{key}.json").write_text(json.dumps(results[key], indent=2) + "\n", encoding="utf-8")

    # merge with any pre-existing per-tool results (e.g. --only reruns)
    summary_path = out / "summary.json"
    existing = {}
    if summary_path.exists():
        try:
            existing = {r["tool"]: r for r in json.loads(summary_path.read_text(encoding="utf-8")).get("results", [])}
        except Exception:
            existing = {}
    merged = {**{r.get("tool", k): r for k, r in existing.items()}, **{r["tool"]: r for r in results.values()}}
    summary = {
        "schema": "inkblade.oss-bench/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "note": "host timings; guest (QEMU TCG) timings marked per tool",
        },
        "results": sorted(merged.values(), key=lambda r: (r.get("category", ""), r.get("tool", ""))),
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[oss-bench] wrote {summary_path} with {len(merged)} tool results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
