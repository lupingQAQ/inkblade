# -*- coding: utf-8 -*-
"""Six cross-domain research effects, replayable from ``inkblade verify-effects``.

Each check has a real differential: vulnerable state vs hardened state, or a
live local HTTP vulnerable server vs a fixed server.  No live K8s/GPU/switch
is claimed; the evidence records exactly what was executed.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lab.depth_sim import start_all as start_depth_sim  # noqa: E402
from lab.fabric_sim.detectors import detect as fabric_detect  # noqa: E402
from lab.fabric_sim.sim import simulate as fabric_simulate  # noqa: E402
from lab.fabric_sim.topology import Topology  # noqa: E402
from inkblade.depth import admission, ebpf, fabric, gpu, identity, vllm  # noqa: E402


def _vllm_fuzz() -> dict[str, Any]:
    vuln = start_depth_sim(mode="vulnerable")
    fixed = start_depth_sim(mode="fixed")
    try:
        v = vllm.SurfaceFuzzer(vuln.url("")).run()
        f = vllm.SurfaceFuzzer(fixed.url("")).run()
    finally:
        vuln.shutdown()
        fixed.shutdown()
    if v["total"] < 200:
        raise AssertionError(f"fuzz cases < 200: {v['total']}")
    if v["bypasses"] < 100:
        raise AssertionError(f"vulnerable bypasses too low: {v['bypasses']}")
    if f["bypasses"] != 0:
        raise AssertionError(f"fixed mode still bypassable: {f['bypasses']}")
    if len(v["surfaces_hit"]) < 4:
        raise AssertionError(f"surfaces hit < 4: {v['surfaces_hit']}")
    return {
        "cases": v["total"],
        "vulnerable_bypasses": v["bypasses"],
        "fixed_bypasses": f["bypasses"],
        "control_status": v["control_status"],
        "surfaces_hit": v["surfaces_hit"],
        "fixed_control_status": f["control_status"],
        "vulnerable_results_sha256": v["results_sha256"],
        "fixed_results_sha256": f["results_sha256"],
        "matrix_entries": len(vllm.entries()),
        "fixed_pairs": sum(1 for e in vllm.entries() if e.get("fixed")),
    }


def _admission() -> dict[str, Any]:
    report = admission.audit()
    if report["vulnerable_admitted"] < 15:
        raise AssertionError(f"admission admitted < 15: {report['vulnerable_admitted']}")
    if report["hardened_admitted"] != 0:
        raise AssertionError(f"hardened admitted != 0: {report['hardened_admitted']}")
    if report["findings"] < 15:
        raise AssertionError(f"admission findings < 15: {report['findings']}")
    return {
        "cases": report["total"],
        "vulnerable_admitted": report["vulnerable_admitted"],
        "hardened_admitted": report["hardened_admitted"],
        "findings": report["findings"],
        "mechanisms": sorted({c["mechanism"] for c in admission.cases()}),
        "results_sha256": report["results_sha256"],
    }


def _ebpf() -> dict[str, Any]:
    report = ebpf.audit()
    if report["vulnerable_missed"] < 10:
        raise AssertionError(f"ebpf missed < 10: {report['vulnerable_missed']}")
    if report["hardened_missed"] != 0:
        raise AssertionError(f"hardened still misses: {report['hardened_details']}")
    if report["coverage_gaps"] < 6:
        raise AssertionError(f"coverage gaps < 6: {report['coverage_gaps']}")
    return {
        "cases": report["total"],
        "missed": report["vulnerable_missed"],
        "hardened_missed": report["hardened_missed"],
        "coverage_gaps": report["coverage_gaps"],
        "categories": report["categories"],
        "results_sha256": report["results_sha256"],
    }


def _gpu() -> dict[str, Any]:
    vuln = gpu.audit(gpu.fixture("vulnerable"))
    hard = gpu.audit(gpu.fixture("hardened"))
    if vuln["findings"] < 10:
        raise AssertionError(f"gpu findings < 10: {vuln['findings']}")
    if vuln["severity"].get("critical", 0) < 3:
        raise AssertionError(f"gpu critical < 3: {vuln['severity']}")
    if hard["findings"] != 0:
        raise AssertionError(f"hardened GPU config findings: {hard['failed_ids']}")
    return {
        "checks": vuln["checks"],
        "findings": vuln["findings"],
        "critical": vuln["severity"].get("critical", 0),
        "high": vuln["severity"].get("high", 0),
        "hardened_findings": hard["findings"],
        "domains": vuln["domains"],
        "snapshot_sha256": vuln["snapshot_sha256"],
    }


def _fabric() -> dict[str, Any]:
    vuln = fabric.audit(fabric.fixture("vulnerable"))
    hard = fabric.audit(fabric.fixture("hardened"))
    plan = fabric.fabric_sim_plan(fabric.fixture("vulnerable"))
    if vuln["checks"] < 20 or vuln["failed"] < 15:
        raise AssertionError(f"fabric checks/failed too low: {vuln['checks']}/{vuln['failed']}")
    if hard["failed"] != 0:
        raise AssertionError(f"hardened fabric failed: {hard['failed_ids']}")
    if "pfc-storm" not in plan["scenarios"] or "ecn" not in plan["scenarios"]:
        raise AssertionError(f"fabric sim plan missing scenarios: {plan['scenarios']}")
    topo = Topology.build(1024)
    storm = fabric_detect(fabric_simulate(topo, "pfc-storm", seed=7))
    baseline = fabric_detect(fabric_simulate(topo, "baseline", seed=7))
    storm_rules = [f["rule"] for f in storm]
    if "fabric.pfc-pause-storm" not in storm_rules:
        raise AssertionError(f"fabric_sim did not detect PFC storm: {storm_rules}")
    if [f["rule"] for f in baseline] != ["fabric.baseline-clean"]:
        raise AssertionError("fabric_sim baseline is not clean")
    return {
        "checks": vuln["checks"],
        "failed": vuln["failed"],
        "hardened_failed": hard["failed"],
        "domains": vuln["domains"],
        "scenarios": plan["scenarios"],
        "detectors": storm_rules,
        "baseline": [f["rule"] for f in baseline],
        "nodes": 1024,
        "snapshot_sha256": vuln["snapshot_sha256"],
    }


def _identity() -> dict[str, Any]:
    report = identity.audit()
    if report["allowed"] < 15:
        raise AssertionError(f"identity allowed < 15: {report['allowed']}")
    if report["hardened_allowed"] != 0:
        raise AssertionError(f"hardened allowed != 0: {report['hardened_allowed']}")
    if not all(row["legit"]["allowed"] for row in report["results"]):
        raise AssertionError("legit request denied by hardened policy")
    if report["findings"] < 15:
        raise AssertionError(f"identity findings < 15: {report['findings']}")
    return {
        "cases": report["total"],
        "allowed": report["allowed"],
        "hardened_allowed": report["hardened_allowed"],
        "legit_allowed": sum(1 for r in report["results"] if r["legit"]["allowed"]),
        "findings": report["findings"],
        "categories": sorted(identity.bypass_categories()),
        "results_sha256": report["results_sha256"],
    }


CHECKS: tuple[tuple[str, str, Callable[[], dict[str, Any]]], ...] = (
    ("depth-vllm-fuzz", "vLLM 五接口面 240 用例差分：vulnerable vs fixed 真实 HTTP", _vllm_fuzz),
    ("depth-admission-semantics", "Kyverno/Gatekeeper 20 语义用例：vulnerable 准入 vs 加固拒绝", _admission),
    ("depth-ebpf-blindspot", "Falco/Tetragon 14 事件覆盖：默认 missed vs 加固全覆盖", _ebpf),
    ("depth-gpu-operator-config", "GPU Operator 20 检查：privileged/MIG/DCGM/DRA 差分", _gpu),
    ("depth-sonic-fabric-link", "SONiC/IB/SHARP 28 检查 + fabric_sim PFC 场景联动", _fabric),
    ("depth-identity-federation", "IRSA/RRSA/PodIdentity/GCP/Azure 21 信任用例差分", _identity),
)


def run_all() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for cid, title, fn in CHECKS:
        started = time.time()
        item: dict[str, Any] = {"id": cid, "title": title, "status": "FAIL",
                                "evidence": {}, "detail": ""}
        try:
            item["evidence"] = fn()
            item["status"] = "PASS"
        except Exception as exc:  # noqa: BLE001
            item["detail"] = f"{type(exc).__name__}: {exc}"
        item["elapsed_ms"] = round((time.time() - started) * 1000, 1)
        results.append(item)
    return results


def run_depth_checks(checks, **_: Any) -> None:
    """Hook for inkblade/verify-effects.py::_Checks."""
    for cid, title, fn in CHECKS:
        checks.run(cid, title, fn)


if __name__ == "__main__":
    doc = {"checks": run_all()}
    doc["summary"] = {
        "total": len(doc["checks"]),
        "passed": sum(1 for c in doc["checks"] if c["status"] == "PASS"),
        "failed": sum(1 for c in doc["checks"] if c["status"] != "PASS"),
    }
    print(json.dumps(doc, ensure_ascii=False, indent=2))
