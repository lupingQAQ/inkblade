# -*- coding: utf-8 -*-
"""Annotate every exploit-registry entry with a deployment requirement.

Buckets
-------
``default-exposed``  unauthenticated reachable path, exploitable with no
                     configuration change beyond the vendor default.
``needs-config``     requires an admin/tenant credential, a non-default
                     feature or a deployment-specific setting.
``function-level``   verified at function/import level; no service exposure is
                     claimed (GPU/model runtime unavailable here).
``hardware-only``    BMC/switch/DPU/NVIDIA/IB hardware path; cannot be reached
                     from a normal workload.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

REGISTRY = ROOT / "inkblade" / "core" / "exploit-registry.json"

HARDWARE_COMPONENTS = {
    "bmc", "sonic", "sonicrestapi", "cumulus", "nvidia", "gpuoperator",
    "dpu", "hami", "cgpu", "nccl", "ucx", "ucxpy", "dradriver", "runc",
}
DEFAULT_EXPOSED = {
    # Verified unauth PUT /route on the SGLang PD bootstrap server.
    "CVE-2026-92972",
    # Verified unauth net/http/pprof on ceph-csi MetricsIP=0.0.0.0.
    "cephcsi-httpserver-go-pprof-exposed-l37-regex",
}
NEEDS_CONFIG = {
    "CVE-2026-40217",  # LiteLLM guardrail admin endpoint
    "CVE-2026-42203",  # LiteLLM prompt template, authenticated surface
}


def bucket(entry: dict) -> str:
    eid = entry.get("id") or ""
    if eid in DEFAULT_EXPOSED:
        return "default-exposed"
    if eid in NEEDS_CONFIG:
        return "needs-config"
    status = entry.get("status")
    method = entry.get("method")
    component = str(entry.get("component") or "").lower()
    if status == "verified" and method == "dynamic-function":
        return "function-level"
    if component in HARDWARE_COMPONENTS or status == "unsupported":
        return "hardware-only" if component in HARDWARE_COMPONENTS else "needs-config"
    return "needs-config"


def main() -> int:
    doc = json.loads(REGISTRY.read_text(encoding="utf-8"))
    entries = doc.get("entries") or []
    for entry in entries:
        entry["deployment_requirement"] = bucket(entry)
    counts: dict[str, int] = {}
    for entry in entries:
        key = entry["deployment_requirement"]
        counts[key] = counts.get(key, 0) + 1
    default_ids = [e["id"] for e in entries if e["deployment_requirement"] == "default-exposed"]

    # Per-profile count of default-exposed PoCs whose module is
    # production-testable in that deployment profile.
    from inkblade.core.surface import matrix, profile_names
    from inkblade.core.registry import load_modules

    mods = load_modules(ROOT / "inkblade" / "modules")
    by_module = {e.get("module"): e for e in entries
                 if e["deployment_requirement"] == "default-exposed"}
    by_profile: dict[str, dict] = {}
    for name in profile_names():
        m = matrix(name, modules=mods)
        verdicts = {r["module"]: r["verdict"] for r in m["modules"]}
        ids = [entry["id"] for module, entry in by_module.items()
               if verdicts.get(module) == "production-testable"]
        by_profile[name] = {
            "default_exposed": len(ids),
            "ids": sorted(ids),
            "coverage_pct": m["summary"]["coverage_pct"],
        }

    doc["deployment"] = {
        "schema": "inkblade-deployment-requirement-v1",
        "field": "deployment_requirement",
        "allowed": ["default-exposed", "needs-config", "function-level", "hardware-only"],
        "counts": counts,
        "default_exploitable": sorted(default_ids),
        "by_profile": by_profile,
        "note": "default-exposed = verified and reachable without a non-default setting; "
                "per-profile counts require the module to be production-testable.",
    }
    REGISTRY.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"counts": counts, "default_exposed": len(default_ids),
                      "by_profile": {k: v["default_exposed"] for k, v in by_profile.items()}},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
