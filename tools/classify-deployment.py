# -*- coding: utf-8 -*-
"""Classify every exploit-registry and 0day-reserve entry by deployment need.

Writes:
  * ``inkblade/core/exploit-registry.json``  -> deployment_requirement/evidence
  * ``inkblade/core/zeroday-registry.json``  -> deployment_requirement/evidence
  * ``inkblade/core/data/deployment-summary.json`` (compact review artifact)

Usage::

    python tools/classify-deployment.py            # dry run (counts only)
    python tools/classify-deployment.py --write    # write registries
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core.deployment import (  # noqa: E402
    ALLOWED,
    classify,
    classify_reserve,
    summarize,
    validate_evidence,
)

EXPLOIT = ROOT / "inkblade" / "core" / "exploit-registry.json"
ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
CASES = ROOT / "lab" / "upstream_verify" / "cases"
SUMMARY = ROOT / "inkblade" / "core" / "data" / "deployment-summary.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def manifest_for(entry: dict) -> dict | None:
    path = CASES / str(entry.get("component")) / str(entry.get("id")) / "manifest.json"
    if not path.is_file():
        return None
    return load(path)


def profile_counts(entries: list[dict]) -> dict:
    """Per-profile count of default-exposed items whose module is testable."""
    try:
        from inkblade.core.registry import load_modules
        from inkblade.core.surface import matrix, profile_names

        mods = load_modules(ROOT / "inkblade" / "modules")
        by_module = {
            e.get("module"): e for e in entries
            if e.get("deployment_requirement") == "default-exposed" and e.get("module")
        }
        result = {}
        for name in profile_names():
            m = matrix(name, modules=mods)
            verdicts = {r["module"]: r["verdict"] for r in m["modules"]}
            ids = [entry["id"] for module, entry in by_module.items()
                   if verdicts.get(module) == "production-testable"]
            result[name] = {
                "default_exposed": len(ids),
                "ids": sorted(ids),
                "coverage_pct": m["summary"]["coverage_pct"],
            }
        return result
    except Exception as exc:  # surface data is optional for classification
        return {"error": f"{type(exc).__name__}: {exc}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    registry = load(EXPLOIT)
    errors: list[str] = []
    for entry in registry["entries"]:
        verdict = classify(entry, manifest_for(entry))
        entry["deployment_requirement"] = verdict["requirement"]
        entry["deployment_evidence"] = verdict["evidence"]
        entry["deployment_basis"] = verdict["basis"]
        problems = validate_evidence(verdict["evidence"])
        if problems:
            errors.append(f"{entry['id']}: {', '.join(problems)}")
        if verdict["requirement"] not in ALLOWED:
            errors.append(f"{entry['id']}: invalid requirement {verdict['requirement']}")

    counts = summarize(registry["entries"])
    default_all = sorted(e["id"] for e in registry["entries"]
                         if e["deployment_requirement"] == "default-exposed")
    default_verified = sorted(e["id"] for e in registry["entries"]
                              if e["deployment_requirement"] == "default-exposed"
                              and e["status"] == "verified")
    default_exposure = sorted(e["id"] for e in registry["entries"]
                              if e["deployment_requirement"] == "default-exposed"
                              and e["status"] == "exposure-verified")
    registry["deployment"] = {
        "schema": "inkblade-deployment-requirement-v1",
        "field": "deployment_requirement",
        "allowed": list(ALLOWED),
        "counts": counts,
        "default_exposed": default_all,
        "default_exploitable": default_verified,
        "default_exposure_verified": default_exposure,
        "by_profile": profile_counts(registry["entries"]),
        "note": "default-exposed = reachable with vendor defaults; exploitability is a "
                "separate axis (status). default_exploitable = verified dynamic RCE/read "
                "primitive on a default deployment; default_exposure_verified = exposure "
                "only (bind/auth posture), no RCE claimed.",
    }

    zeroday = load(ZERODAY)
    reserve = [e for e in zeroday.get("entries") or [] if e.get("state") == "novelty-checked"]
    reserve_counts = {key: 0 for key in ALLOWED}
    for entry in reserve:
        verdict = classify_reserve(entry)
        entry["deployment_requirement"] = verdict["requirement"]
        entry["deployment_evidence"] = verdict["evidence"]
        entry["deployment_basis"] = verdict["basis"]
        entry["default_exposed"] = verdict["requirement"] == "default-exposed"
        reserve_counts[verdict["requirement"]] += 1
        problems = validate_evidence(verdict["evidence"])
        if problems:
            errors.append(f"reserve {entry['id']}: {', '.join(problems)}")
    zeroday["deployment"] = {
        "schema": "inkblade-deployment-requirement-v1",
        "scope": "reserve (state=novelty-checked)",
        "counts": reserve_counts,
        "default_exposed": sorted(e["id"] for e in reserve if e.get("default_exposed")),
        "evidence_rule": "each reserve entry carries deployment_evidence naming the bind, "
                         "missing flag/env, admin key or local checkpoint path",
    }

    summary = {
        "schema": "inkblade-deployment-summary-v1",
        "exploit_registry": {
            "total": len(registry["entries"]),
            "counts": counts,
            "default_exposed": default_all,
            "default_exploitable": default_verified,
            "default_exposure_verified": default_exposure,
            "by_profile": registry["deployment"]["by_profile"],
        },
        "zeroday_reserve": {
            "total": len(reserve),
            "counts": reserve_counts,
            "default_exposed": zeroday["deployment"]["default_exposed"],
        },
    }

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if errors:
        print(f"FAIL: {len(errors)} classification problem(s)", file=sys.stderr)
        for item in errors[:40]:
            print(f"  - {item}", file=sys.stderr)
        return 1
    if args.write:
        dump(EXPLOIT, registry)
        dump(ZERODAY, zeroday)
        SUMMARY.parent.mkdir(parents=True, exist_ok=True)
        dump(SUMMARY, summary)
        print(f"wrote {EXPLOIT}\nwrote {ZERODAY}\nwrote {SUMMARY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
