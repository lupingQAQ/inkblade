# -*- coding: utf-8 -*-
"""Render docs/SURFACE-REALISM.md from the live profiles and module metadata."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core.registry import load_modules  # noqa: E402
from inkblade.core.surface import matrix, profile_names  # noqa: E402

OUT = ROOT / "docs" / "SURFACE-REALISM.md"
REGISTRY = ROOT / "inkblade" / "core" / "exploit-registry.json"


def _req(row: dict) -> str:
    return "; ".join(f"{r['surface']['type']}:{r['surface']['selector']}"
                     for r in row["required_surfaces"]) or "—"


def main() -> int:
    mods = load_modules(ROOT / "inkblade" / "modules")
    matrices = {name: matrix(name, modules=mods) for name in profile_names()}
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    deployment = registry.get("deployment") or {}
    by_profile = deployment.get("by_profile") or {}

    verdicts: dict[str, dict[str, str]] = {}
    for name, doc in matrices.items():
        for row in doc["modules"]:
            verdicts.setdefault(row["module"], {})[name] = row["verdict"]

    globally_absent = sorted(
        key for key, per in verdicts.items()
        if per and all(v == "no-surface" for v in per.values()))
    quarantined = sorted(k for k, m in mods.items() if not m.default_enabled)

    lines = [
        "# Surface realism — 真实部署面与模块可测性",
        "",
        "Generated from `inkblade/profiles/*.json`, `inkblade/profiles/surface-map.json` "
        "and each module's `surfaces` declaration. Re-run: "
        "`python tools/render-surface-docs.py`.",
        "",
        "> **Rule.** A module is `production-testable` only when every required surface is "
        "present in the profile/collection; `conditional` when some required surface is "
        "missing or unverified; `no-surface` when no required surface exists. "
        "`unknown` at runtime requires an explicit `--probe`. The matrix below uses "
        "**profile declarations** (synthetic deployment facts), not a live cluster; "
        "`inkblade surfaces --collect <dir>` recomputes it against real collection output.",
        "",
        "## 1. Profile coverage",
        "",
        "| Profile | Platform | Default modules | production-testable | conditional | no-surface | "
        "Production coverage | Operable coverage | Default-exploitable PoCs |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, doc in matrices.items():
        s = doc["summary"]
        dp = by_profile.get(name, {}).get("default_exposed", 0)
        lines.append(
            f"| `{name}` | {doc.get('description', '').split(';')[0][:60]} | "
            f"{s['default_enabled']} | {s['default_production_testable']} | "
            f"{s['default_conditional']} | {s['default_no_surface']} | "
            f"**{s['coverage_pct']}%** | {s['operable_pct']}% | {dp} |")

    lines += [
        "",
        "Production coverage = `default_production_testable / default_enabled`. "
        "Quarantined modules (`default_enabled=false`) are excluded from the denominator.",
        "",
        "## 2. Quarantined by default (`default_enabled=false`)",
        "",
        "| Module | Required surfaces | No-surface in all profiles | Reason |",
        "|---|---|---|---|",
    ]
    for key in quarantined:
        meta = mods[key]
        req = "; ".join(f"{r.get('type')}:{r.get('selector')}"
                        for r in meta.required_surfaces) or "—"
        reason = meta.default_disabled_reason or (
            "Component not present in the six mainstream deployment profiles; "
            "kept for customers that actually deploy it.")
        lines.append(f"| `{key}` | {req} | {'yes' if key in globally_absent else 'no'} | "
                     f"{reason} |")
    if not quarantined:
        lines.append("| — | — | — | — |")
    pending = [k for k in globally_absent if k not in quarantined]
    if pending:
        lines += [
            "",
            "### No-surface rows not yet quarantined",
            "",
            "| Module | Required surfaces | Owner note |",
            "|---|---|---|",
        ]
        for key in pending:
            meta = mods[key]
            req = "; ".join(f"{r.get('type')}:{r.get('selector')}"
                            for r in meta.required_surfaces) or "—"
            lines.append(f"| `{key}` | {req} | No surface in all six profiles; "
                         "kept enabled by a parallel workstream pending its owner's "
                         "quarantine decision. It is still `no-surface` and cannot run "
                         "when the surface gate is enabled. |")
        lines += ["", f"Global no-surface rows: **{len(globally_absent)}**; explicitly "
                      f"quarantined: **{len(quarantined)}**.", ""]

    lines += [
        "",
        "These modules remain callable explicitly (`inkblade run --module ... --probe` or with "
        "a real `--collect` / `--profile`). They are excluded from the default chain and from "
        "the default coverage denominator, so a green default report no longer implies "
        "coverage of an undeployed component. Other `no-surface` rows owned by parallel "
        "workstreams remain enabled until their owner applies the same quarantine; their "
        "verdict is still `no-surface` and they cannot execute when the surface gate is on.",
        "",
        "## 3. Module × profile verdict matrix",
        "",
        "Legend: **production-testable** = execute against this profile without extra "
        "confirmation; **conditional** = present but missing a required surface or needs "
        "collection; **no-surface** = not deployed (skipped, no finding, not counted).",
        "",
        "| Module | Required surfaces | " + " | ".join(f"`{n}`" for n in matrices) + " |",
        "|---|---|" + "---|" * len(matrices),
    ]
    for key in sorted(mods):
        per = verdicts.get(key, {})
        req = _req(next((r for r in matrices[next(iter(matrices))]["modules"]
                         if r["module"] == key), {"required_surfaces": []}))
        cells = " | ".join(per.get(name, "no-surface") for name in matrices)
        lines.append(f"| `{key}` | {req} | {cells} |")

    lines += [
        "",
        "## 4. Default-exposed exploit PoCs by profile",
        "",
        "`deployment_requirement=default-exposed` means a verified exploit reachable without "
        "a non-default setting. Per-profile counts additionally require the owning module to "
        "be `production-testable` in that profile.",
        "",
        "| Profile | Default-exposed PoCs | IDs |",
        "|---|---:|---|",
    ]
    for name, block in by_profile.items():
        ids = ", ".join(f"`{x}`" for x in block.get("ids") or []) or "—"
        lines.append(f"| `{name}` | {block.get('default_exposed', 0)} | {ids} |")

    lines += [
        "",
        "Global registry counts: "
        + ", ".join(f"`{k}`={v}" for k, v in sorted((deployment.get("counts") or {}).items()))
        + ". Only `default-exposed` entries enter the “默认可利用” number; "
        "`function-level` and `hardware-only` paths are explicitly not service exposure.",
        "",
        "## 5. Collect and verify",
        "",
        "```powershell",
        "inkblade collect --profile ray-vllm --kubeconfig .kube/config "
        "--target http://127.0.0.1:8000/v1/models --files .\\export --hardware .\\hw-export",
        "inkblade surfaces --profile ray-vllm --collect collection",
        "inkblade run --module sglang-route-poison --profile ray-vllm --collect collection",
        "```",
        "",
        "Fixture mode is explicit: `inkblade collect --fixture --profile ray-vllm`.",
        "Every fixture collection and report section is stamped **FIXTURE DATA — not a "
        "production verdict**; fixture mode never counts toward a customer production report.",
        "",
        "## 6. Accelerator chip posture (A/B/C boundary)",
        "",
        "A/B/C/D necessity tiers are defined in [`CHIP-SECURITY-SCOPE.md`](CHIP-SECURITY-SCOPE.md). "
        "Only A (real attack path) counts as chip pentest capability; B is assurance "
        "detection; C is research-only and default-disabled; D (silicon lab, physical "
        "fault injection, Rowhammer/microarchitectural exploitation) is explicitly out "
        "of scope. **C/D are never counted as chip pentest capability.**",
        "",
        "A2 (BMC/DPU/IPMI out-of-band takeover) is covered by existing "
        "`bmc-ipmi-exposure`, `dpu-smartnic-surface`, `redfish-default-credentials` and "
        "`ipmi-cipher-zero-bypass`; this workstream adds the Redfish UpdateService / "
        "FirmwareInventory read-only face.",
        "",
        "| Module | Tier | Default | Research-only | Required surfaces | "
        + " | ".join(f"`{n}`" for n in matrices) + " |",
        "|---|---|---|---|---|" + "---|" * len(matrices),
    ]
    chip_mods = sorted(k for k, m in mods.items() if m.necessity in ("A", "B", "C"))
    for key in chip_mods:
        meta = mods[key]
        req = _req(next((r for r in matrices[next(iter(matrices))]["modules"]
                         if r["module"] == key), {"required_surfaces": []}))
        cells = " | ".join(verdicts.get(key, {}).get(name, "no-surface") for name in matrices)
        lines.append(
            f"| `{key}` | {meta.necessity} | "
            f"{'on' if meta.default_enabled else 'off'} | "
            f"{'yes' if meta.research_only else 'no'} | {req} | {cells} |")
    lines += [
        "",
        "C-tier rows remain callable only with an explicit `--probe` / customer profile; "
        "their presence in this matrix is not a claim of production chip coverage.",
        "",
        f"Snapshot: {len(mods)} modules, {len(matrices)} profiles, "
        f"{len(quarantined)} quarantined modules, {len(globally_absent)} globally no-surface.",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"surface docs: {OUT} ({len(mods)} modules, {len(matrices)} profiles)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
