# -*- coding: utf-8 -*-
"""Render ``docs/WEAPON-READINESS.md`` from the registries + weapon packs.

The document is generated, never hand-edited.  It answers, per component:

    total / verified / default-exposed / needs-config / payload variants / one-click

plus the "default-exploitable" list with the concrete evidence for each entry
and an explicit gap section (no module, static blocker, missing runtime).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "inkblade" / "core" / "exploit-registry.json"
ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
DOC = ROOT / "docs" / "WEAPON-READINESS.md"

import sys

sys.path.insert(0, str(ROOT))
from inkblade.core.weaponization import readiness  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def table(rows: list[dict]) -> list[str]:
    lines = [
        "| Component | total | verified | default-exposed | needs-config | function-level | payload variants | one-click |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['component']}` | {row['total']} | {row['verified']} | "
            f"{row['default_exposed']} | {row['needs_config']} | {row['function_level']} | "
            f"{row['variants']} | {row['one_click']}/{row['total']} |")
    lines.append(
        f"| **Total** | **{sum(r['total'] for r in rows)}** | "
        f"**{sum(r['verified'] for r in rows)}** | **{sum(r['default_exposed'] for r in rows)}** | "
        f"**{sum(r['needs_config'] for r in rows)}** | **{sum(r['function_level'] for r in rows)}** | "
        f"**{sum(r['variants'] for r in rows)}** | "
        f"**{sum(r['one_click'] for r in rows)}/{sum(r['total'] for r in rows)}** |")
    return lines


def default_rows() -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for entry in load(EXPLOIT).get("entries") or []:
        if entry.get("deployment_requirement") != "default-exposed":
            continue
        seen.add(entry["id"])
        rows.append({
            "id": entry["id"],
            "component": entry.get("component"),
            "status": entry.get("status"),
            "evidence": entry.get("deployment_evidence"),
            "impact": "verified dynamic primitive" if entry.get("status") == "verified"
                      else ("exposure-verified (bind/auth, no RCE)" if entry.get("status")
                            == "exposure-verified" else
                            "exposure only (bind/auth posture; no RCE verified)"),
        })
    for entry in (load(ZERODAY).get("entries") or []):
        if entry.get("state") != "novelty-checked":
            continue
        if entry.get("deployment_requirement") != "default-exposed":
            continue
        if entry["id"] in seen:
            continue
        rows.append({
            "id": entry["id"],
            "component": entry.get("component"),
            "status": (entry.get("verification") or {}).get("status"),
            "evidence": entry.get("deployment_evidence"),
            "impact": "verified reserve primitive",
        })
    return sorted(rows, key=lambda r: (r["component"] or "", r["id"]))


def gap_rows() -> list[dict]:
    counts: dict[str, int] = {}
    for entry in load(EXPLOIT).get("entries") or []:
        if entry.get("status") in {"verified", "exposure-verified", "unsupported"}:
            continue
        case = (ROOT / "lab" / "upstream_verify" / "cases" / str(entry.get("component"))
                / str(entry.get("id")) / "manifest.json")
        category = "no manifest"
        if case.is_file():
            category = ((load(case).get("static_blocker") or {}).get("category")
                        or "unclassified")
        counts[category] = counts.get(category, 0) + 1
    return [{"category": k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]


def main() -> int:
    data = readiness()
    registry = load(EXPLOIT)
    zeroday = load(ZERODAY)
    reserve = [e for e in zeroday.get("entries") or []
               if e.get("state") == "novelty-checked"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines: list[str] = [
        "# Weapon readiness — exposure classification, verification and one-click packs",
        "",
        f"Generated: `{now}`. Sources: `inkblade/core/exploit-registry.json` (152 catalog/mining "
        f"entries), `inkblade/core/zeroday-registry.json` ({len(reserve)} reserve entries), "
        "`inkblade/core/data/weapon-packs.json` (reserve packs) and "
        "`inkblade/core/data/version-matrix.json` (payload variants).",
        "",
        "> **Rules.** `deployment_requirement` is independent of `status`. "
        "`default-exposed` means reachable with the vendor's default bind/config (evidence names "
        "the address/flag/file:line). `verified` still requires a dynamic reproduction with a "
        "proof marker. An exposure-only finding is never promoted to RCE.",
        "",
        "## 1. Catalog + mining registry (152 entries)",
        "",
        "Counts: "
        + ", ".join(f"`{k}`={v}" for k, v in data["exploit_registry"]["by_requirement"].items())
        + f"; one-click module-backed: **{sum(r['one_click'] for r in data['exploit_registry']['components'])}"
          f"/152**; payload variants: **{data['exploit_registry']['variants']}**.",
        "",
        *table(data["exploit_registry"]["components"]),
        "",
        "`one-click` = the entry owns a module with `run.py`; `inkblade exploit <id> --dry-run` "
        "resolves it (reserve packs win, catalog entries are synthesised on demand). Entries "
        "without a module stay classified but are not one-click runnable; that is the honest "
        "gap, not a hidden failure.",
        "",
        "## 2. 0day reserve (47 entries, all weaponised)",
        "",
        f"Counts: {', '.join(f'`{k}`={v}' for k, v in data['reserve']['by_requirement'].items())}; "
        f"modules: **{data['reserve']['modules']}**; payload variants: "
        f"**{data['reserve']['variants']}**; one-click: **47/47**.",
        "",
        *table(data["reserve"]["components"]),
        "",
        "Every reserve entry has: one module (11 created in this pass: openrlhf-serve-rm, "
        "msswift-trust-remote-code, verl-prime-code-exec, skyrl-fetch-weights-traversal, "
        "openrlhf-vllm-env-force, openjev-clef-release-module, msswift-eval-escape, onejev-ssrf, "
        "llm2jev-file-read, siliconlab-credential-exfil, msswift-media-local-read), a "
        "version-matrix row, >=2 payload variants, a deployment verdict with evidence, and an "
        "`inkblade exploit <id>` entry (dry-run + `--real`, backup gate for write modules).",
        "",
        "## 3. Default-exposed: the “默认可打” list",
        "",
        "These are reachable without a non-default setting. The impact column separates a "
        "verified primitive from an exposure-only finding.",
        "",
        "| ID | Component | Status | Impact | Evidence |",
        "|---|---|---|---|---|",
    ]
    for row in default_rows():
        evidence = str(row["evidence"] or "").replace("|", "\\|")
        lines.append(f"| `{row['id']}` | `{row['component']}` | {row['status']} | "
                     f"{row['impact']} | {evidence} |")
    lines += [
        "",
        "Reading the list:",
        "",
        "- **CVE-2026-92972** — unauthenticated PD bootstrap `PUT /route` poisons "
        "`prefill_port_table`; the live reproduction returned 200 without credentials.",
        "- **kueueviz / ceph-csi pprof / JuiceFS metrics** — unauthenticated read/exposure on a "
        "default listener (`0.0.0.0` or `::`); these are information-disclosure primitives, not "
        "code execution.",
        "- **LLaMA-Factory (6 cases)** — `GRADIO_SERVER_NAME`/`API_HOST` default to `0.0.0.0` "
        "and the web UI/API have no auth. The real app was launched with the vendor defaults "
        "and served an unauthenticated request from a non-loopback address; no RCE is claimed.",
        "- **djev / SGLang-Omni / dify-shellctl / ms-swift media** — reserve entries whose "
        "default config omits the key/token or allows the path; verified dynamically for the "
        "reserve cohort.",
        "",
        "## 4. Verified status and gaps",
        "",
        f"- Catalog/mining: **37/152 verified RCE** plus **6 exposure-verified** "
        f"(LLaMA-Factory default bind, no RCE claimed); 87 static-only and 22 unsupported "
        f"(BMC/switch/DPU/kernel/runtime hardware paths).",
        f"- Reserve: **{sum(1 for e in reserve if (e.get('verification') or {}).get('status') == 'verified')}"
        f"/{len(reserve)} verified**; all 47 are module-backed and one-click runnable.",
        f"- Static-only blockers (catalog/mining): "
        + ", ".join(f"`{row['category']}`={row['count']}" for row in gap_rows())
        + ".",
        "- Verification target `>=50/152` is **not met**: 37 dynamic + 6 exposure = 43. The exact "
        "blockers are recorded in each manifest (`static_blocker.category/reason`) and must not "
        "be papered over.",
        "",
        "Why the remaining static cases did not become verified:",
        "",
        "- `requires-full-stack` (12): Dify needs API+DB+sandbox, LiteLLM needs Postgres + a "
        "DB-backed virtual key, Open WebUI needs the FastAPI server + DB + session, Megatron is "
        "advisory-only, vLLM/SGLang need a GPU model server.",
        "- `host-toolchain-missing` (4): ceph-csi needs librbd/libceph, SonIC REST needs "
        "swsscommon/Redis, the DRA driver/GPU operator exec sinks are operator-configured with "
        "no tenant input. Three Go cases (kueueviz, Volcano, JuiceFS CSI) were promoted earlier "
        "and are counted in the 37.",
        "- `exposure-only` (6): LLaMA-Factory bind defaults were promoted to "
        "`exposure-verified` — the real web UI/API listened on `0.0.0.0` and served an "
        "unauthenticated request from a non-loopback address. They are counted separately from "
        "the 37 RCE-verified entries and never claimed as RCE.",
        "- `requires-k8s` (5): a live API server/kubelet/CRD and pod-create rights are required; "
        "the QEMU k3s VM can host a cluster but not the vulnerable historical versions.",
        "",
        "## 5. One-click usage",
        "",
        """```powershell
inkblade exploit --list                     # readiness table (reserve + registry)
inkblade exploit djev-open-proxy            # dry-run plan: variants, evidence, marker template
inkblade exploit CVE-2026-92972 --real --target http://127.0.0.1:30000
inkblade exploit skyrl-tinker-api --real --target http://127.0.0.1:8000 `
    --backup-target /var/lib/skyrl/checkpoints
```""",
        "",
        "- `--real` goes through `run_module`, so RoE scope, the surface gate and the backup gate "
        "all apply. A write module without `--backup-target` exits **91** before acting.",
        "- Marker proof: every real run writes `exploit-marker.txt` in the run directory "
        "(`INKBLADE-<run>` + SHA256). The dry-run prints the marker template and never writes.",
        "- Payload variants are listed in the dry-run output; they are request mutations "
        "(`path_suffix`, `path_dotseg`, `method`, `query`, `body_merge`) or file/param payloads "
        "for function-level packs.",
        "",
        "## 6. Method notes",
        "",
        "- Deployment evidence is validated by `inkblade/core/deployment.py::validate_evidence` "
        "and by `tools/verify-exploits.py`; empty/generic evidence fails the gate.",
        "- `tools/classify-deployment.py --write` regenerates the two registries; "
        "`tools/build-weapon-packs.py --write` regenerates packs + version-matrix rows; this "
        "document is rendered by `tools/render-weapon-readiness.py`.",
        "",
    ]
    DOC.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
