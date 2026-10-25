"""lab/bench/_baseline_compare.py — 优化前后同输入对照曲线（开发期度量，产出 docs/SCALE-RESULTS.md）。

做法：对每个 scale 生成**同一份**合成快照，跑两遍 11 个侦察模块：
- legacy：三个已优化模块取 `git show HEAD:<path>`（其余模块未改，直接复用当前实现）；
- current：工作区当前实现。
两遍都只调模块 run({}, {"snapshot": snap})，同进程顺序执行；每 scale 先跑两个小模块预热，
避免把载入/分配器冷启动误记成算法成本。计时不含 tracemalloc（见 scale-bench 的口径说明）。

用法：python lab/bench/_baseline_compare.py --scales 100,1000,5000,10000 [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES_DIR = ROOT / "trident" / "modules"
OPTIMIZED = ("metadata-egress", "network-policy-coverage", "ray-control-plane")
RECON_MODULES = (
    "cloud-integration-fingerprint", "escape-primitives", "exposure-mapping",
    "framework-port-matching", "metadata-egress", "network-policy-coverage",
    "observability-exposure", "privileged-workloads", "ray-control-plane",
    "rbac-mapping", "storage-sharing",
)


def _load(path: Path, tag: str):
    spec = spec_from_file_location(f"cmp_{tag}_{path.parent.name.replace('-', '_')}", path)
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _time_run(mod, snapshot: dict) -> tuple[float, int]:
    started = time.perf_counter()
    result = mod.run({}, {"snapshot": snapshot})
    return (time.perf_counter() - started) * 1000.0, len(result.get("findings") or [])


def _build_snapshot(scale: int) -> dict:
    spec = spec_from_file_location("scale_bench_mod", ROOT / "lab" / "bench" / "scale-bench.py")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_snapshot(scale)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scales", default="100,1000,5000,10000")
    ap.add_argument("--ref", default="128dfd4",
                    help="对比基线 git ref（默认 = 优化前最后一个提交 128dfd4；用 HEAD 会对比到已优化版本）")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    report = {"scales": []}
    with tempfile.TemporaryDirectory(prefix="trident-baseline-") as tmp:
        tmp_dir = Path(tmp)
        (tmp_dir / "_recon-common.py").write_bytes((MODULES_DIR / "_recon-common.py").read_bytes())
        legacy_mods = {}
        for key in OPTIMIZED:
            rel = f"trident/modules/{key}/run.py"
            src = subprocess.run(["git", "show", f"{args.ref}:{rel}"], cwd=ROOT,
                                 capture_output=True, check=True).stdout
            target = tmp_dir / key / "run.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(src)
            legacy_mods[key] = _load(target, "legacy")
        current_mods = {key: _load(MODULES_DIR / key / "run.py", "current") for key in RECON_MODULES}

        for scale in [int(s) for s in args.scales.split(",") if s.strip()]:
            snapshot = _build_snapshot(scale)
            for key in ("rbac-mapping", "storage-sharing"):
                _time_run(current_mods[key], snapshot)  # 预热
            entry = {"scale": scale, "modules": {}}
            for key in RECON_MODULES:
                legacy_mod = legacy_mods.get(key, current_mods[key])
                legacy_ms, legacy_findings = _time_run(legacy_mod, snapshot)
                current_ms, current_findings = _time_run(current_mods[key], snapshot)
                entry["modules"][key] = {
                    "legacy_ms": round(legacy_ms, 1),
                    "current_ms": round(current_ms, 1),
                    "speedup": round(legacy_ms / max(current_ms, 1e-6), 2),
                    "findings_legacy": legacy_findings,
                    "findings_current": current_findings,
                    "findings_equal": legacy_findings == current_findings,
                    "optimized": key in OPTIMIZED,
                }
            entry["legacy_total_ms"] = round(sum(m["legacy_ms"] for m in entry["modules"].values()), 1)
            entry["current_total_ms"] = round(sum(m["current_ms"] for m in entry["modules"].values()), 1)
            entry["total_speedup"] = round(entry["legacy_total_ms"] / max(entry["current_total_ms"], 1e-6), 2)
            entry["all_findings_equal"] = all(m["findings_equal"] for m in entry["modules"].values())
            report["scales"].append(entry)

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(text, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
