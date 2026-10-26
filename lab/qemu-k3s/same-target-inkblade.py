"""same-target-inkblade.py — run the InkBlade chain on the SAME mock target ARTEX scanned.

Timed counterpart of the ARTEX same-target bench (docs/ARTEX-BENCH-RESULT.md):
the chain `flat-network-admin-plane-weight-poison` (sglang-admin-failopen →
slime-weight-pull-poison) is executed against the shared lab/mock_targets
instance the ARTEX worker also probed, with per-step wall time from the
evidence store's steps table and per-request evidence from the target's
/__stats__ counter.

Everything is stdlib; run from the repo root:

    python lab/qemu-k3s/same-target-inkblade.py \
        --target http://127.0.0.1:18080 --out lab/qemu-k3s/out/inkblade-chain.json
"""
from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inkblade.core.chains import dry_run, execute, load_chains  # noqa: E402
from inkblade.core.evidence import EvidenceStore  # noqa: E402
from inkblade.core.roe import init_roe  # noqa: E402
from inkblade.core.users import UserStore  # noqa: E402

MODULES_DIR = REPO_ROOT / "inkblade" / "modules"
CHAINS_DIR = REPO_ROOT / "inkblade" / "chains"
CHAIN_ID = "flat-network-admin-plane-weight-poison"


def _stats(target: str) -> dict:
    req = urllib.request.Request(target.rstrip("/") + "/__stats__", method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _stable_modules_dir() -> Path:
    """Copy of inkblade/modules with only complete modules (module.json + run.py).

    Parallel sessions may be mid-flight adding a module directory to
    inkblade/modules; load_modules() hard-fails on any incomplete module, so the
    bench runs against a filtered snapshot instead of mutating shared state.
    """
    src = MODULES_DIR
    dst = Path(tempfile.mkdtemp(prefix="inkblade-modules-stable-"))
    for d in sorted(p for p in src.iterdir() if p.is_dir()):
        if (d / "module.json").exists() and (d / "run.py").exists():
            shutil.copytree(d, dst / d.name)
    return dst


def _rss_sampler():
    try:
        from lab.bench.bench import MemorySampler

        sampler = MemorySampler(interval_s=0.02)
        sampler.start()
        return sampler
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "out" / "inkblade-chain.json"))
    args = ap.parse_args()
    target = args.target.rstrip("/")
    base = target + "/"
    modules_dir = _stable_modules_dir()

    t_start = time.time()
    start_epoch_ms = int(time.time() * 1000)
    stats_before = _stats(target)
    sampler = _rss_sampler()

    result: dict = {"chain": CHAIN_ID, "target": base, "started_epoch_ms": start_epoch_ms}
    with TemporaryDirectory(prefix="inkblade-same-target-") as td:
        root = Path(td)
        store = EvidenceStore(root, workspace="local-lab")
        users = UserStore(root / "users.json")
        users.create_user("bench-lead", "x", "lead", ["local-lab"])
        users.create_user("bench-tester", "x", "tester", ["local-lab"])
        tester = users.verify("bench-tester", "x")
        init_roe(store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer", "ray-system", "default", "ml-agent"],
            "cidrs": ["127.0.0.0/8"],
            "window": "2026-10-25 00:00 – 23:59（same-target bench）",
            "client": "InkBlade same-target bench（本机 mock，与 ARTEX 同靶场）",
        })

        chains = load_chains(CHAINS_DIR)
        chain = chains[CHAIN_ID]

        t0 = time.perf_counter()
        plan = dry_run(chain, [], modules_dir=modules_dir)
        result["dry_run_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result["verdict"] = plan["verdict"]
        result["missing"] = plan["missing"]

        chain_exec = copy.deepcopy(chain)
        for st in chain_exec["steps"]:
            st.setdefault("params", {})["target"] = base
            if st["module"] == "slime-weight-pull-poison":
                st["params"]["backup_targets"] = [
                    {"kind": "http", "url": base + "pull_weights", "state": {}}]

        run = store.create_run(f"same-target-{time.strftime('%Y%m%d-%H%M%S')}")
        result["run"] = run.name
        t0 = time.perf_counter()
        res = execute(chain_exec, store, tester, modules_dir=modules_dir,
                      findings=[], workers=2, run=run)
        result["execute_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result["ok"] = res["ok"]
        result["steps"] = {sid: {"status": st["status"], **({"error": st["error"]} if "error" in st else {})}
                           for sid, st in res["steps"].items()}

        rows = run.query(
            "SELECT step_key, started_at, finished_at, status FROM steps "
            "WHERE run=? ORDER BY started_at", (run.name,))
        result["step_timings"] = [
            {"step": r[0],
             "ms": round((r[2] - r[1]) * 1000, 1) if r[1] and r[2] else None,
             "status": r[3]} for r in rows]
        result["run_ms"] = round((time.time() - t_start) * 1000, 1)

    stats_after = _stats(target)
    window = [h for h in stats_after["hits"] if h["t_epoch_ms"] >= start_epoch_ms]
    result["target_hits"] = window
    result["target_hit_count"] = len(window)
    result["finished_epoch_ms"] = int(time.time() * 1000)
    if sampler is not None:
        try:
            sampler.stop()
        except Exception:
            pass
        result["max_rss_kb"] = sampler.max_rss_kb
        result["peak_rss_kb"] = sampler.peak_rss_kb

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    summary = json.dumps({k: v for k, v in result.items() if k != "target_hits"},
                         ensure_ascii=False, indent=1)
    print(summary.encode("ascii", "replace").decode("ascii"))
    print(f"[same-target-inkblade] wrote {out}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
