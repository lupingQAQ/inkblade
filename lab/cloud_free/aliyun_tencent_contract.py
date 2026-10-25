# -*- coding: utf-8 -*-
"""阿里云 OSS/ACK 与腾讯云 COS/TKE：沿用 cloud_six_sim 契约仿真（非真实账号）。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    import sys
    sys.path.insert(0, str(REPO))
from lab.cloud_six_sim import run_scenarios
DEFAULT_OUT = REPO / "reports" / "samples" / "cloud-free" / "aliyun-tencent-contract.json"


def run(out: Path | str | None = None) -> dict:
    path = Path(out) if out else DEFAULT_OUT
    result: dict = {
        "schema": "trident-cloud-contract/2026-10",
        "mode": "contract simulation (lab/cloud_six_sim.py), not a real account",
    }
    for mode in ("vulnerable", "fixed"):
        doc = run_scenarios(mode)
        scenarios = [s for s in doc["scenarios"] if s["cloud"] in ("aliyun", "tencent")]
        result[mode] = {
            "scenarios": len(scenarios),
            "as_expected": sum(1 for s in scenarios if s.get("as_expected")),
            "cross_tenant_ok": sum(1 for s in scenarios if s.get("cross_tenant_ok")),
            "rows": [{k: s.get(k) for k in ("scenario", "cloud", "as_expected", "cross_tenant_ok")}
                     for s in scenarios],
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    print(json.dumps(run(args.out), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
