# -*- coding: utf-8 -*-
"""运行 fabric 仿真、写 JSON/SVG/HTML/summary（模拟，非真实硬件）。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from lab.fabric_sim.detectors import detect, verdict
    from lab.fabric_sim.sim import simulate
    from lab.fabric_sim.topology import Topology
    from lab.fabric_sim.viz import render_html, render_svg
else:
    from .detectors import detect, verdict
    from .sim import simulate
    from .topology import Topology
    from .viz import render_html, render_svg

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "reports" / "samples" / "fabric-sim"


def run(nodes: int, scenario: str, out: Path | str | None = None, *, seed: int = 7,
        ranks: int | None = None, chunks: int | None = None) -> dict:
    topo = Topology.build(nodes)
    telemetry = simulate(topo, scenario, seed=seed, ranks=ranks, chunks=chunks)
    findings = detect(telemetry)
    v = verdict(telemetry, findings)
    doc = telemetry.to_dict()
    doc["verdict"] = v
    out_dir = Path(out) if out else DEFAULT_OUT
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"fabric-{scenario}-{nodes}"
    (out_dir / f"{stem}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                                         encoding="utf-8")
    svg = render_svg(telemetry, findings)
    (out_dir / f"{stem}.svg").write_text(svg, encoding="utf-8")
    (out_dir / f"{stem}.html").write_text(render_html(telemetry, findings, svg), encoding="utf-8")
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="InkBlade fabric discrete-event simulation")
    ap.add_argument("--nodes", type=int, default=1024)
    ap.add_argument("--scenario", default="mixed",
                    choices=["baseline", "pfc-storm", "ecn", "rail-mismatch",
                             "straggler", "link-failure", "mixed"])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--ranks", type=int, default=None)
    ap.add_argument("--chunks", type=int, default=None)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    doc = run(args.nodes, args.scenario, args.out, seed=args.seed,
              ranks=args.ranks, chunks=args.chunks)
    print(json.dumps({"scenario": doc["scenario"], "nodes": doc["topology"]["nodes"],
                      "pfc_pause_frames": doc["pfc_pause_frames"],
                      "ecn_marks": doc["ecn_marks"],
                      "cross_rail_flows": doc["cross_rail_flows"],
                      "worst_rank_ms": doc["worst_rank_ms"],
                      "findings": [f["rule"] for f in doc["verdict"]["findings"]]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
