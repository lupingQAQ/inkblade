# -*- coding: utf-8 -*-
"""用真实 trident fabric 模块判定仿真 telemetry（probe/write 只打到 lab 端点）。"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from lab.fabric_sim.server import TelemetryServer
    from lab.fabric_sim.sim import simulate
    from lab.fabric_sim.topology import Topology
else:
    from .server import TelemetryServer
    from .sim import simulate
    from .topology import Topology

REPO = Path(__file__).resolve().parents[2]
MODULES = REPO / "trident" / "modules"
DEFAULT_OUT = REPO / "reports" / "samples" / "fabric-sim" / "module-findings.json"


def _load(key: str):
    path = MODULES / key / "run.py"
    spec = importlib.util.spec_from_file_location(f"fabric_sim_{key.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _snapshot(topology: Topology) -> dict:
    return {
        "nodes": topology.nodes_snapshot(omit_hca_every=17),
        "ib_fabric": {"type": "infiniband", "sm": {"masters": ["sm-0"]}, "partitions": []},
        "roce": {"present": True}, "nvlink": {"present": True},
        "items": [{"kind": "ComputeDomain", "metadata": {"name": "cd-0"},
                   "spec": {"members": [{"name": "gpu-00001"}]}}],
    }


def run(out: Path | str | None = None, *, nodes: int = 1024) -> dict:
    topo = Topology.build(nodes)
    telemetry = simulate(topo, "mixed", seed=7)
    findings: dict[str, list[dict]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        ctx = {"run": SimpleNamespace(dir=tmp)}
        iso = _load("fabric-topology-isolation")
        result = iso.run(ctx, {"snapshot": _snapshot(topo)})
        findings["fabric-topology-isolation"] = result["findings"]
        with TelemetryServer(telemetry) as server:
            pfc = _load("roce-pfc-storm")
            findings["roce-pfc-storm"] = pfc.run(ctx, {
                "target": server.url, "mode": "backup-write",
                "backup_targets": ["sim"], "rounds": 3})["findings"]
            straggler = _load("nccl-straggler-injection")
            findings["nccl-straggler-injection"] = straggler.run(ctx, {
                "target": server.url, "mode": "backup-write",
                "backup_targets": ["sim"], "rank": "rank-7",
                "straggler_ms": 5000})["findings"]
    doc = {
        "schema": "trident-fabric-module-adjudication/2026-10",
        "source": "simulation telemetry -> real trident modules (probe/backup-write against lab HTTP endpoint)",
        "nodes": nodes, "scenario": "mixed",
        "modules": findings,
        "counts": {name: len(items) for name, items in findings.items()},
        "sev": {name: sorted({f.get("sev") for f in items}) for name, items in findings.items()},
    }
    path = Path(out) if out else DEFAULT_OUT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=1024)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    doc = run(args.out, nodes=args.nodes)
    print(json.dumps({"counts": doc["counts"], "sev": doc["sev"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
