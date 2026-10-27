#!/usr/bin/env python3
"""Local-only demo for volcano-scheduler-server-go-pprof-exposed-l162-regex: volcano: pprof-exposed-go @ cmd/scheduler/app/server.go:162."""
# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup
# DEMO-SNIPPET-BEGIN
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _lib.demo import cli, run_demo
MARKER = "INKBLADE-BENIGN-volcano-scheduler-server-go-pprof-exposed-l162-r"
SPEC = {'id': 'volcano-scheduler-server-go-pprof-exposed-l162-regex', 'kind': 'pprof', 'method': 'GET', 'route': '/debug/pprof/cmdline', 'payload': {'probe': 'INKBLADE-BENIGN', 'id': 'volcano-scheduler-server-go-pprof-exposed-l162-regex'}, 'expect_status': 200}
def demo(args):
    # target=127.0.0.1:<port>; args.target 默认 127.0.0.1:0
    result = run_demo(SPEC, target=args.target, marker=args.marker)
    assert result["status"] == 200
    assert args.marker in result.get("body", "") or result.get("marker") == args.marker
    print(result["status"], result.get("body", "")[:160])
    return 0
# DEMO-SNIPPET-END

if __name__ == "__main__":
    raise SystemExit(cli(SPEC, MARKER, demo))
