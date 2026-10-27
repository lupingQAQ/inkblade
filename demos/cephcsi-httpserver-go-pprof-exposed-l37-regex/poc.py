#!/usr/bin/env python3
"""Local-only demo for cephcsi-httpserver-go-pprof-exposed-l37-regex: ceph-csi: pprof-exposed-go @ internal/util/httpserver.go:37."""
# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup
# DEMO-SNIPPET-BEGIN
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _lib.demo import cli, run_demo
MARKER = "INKBLADE-BENIGN-cephcsi-httpserver-go-pprof-exposed-l37-regex"
SPEC = {'id': 'cephcsi-httpserver-go-pprof-exposed-l37-regex', 'kind': 'pprof', 'method': 'GET', 'route': '/debug/pprof/cmdline', 'payload': {'probe': 'INKBLADE-BENIGN', 'id': 'cephcsi-httpserver-go-pprof-exposed-l37-regex'}, 'expect_status': 200}
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
