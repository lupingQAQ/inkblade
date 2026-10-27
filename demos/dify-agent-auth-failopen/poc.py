#!/usr/bin/env python3
"""Local-only demo for dify-agent-auth-failopen: dify-agent backend auth fail-open (token None -> allow all) + public dev token in compose."""
# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup
# DEMO-SNIPPET-BEGIN
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _lib.demo import cli, run_demo
MARKER = "INKBLADE-BENIGN-dify-agent-auth-failopen"
SPEC = {'id': 'dify-agent-auth-failopen', 'kind': 'http', 'method': 'POST', 'route': '/agent-stub/v1/chat', 'payload': {'probe': 'INKBLADE-BENIGN', 'id': 'dify-agent-auth-failopen'}, 'expect_status': 200}
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
