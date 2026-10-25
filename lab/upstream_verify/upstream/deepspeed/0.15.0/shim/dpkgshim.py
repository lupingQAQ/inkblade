"""Attacker-controlled ``dpkg`` executable used by the CVE-2024-43497 PoC.

The vulnerable upstream code resolves ``dpkg`` from PATH and invokes
``subprocess.Popen("dpkg -l libaio-dev apt", shell=True)``.  This shim records
that the PATH hijack reached code execution.  It is not a package manager.
"""

import os
import pathlib


def main():
    marker = pathlib.Path(os.environ["DS_MARKER"])
    marker.write_text(os.environ.get("DS_TEXT", "VERIFIED"), encoding="utf-8")


if __name__ == "__main__":
    main()
