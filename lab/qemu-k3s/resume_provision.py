"""Answer setup-alpine's remaining interactive prompts on the guest console.

setup-alpine still asks a few questions that are not covered by the answer file
(root password, disk erase confirmation, sshd root login). The provisioning
driver answers them while it waits; this helper can be attached to an already
running installer (e.g. after the driver was restarted) without starting a new
install.

    python lab/qemu-k3s/resume_provision.py --timeout 2400
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vm_console import Console  # noqa: E402

RULES = [
    (re.compile(r"Setup a user\?|lower-case loginname", re.I), "\r"),
    (re.compile(r"New password:\s*$"), "trident\r"),
    (re.compile(r"Retype password:\s*$"), "trident\r"),
    (re.compile(r"Allow root ssh login|root ssh login", re.I), "yes\r"),
    (re.compile(r"\[y/N\]|\[Y/n\]|\(y/n\)|Erase the above disk|continue\?", re.I), "y\r"),
    (re.compile(r"mirror number|Enter mirror", re.I), "\r"),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4555)
    ap.add_argument("--log", default=str(Path(__file__).parent / "out" / "serial-provision.log"))
    ap.add_argument("--timeout", type=float, default=2400.0)
    args = ap.parse_args(argv)
    con = Console(port=args.port, log_path=args.log, connect_timeout=60)
    deadline = time.time() + args.timeout
    # The installer is usually blocked on a prompt that was printed *before* we
    # attached, so no new output will arrive on its own. A bare newline accepts
    # the default answer at most setup-alpine questions (e.g. "Setup a user? [no]"),
    # and re-prints prompts where an empty answer is invalid.
    con.send("\r")
    con.pump(3.0)
    print("[resume] answered pending prompt with default (empty line)", flush=True)
    scan = len(con.buf)
    while time.time() < deadline:
        con.pump(1.0)
        chunk = con.buf[scan:]
        for rx, answer in RULES:
            if rx.search(chunk):
                print(f"[resume] prompt {rx.pattern!r} -> {answer.strip()!r}", flush=True)
                con.send(answer)
                scan = len(con.buf)
                break
        if "PROVISION-OK" in con.buf:
            print("[resume] PROVISION-OK", flush=True)
            time.sleep(5)
            break
    else:
        print("[resume] timeout", flush=True)
        return 1
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
