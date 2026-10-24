"""Provision Alpine into the QEMU disk, driven entirely over the serial console.

The KVM-less lab has no shared clipboard and no guest agent, so the live ISO is
driven through QEMU's serial TCP chardev: type the isolinux entry with
``console=ttyS0``, log in as root, fetch ``setup-alpine.sh`` over the user-mode
network gateway (10.0.2.2) and let it install to /dev/vda.

Run from Windows after ``start-vm.ps1 -Mode install`` and after starting the
host HTTP server on port 8000 serving lab/qemu-k3s/http.

    python lab/qemu-k3s/provision_alpine.py --console-port 4555
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vm_console import Console  # noqa: E402

PROMPTS = [
    (re.compile(r"\[y/N\]|\(y/n\)|\[Y/n\]|Erase the above disk|continue\?", re.I), "y\r"),
    (re.compile(r"mirror number|Enter mirror", re.I), "\r"),
    (re.compile(r"Which timezone|Enter timezone", re.I), "\r"),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--console-port", type=int, default=4555)
    ap.add_argument("--log", default=str(Path(__file__).parent / "out" / "serial-provision.log"))
    ap.add_argument("--http-base", default="http://10.0.2.2:8000")
    ap.add_argument("--direct-kernel", action="store_true",
                    help="VM was started with -kernel/-initrd: skip the isolinux cmdline")
    ap.add_argument("--timeout", type=float, default=2700.0)
    args = ap.parse_args(argv)

    started = time.time()
    con = Console(args.host, args.console_port, args.log, connect_timeout=90)
    # isolinux on the Alpine virt ISO waits indefinitely at "boot:" and does not
    # auto-boot, so the serial cmdline can be typed as soon as we attach. Do NOT
    # send a bare CR first: that would boot the default entry, whose console is
    # tty0 (VGA) and which we could no longer see over the serial line.
    time.sleep(2)
    if args.direct_kernel:
        print("[provision] direct kernel/netboot: console already configured", flush=True)
        con.send("\r")  # re-print the login prompt for this fresh connection
    else:
        print("[provision] sending isolinux cmdline (console=ttyS0)", flush=True)
        con.send("virt console=ttyS0,115200\r")
    print("[provision] waiting for login/shell prompt", flush=True)
    con.login(timeout=420)
    print(f"[provision] shell ready after {time.time() - started:.0f}s", flush=True)
    print("[provision] running setup-alpine.sh (this is the slow part under TCG)", flush=True)
    con.send(f"wget -q -O /tmp/setup-alpine.sh {args.http_base}/setup-alpine.sh && sh /tmp/setup-alpine.sh\r")
    deadline = time.time() + args.timeout
    scan = len(con.buf)
    answered = 0
    while time.time() < deadline:
        con.pump(1.0)
        chunk = con.buf[scan:]
        for rx, answer in PROMPTS:
            if rx.search(chunk):
                print(f"[provision] prompt {rx.pattern!r} -> {answer.strip()!r}", flush=True)
                con.send(answer)
                answered += 1
                scan = len(con.buf)
                break
        else:
            if re.search(r"VM#\s*$", con.buf) and "PROVISION-OK" in con.buf:
                print(f"[provision] install finished in {time.time() - started:.0f}s ({answered} prompts answered)", flush=True)
                break
            if re.search(r"PROVISION-OK", chunk):
                print("[provision] PROVISION-OK seen; waiting for poweroff", flush=True)
                scan = len(con.buf)
    else:
        raise SystemExit("provisioning timed out")

    con.pump(5)
    con.close()
    print(f"[provision] done in {time.time() - started:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
