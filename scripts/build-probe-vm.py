#!/usr/bin/env python3
"""Build the InkBlade probe inside the QEMU Alpine VM (native musl).

The Windows host blocks rustc via Smart App Control; the lab VM does not.
Requires paramiko on the host and the VM SSH port (default 127.0.0.1:2222).

Usage:
  python scripts/build-probe-vm.py --archive probe.tar.gz --out probe/dist/inkblade-probe-linux-amd64
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

import paramiko


def run(client, cmd: str, timeout: int = 1800) -> tuple[int, str]:
    print(f"$ {cmd}", flush=True)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    text = (out + err).strip()
    if text:
        print(text[-4000:], flush=True)
    return code, text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="inkblade")
    ap.add_argument("--archive", required=True)
    ap.add_argument("--remote-dir", default="/root/inkblade-probe")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.host, port=args.port, username=args.user, password=args.password, timeout=20)

    rc, _ = run(client, "command -v cargo || true")
    if "cargo" not in _:
        rc, _ = run(client, "apk add --no-cache rust cargo musl-dev build-base", timeout=3600)
        if rc != 0:
            print("apk install failed", file=sys.stderr)
            return 2

    sftp = client.open_sftp()
    run(client, f"rm -rf {args.remote_dir} && mkdir -p {args.remote_dir}")
    sftp.put(args.archive, f"{args.remote_dir}/probe.tar.gz")
    rc, _ = run(client, f"cd {args.remote_dir} && tar xzf probe.tar.gz && ls -la")
    if rc != 0:
        return 3

    rc, _ = run(client, f"cd {args.remote_dir} && cargo build --release", timeout=3600)
    if rc != 0:
        return 4

    remote_bin = f"{args.remote_dir}/target/release/inkblade-probe"
    rc, _ = run(client, f"ls -l {remote_bin} && sha256sum {remote_bin} && head -c 4 {remote_bin} | od -An -tx1")
    if rc != 0:
        return 5

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sftp.get(remote_bin, str(out))
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f"downloaded {out} sha256={digest} size={out.stat().st_size}")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
