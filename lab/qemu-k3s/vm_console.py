"""Serial console driver for the QEMU TCG Alpine/k3s lab.

QEMU is started with ``-serial tcp:127.0.0.1:<port>,server=on,wait=off``; this
module connects to that socket, sends lines, waits for prompt patterns and
mirrors everything into a log file (evidence).

Used by ``run-real-cluster-check.ps1`` for the provisioning phase; can also be
driven manually::

    python lab/qemu-k3s/vm_console.py --log out/serial.log --exec "cat /etc/os-release"

The guest console is a POSIX shell (busybox ash in the Alpine live ISO, then
the installed system), so commands are plain shell lines followed by CR.
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")


class Console:
    """Minimal expect-style driver over a QEMU serial TCP chardev."""

    def __init__(self, host: str = "127.0.0.1", port: int = 4555,
                 log_path: str | Path | None = None, connect_timeout: float = 30.0):
        self.buf = ""
        deadline = time.time() + connect_timeout
        last: Exception | None = None
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((host, port), timeout=5)
                break
            except OSError as exc:  # QEMU not listening yet
                last = exc
                time.sleep(0.5)
        else:
            raise TimeoutError(f"cannot connect to serial console {host}:{port}: {last}")
        self.sock.settimeout(0.4)
        self.log = None
        if log_path:
            p = Path(log_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.log = p.open("a", encoding="utf-8", errors="replace")
            self.log.write(f"\n=== console attach {time.strftime('%Y-%m-%dT%H:%M:%S')} ===\n")
            self.log.flush()
        self._pos = 0
        self._ansi_pending = ""

    # -- io ---------------------------------------------------------------
    def _append(self, text: str) -> None:
        if not text:
            return
        # The guest terminal emits DSR/cursor reports (ESC[6n) after prompts.
        # Keep them in the raw log but strip them from the match buffer so that
        # prompt anchors like /# $/ behave. Hold back a trailing partial escape.
        clean = ANSI.sub("", self._ansi_pending + text)
        idx = clean.rfind("\x1b")
        if idx != -1 and idx >= len(clean) - 8:
            self._ansi_pending = clean[idx:]
            clean = clean[:idx]
        else:
            self._ansi_pending = ""
        text = clean
        self.buf += text
        if len(self.buf) > 200_000:  # keep matching window bounded
            cut = len(self.buf) - 100_000
            self.buf = self.buf[cut:]
            self._pos = max(0, self._pos - cut)
        if self.log:
            self.log.write(text)
            self.log.flush()

    def pump(self, seconds: float = 0.4) -> None:
        end = time.time() + seconds
        while time.time() < end:
            try:
                data = self.sock.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            self._append(data.decode("utf-8", "replace"))

    def send(self, text: str) -> None:
        self.sock.sendall(text.encode("utf-8"))
        if self.log:
            self.log.write(f"\n<<<SEND>>> {text!r}\n")
            self.log.flush()

    def wait(self, pattern: str, timeout: float = 120.0, since: int | None = None) -> re.Match:
        rx = re.compile(pattern, re.M | re.S)
        end = time.time() + timeout
        pos = self._pos if since is None else since
        while True:
            m = rx.search(self.buf, pos)
            if m:
                self._pos = m.end()
                return m
            if time.time() > end:
                tail = ANSI.sub("", self.buf[-1500:])
                raise TimeoutError(f"timeout after {timeout}s waiting for /{pattern}/\n--- tail ---\n{tail}")
            self.pump(0.4)

    def expect_any(self, patterns: list[str], timeout: float = 300.0) -> tuple[int, re.Match]:
        rx = re.compile("|".join(f"(?P<p{i}>{p})" for i, p in enumerate(patterns)), re.M | re.S)
        end = time.time() + timeout
        while True:
            m = rx.search(self.buf, self._pos)
            if m:
                self._pos = m.end()
                idx = next(i for i in range(len(patterns)) if m.group(f"p{i}") is not None)
                return idx, m
            if time.time() > end:
                tail = ANSI.sub("", self.buf[-1500:])
                raise TimeoutError(f"timeout after {timeout}s waiting for any of {patterns}\n--- tail ---\n{tail}")
            self.pump(0.4)

    # -- helpers ----------------------------------------------------------
    def login(self, user: str = "root", password: str | None = None, timeout: float = 240.0) -> None:
        """Wait for a login prompt and log in (Alpine live/installed root)."""
        idx, _ = self.expect_any([r"login:\s*$", r"^[\w.@()/-]+:~#\s*$", r"^[\w.@()/-]+ login:",
                                  r"^[\w.@()/-]+#\s*$"], timeout=timeout)
        if idx in (0, 2):
            self.send(user + "\r")
            if password:
                self.wait(r"[Pp]assword:\s*$", timeout=30)
                self.send(password + "\r")
            self.wait(r"^[\w.@()/-]+:~#\s*$", timeout=60)
        self.send("export PS1='VM# '\r")
        self.wait(r"VM#\s*$", timeout=20)

    def cmd(self, command: str, timeout: float = 600.0, expect: str = r"VM#\s*$",
            echo_marker: bool = True) -> int:
        """Run a shell command and wait for the prompt to come back."""
        if echo_marker:
            # The marker is split so the echoed command line does not itself
            # contain the literal marker; the wait is also line-anchored.
            self.send('echo __BE""GIN__\r')
            self.wait(r"^__BEGIN__\s*$", timeout=30)
        self.send(command.rstrip("\n") + "\r")
        start = self._pos
        self.wait(expect, timeout=timeout)
        return start

    def output_since(self, pos: int) -> str:
        return ANSI.sub("", self.buf[pos:])

    def cmd_output(self, command: str, timeout: float = 600.0) -> str:
        start = self.cmd(command, timeout=timeout)
        return self.output_since(start)

    def close(self) -> None:
        try:
            self.sock.close()
        finally:
            if self.log:
                self.log.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="QEMU serial console driver (lab only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4555)
    ap.add_argument("--log", default=None)
    ap.add_argument("--exec", dest="command", default=None, help="run one shell command and print its output")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--login", action="store_true", help="log in as root first")
    args = ap.parse_args(argv)

    con = Console(args.host, args.port, args.log)
    try:
        if args.login:
            con.login()
        if args.command:
            sys.stdout.write(con.cmd_output(args.command, timeout=args.timeout))
            return 0
        print("attached; Ctrl-C to detach (guest keeps running)", file=sys.stderr)
        while True:
            con.pump(1.0)
    except KeyboardInterrupt:
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    raise SystemExit(main())
