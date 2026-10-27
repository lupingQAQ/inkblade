# -*- coding: utf-8 -*-
"""Run canonical templates natively through the Rust probe on a Linux guest.

Transport: ``ssh -T root@guest /tmp/inkblade-probe run --stdio`` (framed JSON).
The controller lowers templates, sends them, and folds evidence host-side.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.tpl.lower import compile_template, fold_result
from inkblade.tpl.probe import _frame_read, _frame_write, ProbeFailed

KEY = os.path.expanduser(os.environ.get("INKBLADE_LAB_SSH_KEY", "~/.ssh/id_ed25519_gdnet"))
PORT = 2222
GUEST = "root@127.0.0.1"
BINARY = "/tmp/inkblade-probe"
TOKEN = "inkblade-lab-token"


class SSHProbe:
    runtime = "rust"

    def __init__(self, key: str = KEY, port: int = PORT, guest: str = GUEST,
                 binary: str = BINARY, token: str = TOKEN, timeout: int = 120):
        self.key = key
        self.port = port
        self.guest = guest
        self.binary = binary
        self.token = token
        self.timeout = timeout

    def task(self, template: dict, params: dict, task_id: str) -> dict:
        argv = [
            "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=ERROR", "-i", self.key, "-p", str(self.port), self.guest,
            f"{self.binary} run --stdio --token {self.token} --allow-write",
        ]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            challenge = _frame_read(proc.stdout)
            import hmac, secrets
            nonce = secrets.token_hex(8)
            message = f"inkblade-probe/v1|{nonce}|{challenge.get('challenge')}"
            mac = hmac.new(self.token.encode(), message.encode(), "sha256").hexdigest()
            _frame_write(proc.stdin, {"v": 1, "type": "auth", "nonce": nonce, "mac": mac})
            ready = _frame_read(proc.stdout)
            if ready.get("type") != "ready":
                raise ProbeFailed(f"handshake: {ready}")
            _frame_write(proc.stdin, {"v": 1, "type": "req", "id": task_id,
                                      "op": "task",
                                      "args": {"task_id": task_id,
                                               "template": template,
                                               "params": params}})
            response = _frame_read(proc.stdout)
            if not response.get("ok"):
                raise ProbeFailed(str(response.get("error")))
            return response.get("data") or {}
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    def run(self, template: dict, params: dict, context: dict | None = None) -> dict:
        compilation = compile_template(template, params, context or {})
        if not compilation.native_ready:
            raise ProbeFailed("native gap: " + "; ".join(
                f"{g['step']}: {g['reason']}" for g in compilation.gaps[:3]))
        task_id = f"{template.get('key')}-{int(time.time() * 1000)}"
        native = self.task(compilation.native_template, compilation.params, task_id)
        return fold_result(compilation, native)


def ssh_run(command: str, *, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", "-T", "-o", "BatchMode=yes",
                           "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR",
                           "-i", KEY, "-p", str(PORT), GUEST, command],
                          capture_output=True, timeout=timeout)


if __name__ == "__main__":
    from inkblade.tpl.schema import load_template
    from lab.template_range import Range

    scenarios = {"vulnerable": {"*": {"status": 200, "json": {"ok": True}}},
                 "fixed": {"*": {"status": 403, "json": {"error": "denied"}}}}
    with Range(scenarios, host="127.0.0.1") as rng:
        target = f"http://10.0.2.2:{rng._http.server_address[1]}"
        print("target", target)
        print(ssh_run(f"wget -q -O - {target}/healthz || true").stdout.decode()[:200])
        key = "aigateway-auth-bypass"
        d = ROOT / "inkblade" / "modules" / key
        tpl = load_template(d, module_meta=json.loads((d / "module.json").read_text(encoding="utf-8")))
        probe = SSHProbe()
        result = probe.run(tpl, {"target": target, "mode": "probe-only"},
                           {"marker": "INKBLADE-LAB"})
        print(result["status"], [(f["sev"], f["title"][:40]) for f in result["findings"]])
        print(json.dumps(result["steps"], ensure_ascii=False)[:500])
