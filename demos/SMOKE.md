# Demo smoke record

- date: 2026-10-27
- scope: 68 runnable demos under `demos/<id>/`; 7 N/A entries are documented in README.
- command: `python demos/CVE-2023-48022/poc.py --marker INKBLADE-BENIGN-SMOKE`
- output: `200 {"ok": true, "marker": "INKBLADE-BENIGN-SMOKE", "effect": "mock effect reached", "path": "/api/jobs/", ...}`
- cleanup: `cleanup: removed demos/.work/CVE-2023-48022`
- second smoke: `python demos/CVE-2025-32434/poc.py --marker INKBLADE-BENIGN-SMOKE` -> `200 INKBLADE-BENIGN-SMOKE`
- help check: `python demos/CVE-2023-48022/poc.py --help` -> usage line contains `--target`, `--marker`, `--cleanup`
- py_compile: PASS (68 `poc.py` files, `python -m compileall -q demos`)
- bash -n: PASS (68 `run.sh` files)
- default target: `127.0.0.1:0` (loopback only; port 0 = ephemeral)
- safety: benign `INKBLADE-BENIGN-*` markers only; no public URL, real credential, persistence or destructive payload.

smoke: PASS
