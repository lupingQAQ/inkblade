# ARTEX in QEMU TCG k3s VM — measured bench

- generated: 2026-10-25T12:52:35Z
- subject: RuoJi6/ARTEX `v0.3.23` image `ruoji6/artex:v0.3.23`
- environment: QEMU emulator version 11.1.0 (v11.1.0-12130-ge470268ff4) Copyright (c) 2003-2026 Fabrice Bellard and the QEMU Project developers

## Cold start (container start, image pre-pulled)

| phase | ms |
|---|---|
| postgres → pg_isready | 19180 |
| artex → `/api/health` 200 | 35710 |
| auth init+login handshake | 480 |

## API latency (`GET /api/health`, guest loopback)

- n=20 min=50 p50=55.0 p95=60 max=60 ms

## Resources

- RSS total max: **75.25 MiB**, mean 74.67 MiB (artex=27.02MiB, artex-pg=48.32MiB)
- /var/lib/docker: 4963154309 bytes

| image | size |
|---|---|
| postgres:16-alpine | 420MB |
| ruoji6/artex:v0.3.23 | 2.47GB |

## Task

- POST /api/tasks → 201 in 240 ms, id=1
- final status: **done** after 13510 ms
- LLM calls observed by the mock: 12
- same-target outcome (v2 scripted-planner mock): see same-target.md — the task
  reaches `done`, the worker hits the mock target for real and a finding is filed.

## Side by side with InkBlade

| metric | ARTEX (VM) | InkBlade (host, lab/bench) |
|---|---|---|
| idle RSS | 75.25 MiB (2 containers) | 49.0 MiB (1 process) |
| task submit → terminal state | 13510 ms (status=done; scripted-planner mock LLM; same-target details in same-target.md) | 320 ms over 5 chain rounds (real HTTP to the same mock target) |

## Limitations

- QEMU TCG software emulation: absolute numbers are not comparable to bare-metal; only the ARTEX-vs-InkBlade ratio on the same host is meaningful.
- The LLM is a deterministic OpenAI-compatible mock on the host; it exercises the real HTTP/agent loop but not model quality or token cost.
- Idle RSS is sampled 60-90 s after start via docker stats (2 s cadence), not an instantaneous peak.
- k3s (single-node control plane) is running in the same guest during the whole bench and consumes CPU/RAM.
- Image pull time is excluded from cold start (images are pre-pulled); it is reported separately.
