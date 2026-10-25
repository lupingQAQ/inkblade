# ARTEX in QEMU TCG k3s VM — measured bench

- generated: 2026-10-25T01:43:11Z
- subject: RuoJi6/ARTEX `v0.3.23` image `ruoji6/artex:v0.3.23`
- environment: QEMU 11.1.0 (v11.1.0-12130-ge470268ff4) TCG

## Cold start (container start, image pre-pulled)

| phase | ms |
|---|---|
| postgres → pg_isready | 31020 |
| artex → `/api/health` 200 | 37850 |
| auth init+login handshake | 580 |

## API latency (`GET /api/health`, guest loopback)

- n=20 min=60 p50=70.0 p95=70 max=80 ms

## Resources

- RSS total max: **169.84 MiB**, mean 169.64 MiB (artex=67.39MiB, artex-pg=102.9MiB)
- /var/lib/docker: 4901942371 bytes

| image | size |
|---|---|
| postgres:16-alpine | 420MB |
| ruoji6/artex:v0.3.23 | 2.47GB |

## Task

- POST /api/tasks → 201 in 380 ms, id=1
- final status: **running** after 247540 ms
- LLM calls observed by the mock: 4
- the task never reached a terminal state: the deterministic mock cannot emit a valid
  planner plan, so this row is a *submit/agent-loop* number, not a completed scan.

## Side by side with Trident

| metric | ARTEX (VM) | Trident (host, lab/bench) |
|---|---|---|
| idle RSS | 169.84 MiB (2 containers) | 49.0 MiB (1 process) |
| task submit → terminal state | 247540 ms (status=running; mock LLM, no target traffic) | 320 ms over 5 chain rounds (real HTTP to the same mock target) |

## Limitations

- QEMU TCG software emulation: absolute numbers are not comparable to bare metal; only the ARTEX-vs-Trident ratio on the same host is meaningful.
- The LLM is a deterministic OpenAI-compatible mock on the host: the real HTTP/agent protocol is exercised (4 chat-completions calls, 3 advertised tool sets) but model quality and token cost are not measured.
- The mock cannot produce a valid planner plan, so the task stayed in state 'running' for the 240 s observation window and no HTTP request reached the mock target: the same-target scan is NOT claimed, only the task-submission/agent-loop numbers.
- Idle RSS comes from docker stats --no-stream (2 s cadence, 10 samples) 60-90 s after start, not from an instantaneous peak.
- k3s (single-node control plane) runs in the same guest during the whole bench and consumes CPU/RAM.
- Image pull time is excluded from cold start (images pre-pulled); docker pull was measured separately (see docs).
