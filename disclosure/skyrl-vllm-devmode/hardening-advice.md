# Hardening advice — skyrl-vllm-devmode

**Decision: not CVE-eligible.** insecure-default-only: SkyRL sets VLLM_SERVER_DEV_MODE and 0.0.0.0 for its vLLM worker. The executable weakness is in vLLM's unauthenticated dev/RL routes, already covered by vllm-rl-dev-auth-bypass; a separate SkyRL CVE would duplicate it.

## Affected

- Product: SkyRL
- Version: a1e34db
- Root cause: `skyrl_train/workers/vllm_server_actor.py:216`

## Recommended hardening

Do not force 0.0.0.0/dev mode; bind loopback and require an API key.

## Why no CVE

insecure-default-only: SkyRL sets VLLM_SERVER_DEV_MODE and 0.0.0.0 for its vLLM worker. The executable weakness is in vLLM's unauthenticated dev/RL routes, already covered by vllm-rl-dev-auth-bypass; a separate SkyRL CVE would duplicate it.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
