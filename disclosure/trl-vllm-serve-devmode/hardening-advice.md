# Hardening advice — trl-vllm-serve-devmode

**Decision: not CVE-eligible.** insecure-default-only: trl vllm-serve enables vLLM dev endpoints and a public bind. The missing authentication is in vLLM and is covered by vllm-rl-dev-auth-bypass; treat as configuration hardening for trl.

## Affected

- Product: TRL
- Version: 1.15.0
- Root cause: `trl/scripts/vllm_serve.py:103`

## Recommended hardening

Do not set VLLM_SERVER_DEV_MODE by default; bind 127.0.0.1 and pass an api-key.

## Why no CVE

insecure-default-only: trl vllm-serve enables vLLM dev endpoints and a public bind. The missing authentication is in vLLM and is covered by vllm-rl-dev-auth-bypass; treat as configuration hardening for trl.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
