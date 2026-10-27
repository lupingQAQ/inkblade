# Hardening advice — openrlhf-vllm-insecure

**Decision: not CVE-eligible.** insecure-default-only: OpenRLHF unconditionally sets VLLM_ALLOW_INSECURE_SERIALIZATION=1, but the deserialization surface and fix live in vLLM. Hardening recommendation, duplicate of the vLLM control-plane advisory.

## Affected

- Product: OpenRLHF
- Version: 0.11.2 / dc2a7ad
- Root cause: `openrlhf/trainer/ray/vllm_engine.py:95`

## Recommended hardening

Stop forcing insecure serialization; gate it behind an explicit opt-in.

## Why no CVE

insecure-default-only: OpenRLHF unconditionally sets VLLM_ALLOW_INSECURE_SERIALIZATION=1, but the deserialization surface and fix live in vLLM. Hardening recommendation, duplicate of the vLLM control-plane advisory.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
