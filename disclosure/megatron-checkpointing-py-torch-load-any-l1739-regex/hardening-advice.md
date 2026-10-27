# Hardening advice — megatron-checkpointing-py-torch-load-any-l1739-regex

**Decision: not CVE-eligible.** dependency-default-blocks: the sink calls torch.load() without weights_only, so torch >= 2.6 (weights_only=True by default) refuses the payload. Affected only with torch < 2.6, which is a dependency pin, not a Megatron code defect; no version-bounded Megatron fix exists.

## Affected

- Product: Megatron-LM
- Version: core_v0.19.2
- Root cause: `megatron/training/checkpointing.py:1739`

## Recommended hardening

Pass weights_only=True explicitly and document the minimum torch version.

## Why no CVE

dependency-default-blocks: the sink calls torch.load() without weights_only, so torch >= 2.6 (weights_only=True by default) refuses the payload. Affected only with torch < 2.6, which is a dependency pin, not a Megatron code defect; no version-bounded Megatron fix exists.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
