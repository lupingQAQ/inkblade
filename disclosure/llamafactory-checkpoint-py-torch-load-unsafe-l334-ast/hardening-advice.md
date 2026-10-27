# Hardening advice — llamafactory-checkpoint-py-torch-load-unsafe-l334-ast

**Decision: not CVE-eligible.** dedupe-existing-cve: LLaMA-Factory checkpoint torch.load RCE is already covered by public CVE-2026-1839 (same product, same checkpoint trust boundary). A second CVE for a sibling function would duplicate the vendor fix; report as an extension to the existing advisory.

## Affected

- Product: LLaMA-Factory
- Version: v0.9.5
- Root cause: `src/llamafactory/v1/core/utils/checkpoint.py:334`

## Recommended hardening

Apply the same weights_only=True fix to TrainingCheckpointCoordinator.resume.

## Why no CVE

dedupe-existing-cve: LLaMA-Factory checkpoint torch.load RCE is already covered by public CVE-2026-1839 (same product, same checkpoint trust boundary). A second CVE for a sibling function would duplicate the vendor fix; report as an extension to the existing advisory.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
