# Hardening advice — verl-prime-code-exec

**Decision: not CVE-eligible.** by-design: executing model-generated code is the documented function of the prime_code reward scorer. The security gap is the absence of a sandbox, which belongs in a hardening recommendation, not a CVE against intended behaviour.

## Affected

- Product: verl
- Version: 76e837e
- Root cause: `verl/utils/reward_score/prime_code/testing_util.py:616`

## Recommended hardening

Run prime_code evaluation in a network-isolated, resource-limited sandbox with a read-only FS.

## Why no CVE

by-design: executing model-generated code is the documented function of the prime_code reward scorer. The security gap is the absence of a sandbox, which belongs in a hardening recommendation, not a CVE against intended behaviour.

## Status

No disclosure package was generated and nothing will be sent. Keep this item in the reserve as a hardening recommendation only.
