# vLLM 0.32.0 RL control router bypasses --api-key

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | vLLM |
| Affected version | v0.32.0 |
| Weakness | CWE-306 |
| CVSS 3.1 | 9.1 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Impact | With VLLM_SERVER_DEV_MODE=1 (used by SkyRL/TRL recipes), unauthenticated callers pause/resume the engine, abort requests, and trigger weight updates while /v1/* still returns 401. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `vllm/entrypoints/rl/online/api_router.py:31` in `pause_generation`.
- HTTP request -> real vLLM AuthenticationMiddleware (GUARDED_PREFIX excludes /) -> real RL router /pause or /weight_checker -> engine control; --api-key only guards /v1,/v2,/inference,/cohere.

## 3. Preconditions

- VLLM_SERVER_DEV_MODE=1 (SkyRL/TRL recipes)
- vLLM --api-key configured
- port reachable

## 4. Reproduction

- Environment: v0.32.0.
- Observed behaviour: POST /pause, /resume, /abort_requests, /update_weights, /weight_checker without Authorization -> 200; /v1/* -> 401
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

With VLLM_SERVER_DEV_MODE=1 (used by SkyRL/TRL recipes), unauthenticated callers pause/resume the engine, abort requests, and trigger weight updates while /v1/* still returns 401.

## 6. Fix

Include the RL router in GUARDED_PREFIX (or mount it under /v1) and require the API key for every control endpoint.

## 7. Disclosure timeline (planned)

| Milestone | Date (UTC) | Action |
|---|---|---|
| T0 | 2026-10-28 | Private vendor notification with this report and evidence hashes. |
| T0+7 | 2026-11-04 | Re-send through a second private channel if unacknowledged. |
| T0+30 | 2026-11-27 | Ask for fix plan and CVE assignment; refine affected versions. |
| T0+60 | 2026-12-27 | Second reminder; agree advisory publication date if fixed. |
| T0+90 | 2027-01-26 | Default coordinated publication with fix version and credit. |

## 8. Evidence bundle

```text
# evidence bundle: vllm-rl-dev-auth-bypass
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
ae2ef9f01b168902d540e7ea97350afc28ca023d9e663d4a7f47b6394ebd8a8c  result.json
778c2a3f88b8ef6a87df5c947e70c00bf6f2252ee935bb35a347aa437193e6fc  marker.txt
208e115cce2432c9d56af986ea11437bf9dd151ea030562098c6a15a8cfef428  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/vllm-project/vllm/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
