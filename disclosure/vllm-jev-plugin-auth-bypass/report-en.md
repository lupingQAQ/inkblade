# vllm-jev plugin routes bypass the vLLM API-key middleware

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | vllm-jev |
| Affected version | v0.31.0 + vllm-jev 57226d4 |
| Weakness | CWE-306, CWE-863 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | An unauthenticated network client can invoke vllm-jev plugin routes (model choice, system-one control) on a vLLM deployment that is otherwise protected by --api-key. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `vllm_jev/endpoint.py:530` in `choice`.
- HTTP request -> vLLM AuthenticationMiddleware (GUARDED_PREFIX only /v1,/v2,/inference,/cohere) -> plugin route /plugins/vllm-jev/choice -> decision handler; no token check in endpoint.py.

## 3. Preconditions

- vLLM started with --api-key
- vllm-jev endpoint plugin registered
- service port reachable

## 4. Reproduction

- Environment: v0.31.0 + vllm-jev 57226d4.
- Observed behaviour: POST /plugins/vllm-jev/choice without Authorization -> 200; /v1/systemone -> 401
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An unauthenticated network client can invoke vllm-jev plugin routes (model choice, system-one control) on a vLLM deployment that is otherwise protected by --api-key.

## 6. Fix

Route /plugins/* through the same AuthenticationMiddleware as /v1,/v2,/inference,/cohere or require an explicit per-plugin token; add a deny-by-default test for every registered router.

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
# evidence bundle: vllm-jev-plugin-auth-bypass
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
852fa3c96e517d88cd18535922ffd954ff1aaf4a6979bfaf440778a12f0f73bc  LATEST-RESULT.md
be47e947a3d32253690255c10293f4d25ce4b4a09130013abe6728d822a2689a  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/mode-io/vllm-jev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
