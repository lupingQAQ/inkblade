# sglang-omni admin authentication fails open and profiler event_dir is attacker-controlled

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | sglang-omni |
| Affected version | HEAD 204ba29 |
| Weakness | CWE-306, CWE-73 |
| CVSS 3.1 | 9.1 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Impact | Unauthenticated callers can start profilers writing to an attacker-chosen directory and invoke weight/cache control endpoints (pause, update weights) on sglang-omni. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `sglang_omni/http/admin_auth.py:28` in `make_admin_auth_dependency`.
- HTTP request -> FastAPI admin dependency (None -> _no_auth) -> start_profile -> RequestEventRecorder.start(event_dir) -> mkdir/write JSONL under attacker-chosen directory.

## 3. Preconditions

- no SGLANG_OMNI_ADMIN_KEY
- admin/profiler port reachable

## 4. Reproduction

- Environment: HEAD 204ba29.
- Observed behaviour: POST /start_profile with event_dir=attacker path -> 200; /pause_generation and /update_weights_from_disk -> 200
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Unauthenticated callers can start profilers writing to an attacker-chosen directory and invoke weight/cache control endpoints (pause, update weights) on sglang-omni.

## 6. Fix

Make make_admin_auth_dependency fail closed when SGLANG_OMNI_ADMIN_KEY is absent, and constrain event_dir to a server-side allowlisted root.

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
# evidence bundle: sglang-omni-admin-failopen
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
ccdd70cba974362236353f8168e05bff359cb7c9051e9a0976318315e6af4cb2  LATEST-RESULT.md
11cfbb1ab1f05871e71f6b0059d83e78bacebbf721b5717432b1de0d5996d7a1  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/sgl-project/sglang-omni/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
