# djev relays /v1/* without authentication and leaves GET management routes open

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | djev |
| Affected version | e5841cf |
| Weakness | CWE-306, CWE-863 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | An unauthenticated client can relay /v1/* requests to the upstream vLLM service and read management routes; with API_KEY set, GET management routes remain unauthenticated. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `djev/structured_server.py:1990` in `do_POST`.
- HTTP request -> structured_server.do_POST/do_GET -> httpx relay -> upstream vLLM /v1 management surface; key check is optional and absent on GET.

## 3. Preconditions

- djev exposed on 0.0.0.0:8011
- API_KEY unset or attacker uses GET

## 4. Reproduction

- Environment: e5841cf.
- Observed behaviour: unauthenticated POST /v1/* relayed to upstream vLLM; GET management routes remain unauthenticated with key set
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An unauthenticated client can relay /v1/* requests to the upstream vLLM service and read management routes; with API_KEY set, GET management routes remain unauthenticated.

## 6. Fix

Require authentication on every HTTP method (not only POST), reject /v1/* when API_KEY is unset, and bind to loopback by default.

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
# evidence bundle: djev-open-proxy
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
c3204ec59680894f03913953345443ba33f5b0994fac11e34ae3c09da3972bf3  LATEST-RESULT.md
8ca2ead310001db33385de86976f485169a42ed7e2bb4d2f14e82e86a443ae8b  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/mmastrac/djev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
