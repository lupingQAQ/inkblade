# OpenJev-SiliconLabAI leaks server API keys to request-controlled URLs

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | OpenJev-SiliconLabAI |
| Affected version | a08e969 |
| Weakness | CWE-918, CWE-522 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | An unauthenticated caller points base_url/decider_url at an attacker server and receives the service's upstream provider API key and evaluation payloads. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `server/index.ts:40` in `evaluate`.
- HTTP request -> server/index.ts base_url/decider_url -> src/lib/evaluate.ts outbound call with server key -> credential exfiltration.

## 3. Preconditions

- OpenJev-SiliconLabAI service reachable
- server env has provider key

## 4. Reproduction

- Environment: a08e969.
- Observed behaviour: base_url/decider_url -> attacker server -> server sends API key / evaluation payload
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An unauthenticated caller points base_url/decider_url at an attacker server and receives the service's upstream provider API key and evaluation payloads.

## 6. Fix

Do not accept outbound URLs from request data; if required, allowlist and never attach server-side keys to caller-supplied destinations.

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
# evidence bundle: siliconlab-credential-exfil
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
b87b2e206577bab626fdc00407d208069b011bf829f1be91be0df55c246708dd  LATEST-RESULT.md
99e700b69dc279c91532a2f9a7f650af1b7f1fd510bf78bcf3bd53244eda99a0  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/SiliconLabAI/OpenJev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
