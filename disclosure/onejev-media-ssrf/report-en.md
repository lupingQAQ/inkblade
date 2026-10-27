# OneJev media fetch is an unauthenticated SSRF primitive

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | OneJev |
| Affected version | 6122519 |
| Weakness | CWE-918 |
| CVSS 3.1 | 7.5 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Impact | A request carrying a media URL makes the OneJev service fetch arbitrary http(s) targets, exposing internal services and cloud metadata endpoints. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `qev/media.py:101` in `fetch`.
- HTTP request -> /v1/systemone media URL -> urlopen(url) -> internal network.

## 3. Preconditions

- OneJev endpoint reachable
- request can carry media URL

## 4. Reproduction

- Environment: 6122519.
- Observed behaviour: media URL -> urllib urlopen -> internal service; UA=qev marker
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A request carrying a media URL makes the OneJev service fetch arbitrary http(s) targets, exposing internal services and cloud metadata endpoints.

## 6. Fix

Allowlist schemes and hosts, block link-local/private ranges after DNS resolution, and disable redirects.

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
# evidence bundle: onejev-media-ssrf
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
ff389fd23d1f58b98af4e3cccd7422a053ab717975e84a20251fc2637eecb6aa  LATEST-RESULT.md
ce0a3bf94f566cf265f7c23930ffa84400145483d1913404968f087c9725d4d1  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/OmniJev/OneJev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
