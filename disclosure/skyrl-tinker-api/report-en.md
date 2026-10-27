# SkyRL Tinker API exposes unauthenticated model control on 0.0.0.0:8000

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | SkyRL |
| Affected version | a1e34db |
| Weakness | CWE-306 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | An unauthenticated client can create, sample from, and delete models, manipulating the training control plane and checkpoints. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `skyrl/tinker/api.py:?` in `api`.
- HTTP request -> FastAPI Tinker routes (no auth dependency, default 0.0.0.0:8000) -> training control operations.

## 3. Preconditions

- Tinker API started
- port 8000 reachable

## 4. Reproduction

- Environment: a1e34db.
- Observed behaviour: unauthenticated create/sample/delete model control plane -> checkpoint manipulation
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An unauthenticated client can create, sample from, and delete models, manipulating the training control plane and checkpoints.

## 6. Fix

Bind 127.0.0.1 by default and require an API token on all Tinker endpoints.

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
# evidence bundle: skyrl-tinker-api
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
eaa6273a2ffb8c7f279496e4aa62883932ef6b4abc8e929debdbd92fa82e90e8  LATEST-RESULT.md
9ae623f0a1918f9dd02c0f256888a0f0a6a7c73133ba2b2257b20e27bf099cce  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/NovaSky-AI/SkyRL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
