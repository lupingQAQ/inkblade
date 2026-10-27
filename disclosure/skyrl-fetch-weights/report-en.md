# SkyRL /fetch_weights path traversal enables weight poisoning

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | SkyRL |
| Affected version | a1e34db |
| Weakness | CWE-22, CWE-306 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | A caller writes files outside cache_dir via ../ payload names and controls the weights loaded by the next training step. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `skyrl/weight_sync/delta/checkpoint.py:257` in `fetch_weights`.
- HTTP request -> /fetch_weights -> cache_dir / payload_file join (no normalization) -> arbitrary write.

## 3. Preconditions

- /fetch_weights reachable
- shared cache dir writable

## 4. Reproduction

- Environment: a1e34db.
- Observed behaviour: payload_files=../../... -> write outside cache_dir -> control next loaded weights
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A caller writes files outside cache_dir via ../ payload names and controls the weights loaded by the next training step.

## 6. Fix

Authenticate /fetch_weights, reject absolute/.. path components, and resolve under the cache root.

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
# evidence bundle: skyrl-fetch-weights
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
4f6e84a590df38eb82687b3b1b3495b20453d4c563de5ba305344ecd859e12ea  RESULT.md
484b7cb40d1d726bfe97a23e7f9c57a60edaac0121f58b4d3ec68197c29148d3  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/NovaSky-AI/SkyRL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
