# OpenRLHF serve_rm exposes unauthenticated reward scoring on 0.0.0.0:5000

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | OpenRLHF |
| Affected version | 0.11.2 / dc2a7ad |
| Weakness | CWE-306 |
| CVSS 3.1 | 7.5 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| Impact | Any host that can reach port 5000 can score arbitrary prompt/response pairs, forging the reward signal used by RL training. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `openrlhf/cli/serve_rm.py:?` in `serve_rm`.
- HTTP request -> reward model Flask routes (no auth dependency, default 0.0.0.0:5000) -> scoring.

## 3. Preconditions

- serve_rm started
- port 5000 reachable

## 4. Reproduction

- Environment: 0.11.2 / dc2a7ad.
- Observed behaviour: unauthenticated reward scoring -> forged training signal
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Any host that can reach port 5000 can score arbitrary prompt/response pairs, forging the reward signal used by RL training.

## 6. Fix

Bind serve_rm to 127.0.0.1 by default and add a shared-secret or mTLS check before scoring.

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
# evidence bundle: openrlhf-serve-rm
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
8193a6080f90e0ff8362cae7e570e37c3a58a87924f422bdc3480751a2bf9980  RESULT.md
ff49d3fcea2a029522085a95bc228ac32be3cd7b760f55ed73f811e6b607e5c3  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/OpenRLHF/OpenRLHF/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
