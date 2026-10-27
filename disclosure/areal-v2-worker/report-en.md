# AReaL v2 worker loads untrusted checkpoints without authentication

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | AReaL |
| Affected version | 448de52 |
| Weakness | CWE-502, CWE-306 |
| CVSS 3.1 | 9.8 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | A malicious checkpoint sent to the v2 worker executes pickle code on load; /save and /awex extend the same unauthenticated control surface. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `areal/v2/engine/fsdp_engine.py:1965` in `load`.
- HTTP request -> /load -> torch.load(weights_only=False) -> pickle reduce -> RCE.

## 3. Preconditions

- v2 worker reachable
- attacker can supply .pt

## 4. Reproduction

- Environment: 448de52.
- Observed behaviour: malicious .pt -> torch.load(weights_only=False) -> marker RCE
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A malicious checkpoint sent to the v2 worker executes pickle code on load; /save and /awex extend the same unauthenticated control surface.

## 6. Fix

Authenticate worker endpoints and load with weights_only=True plus a signed checkpoint manifest.

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
# evidence bundle: areal-v2-worker
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
5e850d0a8ff81fb606d8023ccfdaa9d36d36b5e6ddb7afa43688f46acbeb7549  LATEST-RESULT.md
d8882b250ff5163cb9d3b00c14acd42760fc404f05f267114582dc1e6f31e3f6  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/areal-project/AReaL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
