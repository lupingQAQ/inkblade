# AReaL data-service worker unpickles unauthenticated request bodies

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | AReaL |
| Affected version | 448de52 |
| Weakness | CWE-502, CWE-306 |
| CVSS 3.1 | 9.8 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | A single POST to the data-service worker executes arbitrary pickle payloads on the worker host. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `areal/infra/data_service/worker/app.py:268` in `run`.
- HTTP request -> /run -> pickle.load(request body) -> object reconstruction -> RCE.

## 3. Preconditions

- data-service worker exposed
- port reachable
- attacker can POST job

## 4. Reproduction

- Environment: 448de52.
- Observed behaviour: pickle.load on request body -> marker RCE
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A single POST to the data-service worker executes arbitrary pickle payloads on the worker host.

## 6. Fix

Authenticate /run, replace pickle with a typed schema, and never deserialize request bodies.

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
# evidence bundle: areal-dataservice-pickle
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
a3aeaf6d2738f8fb052123bca59e9f6bc516ed8ae5a01c8d8a935e50299a7a67  LATEST-RESULT.md
2085fc5bfb6b7b124d777dcc1681ffdf235bbc4c6ce4d6f414a1baf7e7cd7520  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/areal-project/AReaL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
