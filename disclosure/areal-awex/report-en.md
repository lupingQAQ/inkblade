# AReaL /awex allows arbitrary writes and NCCL group joins without authentication

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | AReaL |
| Affected version | 448de52 |
| Weakness | CWE-306, CWE-73 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | An attacker can write arbitrary files through torch.save and join the training NCCL group with a chosen master_addr/port, injecting or exfiltrating weights and gradients. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `areal/sglang/awex:?` in `awex`.
- HTTP request -> /awex -> torch.save(path) + NCCL group join(master_addr/port) -> weight/gradient injection.

## 3. Preconditions

- AReaL SGLang /awex endpoint reachable
- flat network

## 4. Reproduction

- Environment: 448de52.
- Observed behaviour: arbitrary path torch.save + NCCL join with attacker master_addr/port -> weight/gradient injection
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An attacker can write arbitrary files through torch.save and join the training NCCL group with a chosen master_addr/port, injecting or exfiltrating weights and gradients.

## 6. Fix

Authenticate /awex, restrict save paths to a server-side root, and require a shared NCCL secret/allowlist.

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
# evidence bundle: areal-awex
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
d0bddfc3756e03513e634c1b39e6e920e91096809c8626004eaace81b3d88d76  LATEST-RESULT.md
36dc3a608194ee835ac51f04445e33ebe86c5512cb32627444efc1149e8b33c9  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/areal-project/AReaL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
