# slime debug/resume data loaders deserialize untrusted pickle

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | slime |
| Affected version | 05e3b01 |
| Weakness | CWE-502 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | A user who can write the shared NFS/JuiceFS path executes pickle code when a victim loads debug or resume data. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `slime/backends/sglang_utils/load_debug_rollout_data.py:?` in `load_debug_rollout_data`.
- shared checkpoint file -> torch.load(weights_only=False) -> pickle execution in training process.

## 3. Preconditions

- shared NFS/JuiceFS writable by attacker
- victim loads debug/resume data

## 4. Reproduction

- Environment: 05e3b01.
- Observed behaviour: malicious .pt -> torch.load(weights_only=False) -> RCE
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A user who can write the shared NFS/JuiceFS path executes pickle code when a victim loads debug or resume data.

## 6. Fix

Use weights_only=True and a restricted unpickler; verify checkpoint digests before load.

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
# evidence bundle: slime-torch-load
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
27a2a5a18c1f51541f2d5e9f96acb17e35cb4bbee6d4eaf276d26397ece1f304  RESULT.md
7db345f30898f998690f9fcd7681becef6fcff9ce01bf07c39b3b5261bb82700  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/THUDM/slime/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
