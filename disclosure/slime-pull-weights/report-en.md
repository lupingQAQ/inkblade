# slime /pull_weights allows unauthenticated cross-tenant weight access

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | slime |
| Affected version | slime 05e3b01 / SGLang v0.5.15.post1 |
| Weakness | CWE-306, CWE-73 |
| CVSS 3.1 | 8.2 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| Impact | With the slime patch stack deployed, an unauthenticated caller can read or overwrite checkpoint weights outside its tenant directory on the shared PVC/NFS. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `docker/patch/latest/sglang-pull_weights.patch:17` in `pull_weights`.
- HTTP request -> patched SGLang route /pull_weights -> io_struct PullWeightsReqInput -> weight_sync local_checkpoint path join -> shared volume write.

## 3. Preconditions

- slime patch stack deployed
- shared PVC/NFS writable by attacker
- port reachable

## 4. Reproduction

- Environment: slime 05e3b01 / SGLang v0.5.15.post1.
- Observed behaviour: unauthenticated /pull_weights with source_dir/local_checkpoint_dir -> cross-tenant weight write/read
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

With the slime patch stack deployed, an unauthenticated caller can read or overwrite checkpoint weights outside its tenant directory on the shared PVC/NFS.

## 6. Fix

Require admin auth on /pull_weights and resolve both directories under a per-tenant allowlisted root.

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
# evidence bundle: slime-pull-weights
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
856aaab59c500fd78f73511b0ebb9b6ba82cf4225c6a7fdf20c7f44a885e3d2c  LATEST-RESULT.md
5dc31a19f7bef7b226b34b5e8d305d2997c2a7481f4222ddf452d6bf8c2fd5b3  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/THUDM/slime/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
