# verl checkpoint engine deserializes unauthenticated pickle over the network

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | verl |
| Affected version | 76e837e |
| Weakness | CWE-502, CWE-306 |
| CVSS 3.1 | 9.8 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | Anyone who can reach the checkpoint channel sends a pickle stream and executes code in the training process. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `verl/checkpoint_engine:?` in `recv_pyobj`.
- TCP/ZMQ peer -> recv_pyobj -> pickle.loads -> RCE; no authentication on the checkpoint channel.

## 3. Preconditions

- checkpoint engine binds a reachable tcp://ip:port
- flat network

## 4. Reproduction

- Environment: 76e837e.
- Observed behaviour: connect to checkpoint channel -> send pickle -> RCE
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Anyone who can reach the checkpoint channel sends a pickle stream and executes code in the training process.

## 6. Fix

Authenticate the checkpoint channel (mTLS/shared secret) and replace recv_pyobj with a typed, non-executable codec.

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
# evidence bundle: verl-checkpoint-pickle
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
3935714777f9205ac0c9a83951079e79d3fa2549b61a3cbfa5b99e6bf8448694  LATEST-RESULT.md
da619fe9d5d1b96624f5a22157d649b9841c97644c3d760e5c5c7d3c6e06649c  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/verl-project/verl/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
