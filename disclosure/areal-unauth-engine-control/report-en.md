# AReaL proxy rollout control plane allows unauthenticated code execution

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | AReaL |
| Affected version | 448de52 |
| Weakness | CWE-306, CWE-94 |
| CVSS 3.1 | 9.8 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | POST /set_env, /create_engine, and /call allow an unauthenticated client to import and execute arbitrary Python on the rollout host. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `areal/experimental/proxy_rollout_server.py:445` in `set_env`.
- HTTP request -> /set_env (os.environ) -> /create_engine (importlib + getattr) -> /call -> arbitrary method execution.

## 3. Preconditions

- AReaL proxy rollout server exposed
- port reachable

## 4. Reproduction

- Environment: 448de52.
- Observed behaviour: POST /set_env + /create_engine + /call -> arbitrary module import/class/method -> marker RCE
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

POST /set_env, /create_engine, and /call allow an unauthenticated client to import and execute arbitrary Python on the rollout host.

## 6. Fix

Require authentication and replace the generic import/call dispatcher with an allowlisted command set.

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
# evidence bundle: areal-unauth-engine-control
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
1f97257bce3099e5d150d2814347915eeb7f15b66b12f8dd8fdd29a80c6cd1ff  RESULT.md
80b2cb2d4196ba9c8101a4e9e939e25c570ab9646b811da30caee5389ce7ff11  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/areal-project/AReaL/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
