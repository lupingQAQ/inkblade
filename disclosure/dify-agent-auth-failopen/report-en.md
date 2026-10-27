# dify-agent authentication fails open and ships a public development token

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | dify-agent |
| Affected version | v1.17.1 / bbfac7a |
| Weakness | CWE-306, CWE-863 |
| CVSS 3.1 | 9.1 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Impact | Any caller can create execution bindings and trigger host mkdir/rm operations; the public dev token shipped in compose makes the control plane reachable in default deployments. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `dify-agent/src/dify_agent/server/auth.py:17` in `require_token`.
- HTTP request -> auth.py token None -> allow -> execution_bindings -> host mkdir/rm -rf.

## 3. Preconditions

- dify-agent-backend reachable
- token unset/default

## 4. Reproduction

- Environment: v1.17.1 / bbfac7a.
- Observed behaviour: no Bearer -> 201 create binding; wrong Bearer -> 201; host mkdir/rm -rf
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Any caller can create execution bindings and trigger host mkdir/rm operations; the public dev token shipped in compose makes the control plane reachable in default deployments.

## 6. Fix

Fail closed when the token is unset; compare with hmac.compare_digest; remove the public dev token from compose and generate one per install.

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
# evidence bundle: dify-agent-auth-failopen
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
39ebe7d824653350357129a9259e405401c634b54ecfa02cf0c33192a2a23fcd  RESULT.md
b22a093859d0c46d3fe7ec4e3c77af4ac8709617d78733937052d0ce91bbaa30  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/langgenius/dify/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
