# Dify agent-stub ships a hard-coded JWE root key

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | Dify agent-stub |
| Affected version | v1.17.1 |
| Weakness | CWE-798, CWE-321 |
| CVSS 3.1 | 9.1 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Impact | An attacker derives the JWE key offline and forges tokens accepted by /agent-stub/*, reading files and configuration from the control plane. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `dify/docker/docker-compose.yaml:689` in `AGENT_STUB_SECRET`.
- offline JWE mint (public default key) -> HTTP /agent-stub/* -> files/config control plane.

## 3. Preconditions

- stub control plane reachable
- default secret unchanged

## 4. Reproduction

- Environment: v1.17.1.
- Observed behaviour: derive JWE offline -> access /agent-stub/* files/config -> 200
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An attacker derives the JWE key offline and forges tokens accepted by /agent-stub/*, reading files and configuration from the control plane.

## 6. Fix

Generate a random AGENT_STUB_SECRET at install time, refuse to start with the documented default, and rotate the key.

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
# evidence bundle: dify-stub-jwe-default-key
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
39ebe7d824653350357129a9259e405401c634b54ecfa02cf0c33192a2a23fcd  RESULT.md
c4a34bc6af4bb088ee7a6cf9a2e0cddc5d6218e4f073e36805287f49af0f9a81  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/langgenius/dify/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
