# Dify 1.17.1 shellctl sandbox daemon allows unauthenticated host command execution

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | Dify |
| Affected version | v1.17.1 |
| Weakness | CWE-306, CWE-78 |
| CVSS 3.1 | 9.8 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | POST /v1/jobs/run without a token executes arbitrary commands on the sandbox host and can read every tenant home under <home>/dify. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `dify-agent/docker/docker-compose.yaml:559` in `shellctl`.
- HTTP request -> shellctl 0.0.0.0:5004 (no token) -> job run/cwd -> host command execution and tenant home read.

## 3. Preconditions

- dify-agent-local-sandbox:1.17.1 running
- port 5004 reachable

## 4. Reproduction

- Environment: v1.17.1.
- Observed behaviour: POST /v1/jobs/run without token -> arbitrary command; cwd=<home>/dify/victim -> read secrets
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

POST /v1/jobs/run without a token executes arbitrary commands on the sandbox host and can read every tenant home under <home>/dify.

## 6. Fix

Require a per-job token/HMAC on shellctl, bind to the compose network only, and run jobs in a disposable sandbox with a read-only tenant home.

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
# evidence bundle: dify-shellctl-unauth-rce
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
39ebe7d824653350357129a9259e405401c634b54ecfa02cf0c33192a2a23fcd  RESULT.md
dc1182eda19bbfa87e6b8f4adba5fa9f28f53bd56c9a883b25678515d1875522  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/langgenius/dify/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
