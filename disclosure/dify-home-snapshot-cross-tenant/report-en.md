# Dify local runtime snapshots allow cross-tenant home theft

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | Dify local runtime |
| Affected version | v1.17.1 |
| Weakness | CWE-668, CWE-22 |
| CVSS 3.1 | 7.7 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| Impact | A tenant can snapshot another tenant's home and materialize it into its own binding, reading VICTIM-SECRET and other cross-tenant data. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `dify-agent/src/dify_agent/runtime_backend/local.py:240` in `snapshot`.
- HTTP request -> home_snapshots -> local.py control-lease root -> cp -a victim home -> attacker-readable snapshot.

## 3. Preconditions

- runtime_backend=local (default)
- victim binding ref known

## 4. Reproduction

- Environment: v1.17.1.
- Observed behaviour: snapshot victim home -> materialize into attacker binding -> read VICTIM-SECRET
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A tenant can snapshot another tenant's home and materialize it into its own binding, reading VICTIM-SECRET and other cross-tenant data.

## 6. Fix

Namespace snapshot/control-lease directories per tenant, authorize the binding reference, and verify ownership before materialization.

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
# evidence bundle: dify-home-snapshot-cross-tenant
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
39ebe7d824653350357129a9259e405401c634b54ecfa02cf0c33192a2a23fcd  RESULT.md
7fa8c4abebd6b84018c60ae4eb94e83ccd3c1ac65f101e3118db81c86866171e  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/langgenius/dify/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
