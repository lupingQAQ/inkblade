# LLM2Jev image_url permits local file read and SSRF

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | LLM2Jev |
| Affected version | f2bdad6 |
| Weakness | CWE-22, CWE-918 |
| CVSS 3.1 | 7.5 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Impact | A request can read arbitrary files readable by the service (e.g. /etc/passwd, model credentials) and reach internal HTTP services. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `image_inputs.py:40` in `load_image`.
- HTTP request -> image_inputs -> core/multimodal -> file:// or local path open / http fetch -> data returned.

## 3. Preconditions

- LLM2Jev endpoint reachable
- request carries image_url

## 4. Reproduction

- Environment: f2bdad6.
- Observed behaviour: image_url=file:///etc/passwd / local path -> read and parse image; http(s) -> SSRF
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A request can read arbitrary files readable by the service (e.g. /etc/passwd, model credentials) and reach internal HTTP services.

## 6. Fix

Accept only https URLs from an allowlist or base64 payloads; reject file:// and local paths.

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
# evidence bundle: llm2jev-image-file
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
6c12695358b30e70888e91453e1c404b76362d12a583afe940b4a8f47e7cf45c  LATEST-RESULT.md
15e800b0b86df26631776998df14d4ebd3d68d82d66cb3bf1dcd48f0d78ab74f  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/Yinsongxu/LLM2Jev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
