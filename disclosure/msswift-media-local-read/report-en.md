# ms-swift deploy media path allows arbitrary local file read

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | ms-swift |
| Affected version | v4.6.0 |
| Weakness | CWE-22, CWE-73 |
| CVSS 3.1 | 7.5 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Impact | A request containing a local path (image/audio/video) makes swift deploy read any file the service can access and return its content in the response. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `swift/infer_engine/protocol.py:275` in `MultiModalRequestMixin.to_base64`.
- HTTP chat/completion request -> MultiModalRequestMixin.to_base64 -> SafeMediaPath.check (env unset -> allow) -> open(mm_data,'rb') -> base64 in request.

## 3. Preconditions

- swift deploy reachable
- SWIFT_MEDIA_ALLOWED_DIRS unset (default)
- request carries a local media path

## 4. Reproduction

- Environment: v4.6.0.
- Observed behaviour: image/audio/video local path -> SafeMediaPath default allow-all -> open(path).read() -> base64 returned
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A request containing a local path (image/audio/video) makes swift deploy read any file the service can access and return its content in the response.

## 6. Fix

Default SWIFT_MEDIA_ALLOWED_DIRS to the dataset root (deny all when unset), canonicalize and check the resolved path.

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
# evidence bundle: msswift-media-local-read
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
3f7472e915c988a394577d9ecc680b448464951393e314fcfe4d8699719de81e  result.json
ad75ea2efb16a0b2120397c79bcb555555eb7fb8b2f15fd47458d515766c6173  log.txt
a07d6695f370dd1e3e6ebfded1dbe4629006c4c32aece8a8f90d3299dc4110b6  marker.txt
a07d6695f370dd1e3e6ebfded1dbe4629006c4c32aece8a8f90d3299dc4110b6  victim-secret.txt
2c12f679ecce663cc7bc71ab837793e748dca151179b3f05ab72e73e04cba5a8  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/modelscope/ms-swift/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
