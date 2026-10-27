# ms-swift defaults trust_remote_code to True in WebUI/deploy paths

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | ms-swift |
| Affected version | 4.5.3 / fbc61cf |
| Weakness | CWE-829, CWE-94 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| Impact | A malicious or compromised model repository executes Python in the ms-swift service process when loaded through the WebUI or deploy path, leading to host compromise. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `swift/model/loader.py:?` in `ModelLoader`.
- HTTP WebUI/deploy -> model load -> default trust_remote_code=True -> transformers dynamic module import -> execution.

## 3. Preconditions

- ms-swift WebUI or swift deploy reachable
- attacker controls model id/path

## 4. Reproduction

- Environment: 4.5.3 / fbc61cf.
- Observed behaviour: malicious model auto_map executes in service process; PyPI 4.5.3 binds 0.0.0.0
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A malicious or compromised model repository executes Python in the ms-swift service process when loaded through the WebUI or deploy path, leading to host compromise.

## 6. Fix

Default trust_remote_code to False, require an explicit opt-in per model, and pin revisions.

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
# evidence bundle: msswift-trust-remote-code
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
2303aa8fe91cb49a97cef05582fa31a38e579ca7055547a4c0246f96e76cbc1d  LATEST-RESULT.md
04c3a92cd0f8db8e028ddd89a00a95187b8ff83f1b93790e7d07bb221c23ae09  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/modelscope/ms-swift/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
