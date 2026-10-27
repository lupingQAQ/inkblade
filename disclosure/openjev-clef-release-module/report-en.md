# OpenJev Clef release_module executes model-supplied Python

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | openjev |
| Affected version | b4339c6 |
| Weakness | CWE-94, CWE-829 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| Impact | A user able to write the shared model cache/PVC can place joint_schema_model.py and obtain code execution in every process that loads the model. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `openjev/clef_vllm.py:40` in `release_module`.
- model load -> release_module -> importlib exec_module on model-provided joint_schema_model.py -> RCE.

## 3. Preconditions

- attacker can write shared model cache/PVC
- victim loads model

## 4. Reproduction

- Environment: b4339c6.
- Observed behaviour: joint_schema_model.py in model dir -> exec_module -> Python execution
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A user able to write the shared model cache/PVC can place joint_schema_model.py and obtain code execution in every process that loads the model.

## 6. Fix

Load model code only from a signed/pinned artifact, verify a digest before exec_module, and disable model-provided modules by default.

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
# evidence bundle: openjev-clef-release-module
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
5fccfdc65c511e15303add7e9dd27e0fb7c691aa74af9646474b4d75c42c794c  LATEST-RESULT.md
7b3e630eba1a7ec5fc6a5e96d5487e90a97c492a08468963baf11a723100d61f  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/razorback16/openjev/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
