# Open WebUI code-interpreter guard is bypassable with importlib

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | Open WebUI |
| Affected version | v0.12.3 / 91ea4e3 |
| Weakness | CWE-94, CWE-693 |
| CVSS 3.1 | 9.6 (CRITICAL) `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` |
| Impact | Indirect prompt injection in model output reaches <code_interpreter>, bypasses the sandbox guard, and executes commands on the Open WebUI host. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `backend/open_webui/utils/middleware.py:6111` in `execute_code_block`.
- chat/RAG injection -> model emits <code_interpreter> -> server Jupyter -> importlib bypass -> host execution.

## 3. Preconditions

- features.code_interpreter enabled
- indirect prompt injection reaches model output

## 4. Reproduction

- Environment: v0.12.3 / 91ea4e3.
- Observed behaviour: importlib.import_module('subprocess') bypasses __import__ patch -> BYPASS-OK uid=1000
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Indirect prompt injection in model output reaches <code_interpreter>, bypasses the sandbox guard, and executes commands on the Open WebUI host.

## 6. Fix

Run code in a separate container/VM with a read-only FS and no network; do not rely on an in-process __import__ patch.

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
# evidence bundle: openwebui-code-interpreter-bypass
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
1b04bbf4854e8e4afdc2c8fb26b036ce7a8a9a0cb3cb2bc6afd1b73ef11008fd  RESULT.md
88a14f9197198c16e5a9f2692df4d89a0862d18e3a6206c6e76143e8a9c7f5d4  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/open-webui/open-webui/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
