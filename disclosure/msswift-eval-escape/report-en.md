# ms-swift device_groups eval() can be escaped through builtins

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | ms-swift |
| Affected version | 4.5.3 / fbc61cf |
| Weakness | CWE-95 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | An authenticated WebUI user can pass a crafted device_groups/ranks expression that escapes the restricted globals and executes arbitrary Python on the training host. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `swift/ray_utils/resource_manager.py:48` in `parse_ranks`.
- HTTP WebUI -> more_params -> --device_groups -> eval(ranks) -> builtins escape -> execution.

## 3. Preconditions

- WebUI reachable
- attacker controls more_params/device_groups

## 4. Reproduction

- Environment: 4.5.3 / fbc61cf.
- Observed behaviour: ranks expression escapes {'__builtins__':{'list','range'}} -> marker code execution
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An authenticated WebUI user can pass a crafted device_groups/ranks expression that escapes the restricted globals and executes arbitrary Python on the training host.

## 6. Fix

Replace eval() with an AST-validated integer/range parser; never pass user input to eval.

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
# evidence bundle: msswift-eval-escape
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
d9ac199e9c85be7bb679a5cbe8303a8fb329d20b3cdcb04449032aa10aecefb8  LATEST-RESULT.md
d50b70ff6d526f858b5a016761c7ffb519c2eb894200d942b980553ff81f57f8  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/modelscope/ms-swift/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
