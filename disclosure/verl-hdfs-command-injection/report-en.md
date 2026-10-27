# verl HDFS checkpoint copy is vulnerable to shell command injection

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | verl |
| Affected version | 76e837e |
| Weakness | CWE-78 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | A checkpoint path containing shell metacharacters executes arbitrary commands on the training host when the HDFS copy runs. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `verl/utils/checkpoint/checkpoint_handler.py:136` in `copy`.
- checkpoint path -> fs.py os.system('hdfs dfs ... ' + path) -> shell metacharacters -> command execution.

## 3. Preconditions

- HDFS checkpoint path attacker-influenced
- training job runs

## 4. Reproduction

- Environment: 76e837e.
- Observed behaviour: path with ;/$(...) -> os.system -> marker command execution
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A checkpoint path containing shell metacharacters executes arbitrary commands on the training host when the HDFS copy runs.

## 6. Fix

Use subprocess with an argv list, validate the HDFS path, and drop os.system.

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
# evidence bundle: verl-hdfs-command-injection
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
d0965d86c544e222fed5a0fcf45309efca8b54fcbc6ca30064eb79b254d66b31  RESULT.md
b0bbf53cdc7c9d5488c36e2731afefb16bffea8432c47129c4546db7a29e8c44  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/verl-project/verl/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
