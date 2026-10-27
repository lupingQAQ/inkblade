# DeepSpeed checkpoint loaders deserialize untrusted state with weights_only=False

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | DeepSpeed |
| Affected version | v0.19.8 |
| Weakness | CWE-502 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | An actor able to write an AutoEP or ZeRO-3 checkpoint directory obtains pickle code execution in the training process on conversion/resume. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `deepspeed/checkpoint/autoep_universal.py:459` in `consolidate_autoep_expert_files`.
- checkpoint dir -> consolidate_autoep_expert_files -> resolve_expert_ckpt_path/torch.load(weights_only=False) -> pickle reduce -> RCE in conversion process.

## 3. Preconditions

- attacker can write an AutoEP checkpoint directory
- victim runs ds_to_universal conversion

## 4. Reproduction

- Environment: v0.19.8.
- Observed behaviour: malicious layer_<n>_expert_<e>_mp_rank_0_model_states.pt -> torch.load(weights_only=False) -> marker
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

An actor able to write an AutoEP or ZeRO-3 checkpoint directory obtains pickle code execution in the training process on conversion/resume.

## 6. Fix

Pass weights_only=True and load optimizer/dataloader state through a restricted unpickler; sign checkpoints and verify before load.

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
# evidence bundle: deepspeed-autoep-unsafe-load
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
ecb5d36cb0005f177b61c1a74e34880971028ea6206b9d369a97a8463db6eff0  result.json
d09b24c3984c0ce3fd8c8743f5593f9bcded134087d4263a141ab3ba6f647927  log.txt
261eeb62517a553a61c91ac9c57b53b360ff0a99aa1dafd7b191f6dcc541db69  marker.txt
204f4f3d91431faf896731ede30fd8e293ecd152f2ca394383501278e118dcb4  layer_0_expert_0_mp_rank_0_model_states.pt
5eb8553bbd0bd420ce7f87789e855ebed74810e42432b76a56becaa338003d21  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/deepspeedai/DeepSpeed/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
