# ms-swift Serializer.from_tensor unpickles tensor-controlled bytes

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | ms-swift |
| Affected version | v4.6.0 |
| Weakness | CWE-502 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | A peer able to inject tensor bytes into the rank/node serialization path obtains code execution when the victim calls Serializer.from_tensor. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `swift/utils/torch_utils.py:340` in `Serializer.from_tensor`.
- swift.utils.torch_utils.Serializer.from_tensor unpickles a byte prefix of a torch tensor (int64 length header + pickle stream). This helper is used to pass objects between ranks/nodes in the megatron trainer path, so a peer who can inject the tensor bytes gets pickle code execution. Reproduced at function level against the verbatim pinned v4.6.0 upstream module with the real installed torch/numpy.

## 3. Preconditions

- attacker can inject the tensor bytes carried through the rank/node serialization path
- victim deserialises with Serializer.from_tensor

## 4. Reproduction

- Environment: v4.6.0.
- Observed behaviour: swift.utils.torch_utils.Serializer.from_tensor unpickles a byte prefix of a torch tensor (int64 length header + pickle stream). This helper is used to pass objects between ranks/nodes in the megatron trainer path, so a peer who can inject the tensor bytes gets pickle code execution. Reproduced at fu
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

A peer able to inject tensor bytes into the rank/node serialization path obtains code execution when the victim calls Serializer.from_tensor.

## 6. Fix

Use a safe tensor container and validate length/type headers before unpickling; reject pickle payloads.

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
# evidence bundle: msswift-torch-utils-py-pickle-loads-l340-ast
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
6b4a40dfb10ff124de98506dfa68f44ba580c528d3aae2fb87e4e48f4ab532a0  result.json
106cc6e88deafbf034135b6e49135db4c35d8f095419cd773b0e13a58d4d2173  log.txt
e460c5be5a75e46cc4664db1bf0b1ff7f909e458cf4053fface0c209fdf00ee9  marker.txt
769333d49f38b16e35729c4c45d47ca35996aabd23b0dcc9e6aade775bef38bf  run.json
f19a015d357be40753b28b962e020f410c78f02fd47b9ab191538c53f91f73e1  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/modelscope/ms-swift/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
