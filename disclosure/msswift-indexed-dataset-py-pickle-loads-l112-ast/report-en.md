# ms-swift IndexedDataset unpickles attacker-writable packing cache

> **Status: DRAFT — NOT SENT.** Prepared 2026-10-27T00:00:00+00:00 for coordinated disclosure. No email, advisory, or CVE request has been submitted.

## 1. Summary

| Field | Value |
|---|---|
| Product | ms-swift |
| Affected version | v4.6.0 |
| Weakness | CWE-502 |
| CVSS 3.1 | 8.8 (HIGH) `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Impact | Writing data.idx or a data-*.bin shard in the packing cache yields code execution the next time a training job opens the IndexedDataset. |
| CVE | placeholder `CVE-0000-xxxx` only; not requested |

## 2. Root cause

- `swift/dataset/indexed_dataset.py:112` in `IndexedDataset.__init__`.
- ms-swift packing cache loader IndexedDataset.__init__ opens data.idx with pickle.load(f). The cache dir (PACKING_CACHE or the swift cache) is attacker-writable in the shared-storage threat model; whoever plants data.idx gets pickle code execution the next time a training run opens the packed dataset. Reproduced at function level against the verbatim pinned v4.6.0 upstream file (package tree stubbed; os/pickle/real BinReader are the upstream code).

## 3. Preconditions

- attacker can write the swift packing cache dir (PACKING_CACHE or dataset cache)
- a training job opens the packed IndexedDataset

## 4. Reproduction

- Environment: v4.6.0.
- Observed behaviour: ms-swift packing cache loader IndexedDataset.__init__ opens data.idx with pickle.load(f). The cache dir (PACKING_CACHE or the swift cache) is attacker-writable in the shared-storage threat model; whoever plants data.idx gets pickle code execution the next time a training run opens the packed dataset
- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped with this report.

## 5. Impact

Writing data.idx or a data-*.bin shard in the packing cache yields code execution the next time a training job opens the IndexedDataset.

## 6. Fix

Replace pickle with a restricted format (safetensors/npz/json) and verify a manifest digest before load.

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
# evidence bundle: msswift-indexed-dataset-py-pickle-loads-l112-ast
# generated: 2026-10-27T00:00:00+00:00
# logical names only; no host paths are stored in the disclosure tree
61493067b6c207fe9ad1d3bc96c2a24167289567f795cb2d7bd212db7e9af468  result.json
15be8a496fb179086d85425bd10c15eaac1fa9c44374d3353b9a3c9e6f00227b  log.txt
5339fb1eeea713c369c347f162eff7cfc07ef126cd151ab11737cbf0814d8090  marker.txt
cd1f1c5af22fd9ccc869640d75ebbac2916380e674a89ac43d65935b07a7da3e  data.idx
441eccea2a3b2c51b310ee079fde550c20fbcf21ab2d2f0a506807a3bad4bab6  run.json
72055204ed754fd07ff0c69dba222b3e085302515777c9f3903f2e2f01e535b6  inventory-entry.json
```

## 9. Credits and contact

- Reported by: InkBlade security research (coordinated disclosure).
- Preferred channel: https://github.com/modelscope/ms-swift/security/advisories/new (private advisory draft).
- CNVD/CNNVD: secondary channels after the vendor has been notified.

## 10. Legal and authorization

Testing was performed in a local, authorized lab against upstream open-source code. This document is a draft for human review and legal check before any transmission.
