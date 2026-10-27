# InkBlade Progress

Updated: 2026-10-27 (final probe rebuild and acceptance)

## Snapshot

- Probe release: tag `probe-v0.1.1`, source commit `1f0f57c`; CI run 40430384961
  - `probe/dist/inkblade-probe-linux-amd64` — 2,066,112 B — `c8d2f118…b726f3`
  - `probe/dist/inkblade-probe-linux-arm64` — 1,775,584 B — `6d480367…a38e4`
  - two independent CI builds produced byte-identical files
- Modules: 287 `module.json`, 286 `template.json`, 1 `probe-bootstrap`; legacy `run.py` = 0 in the
  worktree and 0 at `HEAD`
- Rust runtime: 286/286 templates × vulnerable/fixed × 3 repeats, `runtime=rust`, 0 failures, 802s
  (`reports/probe-coverage/evidence.json`, `evidence-native.json`)
- Fixed-state negative control: 35/286 return `status=ok`; 49/286 report no identical finding;
  the remaining 237 share fixture inputs across states and are execution-verified only
  (`docs/PROBE-COVERAGE.md` §6)
- Requirements: done 91 / partial 26 / not-done 0 / blocked-resource 7 (124 total)
- Tests: `Ran 1841 tests in 1073.350s — OK (skipped=13)`
- Gates: public-tree 0 hits · docs-links 0 problems · release verify 72/72 · compileall clean
- Repository private; GitHub Pages not enabled

## Active work streams

1. S5 template equivalence: 48 equivalent / 238 reduced; reduced semantics still open.
2. Resource-bound validation: real GPU/10k cluster, hardware TEE, six clouds, public Fulcio
   identity, distributed SaaS.
3. Disclosure closeout: 30 packages generated, none sent.
4. Defense products: 4 replayed on QEMU k3s, 7 N/A with blocking facts.

## Reporting cadence

- Report on every agent completion and every milestone commit.
- Update this file at each checkpoint with HEAD, counts, and blockers.

## Known blockers

- Real GPU / 10k-node / hardware / cloud-account validation is resource-bound.
- Fixed-state negative control needs per-template mock inputs before the remaining 251 templates can
  be called fully two-state verified.
