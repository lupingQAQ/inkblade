# InkBlade Progress

Updated: 2026-10-27 (agent runtime, coverage closure, file audit, defense bypass)

## Snapshot

- Code HEAD: `687824e` (file and operation audit timeline); docs/matrix snapshot `80afe6c`,
  with this count/test refresh stacked on top
- Probe release: tag `probe-v0.1.1`, source commit `1f0f57c`; CI run 40430384961
  - `probe/dist/inkblade-probe-linux-amd64` — 2,066,112 B — `c8d2f118…b726f3`
  - `probe/dist/inkblade-probe-linux-arm64` — 1,775,584 B — `6d480367…a38e4`
  - two independent CI builds produced byte-identical files
- Modules: 287 `module.json`, 286 `template.json`, 1 `probe-bootstrap`; legacy `run.py` = 0 in the
  worktree and 0 at `HEAD`
- Rust runtime: 286/286 templates × vulnerable/fixed × 3 repeats, `runtime=rust`, 0 failures, 802s
  (`reports/probe-coverage/evidence.json`, `evidence-native.json`)
- Negative control (do not overstate): 35/286 fixed-state runs return `status=ok` (strict
  `verified`), 49/286 report no identical finding, 237/286 report the same finding in both states
  and are execution-verified only; 251/286 are not strictly two-state verified
- Template equivalence: 48 equivalent / 238 reduced (reduced semantics still open)
- Requirements: done 94 / partial 28 / not-done 0 / blocked-resource 7 (129 total);
  `docs/REQUIREMENTS-MATRIX.md` §2.4, unfinished items by class in §3.5
- Tests: `Ran 1936 tests in 1288.533s — OK (skipped=13)`
- Gates: public-tree 0 hits · docs-links 0 problems · release verify 72/72 · compileall clean
- Repository private; GitHub Pages not enabled

## Capabilities landed on 2026-10-27

- **Agent event-sourced runtime** (`5244259`): EventLog hash chain + checkpoint/resume/replay,
  PlanGraph with evidence gating, frontier scheduler (lease/retry/DLQ/four budgets), role workers
  (recon/exploit/verify/report), probe-only execution; `docs/AGENT-AUTONOMY.md`;
  68 tests in `tests/test_agent_*.py`; end-to-end only on the mock `runtime=reference` range.
- **Cross-cluster relay + coverage closure** (`3c84696`): multi-kubeconfig registration, dial/SOCKS5
  reach, kubectl/sa-token/exec deployment, parent-chain loop prevention, per-cluster RoE and budget,
  transport fallback (`inkblade/agent/relay.py`); four closure criteria + objective gate, proof at
  `reports/samples/coverage-closure/coverage-proof.json` (4 assets / 3 edges / 2 probes / 0 gaps);
  20 tests (`tests/test_agent_relay.py`, `tests/test_agent_coverage.py`); `docs/AGENT-COVERAGE.md`,
  `docs/COVERAGE-CLOSURE.md`; relay exercised on fake kubectl/API/SOCKS5 only.
- **Defense-aware bypass execution path** (`ee42f1d`): `security_posture` in `collect`,
  `defense:<product>` facts, product→technique selection in `core/defense_policy.py`, scheduler
  refuses offensive intents without `bypass.technique_id`; real QEMU k3s Kyverno 1.19.2 + Falco
  0.45.1: 6 techniques → 5 bypass-confirmed, 1 detected, 0 failed; imagescan/veinmind/WAF/netobserv
  return `policy-refused`; 32 tests; `docs/DEFENSE-BYPASS-PATH.md`.
- **File and operation audit timeline** (`687824e`): probe `audit-exec`/`read-file`/`list-files`
  (`probe/src/auditops.rs`), `file_ops` in evidence DB, unified `timeline.json`, WebUI ops ledger
  with evidence-browser linkage, `/api/v1/{timeline,file-ops}`, report ledger section and
  auditd/Falco/OTel keys; 17 tests; `docs/FILE-AUDIT.md`.

## Active work streams

1. S5 template equivalence: 48 equivalent / 238 reduced; reduced semantics still open.
2. Resource-bound validation: real GPU/10k cluster, hardware TEE, six clouds, public Fulcio
   identity, distributed SaaS, real cross-cluster relay (TLS client certs, production SOCKS5).
3. Disclosure closeout: 30 packages generated, none sent.
4. Defense products: 4 replayed on QEMU k3s, 7 N/A with blocking facts; bypass conclusions are
   scoped to the deployed Kyverno/Falco rulesets.

## Reporting cadence

- Report on every agent completion and every milestone commit.
- Update this file at each checkpoint with HEAD, counts, and blockers.

## Known blockers

- 7 `blocked-resource` requirements (real GPU/fabric, hardware TEE, six clouds, real LLM runtime,
  Fulcio identity, distributed SaaS, bare-metal ARTEX) — see matrix §3.5.2.
- 28 `partial` requirements — see matrix §3.5.1; do not report them as done.
- Fixed-state negative control needs per-template mock inputs before the remaining 251 templates can
  be called fully two-state verified.

## Final regression (2026-10-27)
- Ran 1936 tests, OK (skipped=13) — `reports/samples/requirements/suite-summary.txt`
- Code HEAD `687824e`; docs/matrix commit `80afe6c`; 286 templates; probe v0.1.1; 5/6 bypass-confirmed
- Remaining: **28 partial**, 7 blocked-resource, 238 reduced templates, negative-control 35/286 —
  by class in `docs/REQUIREMENTS-MATRIX.md` §3.5 (129 requirements total, done 94)

## Full regression after reverse + mlproxy (2026-10-27)
- Ran 1998 tests, OK (skipped=13)
- HEAD 4472f38; encrypted reverse channel TLS/WSS/HTTPS; gRPC/Redis ML proxy; loopback SOCKS5
- Still pending: QUIC/WebTransport/MASQUE, ZMTP+CURVE, TCPStore/Gloo, NCCL/UCX profiles
