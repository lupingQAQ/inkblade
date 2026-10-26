# Audit package

This document is what a security reviewer, an assessor, or a customer's AppSec
team needs in order to evaluate InkBlade without reverse-engineering it. It
states the threat model, the attack surface, the controls that exist, the
evidence that the controls work, and - deliberately - what is still missing.

Scope of this package: the code in this repository at the release commit, the
shipped container image and Helm chart, and the release pipeline. It does not
certify any particular deployment: a deployment inherits the operator's cluster
RBAC, network policy and identity provider.

---

## 1. What InkBlade is, in risk terms

InkBlade is an **authorized adversary emulation platform** for Kubernetes ML
clusters. It reads cluster state, probes ML serving endpoints, and (at higher
authorization levels) executes proof-of-concept actions. It produces evidence and
a report.

Three consequences follow, and they drive every control below:

1. **It is high-privilege by nature.** A kubeconfig with broad read access, plus
   the ability to reach model endpoints, is the point of the product.
2. **It changes state when authorized to.** 67 of 275 modules declare
   `writes: true`. Those are gated twice: by the RoE level and by a mandatory
   backup/rollback declaration.
3. **It stores sensitive output.** Evidence contains cluster topology, service
   configuration, and potentially model metadata or credentials captured from
   in-scope targets.

Therefore the primary security property is not "cannot be abused" (it can be,
with a cluster credential - that is the product) but **"cannot act outside a
signed scope, and cannot lie about what it did"**.

---

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Authorization record (RoE + consent) | proves the activity was permitted | `<home>/<workspace>/consent.json`, HMAC-bound |
| Evidence bundle | grounds every finding; underpins the report | `evidence.db`, `runs/<run>/steps/*/manifest.sha256` |
| Cluster credentials | blast radius if leaked | kubeconfig supplied by the operator; never copied into the report |
| Target responses | may contain secrets/PII | artifacts under the run directory |
| Reports and rules pack | delivered to the customer; may be shared more widely | `reports/` |
| Module registry | defines what the tool can do | `inkblade/modules/**/module.json` |
| Plugin code | third-party code executed in-process | `plugins/` (operator-chosen path) |
| Release artifacts | supply-chain integrity | wheel/sdist, image, SBOM, signatures |

---

## 3. Threat model

Actors: **operator** (authorized user), **reviewer/observer**, **plugin author**,
**customer**, **attacker with repo or CI access**, **attacker with network access
to the UI**.

| # | Threat | Vector | Control | Residual |
|---|---|---|---|---|
| T1 | Unauthorized assessment activity | operator runs without approval | RoE must be pinned and signed; CLI exits `91`, API returns `423`; level ceiling per module | a lead can sign a wrong scope - review process, not code |
| T2 | Scope escape | module targets an out-of-scope namespace/CIDR | scope fields pinned in RoE; `scope_violation` checks on target resolution; loopback default | regex/parse gaps in exotic target forms (see L2) |
| T3 | Irreversible change | write module runs without rollback | `writes: true` requires backup targets; backup gate refuses without them | rollback quality depends on the module author |
| T4 | Evidence tampering | operator edits a step after the fact | per-step `manifest.sha256`, hash-chained run context, DB + filesystem layers | a user with write access to the workspace can delete a whole run; detection, not prevention |
| T5 | Forged authorization | edit `consent.json` to widen scope | SHA-256 over canonical fields + HMAC keyed by the workspace key | key lives next to the evidence; protects integrity of the record, not against the workspace owner |
| T6 | Malicious plugin | third-party plugin exfiltrates or destroys | strict manifest, entrypoint containment, SHA-256 fingerprint, trust store pin, refusal by default | **in-process execution cannot be sandboxed** (L1) |
| T7 | Credential/data leak into report | raw tokens appear in output | redaction path for reports (`--redact`), evidence kept separate from deliverables | redaction is pattern-based; unknown secret formats can slip through |
| T8 | Network exposure of the UI | UI bound beyond loopback | default `127.0.0.1`; `--host` warns; chart defaults to ClusterIP + read-only RBAC; session auth required | a deliberately exposed UI behind no TLS/proxy is the operator's risk |
| T9 | Supply-chain compromise | tampered artifact or dependency | stdlib-only runtime, pinned CI actions, SHA-256 checksums, CycloneDX SBOM, cosign keyless (opt-in) | signing is best-effort and only present when OIDC is available |
| T10 | Privilege escalation via the container | container escape, root in container | uid/gid 10001, no capabilities, `readOnlyRootFilesystem`, no host mounts, dropped seccomp default is `RuntimeDefault` | kernel-level escape is out of scope (cluster's responsibility) |
| T11 | Denial of service against the tool | huge manifest, zip bomb, runaway module | manifest 256 KiB / entrypoint 16 MiB limits, per-step timeouts, workspace quota is operator-defined | a plugin can still exhaust memory (L1) |
| T12 | Repudiation | "the tool did it, not me" | per-action actor/role recorded in evidence; RoE binds a named client | actor strings are self-asserted by the CLI user |

### Trust boundaries

```text
[operator shell] --argv/params--> [CLI] --roE check--> [runner] --kubectl/HTTP--> [cluster / model endpoints]
                                     |                    |
                             [evidence store]      [plugin code]  <-- same process, no sandbox
                                     |
                              [report renderer] --> [deliverables]
```

Boundaries that matter: CLI -> runner (scope/level enforcement), runner ->
evidence (integrity), runner -> plugin (integrity only), evidence -> report
(redaction), CI -> artifacts (signing).

---

## 4. Attack surface inventory

| Surface | Entry point | Authn | Notes |
|---|---|---|---|
| CLI | `inkblade <cmd> [flags]` | OS user + RoE | 40+ subcommands; exit code `91` is a refusal |
| HTTP API | `/api/v1/...` | Bearer session (`/api/login`) | write routes additionally RoE-gated |
| Web UI | static assets + API | session | self-hosted assets, no external CDN |
| MCP server | `inkblade mcp` (stdio JSON-RPC) | parent process trust | tool calls map to read-only operations |
| Plugin loader | `inkblade/sdk/loader.py` | trust store | executes Python in-process |
| Collectors | `inkblade/collect/*` | operator credentials | `kubectl get` only; HTTP GET fingerprinting |
| Chain executor | `inkblade execute` | RoE + level + backup gate | dry-run available |
| Report renderer | Markdown/HTML templates | - | escaping and redaction are the controls |
| Rule generator | Kyverno/Gatekeeper/Sigma/Falco/Suricata output | - | output is data, not executed by InkBlade |
| Container image | `inkblade` entrypoint | - | non-root, read-only FS, no shell tooling added |
| Helm chart | Deployment/Service/PVC/SA/RBAC | Kubernetes RBAC | read-only verbs by default |
| Release pipeline | `.github/workflows/*` | OIDC / GITHUB_TOKEN | publishing steps opt-in, non-blocking |

### Inputs an attacker can influence

Cluster objects (names, annotations, labels), HTTP responses from probed
endpoints (headers, bodies, redirects), model metadata files, plugin manifests and
code, and operator-supplied JSON params. Every one of these is treated as
untrusted data: parsers are defensive, output is escaped, and nothing from a
target is `eval`'d or executed.

---

## 5. Controls implemented

| Control | Implementation | Verified by |
|---|---|---|
| RoE gate | `inkblade/core/roe.py`: `assert_execution_allowed`, exit `91` / HTTP `423` | `tests/test_roe.py`, `tests/test_consent_signature.py`, `tests/test_webui_readonly.py` |
| Authorization integrity | canonical JSON + SHA-256 + HMAC, constant-time compare | `tests/test_consent_signature.py` |
| Level ceiling | `min_level` per module vs pinned level | `tests/test_runner_scope_audit.py`, `tests/test_runner.py` |
| Scope enforcement | namespace/CIDR checks in `in_scope`/`scope_violation` | `tests/test_roe.py` |
| Backup gate | write modules require `backup_targets`; runner refuses otherwise | `tests/test_runner.py`, `tests/test_backup.py` |
| Evidence integrity | per-step tarball + `manifest.sha256`, SQLite index | `tests/test_evidence.py` |
| Report redaction | `--redact` path, disclosure fixtures | `tests/test_reports.py`, `tests/test_disclosure_packages.py` |
| Surface gating | `required_surfaces` vs collected inventory; skipped != passed | `tests/test_surface_realism.py`, `tests/test_assess_inventory.py` |
| Plugin manifest strictness | unknown keys, entrypoint containment, write-level floor | `tests/test_sdk.py` |
| Plugin trust pinning | SHA-256 fingerprint + trust store, refusal by default | `tests/test_sdk.py` |
| Container hardening | uid 10001, no caps, read-only root FS, HEALTHCHECK | `scripts/release/verify.py`, `docker.yml` smoke job |
| Chart least privilege | `readOnly: true` -> get/list/watch only | `scripts/release/verify.py` structure checks; `helm lint` when available |
| Vendored asset integrity | `SHA256SUMS` for web assets | `tests/test_vendor_checksums.py` |
| Public-tree hygiene | no local absolute paths, workspace names or internal docs | `tests/test_public_tree.py`, CI `public-tree` job |
| Supply-chain artifacts | CycloneDX SBOM, SHA-256, cosign keyless bundles | `.github/workflows/release.yml` |
| Dependency minimalism | runtime has **no third-party dependencies** | `pyproject.toml` (`dependencies = []`) |

---

## 6. Evidence

Recorded on 2026-10-27, Windows 11 / Python 3.12.15, from a clean checkout of
the release commit. Commands are exactly the ones listed; results are copied from
the terminal, not paraphrased.

| Check | Command | Result |
|---|---|---|
| Byte-compile | `python scripts/release/compile-check.py` | `compile-check: inkblade -> ok`, exit 0 |
| Byte-compile (manual) | `python -m compileall -q inkblade` | exit 0, no output |
| Public-tree hygiene | `python scripts/check-public-tree.py --root .` | `public-tree: 0 hits`, exit 0 |
| Vendored assets | `python -m unittest tests.test_vendor_checksums -v` | Ran 4 tests, OK |
| Plugin SDK contract | `python -m unittest tests.test_sdk -v` | Ran 37 tests, OK |
| Trial command | `python -m unittest tests.test_trial -v` | Ran 8 tests, OK |
| Offline demo (trial) | `python -m inkblade trial --out <tmp>` | 7.31 s, 10 findings (8 high, 2 medium), 7/7 artifacts present |
| Release hygiene gate | `python scripts/release/verify.py` | 62/62 checks passed (helm structural fallback: helm not installed) |
| Wheel build | `python scripts/release/build.py --out <tmp> --clean` | `inkblade-0.2.0-py3-none-any.whl`, 2.9 MB, 1014 entries |
| Wheel contents | `zipfile` listing | `inkblade/profiles/*.json` 10, `inkblade/sdk/*` 8, `inkblade/modules/*` 568, `inkblade/probes/*` 91 |
| Wheel install | fresh venv + `pip install <wheel>` + `inkblade trial --no-demo` | console script resolves, environment-check card renders |
| SBOM | `python scripts/release/sbom.py --dist <tmp> --out <tmp>/sbom.cdx.json` | CycloneDX 1.5, 1 file component (wheel) with SHA-256 |
| CLI entry point | `python scripts/release/smoke.py` | `--help` renders all subcommands, exit 0 |
| Full unit suite | `python -m unittest discover -s tests -t .` | __FULL_SUITE__ |
| Container build | `docker build -t inkblade:trial .` | not executed on this host (no Docker); covered by `docker.yml` (buildx, amd64+arm64, PR smoke job) |
| Chart render | `helm lint deploy/helm/inkblade` | not executed on this host (helm absent); `verify.py` validates structure and `ci.yml`/`release-hygiene` re-runs the gate on Ubuntu |
| Keyless signing | `cosign sign-blob` | not executed on this host (no OIDC identity); `release.yml` signs on tag with `id-token: write` and is non-blocking |

What these results prove: the package builds and installs, the shipped data files
are present, the demo produces a complete artifact set, the hygiene/contract
gates pass, and the SDK rejects what it should. What they do **not** prove: any
behaviour on a real cluster, exploitation success rate, or absence of false
positives - those require the pilot evidence described in `docs/PILOT-KIT.md`.

---

## 7. Known limitations and residual risk

| # | Limitation | Impact | Mitigation / decision |
|---|---|---|---|
| L1 | Plugins run in-process; Python cannot sandbox them | a malicious plugin has the operator's privileges | trust-store pinning + refusal by default + documented isolation (container/VM). Accepted risk for first-party plugins. |
| L2 | Scope checks are parser-based (namespace strings, CIDR math) | exotic target forms could evade scope | CIDR validation uses `ipaddress`; namespace matching is exact; an evasion is a security-relevant bug - report it |
| L3 | Evidence is tamper-**evident**, not tamper-**proof** | workspace owner can delete a run | hash manifests + external retention; pilots archive the bundle off-host |
| L4 | Redaction is pattern-based | unknown secret formats may pass through | reports keep evidence references rather than raw bodies where possible; customer reviews before distribution |
| L5 | CVE coverage is a curated registry, not a database | false negatives outside the registry | coverage is reported explicitly; `static-only` entries are excluded from verified counts |
| L6 | Demo/mock paths are synthetic | a green demo is not a claim about a real cluster | `docs/TRIAL.md` states this; pilots measure separately |
| L7 | Single-writer workspace (Recreate strategy, RWO volume) | no horizontal scaling of one workspace | by design: one assessment, one writer, no split-brain evidence |
| L8 | Keyless signing is opt-in and best-effort | some releases may ship unsigned | release notes state signature availability; checksums always present |
| L9 | No independent third-party audit yet | unknown-unknowns in the threat model | see section 8; the project accepts external review |
| L10 | Web UI session model is simple (bearer token in `users.json`) | token theft = session theft | bind to loopback by default; TLS termination and IdP integration are deployment responsibilities |
| L11 | Rules output is generated, not validated against a live admission controller in CI | a rule may not apply cleanly to every version | rule packs carry version metadata; validate in the pilot cluster |

### Accepted risks (explicit)

* Running against a cluster necessarily requires broad read access; the product
  does not attempt to reduce that, it records it.
* The tool cannot protect a user who signs an incorrect RoE.
* A user with filesystem access to the workspace is trusted to keep it.

---

## 8. External audit checklist

What to hand an assessor (all reproducible from the release commit):

1. **Source**: repository at the release tag (commit SHA in the release notes).
2. **Artifacts**: wheel, sdist, `SHA256SUMS`, `sbom.cdx.json`, optional
   `.sigstore.json` bundles.
3. **Image**: `ghcr.io/<owner>/inkblade@sha256:...` digest, plus `docker inspect`
   output showing uid 10001.
4. **Chart**: `helm template` output with default values, and the values used in
   the assessed deployment.
5. **Evidence of tests**: CI run URL for the tag (Windows + Ubuntu, Python
   3.10-3.13), plus the local run recorded in section 6.
6. **This document** and `SECURITY.md`.
7. **Data-flow description**: section 3 and the CLI/API surface in section 4.

Questions the audit should answer:

- [ ] Can any code path execute a module or chain without a verified RoE?
- [ ] Can a module exceed the pinned level or escape the pinned scope?
- [ ] Can a write module run without a rollback declaration, and is the rollback
      exercised by a test?
- [ ] Is every finding traceable to evidence that cannot be silently edited?
- [ ] Can a target-controlled string reach a shell, an `eval`, a template, or the
      report without escaping?
- [ ] Can a third-party plugin be loaded without an explicit trust decision?
- [ ] Does the shipped container/chart default to least privilege, and is the
      escalation path explicit?
- [ ] Are release artifacts verifiable (checksums, signature, SBOM)?
- [ ] Does the tool write outside the workspace or the declared scope?
- [ ] Are credentials kept out of reports and rules packs?

Out of scope for this package: the customer's cluster configuration, the
correctness of their RoE, IdP/SSO integration, and kernel/container-runtime
isolation.

### Suggested engagement shape

| Phase | Duration | Output |
|---|---|---|
| Code review (core, SDK, report path) | 5-8 days | findings by severity |
| Dynamic testing in a lab cluster | 3-5 days | exploit/abuse attempts, evidence |
| Supply-chain review (CI, image, chart) | 1-2 days | pipeline findings |
| Retest | 1-2 days | closure evidence |

---

## 9. Reproducing the evidence

```bash
git clone https://github.com/inkblade/inkblade.git
cd inkblade
python -m pip install -e .

python scripts/release/compile-check.py
python scripts/check-public-tree.py --root .
python -m unittest tests.test_vendor_checksums tests.test_sdk -v
python scripts/release/verify.py
python -m unittest discover -s tests -t .

python scripts/release/build.py --out dist
python scripts/release/sbom.py --dist dist --out dist/sbom.cdx.json

python -m inkblade trial --out /tmp/inkblade-trial
```

Expected: 0 hits from the public-tree scan, all unit tests green, `verify.py`
passing every check (helm checks fall back to structural validation when `helm`
is absent), a wheel + sdist + SBOM in `dist/`, and a trial card with all artifacts
present.

---

## 10. Contacts

| Topic | Channel |
|---|---|
| Vulnerability in InkBlade | private advisory (see `SECURITY.md`) |
| Audit logistics / evidence requests | maintainers listed in `CODEOWNERS` |
| Trial feedback | `docs/FEEDBACK.md` |
| Conduct | `CODE_OF_CONDUCT.md` |

This package is updated at every minor release; the version it describes is the
one in `CHANGELOG.md`.
