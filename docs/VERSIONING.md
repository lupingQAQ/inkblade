# Versioning, compatibility and deprecation

InkBlade follows [Semantic Versioning 2.0.0](https://semver.org/). This document
states what each version component promises, how long support lasts, and how
removals happen. It is normative for maintainers and predictive for users.

---

## 1. What the version numbers mean

Format: `MAJOR.MINOR.PATCH` (`0.2.0`, `1.4.2`, ...).

| Component | Bumped when |
|---|---|
| `MAJOR` | a documented public contract breaks (CLI flags/exit codes, report schema, manifest contract, plugin `sdk.api`, HTTP API, evidence layout) |
| `MINOR` | functionality is added in a backward-compatible way (new modules, new CLI commands, new optional manifest fields, new export formats) |
| `PATCH` | backward-compatible fixes only (security fixes, false-positive corrections, docs, performance) |

Pre-releases use `-rc.N` / `-beta.N`. Tags are `v`-prefixed: `v0.2.0`.

### 0.x is not 1.0

While `MAJOR == 0`, a `MINOR` bump may contain a breaking change **but only with
a deprecation cycle** (section 4) and a `CHANGELOG.md` "Breaking" entry. We do
not use 0.x as cover for silent breakage: the practical promise is the same as
1.x, with shorter windows.

At `1.0.0` the stability budget below becomes binding without exceptions.

---

## 2. Version surfaces

| Surface | Where | Compatibility promise |
|---|---|---|
| CLI commands & flags | `inkblade --help` | flags are never removed without deprecation; new flags are additive |
| CLI exit codes | `91` = authorization/refusal, `2` = usage, `1` = failure | stable; new codes may appear, existing meanings do not change |
| Report documents | `reports/*.md`, `reports/*.json` | front-matter and JSON keys are additive; a key is never repurposed |
| Evidence layout | `evidence.db`, `steps/*/manifest.sha256`, `consent.json` | readers support files written by any supported minor |
| Manifest contract | `module.json` | new optional fields only; unknown top-level keys are rejected for plugins, tolerated for built-ins |
| Plugin SDK | `inkblade.sdk`, `sdk.api` | `sdk.api` bumps on breaking change; old value supported for one minor |
| HTTP API | `/api/v1/...` | path version is the contract; breaking change = `/api/v2` |
| Export formats | SARIF 2.1.0, OCSF 1.x, OpenVEX, CycloneDX 1.5 | upstream spec versions, announced in the changelog |
| Container image | `ghcr.io/<owner>/inkblade:<version>` | immutable digest per release; `latest` is a convenience tag only |
| Helm chart | `deploy/helm/inkblade`, independent `version` | chart `version` follows SemVer; `appVersion` tracks the release |

Anything not listed (internal modules, private helpers, `_`-prefixed names, test
fixtures) is not a contract.

---

## 3. Support windows

| Release line | Support | Security fixes | Notes |
|---|---|---|---|
| latest `MINOR` | full | yes | active development |
| previous `MINOR` | bug fixes | yes, until the next `MINOR` + 30 days | upgrade window |
| older `MINOR` | none | critical only, best effort | see LTS below |
| LTS line (`x.y` designated in the release notes) | 12 months | yes | for regulated pilots |

Practical policy while `0.x`:

* one active line at a time;
* the previous line receives **security fixes only** for 90 days after a new
  minor (or 30 days if the minor contains a security fix);
* Python support: 3.10 - 3.13 today. Dropping a Python version requires a `MINOR`
  bump and a changelog entry; it is treated as breaking for downstream packagers.

### Long-term support (LTS)

An LTS designation is announced with the release (`v1.2.0 LTS`) and lasts 12
months for security-only fixes. LTS criteria: no schema change for 6 months, a
recorded external audit or pentest, and at least one production reference pilot.
While the project is `0.x`, no LTS is offered; pilots should pin an exact version
and plan a re-validation at each minor.

---

## 4. Deprecation policy

A feature is deprecated before it is removed.

1. **Announce** in `CHANGELOG.md` under `Deprecated`, in the docs page that owns
   the feature, and (where runtime-visible) via a one-line warning on stderr or a
   `DeprecationWarning`.
2. **Wait**: at least **two minor releases** or **90 days**, whichever is longer.
3. **Remove** in a `MAJOR` (or, while `0.x`, in a `MINOR` with a `Breaking`
   changelog entry), and document the replacement plus a migration snippet.

Security-driven removals may shorten the window; the changelog then says why and
links the advisory.

Deprecation ledger lives at the bottom of this file.

### Currently deprecated

| Feature | Deprecated in | Earliest removal | Replacement |
|---|---|---|---|
| _(none)_ | | | |

---

## 5. Release checklist (maintainers)

1. `python -m unittest discover -s tests -t .` is green on the full matrix.
2. `python scripts/check-public-tree.py --root .` reports 0 hits.
3. `python scripts/release/compile-check.py` passes.
4. `python -m unittest tests.test_vendor_checksums tests.test_sdk -v` passes.
5. `python scripts/release/verify.py` passes (metadata, docs, helm structure, SDK).
6. `CHANGELOG.md` has an entry for the version, with `Breaking` if applicable.
7. `pyproject.toml` version and `deploy/helm/inkblade/Chart.yaml`
   (`version` + `appVersion`) agree with the tag.
8. Tag `vX.Y.Z`; CI builds wheel/sdist, SBOM, checksums, cosign keyless bundles,
   drafts the GitHub Release, and (when `PYPI_PUBLISH=true`) publishes to PyPI.
9. Post-release: bump to the next `-dev` version in `main`, publish image digests
   in the release notes, update the support table above.

### What CI enforces, and what it does not

CI proves: the package builds, tests pass on Windows/Linux x Python 3.10-3.13,
the public tree is clean, vendored assets match their hashes, the SDK contract
holds, and artifacts can be signed. CI does **not** prove: coverage of real
clusters, absence of false positives, or fitness for a regulated environment -
those require a pilot (`docs/PILOT-KIT.md`) and, for regulated use, an external
audit (`docs/AUDIT-PACKAGE.md`).

---

## 6. Changelog rules

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/1.1.0/):

* one section per released version, newest first;
* categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`;
* every user-visible change is listed; internal refactors are not;
* security entries reference an advisory id once published, never an unpatched
  exploit detail;
* `Unreleased` collects pending work and is emptied at release time.

---

## 7. Verifying a release artifact

```bash
# checksums shipped with the release
sha256sum --check SHA256SUMS

# keyless signature (Sigstore)
cosign verify-blob --bundle inkblade-0.2.0-py3-none-any.whl.sigstore.json \
  --certificate-identity-regexp '^https://github.com/inkblade/inkblade/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  inkblade-0.2.0-py3-none-any.whl

# SBOM
python -c "import json;d=json.load(open('sbom.cdx.json'));print(d['specVersion'], len(d['components']))"
```

Signatures are produced only when the release workflow has an OIDC identity; the
release notes state whether signatures are present for that tag.
