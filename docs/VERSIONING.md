# Versioning, compatibility and deprecation

Semantic Versioning 2.0.0. Tags are `v`-prefixed; pre-releases use `-rc.N` / `-beta.N`.

| Component | Bumped when |
|---|---|
| `MAJOR` | a documented contract breaks: CLI flags/exit codes, report schema, manifest contract, `sdk.api`, HTTP API, evidence layout |
| `MINOR` | backward-compatible additions: modules, commands, optional manifest fields, export formats |
| `PATCH` | backward-compatible fixes only: security, false positives, docs, performance |

While `MAJOR == 0`: a `MINOR` bump may break something, but only through the deprecation
cycle below and a "Breaking" entry in `CHANGELOG.md`. At `1.0.0` the windows become binding.

## Contracts

| Surface | Where | Promise |
|---|---|---|
| CLI flags | `inkblade --help` | never removed without deprecation; additions only |
| Exit codes | `91` refusal, `2` usage, `1` failure | stable meaning; new codes may appear |
| Reports | `reports/*.md`, `*.json` | additive keys; keys are never repurposed |
| Evidence | `evidence.db`, `steps/*/manifest.sha256`, `consent.json` | readable across supported minors |
| `module.json` | module manifests | new optional fields only |
| Plugin SDK | `inkblade.sdk`, `sdk.api` | `sdk.api` bumps on a break, old value kept one minor |
| HTTP API | `/api/v1/...` | path version is the contract; a break means `/api/v2` |
| Exports | SARIF 2.1.0, OCSF, OpenVEX, CycloneDX | upstream spec versions, announced in the changelog |
| Chart | `deploy/helm/inkblade` | chart `version` is SemVer; `appVersion` tracks the release |

## Support

| Line | Fixes | Security | Notes |
|---|---|---|---|
| latest `MINOR` | full | yes | active development |
| previous `MINOR` | bug fixes | until next `MINOR` + 30 days | upgrade window |
| older `MINOR` | none | critical, best effort | see LTS |
| LTS (`x.y` in release notes) | 12 months | yes | regulated pilots |

## Deprecation

| Phase | Requirement |
|---|---|
| Announce | `CHANGELOG.md` under "Deprecated", and in `--help` where the flag lives |
| Keep | one `MINOR` cycle, minimum 30 days |
| Remove | next `MINOR` (0.x) or next `MAJOR` (1.x+), with a "Removed" entry naming the replacement |
| Security | a fix may shorten the cycle; it does not skip the changelog entry |

## Release checklist

| Check | Command |
|---|---|
| tests on Windows + Linux, Python 3.10–3.13 | `python scripts/run-public-tests.py` |
| changelog has version and date | manual |
| wheel, sdist, `SHA256SUMS`, SBOM | `python scripts/release/build.py --out dist` |
| container image with an immutable digest | `docker.yml` |
| docs regenerated and link-clean | `python scripts/build-docs-site.py --check` |
