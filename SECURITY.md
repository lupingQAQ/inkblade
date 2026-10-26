# Security Policy / 漏洞披露政策

## Supported versions / 支持版本

| Version | Supported | Notes |
|---|---|---|
| 0.2.x | ✅ | current release line |
| 0.1.x | security fixes only | 90 days after 0.2.0 |

Pre-1.0 support follows `docs/VERSIONING.md`: one active minor line, the previous
line receives security fixes for 90 days (30 days when the new minor itself
carries a security fix). Pin an exact version for regulated pilots.

## Reporting a vulnerability / 报告漏洞

**请勿在公开 Issue、Discussion、PR 或社交媒体中披露未修复漏洞。**

**Do not disclose unfixed vulnerabilities in public issues, discussions, pull
requests, or social media.**

### Private channel / 私密渠道（首选）

Use the repository hosting platform's **private vulnerability reporting**:

1. Open the repository on GitHub.
2. Go to **Security → Advisories → Report a vulnerability**.
3. Provide a description, affected version/commit, reproduction steps, impact,
   and any suggested fix.

The advisory is visible only to the maintainers and to you.

If private advisories are unavailable, open a **minimal public issue** that says
only "I need a private security contact channel" — do not include vulnerability
details, proofs of concept, or affected asset names. A maintainer will move the
conversation to a private channel.

### What to include / 报告内容

- Affected component / module key / version or commit.
- Environment (OS, Python version, deployment mode).
- Reproduction steps and expected vs. actual behavior.
- Impact assessment (confidentiality / integrity / availability).
- Whether the issue affects the public tree, private deployments, or both.
- Your preferred attribution (or "anonymous").

## Our commitment / 处理承诺

| Stage | Target |
|---|---|
| Acknowledge receipt | within **7 calendar days** |
| Triage + severity assessment | within **14 calendar days** |
| Fix or mitigation plan | within **30 calendar days** for high/critical |
| Public advisory | **90 calendar days** after receipt, or earlier by mutual agreement |

We follow a **90-day coordinated publication** window. If a fix is not ready at
day 90, we will agree on a revised timeline with you and publish an advisory
with mitigations. We will credit reporters unless anonymity is requested.

### Severity, CVE handling and publication timeline

We score with **CVSS 3.1** and publish the vector in the advisory. Severity drives
the fix target:

| Severity (CVSS) | Fix target | Advisory |
|---|---|---|
| Critical (9.0-10.0) | 7 days | GitHub Security Advisory + CVE, coordinated with you |
| High (7.0-8.9) | 30 days | GitHub Security Advisory + CVE |
| Medium (4.0-6.9) | 60 days | GitHub Security Advisory (CVE on request) |
| Low (0.1-3.9) | next minor | Changelog + advisory if user action is needed |

Process:

1. **Receipt** within 7 calendar days - we confirm the report arrived and assign a
   handler.
2. **Triage** within 14 calendar days - reproduction status, CVSS vector, affected
   versions, whether it is in scope.
3. **CVE request** - for High/Critical (and on request for Medium) we request a CVE
   through GitHub's CNA. The advisory and the CVE record are published together,
   after a fixed version exists.
4. **Publication** - 90 calendar days from receipt, or earlier by
   mutual agreement. If a fix is not ready at day 90 we agree a revised date in
   writing and publish an advisory with mitigations; we do not silently extend.
5. **Credit** - reporters are credited by name or handle unless anonymity is
   requested. Tell us your preferred attribution in the first message.

We will:

- keep you informed at receipt, triage, fix-ready and publication;
- share the patch or a mitigation before publication so you can validate it;
- publish the advisory even when the affected deployment is unusual, if a
  plausible production path exists;
- never ask you to test against systems you do not own.

We will not:

- pursue legal action for good-faith research that follows this policy;
- publish your identity, infrastructure details or report content without
  permission;
- treat a missing proof-of-concept as a reason to close a report.

### Out-of-band contact

If GitHub private reporting is unavailable (for example during an outage), open a
minimal public issue titled `[security] private channel request` with **no
details** and a maintainer will open a private thread. Do not paste payloads,
endpoints or affected asset names into any public field.

## Scope / 范围

In scope:

- The InkBlade platform code in this repository (`inkblade/`, `scripts/`, `deploy/`).
- Authorization, evidence-integrity, backup/rollback, report-redaction and
  rule-generation logic.
- Supply-chain issues in vendored assets or packaging metadata.
- The plugin SDK and plugin loading path (`inkblade/sdk/`): manifest bypasses,
  entrypoint escapes, fingerprint/trust-store weaknesses, result-schema
  confusion.
- The container image and Helm chart defaults (`Dockerfile`, `deploy/helm/`):
  privilege, filesystem, RBAC and network exposure of the shipped defaults.
- Release artifacts: checksums, SBOM, keyless signature workflows in
  `.github/workflows/release.yml`.

Out of scope:

- Vulnerabilities in third-party products that InkBlade merely tests or
  references (report them to the upstream maintainer).
- Findings that require a deliberately misconfigured test target without a
  plausible production deployment path.
- Social engineering, physical access, or denial-of-service against the
  maintainers' infrastructure.

## Safe harbor / 安全港

We will not pursue legal action for good-faith security research that:

- stays within the scope above,
- avoids privacy violations, data destruction, and service disruption,
- uses only synthetic test data or accounts you are authorized to use,
- and follows this coordinated publication process.

## Authorization reminder / 授权提醒

InkBlade is a penetration-testing platform. Running it against assets without
**written authorization** is prohibited and may be illegal. The maintainers do
not authorize any use against third-party systems.
