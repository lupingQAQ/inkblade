# Security Policy / 漏洞披露政策

## Supported versions / 支持版本

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

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
| Coordinated disclosure | **90 calendar days** after receipt, or earlier by mutual agreement |

We follow a **90-day coordinated disclosure** window. If a fix is not ready at
day 90, we will agree on a revised timeline with you and publish an advisory
with mitigations. We will credit reporters unless anonymity is requested.

## Scope / 范围

In scope:

- The Trident platform code in this repository (`trident/`, `lab/`, `scripts/`).
- Authorization, evidence-integrity, backup/rollback, report-redaction and
  rule-generation logic.
- Supply-chain issues in vendored assets or packaging metadata.

Out of scope:

- Vulnerabilities in third-party products that Trident merely tests or
  references (report them to the upstream vendor).
- Findings that require a deliberately misconfigured lab target without a
  plausible production deployment path.
- Social engineering, physical access, or denial-of-service against the
  maintainers' infrastructure.

## Safe harbor / 安全港

We will not pursue legal action for good-faith security research that:

- stays within the scope above,
- avoids privacy violations, data destruction, and service disruption,
- uses only synthetic lab data or accounts you are authorized to use,
- and follows this coordinated disclosure process.

## Authorization reminder / 授权提醒

Trident is a penetration-testing platform. Running it against assets without
**written authorization** is prohibited and may be illegal. The maintainers do
not authorize any use against third-party systems.
