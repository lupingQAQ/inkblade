# Contributing to InkBlade（墨刃零） / 贡献指南

Thanks for contributing! InkBlade is an authorized-testing platform; please read
[`SECURITY.md`](SECURITY.md) and the authorization reminder before you start.

## Development setup / 开发环境

- Python **3.10+**.
- Runtime uses **standard library only**; do not add runtime third-party
  dependencies without prior discussion.
- Optional dev conveniences (`zstandard`, `cryptography`) must remain optional;
  code must degrade gracefully when they are absent.

```bash
git clone <your-fork-url>
cd inkblade
python -m unittest discover -s tests -v
python scripts/check-public-tree.py
```

## Workflow / 开发流程

1. Open an issue (or discuss in an existing one) for non-trivial changes.
2. Write a failing test first, then the minimal implementation (TDD).
3. Keep changes focused; do not mix refactors with behavior changes.
4. Run the full suite and the public-tree scanner before committing.
5. Update docs / samples when behavior or output changes.

## Tests / 测试

```bash
python -m unittest discover -s tests -v       # full suite
python -m unittest tests.test_verify_effects -v
python scripts/check-public-tree.py           # must report 0 hits
python inkblade/e2e-check.py                   # end-to-end acceptance samples
python -m inkblade.verify-effects --out reports/samples/effects/
```

Tests must be deterministic and must not depend on external network access or
real credentials. New modules should cover both `vulnerable` and `fixed` mock
states.

## Module authoring / 模块作者规范

Each module lives in `inkblade/modules/<key>/`:

```
module.json   # key/name/series/description/min_level/writes/requires/...
run.py        # def run(ctx, params) -> {"summary", "artifacts", "findings"}
```

Rules:

- `key` is lowercase words with hyphens, equals the directory name, no digits.
- `module.json` must declare `min_level`, `writes`, and `requires`.
- Write modules (`writes: true`) must honor `backup_targets` and must not write
  without a backup receipt (the runner enforces this).
- Findings must include `sev`, `title`, `detail`, `evidence` (or equivalent).
- Never embed real credentials, customer data, or internal infrastructure
  names. Use `MOCK*` / `FAKE*` fixtures and RFC 5737 documentation ranges.
- Do not add undisclosed zero-day details. Follow the disclosure process in
  `SECURITY.md`; public modules may carry `is_zeroday: true` as a class label.

## Public tree hygiene / 公开树卫生

Do not commit:

- Absolute local paths (drive letters, user home, workspace names).
- References to internal design/worklog documents that are not part of this
  repository.
- Real IPs, hostnames, tokens, API keys, kubeconfigs, or report exports from a
  customer engagement.

`python scripts/check-public-tree.py` must report **0 hits**. CI/PRs that
introduce hits will be rejected.

## Style / 代码风格

- Match the existing code: 4-space indentation, type hints on public functions,
  `from __future__ import annotations`.
- Keep comments/docstrings in Chinese where the surrounding module is Chinese;
  English is welcome for new public-facing docs.
- Prefer small pure helpers and explicit data structures over clever tricks.
- No `eval` on untrusted input; the chain expression evaluator is intentionally
  a whitelisted parser.

## Commit / 提交

- Use conventional-style subjects: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
- Add explicit paths (`git add path/to/file`) rather than blanket staging.
- By contributing, you agree that your contribution is licensed under
  Apache-2.0 and that you have the right to submit it (DCO-style sign-off:
  add `Signed-off-by: Name <email>` to the commit message).

## Code of conduct / 行为准则

Be respectful, assume good faith, and keep discussions technical. Harassment
or disclosure of private information is not tolerated.
