# Pull request

## What changed

<!-- One paragraph. Link the issue: "Closes #123". -->

## Type

- [ ] Bug fix (no behaviour change beyond the fix)
- [ ] New capability (module, chain, command, export format)
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Release engineering / CI / packaging
- [ ] Security hardening

## Safety review (required for anything touching execution)

- [ ] No new write-capable path, **or** the change declares `writes`, `min_level`,
      required surfaces and a rollback path.
- [ ] Authorization gates still apply: no code path executes a module or chain
      without a signed RoE.
- [ ] Evidence remains complete: every new step writes an artifact and a
      `manifest.sha256`.
- [ ] Report redaction still holds: no raw credentials or customer identifiers in
      outputs.

## Verification

Paste the commands you ran and their result. "Tests pass" without output is not
evidence.

```text
python -m unittest discover -s tests -t .
python scripts/check-public-tree.py --root .
python -m unittest tests.test_vendor_checksums tests.test_sdk -v
python scripts/release/compile-check.py
python scripts/release/verify.py
```

- [ ] Full unittest suite passes locally
- [ ] New behaviour is covered by a test that fails without the change
- [ ] Public-tree scan reports 0 hits
- [ ] Docs updated (command reference, TRIAL/PILOT-KIT/PLUGIN-SDK when relevant)
- [ ] `CHANGELOG.md` updated under `Unreleased`

## Compatibility

- [ ] No public contract change, **or** the change is documented in
      `CHANGELOG.md` and `docs/VERSIONING.md` deprecation rules are followed
- [ ] Manifest / SDK contract unchanged **or** `sdk.api` / manifest changes are
      called out explicitly

## Notes for reviewers

<!-- Risk, rollback, follow-ups, anything you are unsure about. -->
