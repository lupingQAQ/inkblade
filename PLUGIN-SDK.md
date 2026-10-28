# Plugin SDK

InkBlade modules are plain directories: a `module.json` manifest plus a Python
entrypoint. The SDK (`inkblade.sdk`) ships the same contract, a strict validator,
a fingerprinted loader and a scaffold. Everything below is standard library only.

```bash
inkblade sdk new my-check --dest plugins          # scaffold
inkblade sdk lint plugins/my-check                # validate
inkblade sdk run plugins/my-check --allow-unsigned \
  --params-json '{"target": "asset-17"}'          # execute
inkblade sdk trust plugins/my-check --store trust.json   # pin for repeat use
```

A worked example lives in `inkblade/sdk/examples/hello-surface/` and is covered
by `tests/test_sdk.py`.

---

## 1. Directory layout

```text
plugins/my-check/
  module.json        # manifest (required)
  run.py             # entrypoint (default; configurable via sdk.entrypoint)
  README.md          # optional but recommended
  data/*.json        # optional data files, fingerprinted with the rest
```

The directory name **must** equal `module.json`'s `key`.

---

## 2. Manifest reference

`module.json` is the same document the built-in registry consumes, plus an
optional `sdk` block.

### Required

| Field | Type | Contract |
|---|---|---|
| `key` | string | `^[a-z][a-z0-9-]{1,62}$`, equals the directory name |
| `name` | object | `{"en": "...", "zh": "..."}`; `en` is mandatory for plugins |
| `series` | string | one of the series enum below (aliases accepted) |
| `description` | string | what it does, what it proves; < 4000 chars |
| `min_level` | string | one of the level enum below (aliases accepted) |
| `writes` | boolean | `true` only if the plugin changes any state |
| `requires` | array | module keys that must run first (may be empty) |

### Optional

| Field | Type | Meaning |
|---|---|---|
| `params_schema` | object | `{"param": "human description"}`; used by the UI/CLI |
| `produces` | string | artifacts/findings it emits |
| `knowledge` | string | path to background documentation |
| `combo_signature` | string | identifier used by chain composition |
| `private` | boolean | excluded from the public tree |
| `surfaces` / `required_surfaces` | array | `[{"type": "k8s-object", "selector": "Pod"}]` |
| `default_enabled` | boolean | `false` hides it from default coverage |
| `research_only` | boolean | requires `default_enabled: false` |
| `default_disabled_reason` | string | why it is off by default |
| `necessity` | string | why the module matters for the assessment |
| `sdk` | object | plugin block, see below |

### `sdk` block

```json
"sdk": {
  "api": 1,
  "entrypoint": "run.py",
  "license": "Apache-2.0",
  "homepage": "https://example.invalid/my-check",
  "publisher": "ACME Security"
}
```

| Key | Default | Notes |
|---|---|---|
| `api` | required in strict mode | must be `1`; bumped on breaking SDK changes |
| `entrypoint` | `run.py` | relative path, `.py`, no `..`, forward slashes |
| `license` | `""` | SPDX identifier; warned when missing |
| `homepage` | `""` | warned when missing |
| `publisher` | `""` | copied into trust store entries |

Unknown top-level keys are rejected in strict mode. Vendor extensions must be
prefixed with `x-` (for example `"x-acme-risk": "low"`).

---

## 3. Enumerations

`series` describes the assessment discipline; `min_level` is the lowest
authorization level at which the module may run.

| `series` canonical | aliases |
|---|---|
| `侦察` | `recon` |
| `横向利用` | `lateral` |
| `权限链` | `privesc` |
| `窃取与数据泄露` | `theft` |
| `核心代码` | `code` |
| `网络架构` | `network` |
| `混合云` | `hybrid-cloud` |
| `情报` | `intel` |

| `min_level` canonical | aliases | meaning |
|---|---|---|
| `只读侦察` | `read-only` | GET/`kubectl get` only |
| `主动探测` | `probe` | benign probes, lab credentials |
| `利用验证` | `exploit` | proof-of-concept execution |
| `全影响演示` | `full-impact` | data-plane impact on a canary |

Write the canonical value into `module.json`: the built-in registry compares
strings exactly, and only the SDK validator normalizes aliases. `inkblade sdk
new` always writes the canonical form.

---

## 4. Entrypoint contract

```python
def run(ctx: dict, params: dict) -> dict:
    ...
```

### Context (`ctx`)

| Key | Type | Guaranteed |
|---|---|---|
| `ctx["run"].dir` | `pathlib.Path` | exists; `traces/` and `artifacts/` are pre-created |
| `ctx["run"].key` | `str` | module key |
| `ctx["marker"]` | `str` | per-run nonce prefix for synthetic data |
| `ctx["meta"]` | `dict` | assessment metadata (may be empty) |
| `ctx["plugin"]` | `dict` | `key`, `fingerprint`, `trusted`, `trust_source` |

Write only inside `ctx["run"].dir`. The SDK does not stop you from writing
elsewhere; doing so invalidates the evidence bundle and is a review blocker.

### Result document

```python
{
  "summary": "one line, shown in the UI",
  "findings": [
      {"sev": "high", "title": "short title", "detail": "{\"json\": \"string\"}"}
  ],
  "artifacts": ["<absolute path inside run dir>"],
}
```

Rules enforced by `run_plugin`:

* `run()` returns an object; `summary` is a string.
* `findings` is a list of objects; `sev` is one of
  `critical|high|medium|low|info`; `title` is non-empty.
* `detail` is a **string** (JSON-encoded payload). Use
  `inkblade.sdk.encode_detail(dict)` to serialize.
* `artifacts` is a list of strings.

Anything else raises `PluginResultError` before the result reaches a report.

### Declaring side effects

* `writes: false` - the plugin must not change target state. Enforced by review,
  not by the runtime.
* `writes: true` - allowed only at `min_level` `利用验证` or higher, and the runner
  requires `backup_targets` in `params` so the action can be rolled back. Declare
  the surfaces you touch so the runner can skip you when they are absent.

---

## 5. Validation profiles

```python
from inkblade.sdk import load_manifest, lint_manifest

load_manifest("plugins/my-check", strict=True)   # plugins: strict
load_manifest("inkblade/modules/<key>", strict=False)  # built-ins: legacy
lint_manifest("plugins/my-check")                 # errors + warnings dict
```

Strict mode adds:

1. no unknown top-level keys (unless `x-` prefixed),
2. `sdk.api` present and equal to `1`,
3. `writes: true` requires `min_level` >= `利用验证`,
4. `research_only: true` requires `default_enabled: false`,
5. manifest <= 256 KiB, entrypoint <= 16 MiB.

`tests/test_sdk.py::TestBuiltinCompatibility` validates all built-in modules in
legacy mode on every CI run, so the two profiles cannot drift.

---

## 6. Trust model

Plugins execute **in-process**. Python cannot sandbox that; the SDK therefore
front-loads integrity:

1. `plugin_fingerprint(dir)` - SHA-256 over every file name and content
   (sorted, excluding `__pycache__`, `*.pyc`, VCS dirs). Deterministic.
2. `load_plugin(dir)` **refuses** to import unless you either
   * provide a trust store containing that key with a matching fingerprint, or
   * pass `allow_unsigned=True` explicitly.
3. Entrypoint containment: the resolved path must stay inside the plugin
   directory, so `../../evil.py` and symlink escapes are rejected before import.

Trust store format:

```json
{
  "version": 1,
  "plugins": {
    "my-check": {
      "fingerprint": "9f2c...64 hex chars",
      "publisher": "ACME Security",
      "allow": true
    }
  }
}
```

`"allow": false` blocks a key even with `allow_unsigned=True` - useful when a
plugin is pulled from a marketplace.

Create and update it with:

```bash
inkblade sdk trust plugins/my-check --store trust.json --publisher "ACME Security"
```

Re-pin after **every** code change; the fingerprint changes.

### Isolation guidance

| Plugin provenance | Recommended execution |
|---|---|
| First-party, reviewed | in-process, trust store pinned |
| Third-party, reviewed | in-process, trust store pinned, dedicated workspace |
| Third-party, unreviewed | container or VM, no credentials, egress allowlist |
| Marketplace / unknown | do not run; read the code first |

In-process plugins inherit the CLI's credentials (kubeconfig, tokens). That is
why `allow_unsigned` is not the default and why the Helm chart ships a read-only
ServiceAccount.

---

## 7. CLI reference

| Command | Purpose |
|---|---|
| `inkblade sdk new <key> --dest DIR` | scaffold `module.json`, `run.py`, `README.md` |
| `inkblade sdk new <key> --writes --min-level exploit` | write-capable skeleton (rejects `probe`) |
| `inkblade sdk lint <dir> [...]` | validate, print errors/warnings, exit 1 on error |
| `inkblade sdk validate <dir>` | alias of `lint` for CI |
| `inkblade sdk trust <dir> --store FILE` | add/update the fingerprint pin |
| `inkblade sdk run <dir> --params-json '{...}'` | execute once, print findings + run dir |
| `inkblade sdk run <dir> --store FILE` | execute with a trust store (no `--allow-unsigned`) |
| `inkblade sdk list <root>` | lint every plugin under a directory |

`python -m inkblade.sdk ...` is equivalent when the console script is not on
`PATH`.

---

## 8. Testing your plugin

```python
import unittest
from pathlib import Path
from inkblade.sdk import lint_manifest, load_plugin, run_plugin

PLUGIN = Path("plugins/my-check")

class TestMyCheck(unittest.TestCase):
    def test_manifest(self):
        report = lint_manifest(PLUGIN)
        self.assertEqual(report["errors"], [])

    def test_runs_offline(self):
        plugin = load_plugin(PLUGIN, allow_unsigned=True)
        result = run_plugin(plugin, {"target": "asset-17"}, workspace=".tmp-test")
        self.assertEqual(result["findings"][0]["sev"], "info")
```

CI (GitHub Actions):

```yaml
- run: python -m unittest tests.test_my_plugin -v
- run: inkblade sdk lint plugins/my-check
```

Keep plugin tests offline: no sockets, no cluster, fixed inputs, asserted
artifact content.

---

## 9. Compatibility policy

| Change | Version impact |
|---|---|
| New optional manifest field | minor |
| New result key (ignored by older runners) | minor |
| `sdk.api` bump | major; both values supported for one minor release |
| Entrypoint signature change | major |
| Stricter validation of an existing field | minor + deprecation window (see `docs/VERSIONING.md`) |

The SDK never imports your plugin at lint time - validation is static, so a
broken plugin cannot break `inkblade sdk lint`.

---

## 10. Anti-patterns

| Don't | Why |
|---|---|
| Write outside `ctx["run"].dir` | breaks evidence integrity and report linkage |
| Return a dict as `detail` | contract is a JSON *string*; use `encode_detail` |
| Put network calls in `run()` at import time | lint/CI must stay offline; do work inside `run` |
| Mark `writes: true` with `min_level: 主动探测` | rejected by the strict validator |
| Hardcode absolute paths | breaks on Windows/Linux and leaks operator layout |
| Rely on a sibling module name being unique | sibling imports are cached in `sys.modules` by bare name; prefix helpers with the plugin key |
| Let `run()` raise on bad input | the CLI reports it as a plugin failure, but the run stops; validate params first |
| Bundle secrets in the plugin | plugins are fingerprinted and published; use params |
| Catch `BaseException` | hides `KeyboardInterrupt`; the runner cannot stop the run |

Questions: open a discussion or an issue (see `.github/ISSUE_TEMPLATE`).
