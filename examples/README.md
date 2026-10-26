# Examples

Small, runnable examples that ship with the public build. None of them touches a
network or a cluster.

| Path | What it shows |
|---|---|
| `module-hello/` | The module contract: `module.json` + `run(ctx, params)` returning `summary` / `findings` / `artifacts`. |
| `chain-minimal.json` | A one-step chain that maps a module into an ordered plan. |
| `dry-run/` | Output of `inkblade pilot --dry-run` (generated on demand). |

## Run the module example

```bash
inkblade module add examples/module-hello        # optional: copy into the workspace
inkblade run --module example-hello --params '{"target":"in-scope-host"}'
```

The module writes one JSON artifact under the run directory and emits a single
informational finding. It is read-only by construction (`"writes": false`), so it
needs no backup target.

## Run the chain example

```bash
inkblade execute --chain examples/chain-minimal.json --dry-run
```

`--dry-run` prints the plan and the precondition state without executing anything.
Remove `--dry-run` only after a consent record covers the target.

## Write your own

```bash
inkblade sdk new my-check          # scaffold a plugin
inkblade sdk lint my-check         # manifest + entrypoint checks
inkblade sdk validate my-check     # result-schema checks
inkblade sdk trust my-check        # pin the SHA-256 fingerprint
```

The manifest contract is documented in `docs/PLUGIN-SDK.md`.
