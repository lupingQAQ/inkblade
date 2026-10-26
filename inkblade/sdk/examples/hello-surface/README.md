# hello-surface

Reference plugin for the InkBlade plugin SDK. Read-only, network-free, safe to
run in CI as a contract test.

- manifest: [`module.json`](module.json)
- entrypoint: [`run.py`](run.py)
- series `recon`, level `read-only`, `writes: false`

## Try it

```bash
inkblade sdk lint inkblade/sdk/examples/hello-surface
inkblade sdk run inkblade/sdk/examples/hello-surface \
  --params-json '{"target": "http://127.0.0.1:8000", "note": "trial"}' \
  --allow-unsigned
```

Expected output: one `info` finding (`hello-surface: target recorded`) and
`artifacts/hello-surface.json` inside the run directory.

For a pinned workflow, generate a trust entry first:

```bash
inkblade sdk trust inkblade/sdk/examples/hello-surface --store trust.json
inkblade sdk run inkblade/sdk/examples/hello-surface --store trust.json \
  --params-json '{"target": "http://127.0.0.1:8000"}'
```
