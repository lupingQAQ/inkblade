# inkblade-probe

The only executable dropped into a target Pod.  It is a single static Rust
binary; there is no Python, shell interpreter, or module code in the target.

- Transport: 4-byte big-endian length + UTF-8 JSON frames, challenge-HMAC-SHA256
- Native ops: `http` (TLS + bounded redirects), `tcp`, `exec` (argv allow-list),
  `fs`, `k8s`, `socks`, `spawn`, `assert`, `extract`, `sleep`
- Declarative templates: canonical modules are `inkblade/modules/<key>/template.json`;
  the controller lowers them to the probe dialect (see `TEMPLATE-ENGINE.md`)
- Registry/multiplex: every frame carries `probe_id`/`parent_id`/task id; child
  probes are spawned by a parent and addressed through the parent's framed
  connection
- Upload/download: chunked, sha256 verified; `/tmp`/`/dev/shm` only
- Audit: JSON lines to stderr (protocol owns stdout) and an optional file
- Read-only by default; write surfaces require `--allow-write` and a controller
  backup receipt

## Build

Local (requires Rust and a musl toolchain):

```sh
cargo build --release --target x86_64-unknown-linux-musl
# aarch64-unknown-linux-musl uses the matching cross linker
```

The release workflow `.github/workflows/probe-release.yml` builds both musl
targets and publishes:

```
inkblade-probe-linux-amd64
inkblade-probe-linux-arm64
SHA256SUMS
```

Binaries are **built by CI**, not checked into the tree.  `dist/` is ignored by
git; `INKBLADE_PROBE_BIN` can point at a local build for the dynamic tests.

## Test

```sh
cargo test --locked --all-targets
INKBLADE_PROBE_BIN=... python -m unittest tests.test_probe_rust_dynamic -v
```

The Python suite always runs a protocol-compatible fake probe; the Rust binary
tests are skipped when no artifact is present, so a source checkout without a
Rust toolchain stays green.
