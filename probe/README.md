# inkblade-probe

Read-only in-pod fact collector for InkBlade. One static binary, no dependencies,
no network, no writes outside `--out`.

The probe answers a narrow question before an engagement starts: *what does this
pod actually see?* Capabilities, seccomp mode, sensitive mounts, accelerator and
RDMA devices, service-account token presence, and the names (never the values) of
security-relevant environment variables.

## Why a separate binary

A pod often has no Python, no shell and no writable root filesystem. A static
musl binary drops in with `kubectl exec`, prints JSON to stdout, and leaves
nothing behind. It is also the only part of the platform written in Rust, which
keeps the runtime surface small and auditable.

## Build

Requires Rust 1.74+.

```bash
# host build (glibc) for local testing
cargo build --release
./target/release/inkblade-probe --help

# static musl builds, the ones shipped in Releases
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Cross-compiling to arm64 from x86_64 is easiest with the `cross` tool:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-musl
```

Release assets are built by CI (`.github/workflows/probe-release.yml`) and
published as:

| Asset | Contents |
|---|---|
| `inkblade-probe-linux-amd64` | x86_64-unknown-linux-musl, stripped |
| `inkblade-probe-linux-arm64` | aarch64-unknown-linux-musl, stripped |
| `SHA256SUMS` | checksums for both |

The repository never contains compiled binaries. Verify a download with
`sha256sum -c SHA256SUMS`.

## Usage

```bash
# full document
inkblade-probe

# only the probes object, straight into assess
inkblade-probe --emit probes --out probes.json
inkblade assess cves --probes probes.json

# inside a pod
kubectl exec -n <ns> <pod> -- /tmp/inkblade-probe --emit probes
kubectl cp <ns>/<pod>:/tmp/inkblade-probe.json ./probes.json
```

| Flag | Meaning |
|---|---|
| `--emit full` | full document, schema `inkblade-probe/1` (default) |
| `--emit probes` | only the `probes` object (the `--probes` input shape) |
| `--out PATH` | write to `PATH` instead of stdout |
| `--max-bytes N` | per-file read cap (default 65536, max 4194304) |
| `-h/--help`, `-V/--version` | usage / version |

Exit codes: `0` success, `1` write failure, `2` bad arguments.

## Protocol

One JSON document on stdout, newline-terminated, UTF-8, no streaming.

```json
{
  "schema": "inkblade-probe/1",
  "tool": "inkblade-probe",
  "version": "0.1.0",
  "collected_at": 1793000000,
  "host": {
    "hostname": "train-0",
    "kernel": "5.15.0-119-generic",
    "os_release": {"ID": "ubuntu", "VERSION_ID": "22.04"},
    "pid1_cmdline": "/usr/bin/python3 -m vllm.entrypoints.openai.api_server"
  },
  "probes": {
    "in_container": true,
    "cap_effective": "000001ffffffffff",
    "seccomp_mode": "2",
    "no_new_privs": "1",
    "service_account_token_present": true,
    "service_account_token_bytes": 8941,
    "gpu_devices": ["/dev/nvidia0", "/dev/nvidiactl"],
    "nvidia_driver": "550.54.15",
    "rdma_devices": ["mlx5_0"],
    "sensitive_mounts": ["/dev/shm", "/var/run/secrets/kubernetes.io/serviceaccount"],
    "env_names": {"NVIDIA_VISIBLE_DEVICES": "<present>", "VLLM_": "<present>"},
    "uid": 10001,
    "max_read_bytes": 65536
  }
}
```

`probes` is a flat object of scalars, arrays and string maps. `inkblade assess
cves --probes probes.json` merges each key into `inventory.probes.<key>`, so the
document can be cited as evidence without further conversion.

## Security controls

The probe is deliberately boring:

1. **Fixed read allowlist.** `/proc/self/status`, `/proc/self/cgroup`,
   `/proc/1/cgroup`, `/proc/1/cmdline`, `/proc/self/mountinfo`, `/proc/sys/kernel/*`,
   `/etc/os-release`, `/proc/driver/nvidia/gpus/*/information`,
   `/sys/class/infiniband`, and directory listings of `/dev`. No path comes from
   user input, so there is no traversal surface.
2. **Bounded reads.** Every file is capped (`--max-bytes`, default 64 KiB,
   hard maximum 4 MiB); `/proc/self/status` is parsed line by line.
3. **No credential contents.** The service-account token is `stat`-ed for
   existence and size only; it is never opened. Environment variables are
   reported as names with the literal value `<present>` — values may carry API
   keys, endpoints or tenant identifiers.
4. **No network.** The binary does not link a socket API, does not resolve names
   and does not call out. `imds_reachable` is intentionally absent: reachability
   is an active check and belongs to the operator, not to a passive collector.
5. **No subprocesses.** No shell, no `kubectl`, no `exec`.
6. **No writes except `--out`.** Nothing is cached, no temp files, no stdout
   pollution on error (errors go to stderr).
7. **No third-party crates.** `Cargo.toml` has an empty `[dependencies]`; the
   build is reproducible offline and the dependency-review surface is the Rust
   standard library.
8. **Static linking.** musl targets, `panic = "abort"`, symbols stripped — the
   binary runs on distroless images with no glibc version games.

## Reading the output safely

The document is evidence, not a secret, but treat it as engagement material:
capabilities and device lists describe your own cluster. Redact `hostname`,
`env_names` and `pid1_cmdline` before attaching it to a report that leaves the
team.

## Licence

Apache-2.0, same as the platform. See `../LICENSE` and `../NOTICE`.
