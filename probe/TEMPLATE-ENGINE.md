# Rust probe template engine — contract (v1)

Status: **normative** for `inkblade-probe` and the Python conformance runtime.
Schema: [`schema/probe-template.schema.json`](schema/probe-template.schema.json).
Modules are declarative templates only. No Python, shell interpreter, or module
code is ever uploaded to a target Pod.

## 1. Transport

The probe runs as an authenticated framed server
(`inkblade-probe run --stdio --token-file …`, see `probe/src/server.rs`):
4-byte big-endian length + UTF-8 JSON frames, challenge-HMAC-SHA256 handshake.
The controller sends one `task` request:

```json
{"v":1, "type":"req", "id":"<task>", "op":"task",
 "args":{"task_id":"<task>", "template": { "...": "probe dialect" },
         "params": {"target": "http://…", "mode": "probe-only"}}}
```

The probe replies with one response frame:

```json
{"v":1,"type":"resp","id":"<task>","ok":true,
 "data":{"ok":true,"task_id":"…","probe_id":"…","template":"<name>",
         "steps":[{"step":"probe1","op":"http","ok":true,"result":{…}}],
         "vars":{"steps.probe1":{…},"target":"…","last":{…}},
         "duration_ms":42}}
```

Two dialects are involved and only one is executable in the Pod:

1. **Canonical template** (`inkblade/modules/*/template.json`, this schema):
   inputs, payload variants, version matrix, checks, findings, artifacts.
2. **Probe dialect** (`probe/src/template.rs`): `steps[]` with `op`
   (`http`/`tcp`/`exec`/`fs`/`k8s`/`socks`/`spawn`/`assert`/`extract`/`sleep`),
   flat `{{name}}` variables, `steps.<id>` lookups.

`inkblade/tpl/lower.py::compile_template` lowers (1) → (2): resolves inputs and
non-step placeholders, drops `when=false` and write steps in `probe-only`,
maps ops, and reports **capability gaps**. The controller then folds the
probe's step evidence into checks/findings/artifacts with the same expression
language (`lower.py::fold_result`). This is declarative post-processing of probe
evidence — no module code runs on the host, and a gap raises
`ProbeUnavailable` instead of falling back.

Exit codes: `0` result produced, `2` invalid request/auth, `3` unsupported
op/schema, `4` budget exceeded. A non-zero exit or `ok:false` frame is a
`ProbeFailed`; the controller never retries on the host.

## 2. Operations

All ops render `{{ expr }}` placeholders first (see §3). Unknown placeholders
are a request error, never a silent empty string.

| op | required | behaviour |
|---|---|---|
| `http` | `method`, `url` | One request. `body` JSON is serialised; string bodies are sent verbatim. Response `status`, `headers`, `text`, `json`, `bytes`, `sha256`. `expect.status` / `expect.body_contains` / `expect.header_contains` decide `ok`. |
| `tcp` | `host`, `port` | Connect, optional `send`/`send_b64`, read up to `read_bytes`; `expect_prefix` decides `ok`. |
| `exec` | `argv[]` | `argv` is an argument vector; never a shell string. `stdin`, `env`, `timeout_ms`. `ok = rc == 0`. |
| `spawn` | `argv[]` | Start a process; `detach` returns the pid immediately, otherwise waits. |
| `fs` | `action` (`read`/`list`/`stat`/`write`/`hash`) | `read` returns `text` and, with `json:true`, parsed `json`. `write` is a write-surface op (see §5). |
| `k8s` | `verb`, `resource` | kubectl-equivalent via ServiceAccount token. `api_version` is `v1` or `group/version`; `namespace=""` means all namespaces for `list`. Only `get/list/create/patch/delete/apply`; no exec/port-forward. |
| `socks` | `socket_path`, `request` | Unix socket connect/send/read (docker/containerd/kubelet sockets). |

### Kubernetes shim

- Endpoint: `INKBLADE_K8S_API` or `https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT`.
- Bearer token: `INKBLADE_K8S_TOKEN` or `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- CA: `INKBLADE_K8S_CA` or the service-account `ca.crt`; hostname verification is
  on by default (`tls_verify` only weakens per-request when explicitly set).
- Namespace default: service-account namespace file.
- Core: `/api/v1/...`; groups: `/apis/<group>/<version>/...`.
- `list` adds `limit=500` and optional `labelSelector`.
- Response JSON is passed through untouched so templates can assert on it.

## 3. Expression language

Deterministic, total (never raises at runtime; errors become `null`/false),
standard-library only on both sides.

```
expr    := or
or      := and ("or" and)*
and     := not ("and" not)*
not     := "not" not | cmp
cmp     := sum (("=="|"!="|"<"|"<="|">"|">="|"in"|"contains"|"startswith"
                 |"endswith"|"matches") sum)?
sum     := mul (("+"|"-") mul)*
mul     := unary (("*"|"/"|"%") unary)*
postfix := primary ("." NAME | "[" INT "]" | "[" "*" "]" )*
primary := NUMBER | STRING | true | false | null | NAME | NAME "(" args ")" | "(" expr ")"
```

- Paths: `steps.<id>.<field>`, `params.<name>`, `input.<name>`, `vars.<name>`,
  `ctx.marker`, `payload.<name>`. `[*]` flattens arrays; `.field` on an array
  maps over objects.
- Missing → `null`; `== null` is true only for missing/null.
- Functions: `len`, `count`, `int`, `float`, `str`, `bool`, `lower`, `upper`,
  `trim`, `replace`, `split`, `join`, `keys`, `values`, `exists`, `default`,
  `coalesce`, `sha256`, `b64encode`, `b64decode`, `json`, `min`, `max`, `abs`,
  `sum`, `round`, `range`, `now_ms`, `contains`, `startswith`, `endswith`,
  `matches(pattern, value)`, `any(list, expr)`, `all(list, expr)`,
  `count_if(list, expr)`, `first(list, expr)`, `map(list, expr)`.
- `any`/`all`/`count_if`/`map` bind the element as `it` (and the current
  `for_each` alias inside findings).
- `matches` is glob (`*`, `?`), not regex; no backtracking engine, no ReDoS.

Interpolation: `{{ expr }}`; a value that is exactly one placeholder keeps its
JSON type, mixed strings are rendered. `null` renders as an empty string.

## 4. Evaluation order

1. Resolve `inputs` (`required` missing → `status=skipped`).
2. Render `vars` (in declaration order; later vars may reference earlier ones).
3. Execute `steps` in order:
   - `when=false` → `skipped`;
   - `write=true` inside `mode != backup-write` → `skipped`;
   - failure without `allow_failure` aborts with `status=error`;
   - `timeout_ms` per step, `limits.timeout_ms` overall, request budget.
4. Evaluate `checks` (all of them). A failing `fatal` check forces `status=error`
   and suppresses findings/artifacts.
5. Evaluate `findings`: optional `for_each` + `as`, `when`, then render strings.
6. Materialise `artifacts` (JSON/text/binary), compute `sha256`, cap bytes.
7. `status = error | findings (if any) | ok`.

Step results are namespaced under `steps.<id>` and expose `ok`, `status`,
`error`, `skipped` plus op fields (`text`, `json`, `headers`, `entries`,
`stdout`, `stderr`, `rc`, `exists`, `size`, `sha256`, …).

## 5. Security invariants

- **No interpreter in the Pod.** Only the Rust binary and JSON templates.
- `exec` requires an argv array; a single shell-looking string is rejected by
  the validator and by the probe. No `sh -c`, no `python -c`.
- Write-surface ops (`fs.write`, `k8s create/patch/delete/apply`, `http`
  non-idempotent methods marked `write:true`, `exec` marked `write:true`) are
  refused unless `params.mode == "backup-write"` *and* the host has already
  produced a backup receipt (RoE/backup/audit gates in `core/runner.py`).
- The probe enforces `limits`: max frame/body bytes, max HTTP requests, total
  timeout. Truncated bodies are flagged; they are never silently parsed.
- Every finding carries the step evidence digest; the host stores the probe
  result digest in `probe_evidence` and the step archive.

## 6. Determinism and conformance

The Python runtime (`inkblade/tpl/engine.py`, `runtime="reference"`) implements
this contract exactly and is used by the mock range in CI. It requires an
explicit opt-in (`INKBLADE_ALLOW_REFERENCE_PROBE=1`) and its results are stamped
`runtime="reference"`. Production sessions use `runtime="rust"`; if no probe is
available the host raises `ProbeUnavailable` — there is no fallback.

Conformance corpus: `tests/test_probe_templates.py` (engine) and the per-batch
dynamic suites (`tests/test_probe_templates_*.py`) run every template against
`lab/template_range.py` in two states and record evidence in
`reports/probe-coverage/evidence.json`.

## 7. Native capability matrix (v0.1.0 crate)

| Capability | Probe native | Controller lowering | Gap policy |
|---|---|---|---|
| `http` GET/POST/etc., headers, JSON body, `expect.status` | yes | precomputed placeholders | body/header expectations folded |
| `tcp` connect/send/read | yes | `send` → `send_b64` | — |
| `exec` argv (no shell) | yes | argv rendered | no stdin (reported) |
| `fs` read/list/stat/write/mkdir/remove/chmod | yes | `content` → `data` | `fs.hash` gap |
| `k8s` list/get core v1 | yes | `verb` → `action` | write verbs and non-core groups are **gaps** until the probe adds them (no host workaround) |
| `socks` | serve only | client ops are gaps | Unix-socket client op is a **gap** |
| `spawn` | yes | argv rendered | — |
| `assert` / `extract` | yes | checks/findings folded controller-side | — |
| findings/artifacts/checks | no | folded from probe evidence | no module code |

`tools/template-coverage.py` records `native_ready` and the gap reasons per
module. `compile_template` refuses to run (raises `ProbeUnavailable`) when a
required step is a gap, so the host can never silently execute it.

Closing the two gaps (k8s write verbs, Unix-socket client) is tracked as probe
work; until then those templates are dynamically verified with the conformance
runtime and their coverage row says `native=gap`.

## 8. Packaging and bootstrap

- Template JSON is sent inline (`run-template` stdin), so no file upload is
  needed for module execution.
- The only uploaded artifact is the static Rust binary, via the explicitly
  registered `probe-bootstrap` module (`inkblade/probe-bootstrap.json`).
- Binaries are pinned by sha256 in the release gate; `install_probe` verifies the
  digest before uploading.
