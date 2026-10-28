# InkBlade probe architecture — one execution model

> Status: normative. Every module is a declarative template executed natively by
> the Rust probe in the target Pod. Python remains only as the controller
> (authorization, scheduling, evidence, reporting). There is no adapter and no host fallback.

## 1. The three planes

```
┌──────────────────────────────┐        framed JSON (HMAC)        ┌──────────────────────────┐
│ Controller (Python, trusted) │  ──────────────────────────────▶ │ Rust probe (in target Pod)│
│ inkblade/core + inkblade/tpl │ ◀──────────────────────────────  │ inkblade-probe           │
│ RoE · backup · audit · report│        task result + evidence     │ http/tcp/exec/fs/k8s/... │
└──────────────┬───────────────┘                                  └──────────────────────────┘
               │ template.json (declarative)
               ▼
      inkblade/modules/<key>/template.json
```

1. **Template plane** — `template.json` is the only module form: inputs,
   payload variants, steps, computed state, checks, findings, artifacts, version
   matrix, limits.
2. **Probe plane** — a static Rust binary (`probe/`) speaking an authenticated
   framed protocol. It executes ops natively. No Python, no shell, no module
   code is uploaded.
3. **Control plane** — Python orchestrates: consent/level/scope gates, backup
   receipts, audit rows, three-layer evidence, reports. It lowers templates to
   the probe dialect and folds probe evidence into findings/artifacts.

## 2. Execution sequence

1. `run_module()` loads `module.json` + `template.json` (registry rejects a
   missing template or a legacy `run.py`).
2. **Consent gate** — signed consent, expiry, scope, level, role `execute`.
3. **Abort gate** — workspace kill switch.
4. **Scope gate** — `host`/`target_ns`/`namespace` must be in scope.
5. **Surface gate** — `absent` → skipped (no finding, no coverage); `unknown`
   needs `--probe`.
6. **Backup gate** — write modules need a snapshot receipt before any execution.
7. **Probe execution** — the controller resolves a probe transport:
   `session.probe` → session/channel `task` → explicit local framed client.
   No transport ⇒ `ProbeUnavailable` (never host execution).
8. **Evidence** — probe step evidence, artifacts (sha256 verified), traffic
   table, step archive, findings, audit row.
9. **Failure** — a probe error is `TemplateExecutionError`; write modules roll
   back using the receipt. Refusals keep exit code 91.

## 3. Template semantics

Authoritative schema: `probe/schema/probe-template.schema.json`.
Engine/expression reference: `inkblade/tpl/engine.py`, `inkblade/tpl/expr.py`.
Rust contract: `probe/TEMPLATE-ENGINE.md`.

- Ops: `http`, `tcp`, `exec` (argv only), `fs`
  (`read/list/stat/write/hash`), `k8s`
  (`get/list/create/patch/delete/apply` via ServiceAccount token), `socks`
  (Unix socket), `spawn`. `repeat` executes an op N times with `{{i}}`.
- `computed` derives named state after steps (`vars.<name>`), so a rule is
  written once and reused by checks/findings.
- `findings` support `for_each` + `as`, `when`, severity, title/detail/evidence/
  mapping/fix, CVE ids and a version matrix.
- `artifacts` are JSON/text/binary built from `from` or `fields`, hashed and
  stored under `runs/<run>/artifacts/<module>/`.
- Expressions are total and sandboxed (no eval, no regex, no I/O): paths,
  comparisons, `and/or/not`, glob `matches`, `any/all/filter/map/count_if`,
  `if`, hashing/encoding helpers.

Write steps (`fs.write`, `k8s` writes, write HTTP, write exec/spawn) execute only
when `params.mode = "backup-write"` **and** the runner has a backup receipt.

## 4. Rust probe integration

The probe (`probe/src/server.rs`) exposes `op:"task"` with
`args:{task_id, template, params}`; the result contains `steps[]` and a `vars`
map (`steps.<id>`). A delivered probe session is identified by `probe_id`; child
probes spawned from a foothold carry `parent_id`, so the controller can keep the
provenance tree (root → child → lateral probe) without uploading Python. The
controller:

1. `inkblade/tpl/lower.py::compile_template` resolves inputs/non-step
   placeholders, drops skipped steps and write steps in probe-only mode, maps
   ops to the probe dialect and reports capability gaps.
2. `RustProbe.run` sends the lowered template and folds the result with
   `fold_result` — the same expression evaluator as the reference runtime.
3. A required step that the probe cannot execute raises `ProbeUnavailable`.
   Current native gaps: k8s write verbs, non-core API groups, Unix-socket client,
   `fs.hash`, exec stdin. They are reported per module in the coverage table.

## 5. Bootstrap (the only host action)

`inkblade/probe-bootstrap.json` registers exactly one bootstrap module,
`probe-bootstrap`. It uploads the static Rust binary, verifies its sha256 and
chmods it. It never uploads Python and never executes module logic. Every other
module is `execution: "template"`.

The controller records the bootstrap as an entry session, not an implicit
precondition:

```
session mode          entry vector             first probe source
kubeconfig            kubeconfig               kubectl / manifest
external              external-http (proof)    RCE callback (base64 /tmp)
foothold              sa-token / pod-shell     kubectl cp + exec
```

`external` is bounded: profile version/fingerprint requests only, a signed
proof object, and no exploit until `vulnerable`; without a foothold only
read-only recon is legal. The session record stores the credential SHA-256
fingerprint (never the credential), the evidence run, probe ids/parent ids,
channel state and every transition in `actions` + `audit.jsonl`.

`inkblade/core/probes.py` is the SQLite registry and controller: probe id,
parent, namespace/node, capabilities, last_seen, status, task rows and
leaf-first cleanup. `inkblade/core/probe_task.py` translates controller actions
into `task`/`upload`/`download`/`spawn` requests; an action that needs an
interpreter is rejected, never executed on the host. `inkblade/channel.py`
carries the same framed protocol over `kubectl exec -i` and exposes loopback
SOCKS5 / port forwards; see [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md).


## 6. Verification

- Every template is exercised dynamically against real probe surfaces; per-module evidence is in `reports/probe-coverage/`.
- Native Linux verification: 286/286 `runtime=rust`, repeat-consistent; evidence in `reports/probe-coverage/evidence-native.json`.
- Lint: `tools/template-lint.py --strict` validates schema, metadata, expressions and the no-interpreter rule.

## 7. Runtime notes

- 286 module templates plus one bootstrap registration.
- Templates are JSON; the probe executes them inside the target Pod. No target-side interpreter is required.
- Evidence, probe identity and cleanup receipts are recorded per task.
