# InkBlade probe architecture — one execution model

> Status: normative. Every module is a declarative template executed natively by
> the Rust probe in the target Pod. Python remains only as the controller
> (authorization, scheduling, evidence, reporting) and as a CI conformance
> runtime for the isolated verification range. There is no adapter and no host fallback.

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

- `inkblade/tpl/engine.py` is a conformance runtime implementing the same
  contract. It is opt-in (`INKBLADE_ALLOW_REFERENCE_PROBE=1`), stamps
  `runtime="reference"` in results, and is used only by CI/lab.
- `lab/template_range.py` is the isolated verification range: HTTP, TCP, Unix socket and a fake
  Kubernetes API with two-state scenarios.
- Dynamic suites: `tests/test_probe_templates*.py`,
  `tests/test_probe_defense_bypass.py`, `test_probe_cache_gateway.py`,
  `test_probe_privesc.py`, `test_probe_cve.py`, `test_probe_longctx.py`.
- Coverage: `tools/template-coverage.py` → `docs/PROBE-COVERAGE.md` +
  `reports/probe-coverage/coverage.json`; per-module evidence digests are in
  `reports/probe-coverage/evidence.json`.
- Native run: `tools/native-verify.py` drives the static Linux probe over SSH
  (QEMU TCG Alpine guest) through the framed protocol, two states per template,
  three repeats per state.
  Result: **286/286 `runtime=rust`, 0 failures, 286/286 repeat-consistent**, binary sha256
  `c8d2f118460349a9c4303250b737adb0ccb28a1598e59c16d1f0d3f230b726f3` (probe 0.1.1), source
  commit `1f0f57c`; raw evidence in
  `reports/probe-coverage/evidence-native.json`. The fixed-state negative control is only
  conclusive for templates whose inputs come from the isolated test target (`PROBE-COVERAGE.md` §6).
- Lint: `tools/template-lint.py --strict` (schema, metadata equality,
  expressions, no `run.py`).

## 7. Migration status

- 286 module templates + 1 bootstrap registration, all dynamically exercised in
  two states against the isolated verification range.
- 48 templates are behavioural equivalents of the pre-migration module logic
  (defense bypass 11, cache 7, AI gateway 8, privilege chain 15, long-context 8
  minus overlaps counted once). The rest are probe-plan templates marked
  `fidelity: reduced`; they execute the real surface probe and emit
  documented findings but do not reproduce every Python branch.
- Legacy `run.py` files are removed. The `_*-common.py` / `_cve-specs.py`
  libraries are build-time specifications used by the template generators and
  tests; they are not reachable from the runtime.
- Legacy per-family Python unit tests for `run.py` internals were retired with
  the execution path; template dynamic suites replace them.

## 8. Invariants

- No interpreter in the target Pod.
- No host execution of module logic; no adapter fallback.
- RoE, level, surface, backup and audit gates unchanged.
- Every finding is anchored to sha256 evidence and a step archive.
- A missing probe fails loudly; a missing target surface is skipped and counted.

## 9. 证据 / 限制

- **目标侧零 Python**：目标 Pod 内只执行静态 Rust 探针与声明式 `template.json`；
  控制器只负责授权、降级、证据与报告，宿主不执行模块逻辑。
- **证据**：每个 finding 绑定步骤归档 SHA-256；参考运行时结果标记
  `runtime="reference"`，生产结果标记 `runtime="rust"`，两者不混写。
- **限制**：原生探针仍有 k8s 写动词、非核心 API 组、Unix socket、`fs.hash`、
  exec stdin 等能力缺口；缺口按模块记录，缺失时抛 `ProbeUnavailable`，不静默回退。
- **实测边界**：mock range 用于两态回归；真实 k3s 结论只在有 kubeconfig/探针二进制的
  环境出具，不与 mock 结果合并。
