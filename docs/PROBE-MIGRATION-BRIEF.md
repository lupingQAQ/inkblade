# Probe migration brief (module → declarative template)

Read this before touching a module. The runtime contract is
`probe/TEMPLATE-ENGINE.md`; the schema is
`probe/schema/probe-template.schema.json`; the evaluator is
`inkblade/tpl/expr.py` + `inkblade/tpl/engine.py`.

## Non-negotiables

- A module is **only** `module.json` + `template.json`. Delete `run.py` when the
  template is equivalent. No Python, shell or interpreter in the target Pod.
- No host fallback: if a template cannot run, it must fail/skip explicitly.
  Never call the old Python implementation from the template path.
- Keep `module.json` metadata unchanged except adding/keeping
  `"execution": "template"` (default). `template.meta` must equal it
  (`name.zh/en`, `series`, `min_level`, `writes`, `requires`).
- Write-capable modules keep `writes: true`, `modes.backup_write: true`,
  `requires_backup: true`, and mark write steps with `"write": true`. RoE,
  backup receipts and audit stay in `core/runner.py` — do not bypass them.
- Only edit your assigned module directories and your batch test file. Do not
  touch shared code, other modules, docs or git.

## Template shape (canonical)

```json
{
  "schema": "inkblade-probe-template-v1",
  "key": "module-key",
  "version": "1.0.0",
  "meta": {"name": {"zh": "...", "en": "..."}, "series": "...",
           "min_level": "...", "writes": false, "requires": [],
           "surfaces": [], "cves": [], "fidelity": "equivalent"},
  "inputs": {"target": {"from": "params.target", "required": true}},
  "defaults": {"timeout_ms": 8000, "tls_verify": false},
  "vars": {"static": "values"},
  "computed": {"state": "if(steps.x.status == 200, 'open', 'closed')"},
  "steps": [
    {"id": "probe", "op": "http", "method": "GET", "url": "{{input.target}}/v1/models",
     "headers": {}, "body": null, "save": "probe", "allow_failure": true,
     "expect": {"status": [200]}}
  ],
  "checks": [{"id": "reachable", "when": "steps.probe.status != null",
              "fatal": false, "message": "..."}],
  "findings": [
    {"id": "exposed", "when": "steps.probe.status == 200", "sev": "high",
     "title": "...", "detail": "...", "evidence": "{{steps.probe.sha256}}",
     "mapping": "...", "fix": "..."}
  ],
  "artifacts": [{"name": "trace.json", "kind": "json",
                 "fields": {"route": "'/v1/models'", "status": "steps.probe.status"}}],
  "payloads": {"benign": {"marker": "INKBLADE-BENIGN"}},
  "limits": {"timeout_ms": 60000, "max_http_requests": 32}
}
```

Ops: `http` (method/url/headers/body/expect), `tcp` (host/port/send/expect_prefix),
`exec` (argv array only), `fs` (read/list/stat/write/hash; `json:true` parses),
`k8s` (verb get/list/create/patch/delete/apply, resource/api_version/namespace/name/body),
`socks` (socket_path/request), `spawn` (argv/detach).

Step fields: `when` (expression), `save`, `write`, `allow_failure`, `timeout_ms`.
Findings: `for_each` + `as` (default `it`), `when`, `sev`, `title/detail/evidence/
mapping/fix`, `cves`, `version_matrix`, `max_emit`.
Artifacts: `from` expression **or** `fields` object of expressions. Literal
strings in `fields` need quotes: `"'/v1/models'"`.
`computed` runs after steps; reference as `vars.<name>` or `computed.<name>`.

Expressions: paths (`steps.x.json.y`, `params.x`, `input.x`, `vars.x`, `it.x`),
`and/or/not`, comparisons, `in`, `contains`, `startswith`, `endswith`,
`matches(pattern, value)` (glob), `any/all/count_if/filter/map(list, expr)`,
`len/count/int/str/lower/upper/trim/default/coalesce/sha256/join/split/json`,
`if(cond,a,b)`, `[...]` array literals, `+` for numbers/strings (also `concat`
for lists). Missing values are `null`; never invent values.

## Workflow per module

1. Read `module.json`, `run.py`, the module's tests and family fixtures. The old
   implementation is the behavioural spec; keep finding severities and the
   core condition semantics.
2. Write `template.json`. Prefer 1–8 steps. For snapshot modules use
   `fs read` + `computed` + `for_each` findings. For target modules use the real
   endpoints/methods from `run.py` and assertion logic from its `if` branches.
3. Keep `version_matrix` for CVE/version modules (product + source + vulnerable/
   fixed ranges) and `payloads` (benign/attack variants) where the module
   distinguishes them.
4. `python tools/template-lint.py` must be clean; `python tools/template-run.py
   --module <key> --fixture ...` or `--range` must produce findings.
5. Add a test in your batch file (see `tests/test_probe_defense_bypass.py` and
   `tests/test_probe_templates.py`): vulnerable state ⇒ expected finding(s),
   fixed/absent state ⇒ none or info only. Use `lab/template_range.py` for HTTP,
   existing `lab/fixtures/**` for snapshots. Record evidence:
   `reports/probe-coverage/evidence.json` may be updated in the test's
   `tearDownClass` (see the defense suite); otherwise just report the result.
6. Delete `run.py` only after the template passes. Update the family test file so
   it no longer imports `run.py`; replace direct-module assertions with template
   execution. If a test checks Python internals that no longer exist, remove that
   case and add an equivalent template assertion.
7. Report per module: key, fidelity (`equivalent`/`reduced`), what changed,
   test names, and any semantics you could not express.

## Commands

```powershell
$env:PYTHONPATH='.'
$py = "python"
& $py tools/template-lint.py
& $py tools/template-run.py --module <key> --fixture <path>
& $py -m unittest tests.test_probe_<batch> -v
```

Notes:
- Files are UTF-8; PowerShell `Get-Content` may mis-render Chinese. Use Python
  with `encoding="utf-8"` for edits/inspection.
- Do not run the whole unittest suite (20+ minutes). Run only your batch tests.
- Existing family simulators (`lab/cache_sim.py`, `lab/ai_gateway_sim.py`,
  `lab/privesc_sim.py`, …) are the mock ranges; reuse their `start_all(mode=...)`
  helpers for two-state tests.
