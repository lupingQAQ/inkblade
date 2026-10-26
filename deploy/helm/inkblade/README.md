# InkBlade Helm chart

Deploys the InkBlade web UI + API for authorized ML-cluster assessment.

```bash
helm lint deploy/helm/inkblade
helm template trial deploy/helm/inkblade --namespace inkblade > /dev/null
helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace
```

`helm install` prints the five-minute trial path (see `templates/NOTES.txt`).
Longer walkthroughs: `docs/TRIAL.md`, `docs/PILOT-KIT.md`.

## Safety defaults

| Setting | Default | Why |
|---|---|---|
| `readOnly` | `true` | ServiceAccount receives `get/list/watch` only |
| `containerSecurityContext.readOnlyRootFilesystem` | `true` | no writable system paths; `/data` + `/tmp` only |
| `podSecurityContext.runAsUser` | `10001` | matches the image's non-root user |
| `rbac.includeSecrets` | `true` | credential-exposure findings; set `false` for strict least privilege |
| `persistence.enabled` | `true` | evidence survives restarts |

Write verbs are opt-in twice: `readOnly=false` **and** `rbac.allowWrite=true`.
Even then, the application's RoE gate returns HTTP 423 until a signed rules of
engagement record exists for the workspace.

## Values worth knowing

| Key | Meaning |
|---|---|
| `image.repository` / `image.tag` | image reference, tag defaults to chart `appVersion` |
| `usersSecret.name` | Secret with a `users.json` from `inkblade user add` |
| `persistence.existingClaim` | reuse an existing PVC instead of creating one |
| `rbac.clusterWide` | `false` renders a namespaced Role/RoleBinding per `rbac.namespaces` |
| `extraArgs` | appended after `--home /data ui --host 0.0.0.0` |
| `probes.*.path` | defaults to the public `/api/v1/openapi.json` |

## Uninstall

```bash
helm uninstall inkblade --namespace inkblade
```

The PVC (`<release>-inkblade-data`) is intentionally **not** deleted; remove it
manually once the evidence has been archived.
