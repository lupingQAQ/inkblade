#!/bin/sh
# Relax Kyverno startup probes for slow QEMU TCG. This changes only the lab
# deployment's probe timing, not product code.
set -eu
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
PATCH='[{"op":"replace","path":"/spec/template/spec/containers/0/startupProbe/failureThreshold","value":90},{"op":"replace","path":"/spec/template/spec/containers/0/startupProbe/periodSeconds","value":10},{"op":"replace","path":"/spec/template/spec/containers/0/startupProbe/timeoutSeconds","value":10}]'
for d in kyverno-admission-controller kyverno-background-controller kyverno-cleanup-controller kyverno-reports-controller; do
  echo "== $d"
  kubectl -n kyverno patch deploy "$d" --type=json -p "$PATCH" || true
done
