#!/bin/sh
# Run Kyverno admission probes and record raw output (real cluster).
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /root/defense-lab || exit 1
OUT=/root/defense-lab/evidence/kyverno-probes.txt
: > "$OUT"
echo "===== kubectl apply (multi-doc, expected: 3 denies / 2 admits) =====" >> "$OUT"
kubectl apply -f 20-kyverno-probes.yaml >> "$OUT" 2>&1
echo "rc=$?" >> "$OUT"
sleep 3
echo "===== pods in defense-lab =====" >> "$OUT"
kubectl get pods -n defense-lab -o wide >> "$OUT" 2>&1
echo "===== pods in default (exempt-namespace control) =====" >> "$OUT"
kubectl get pods -n default -o wide | grep kyverno-probe >> "$OUT" 2>&1
echo "===== recent admission events =====" >> "$OUT"
kubectl get events -n defense-lab --sort-by=.lastTimestamp | tail -12 >> "$OUT" 2>&1
cat "$OUT"
