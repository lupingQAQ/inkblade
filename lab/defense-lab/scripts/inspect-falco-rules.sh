#!/bin/sh
# Inspect Falco default rules and run two extra benign write probes.
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /root/defense-lab || exit 1
POD=$(kubectl -n kube-system get pod -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
echo "falco_pod=$POD" | tee evidence/falco-rules.txt
{
  echo "--- Write below etc ---"
  kubectl -n kube-system exec "$POD" -- sh -c "grep -n -A7 'rule: Write below etc' /etc/falco/falco_rules.yaml"
  echo "--- Read sensitive file untrusted ---"
  kubectl -n kube-system exec "$POD" -- sh -c "grep -n -A7 'rule: Read sensitive file untrusted' /etc/falco/falco_rules.yaml"
  echo "--- disabled rule count ---"
  kubectl -n kube-system exec "$POD" -- sh -c "grep -c 'enabled: false' /etc/falco/falco_rules.yaml"
  echo "--- Write below binary dir ---"
  kubectl -n kube-system exec "$POD" -- sh -c "grep -n -A7 'rule: Write below binary dir' /etc/falco/falco_rules.yaml"
} >> evidence/falco-rules.txt 2>&1

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "start2=$TS" >> evidence/falco-probe-time.txt
kubectl -n default exec falco-probe -- sh -c '
  echo INKBLADE-BENIGN:falco:binary-dir-write > /bin/inkblade-benign-marker
  echo INKBLADE-BENIGN:falco:monitored-path-write2 > /tmp/inkblade-benign-monitored2.marker
' 2>&1
sleep 8
kubectl -n kube-system logs "$POD" --since-time="$TS" --timestamps 2>&1 >> evidence/falco-alerts.txt
echo "--- new alerts ---"
kubectl -n kube-system logs "$POD" --since-time="$TS" --timestamps 2>&1 | tail -20
