#!/bin/sh
# Falco benign probes in the real QEMU k3s cluster.
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /root/defense-lab || exit 1
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "start=$TS" | tee evidence/falco-probe-time.txt
kubectl -n default exec falco-probe -- sh -c '
  echo INKBLADE-BENIGN:falco:monitored-path-write > /tmp/inkblade-benign-monitored.marker
  echo INKBLADE-BENIGN:falco:sensitive-path-access > /etc/inkblade-benign-sensitive.marker
  cp /bin/echo /tmp/inkblade-echo
  /tmp/inkblade-echo INKBLADE-BENIGN:falco:tool-rename-exec
  cat /etc/inkblade-benign-sensitive.marker
' 2>&1
echo "exec_rc=$?"
sleep 10
kubectl -n kube-system logs -l app.kubernetes.io/name=falco --since-time="$TS" --timestamps 2>&1 > evidence/falco-alerts.txt
echo "--- alerts ---"
wc -l evidence/falco-alerts.txt
tail -60 evidence/falco-alerts.txt
