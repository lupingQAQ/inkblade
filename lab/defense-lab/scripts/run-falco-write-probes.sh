#!/bin/sh
# Falco probes via crictl (kubectl exec hangs under QEMU TCG load).
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /root/defense-lab || exit 1
FALCO_ID=$(crictl ps | grep kube-system | grep ' falco ' | awk '{print $1}' | head -1)
PROBE_ID=$(crictl ps | grep falco-probe | awk '{print $1}' | head -1)
echo "falco=$FALCO_ID probe=$PROBE_ID" | tee evidence/falco-ids.txt
{
  echo "--- Write below etc ---"
  crictl exec -i "$FALCO_ID" sh -c "grep -n -A7 'rule: Write below etc' /etc/falco/falco_rules.yaml"
  echo "--- Read sensitive file untrusted ---"
  crictl exec -i "$FALCO_ID" sh -c "grep -n -A7 'rule: Read sensitive file untrusted' /etc/falco/falco_rules.yaml"
  echo "--- Write below binary dir ---"
  crictl exec -i "$FALCO_ID" sh -c "grep -n -A7 'rule: Write below binary dir' /etc/falco/falco_rules.yaml"
  echo "--- enabled false count ---"
  crictl exec -i "$FALCO_ID" sh -c "grep -c 'enabled: false' /etc/falco/falco_rules.yaml"
} > evidence/falco-rules.txt 2>&1

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "start3=$TS" >> evidence/falco-probe-time.txt
crictl exec -i "$PROBE_ID" sh -c '
  echo INKBLADE-BENIGN:falco:binary-dir-write > /bin/inkblade-benign-marker
  echo INKBLADE-BENIGN:falco:monitored-path-write3 > /tmp/inkblade-benign-monitored3.marker
  cat /bin/inkblade-benign-marker
' 2>&1
sleep 8
echo "--- falco alerts since $TS ---"
crictl logs --since="$TS" "$FALCO_ID" 2>&1 | tee -a evidence/falco-alerts.txt | tail -40
