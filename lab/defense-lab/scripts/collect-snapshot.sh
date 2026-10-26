#!/bin/sh
# Collect real cluster/product state for the defense lab (read-only).
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /root/defense-lab || exit 1
OUT=evidence/cluster-snapshot.txt
{
  echo "=== date ==="; date -u
  echo "=== kernel ==="; uname -a
  echo "=== lsm ==="; cat /sys/kernel/security/lsm 2>&1
  echo "=== btf ==="; ls -l /sys/kernel/btf/vmlinux 2>&1
  echo "=== k3s ==="; k3s --version 2>&1 | head -2
  echo "=== nodes ==="; timeout 60 kubectl get nodes -o wide 2>&1
  echo "=== kyverno pods ==="; timeout 60 kubectl -n kyverno get pods -o wide 2>&1
  echo "=== kyverno policies ==="; timeout 60 kubectl get validatingpolicy 2>&1
  echo "=== kyverno images ==="; timeout 60 kubectl -n kyverno get deploy -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[0].image}{"\n"}{end}' 2>&1
  echo "=== falco ds ==="; timeout 60 kubectl -n kube-system get ds falco -o wide 2>&1
  echo "=== falco image ==="; crictl ps | grep kube-system | grep ' falco ' 2>&1
  echo "=== falco version ==="; crictl logs $(crictl ps | grep kube-system | grep ' falco ' | awk '{print $1}' | head -1) 2>&1 | grep -m1 'Falco version'
  echo "=== docker images ==="; docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E 'modsecurity|python|alpine|inkblade' 2>&1
  echo "=== waf containers ==="; docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep waf 2>&1
  echo "=== trivy version ==="; ./trivy --version 2>&1 | head -2
  echo "=== trivy db ==="; ls -lh trivy-cache/db/trivy.db 2>&1
  echo "=== disk ==="; df -h / | tail -1
  echo "=== memory ==="; free -m | head -2
} > "$OUT" 2>&1
cat "$OUT"
