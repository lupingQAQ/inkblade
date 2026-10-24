#!/bin/sh
# install-k3s.sh -- run INSIDE the installed Alpine VM (QEMU TCG guest).
#
# Prepares an Alpine host for single-node k3s (cgroups, swap off, br_netfilter),
# installs k3s with traefik/metrics-server disabled to keep the 2 GB TCG guest
# usable, then waits for the node to become Ready and dumps cluster state.
#
# Prints "K3S-READY" only after `kubectl get nodes` reports Ready.
set -eu
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

echo "[install-k3s] base packages (apk)"
apk update
apk add --no-cache curl ca-certificates iptables ip6tables conntrack-tools bash

echo "[install-k3s] host prep: swap off, modules, forwarding"
swapoff -a 2>/dev/null || true
sed -i '/[[:space:]]swap[[:space:]]/s/^/#/' /etc/fstab 2>/dev/null || true
modprobe br_netfilter 2>/dev/null || true
modprobe overlay 2>/dev/null || true
grep -qx br_netfilter /etc/modules 2>/dev/null || echo br_netfilter >> /etc/modules
grep -qx overlay /etc/modules 2>/dev/null || echo overlay >> /etc/modules
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-k3s.conf
mount | grep -E 'cgroup' || true

echo "[install-k3s] installing k3s (skip selinux runtime, disable traefik/metrics-server)"
curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
# shellcheck disable=SC2086
INSTALL_K3S_SKIP_SELINUX_RUNTIME=1 \
    INSTALL_K3S_EXEC="--disable traefik --disable metrics-server --write-kubeconfig-mode 644" \
    sh /tmp/k3s-install.sh

echo "[install-k3s] waiting for node Ready (TCG is slow: up to 20 min)"
i=0
while [ "$i" -lt 240 ]; do
    if kubectl get nodes 2>/dev/null | grep -q ' Ready'; then
        echo "[install-k3s] node Ready after $((i * 5))s"
        break
    fi
    i=$((i + 1))
    sleep 5
done

{
    echo "--- k3s version ---"
    k3s --version || true
    echo "--- nodes ---"
    kubectl get nodes -o wide || true
    echo "--- kube-system pods ---"
    kubectl -n kube-system get pods -o wide || true
    echo "--- services ---"
    kubectl get svc -A || true
} 2>&1

if ! kubectl get nodes 2>/dev/null | grep -q ' Ready'; then
    echo "[install-k3s] ERROR: node never became Ready; last k3s log:" >&2
    tail -n 80 /var/log/k3s.log 2>/dev/null || true
    rc-service k3s status 2>/dev/null || true
    exit 4
fi

echo "K3S-READY"
