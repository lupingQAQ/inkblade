#!/bin/sh
# =============================================================================
# artex-bench-setup.sh — guest-side (Alpine k3s VM) prep for the ARTEX bench.
#
# Idempotent. Installs docker if missing, writes the daemon proxy config that
# points at the QEMU user-net gateway (10.0.2.2 = host loopback, where the host
# proxy listens on 7897), starts dockerd and pulls the pinned images.
#
#   sh artex-bench-setup.sh pull      # install + pull images only
#   sh artex-bench-setup.sh status    # show docker/image size summary
#
# Pinned tags: ruoji6/artex:v0.3.23 (repo tag v0.3.23, commit 620ca5d) and
# postgres:16-alpine (same tag docker-compose.yml defaults to).
# =============================================================================
set -eu

ARTEX_IMAGE="${ARTEX_IMAGE:-ruoji6/artex:v0.3.23}"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PROXY="${PROXY:-http://10.0.2.2:7897}"

write_daemon_json() {
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
{
  "proxies": {
    "http-proxy": "$PROXY",
    "https-proxy": "$PROXY",
    "no-proxy": "localhost,127.0.0.1,10.42.0.0/16,10.43.0.0/16,10.0.2.0/24"
  },
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "2" }
}
EOF
}

install_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "[setup] installing docker via apk"
        apk update >/dev/null
        apk add --no-cache docker docker-cli-compose >/dev/null
    fi
    write_daemon_json
    rc-update add docker default >/dev/null 2>&1 || true
    if ! docker info >/dev/null 2>&1; then
        service docker start >/dev/null 2>&1 || rc-service docker start
        i=0
        while [ "$i" -lt 60 ]; do
            docker info >/dev/null 2>&1 && break
            i=$((i + 1)); sleep 2
        done
    fi
    docker info >/dev/null 2>&1 || { echo "[setup] dockerd did not come up" >&2; tail -20 /var/log/docker.log >&2 || true; exit 1; }
}

case "${1:-pull}" in
    pull)
        install_docker
        echo "[setup] docker: $(docker --version)"
        PULL_T0=$(awk '{printf "%d", $1}' /proc/uptime)
        for img in "$PG_IMAGE" "$ARTEX_IMAGE"; do
            echo "[setup] pulling $img"
            docker pull "$img" 2>&1 | tail -3
        done
        PULL_T1=$(awk '{printf "%d", $1}' /proc/uptime)
        echo "[setup] pull_seconds=$((PULL_T1 - PULL_T0))"
        echo "[setup] images:"
        docker images --format '{{.Repository}}:{{.Tag}} {{.Size}} {{.ID}}'
        echo "[setup] docker_root_bytes=$(du -sb /var/lib/docker 2>/dev/null | cut -f1)"
        ;;
    status)
        docker info 2>/dev/null | sed -n '1,40p'
        echo '--- images ---'
        docker images --format '{{.Repository}}:{{.Tag}} {{.Size}} {{.ID}}' 2>/dev/null || true
        echo '--- disk ---'
        df -h / | tail -1
        du -sh /var/lib/docker 2>/dev/null || true
        ;;
    *)
        echo "usage: $0 [pull|status]" >&2
        exit 2
        ;;
esac
