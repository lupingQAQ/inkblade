#!/bin/sh
# Real Trivy scans against benign local image samples (Docker socket in VM).
set -u
cd /root/defense-lab || exit 1
export TRIVY_CACHE_DIR=/root/defense-lab/trivy-cache
run() {
  name="$1"; ref="$2"
  echo "=== $name ($ref) ==="
  ./trivy image --image-src docker --scanners vuln,secret --skip-db-update \
    --format json --output "evidence/trivy-$name.json" --quiet "$ref"
  echo "rc=$?"
  ls -lh "evidence/trivy-$name.json"
}
run plain inkblade-benign/plain:lab
run secret inkblade-benign/secret:lab
run deep inkblade-benign/deep:lab
run compressed inkblade-benign/compressed:lab
run renamed inkblade-benign/renamed:lab
run alpine310 docker.io/library/alpine:3.10
