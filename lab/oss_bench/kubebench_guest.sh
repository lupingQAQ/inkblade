#!/bin/sh
# kube-bench guest runner (Alpine/k3s QEMU TCG lab).
# Runs inside the guest over ssh (sh -s < this file, LF endings).  Prints
# machine-readable markers; the host-side bench collects them.
#
# Env: KUBEBENCH_RUNS (default 1), PROFILE (optional benchmark id).
set -u

IMAGE="aquasec/kube-bench:v0.16.0"
RUNS="${KUBEBENCH_RUNS:-1}"
PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--benchmark $PROFILE"

echo "__KB_IMAGE__ $IMAGE"
docker images "$IMAGE" --format '{{.Repository}}:{{.Tag}} {{.Size}}' | sed 's/^/__KB_IMGSIZE__ /'

i=1
while [ "$i" -le "$RUNS" ]; do
  OUT="/tmp/kubebench-run$i.json"
  T0=$(date +%s)
  docker run --rm --network=host --pid=host \
    -e KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
    -v /etc:/etc:ro -v /var:/var:ro \
    "$IMAGE" $PROFILE_ARG --json > "$OUT" 2> "/tmp/kubebench-run$i.err"
  RC=$?
  T1=$(date +%s)
  echo "__KB_RUN__ run=$i rc=$RC elapsed_s=$(( T1 - T0 )) json_bytes=$(wc -c < "$OUT" | tr -d ' ')"
  i=$(( i + 1 ))
done

echo "__KB_STDERR_TAIL__"
tail -3 /tmp/kubebench-run1.err 2>/dev/null
echo "__KB_JSON_FOOTER__"
tail -c 200 /tmp/kubebench-run1.json 2>/dev/null
echo ""
echo "__KB_DONE__"
