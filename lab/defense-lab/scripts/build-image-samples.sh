#!/bin/sh
# Build benign image samples for the real Trivy lab.
set -eu
export DOCKER_BUILDKIT=0
cd /root/defense-lab || exit 1
mkdir -p samples
mk() {
  name="$1"; body="$2"
  mkdir -p "samples/$name"
  printf '%s\n' "$body" > "samples/$name/Dockerfile"
  docker build -q -t "inkblade-benign/$name:lab" "samples/$name"
}
mk plain "FROM docker.io/library/alpine:3.21
RUN echo INKBLADE-BENIGN:imagescan:plain-layer-sample > /opt/inkblade-benign-plain.txt"
mk secret "FROM docker.io/library/alpine:3.21
RUN printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /opt/inkblade-benign-creds.txt"
mk deep "FROM docker.io/library/alpine:3.21
RUN printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n' > /opt/inkblade-deep-creds.txt
RUN rm -f /opt/inkblade-deep-creds.txt && echo INKBLADE-BENIGN:imagescan:deep-layer-benign > /opt/inkblade-benign-deep.txt"
mk compressed "FROM docker.io/library/alpine:3.21
RUN mkdir -p /tmp/c && printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n' > /tmp/c/creds.txt && tar czf /opt/inkblade-benign-archive.tgz -C /tmp/c creds.txt && rm -rf /tmp/c"
mk renamed "FROM docker.io/library/alpine:3.21
RUN cp /bin/busybox /usr/local/bin/not-a-rootkit && echo INKBLADE-BENIGN:imagescan:renamed-benign-tool-layer > /usr/local/bin/readme.txt"
docker pull -q docker.io/library/alpine:3.10 >/dev/null
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep -E 'inkblade-benign|alpine'
