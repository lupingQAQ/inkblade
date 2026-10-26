#!/bin/sh
# Start Coraza/ModSecurity + OWASP CRS WAF in front of a static Python backend
# inside the QEMU VM (Docker), then send benign marker requests.
set -u
cd /root/defense-lab || exit 1
docker rm -f waf-backend waf 2>/dev/null || true
docker network create wafnet 2>/dev/null || true
docker run -d --name waf-backend --network wafnet docker.io/library/python:3.12-alpine \
  python -m http.server 8080 >/dev/null
docker run -d --name waf --network wafnet -p 8080:8080 \
  -e BACKEND=http://waf-backend:8080 -e PORT=8080 -e SERVER_NAME=localhost \
  -e MODSEC_RULE_ENGINE=on -e BLOCKING_PARANOIA=1 \
  owasp/modsecurity-crs:nginx >/dev/null
sleep 8
docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E 'waf'
echo "--- waf version ---"
docker exec waf nginx -v 2>&1
docker exec waf sh -c 'cat /opt/owasp-crs/crs-setup.conf 2>/dev/null | grep -m1 -i version; ls /opt/owasp-crs/rules | wc -l'
