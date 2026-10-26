#!/bin/sh
# Benign WAF probes: plain, encoded, double-encoded, case, chunked, oversized.
# The backend is a static python http.server: no payload is executed.
set -u
cd /root/defense-lab || exit 1
OUT=evidence/waf-probes.txt
: > "$OUT"
B=http://127.0.0.1:8080
req() {
  label="$1"; shift
  before=$(docker logs waf-backend 2>&1 | wc -l)
  code=$(curl -sS --max-time 25 -o /dev/null -w '%{http_code}' "$@" 2>>"$OUT")
  after=$(docker logs waf-backend 2>&1 | wc -l)
  echo "$label status=$code backend_delta=$((after - before))" | tee -a "$OUT"
}
{
  echo "=== versions ==="
  docker exec waf nginx -v 2>&1
  docker exec waf sh -c 'cat /opt/owasp-crs/CRS_VERSION 2>/dev/null || grep -rm1 ver /opt/owasp-crs/crs-setup.conf'
  docker exec waf sh -c 'dpkg -l 2>/dev/null | grep -i modsecurity | head -3'
  echo "=== probes ==="
} >> "$OUT"

req plain-benign-request "$B/v1/completions?q=INKBLADE-BENIGN:waf-inference:plain-benign-request"
req encoded-request-variant "$B/v1/completions?q=%3Cscript%3EINKBLADE-BENIGN%3C%2Fscript%3E"
req double-encoded-variant "$B/v1/completions?q=%253Cscript%253EINKBLADE-BENIGN%253C%252Fscript%253E"
req unicode-request-variant "$B/v1/completions?q=%EF%BC%9Cscript%EF%BC%9EINKBLADE-BENIGN"
req case-variant "$B/v1/completions?q=%3CScRiPt%3EINKBLADE-BENIGN%3C%2FsCrIpT%3E"
req sqli-literal "$B/v1/completions?q=INKBLADE-BENIGN%27%20UNION%20SELECT%20marker"

printf '{"prompt":"INKBLADE-BENIGN:waf-inference:chunked-request-variant","extra":"<script>marker</script>"}' > /tmp/waf-chunk.json
req chunked-request-variant -X POST -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @/tmp/waf-chunk.json "$B/v1/completions"

BIG=$(printf 'A%.0s' $(seq 1 9000))
req oversized-benign-variant "$B/v1/completions?q=INKBLADE-BENIGN:oversized&pad=$BIG"

echo "=== backend log tail ===" >> "$OUT"
docker logs waf-backend 2>&1 | tail -12 >> "$OUT"
echo "=== waf audit log tail ===" >> "$OUT"
docker exec waf sh -c 'tail -40 /var/log/modsecurity/audit.log 2>/dev/null || find /var/log -name "audit*.log" -exec tail -20 {} \;' >> "$OUT" 2>&1
echo "=== nginx error log tail (rule ids) ===" >> "$OUT"
docker exec waf sh -c 'grep -o "\[id \"[0-9]*\"\].*" /var/log/nginx/error.log 2>/dev/null | tail -20' >> "$OUT" 2>&1
cat "$OUT"
