#!/bin/sh
# =============================================================================
# artex-bench-run.sh — guest-side ARTEX bench: start stack, measure, submit task.
#
# Runs inside the QEMU/Alpine VM. Prints `KEY=value` lines (parsed on the host by
# lab/qemu-k3s/artex-bench-collect.py) — no python/jq needed in the guest.
#
#   sh artex-bench-run.sh            # full run (clean start, task, samples)
#   KEEP=1 sh artex-bench-run.sh     # leave containers running afterwards
#
# What is measured (all wall-clock inside the guest):
#   PG_READY_MS            docker run postgres -> pg_isready OK
#   COLD_START_HEALTH_MS   docker run artex    -> GET /api/health == 200
#   AUTH_MS                POST /api/auth/init + /api/auth/login round trip
#   HEALTH_MS_LIST         N sequential GET /api/health latencies (ms)
#   TASK_MS                POST /api/tasks -> terminal status (or timeout)
#   STATS_*                docker stats samples (raw MemUsage/MemPerc strings)
#
# ARTEX is run unmodified (AGPL-3.0: black-box only, no code reuse).
# LLM traffic goes to the host mock at $LLM_BASE (10.0.2.2 = QEMU user-net host).
# =============================================================================
set -eu

ARTEX_IMAGE="${ARTEX_IMAGE:-ruoji6/artex:v0.3.23}"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PG_PASS="${PG_PASS:-artexbench}"
ADMIN_PASS="${ADMIN_PASS:-ArtexBench2026}"
LLM_BASE="${LLM_BASE:-http://10.0.2.2:18081/v1}"
LLM_MODEL="${LLM_MODEL:-mock-agent-model}"
MOCK_TARGET="${MOCK_TARGET:-http://10.0.2.2:30080}"
HEALTH_SAMPLES="${HEALTH_SAMPLES:-20}"
STATS_SAMPLES="${STATS_SAMPLES:-10}"
STATS_INTERVAL="${STATS_INTERVAL:-2}"
TASK_TIMEOUT_S="${TASK_TIMEOUT_S:-240}"
OUT="${OUT:-/root/artex-bench-raw.txt}"
KEEP="${KEEP:-0}"

: > "$OUT"
log() { echo "[run] $*" >&2; }
emit() { echo "$*" >> "$OUT"; }
now_ms() { awk '{printf "%d", $1 * 1000}' /proc/uptime; }
code_of() { curl -s -o "$2" -w '%{http_code}' -m "${3:-10}" "$1" || echo "000"; }

emit "TS_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "GUEST_CPUS=$(nproc)"
emit "GUEST_MEM_TOTAL_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
emit "GUEST_LOADAVG=$(cut -d' ' -f1-3 /proc/loadavg)"

# --- 0. clean slate -----------------------------------------------------------
docker rm -f artex artex-pg >/dev/null 2>&1 || true
docker network rm artex-net >/dev/null 2>&1 || true
rm -rf /root/artex-data
docker network create artex-net >/dev/null
log "network ready"

# --- 1. postgres --------------------------------------------------------------
T0=$(now_ms)
docker run -d --name artex-pg --network artex-net \
    -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=artex \
    "$PG_IMAGE" >/dev/null
i=0; pg_ready=0
while [ "$i" -lt 150 ]; do
    if docker exec artex-pg pg_isready -U artex -d artex >/dev/null 2>&1; then pg_ready=1; break; fi
    i=$((i + 1)); sleep 2
done
emit "PG_READY=$pg_ready"
emit "PG_READY_MS=$(( $(now_ms) - T0 ))"
log "postgres ready=$pg_ready after $(( $(now_ms) - T0 ))ms"

# --- 2. artex cold start (image already pulled; this is container start only) --
T1=$(now_ms)
docker run -d --name artex --network artex-net -p 8787:8787 \
    -e ARTEX_PG_DSN="postgres://artex:$PG_PASS@artex-pg:5432/artex?sslmode=disable" \
    -e ARTEX_LLM_PROVIDER=openai \
    -e ARTEX_LLM_BASE_URL="$LLM_BASE" \
    -e ARTEX_LLM_MODEL="$LLM_MODEL" \
    -e OPENAI_API_KEY=mock-key-for-lab \
    -v /root/artex-data:/app/data \
    "$ARTEX_IMAGE" >/dev/null

i=0; healthy=0
while [ "$i" -lt 420 ]; do
    c=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:8787/api/health || true)
    if [ "$c" = "200" ]; then healthy=1; break; fi
    i=$((i + 1)); sleep 1
done
emit "HEALTH_OK=$healthy"
emit "COLD_START_HEALTH_MS=$(( $(now_ms) - T1 ))"
emit "COLD_START_HEALTH_HTTP=$c"
log "artex health=$healthy after $(( $(now_ms) - T1 ))ms"

# --- 3. first-run admin password + login --------------------------------------
AUTH_T0=$(now_ms)
init_code=$(curl -s -o /tmp/init.json -w '%{http_code}' -m 30 -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"$ADMIN_PASS\"}" http://127.0.0.1:8787/api/auth/init || echo 000)
login_code=$(curl -s -o /tmp/login.json -w '%{http_code}' -m 30 -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"$ADMIN_PASS\"}" http://127.0.0.1:8787/api/auth/login || echo 000)
TOKEN=$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/login.json 2>/dev/null || true)
emit "AUTH_INIT_HTTP=$init_code"
emit "AUTH_LOGIN_HTTP=$login_code"
emit "AUTH_TOKEN_LEN=${#TOKEN}"
emit "AUTH_MS=$(( $(now_ms) - AUTH_T0 ))"
log "auth init=$init_code login=$login_code token_len=${#TOKEN}"

# --- 4. idle RSS / API latency (30 s after start, loop steady state) ----------
sleep 30
AUTH_HDR="Authorization: Bearer $TOKEN"
LIST=""
n=0
while [ "$n" -lt "$HEALTH_SAMPLES" ]; do
    t=$(now_ms)
    c=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1:8787/api/health || echo 000)
    dt=$(( $(now_ms) - t ))
    LIST="$LIST,$dt"
    n=$((n + 1))
done
emit "HEALTH_MS_LIST=${LIST#,}"
emit "HEALTH_LAST_HTTP=$c"

emit "TASKS_LIST_BEGIN_MS=$(now_ms)"
tt=$(now_ms)
tasks_http=$(curl -s -o /tmp/tasks.json -w '%{http_code}' -m 20 -H "$AUTH_HDR" http://127.0.0.1:8787/api/tasks || echo 000)
emit "TASKS_LIST_MS=$(( $(now_ms) - tt ))"
emit "TASKS_LIST_HTTP=$tasks_http"

S=1
while [ "$S" -le "$STATS_SAMPLES" ]; do
    docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}' 2>/dev/null > /tmp/stats.txt || true
    joined=$(awk 'BEGIN{ORS=""} {if (NR>1) printf ";;"; printf "%s", $0} END{print ""}' /tmp/stats.txt)
    emit "STATS_$S=$joined"
    [ "$S" -lt "$STATS_SAMPLES" ] && sleep "$STATS_INTERVAL"
    S=$((S + 1))
done

# --- 5. one scan task against the shared mock target --------------------------
# same-target bench: the goal names the exact probe surface (route manifest,
# unauth admin action, weight pull) so the scripted-planner mock and the
# Trident chain flat-network-admin-plane-weight-poison exercise the same faces.
now_epoch_ms() { date +%s%3N 2>/dev/null | awk '{ if (length($0) <= 10) printf "%d000", $0; else print $0 }'; }
GOAL="Probe the authorized lab target $MOCK_TARGET without credentials: fetch its route manifest, exercise unauthenticated admin action and weight pull, and record confirmed endpoints as findings."
DESC="ARTEX same-target bench scan of the Trident mock lab at $MOCK_TARGET (authorized lab)."
TASK_BODY=$(printf '{"description":"%s","goal":"%s"}' "$DESC" "$GOAL")
T2=$(now_ms)
task_code=$(curl -s -o /tmp/task.json -w '%{http_code}' -m 60 -X POST \
    -H 'Content-Type: application/json' -H "$AUTH_HDR" \
    -d "$TASK_BODY" http://127.0.0.1:8787/api/tasks || echo 000)
TASK_ID=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p' /tmp/task.json 2>/dev/null | head -1)
emit "TASK_HTTP=$task_code"
emit "TASK_ID=$TASK_ID"
emit "TASK_ACCEPT_MS=$(( $(now_ms) - T2 ))"
emit "TASK_SUBMIT_EPOCH_MS=$(now_epoch_ms)"
log "task create http=$task_code id=$TASK_ID"

status=""
elapsed=0
S=1
if [ -n "$TASK_ID" ]; then
    while [ "$elapsed" -lt "$TASK_TIMEOUT_S" ]; do
        curl -s -o /tmp/task-get.json -m 10 -H "$AUTH_HDR" \
            "http://127.0.0.1:8787/api/tasks/$TASK_ID" >/dev/null 2>&1 || true
        status=$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/task-get.json 2>/dev/null | head -1)
        emit "TASK_POLL=$elapsed,$status"
        # RSS during the task window (docker stats while the task runs)
        docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}' 2>/dev/null > /tmp/tstats.txt || true
        joined=$(awk 'BEGIN{ORS=""} {if (NR>1) printf ";;"; printf "%s", $0} END{print ""}' /tmp/tstats.txt)
        emit "TASK_STATS_$S=$joined"
        S=$((S + 1))
        case "$status" in
            done|failed|timeout) break ;;
        esac
        sleep 3
        elapsed=$((elapsed + 3))
    done
fi
emit "TASK_FINAL_STATUS=$status"
emit "TASK_TOTAL_MS=$(( $(now_ms) - T2 ))"
emit "TASK_DONE_EPOCH_MS=$(now_epoch_ms)"
# full task list JSON (findings / goals / tokens) as single-line evidence
TASKS_JSON=$(curl -s -m 20 -H "$AUTH_HDR" http://127.0.0.1:8787/api/tasks)
emit "TASKS_JSON=$TASKS_JSON"

# --- 6. disk / image footprint ------------------------------------------------
docker images --format '{{.Repository}}:{{.Tag}}|{{.Size}}|{{.ID}}' 2>/dev/null > /tmp/images.txt || true
while IFS= read -r line; do emit "IMAGE=$line"; done < /tmp/images.txt
docker system df 2>/dev/null | sed 's/  */ /g' > /tmp/df.txt || true
while IFS= read -r line; do emit "SYSTEM_DF=$line"; done < /tmp/df.txt
emit "DOCKER_ROOT_BYTES=$(du -sb /var/lib/docker 2>/dev/null | cut -f1)"
emit "DISK_ROOT=$(df -k / | awk 'NR==2{print $2"|"$3"|"$4}')"
emit "GUEST_LOADAVG_END=$(cut -d' ' -f1-3 /proc/loadavg)"
emit "TS_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$KEEP" != "1" ]; then
    log "leaving containers running (KEEP=0 still keeps them for host-side inspection); use 'docker rm -f artex artex-pg' to clean"
fi
log "done -> $OUT"
