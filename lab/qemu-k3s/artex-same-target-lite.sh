#!/bin/sh
# artex-same-target-lite.sh — iteration driver: clean tasks, submit bench task, poll.
# Prints KEY=value lines; JSON blobs on single lines.
set -eu
API=http://127.0.0.1:8787
ADMIN_PASS="${ADMIN_PASS:-ArtexBench2026}"
TARGET="${MOCK_TARGET:-http://10.0.2.2:18080}"
TASK_TIMEOUT_S="${TASK_TIMEOUT_S:-420}"
OUT="${OUT:-/root/artex-same-target-raw.txt}"
: > "$OUT"
log() { echo "[lite] $*" >&2; }
emit() { echo "$*" >> "$OUT"; }
now_ms() { awk '{printf "%d", $1 * 1000}' /proc/uptime; }

TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"ARTEX\",\"password\":\"$ADMIN_PASS\"}" \
    $API/api/auth/login | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "login failed" >&2; exit 1; }
AUTH="Authorization: Bearer $TOKEN"
emit "LOGIN_OK=1"

# --- clean slate: delete every existing task (engine stops, graphs dropped) ---
IDS=$(curl -s -H "$AUTH" $API/api/tasks | tr ',' '\n' | sed -n 's/.*"id": *"\([0-9]*\)".*/\1/p')
for id in $IDS; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X DELETE -H "$AUTH" "$API/api/tasks/$id" || echo 000)
    emit "DELETED_TASK=$id,$code"
    log "deleted task $id -> $code"
    sleep 2
done

GOAL="Probe the authorized lab target $TARGET without credentials: fetch its route manifest, exercise unauthenticated admin action and weight pull, and record confirmed endpoints as findings."
DESC="ARTEX same-target bench scan of the InkBlade mock lab at $TARGET (authorized lab)."

T0=$(now_ms)
code=$(curl -s -o /tmp/task.json -w '%{http_code}' -m 60 -X POST -H 'Content-Type: application/json' -H "$AUTH" \
    -d "{\"description\":\"$DESC\",\"goal\":\"$GOAL\"}" $API/api/tasks || echo 000)
TASK_ID=$(sed -n 's/.*"id": *"\([0-9]*\)".*/\1/p' /tmp/task.json | head -1)
emit "TASK_HTTP=$code"
emit "TASK_ID=$TASK_ID"
emit "TASK_ACCEPT_MS=$(( $(now_ms) - T0 ))"
emit "TASK_SUBMIT_EPOCH_MS=$(date +%s%3N)"
log "task created http=$code id=$TASK_ID"

status=""
elapsed=0
while [ "$elapsed" -lt "$TASK_TIMEOUT_S" ]; do
    curl -s -o /tmp/task-get.json -m 10 -H "$AUTH" "$API/api/tasks/$TASK_ID" >/dev/null 2>&1 || true
    status=$(sed -n 's/.*"status": *"\([^"]*\)".*/\1/p' /tmp/task-get.json | head -1)
    emit "TASK_POLL=$elapsed,$status"
    case "$status" in
        done|failed|timeout) break ;;
    esac
    sleep 3
    elapsed=$((elapsed + 3))
done
emit "TASK_FINAL_STATUS=$status"
emit "TASK_TOTAL_MS=$(( $(now_ms) - T0 ))"
emit "TASK_DONE_EPOCH_MS=$(date +%s%3N)"

# full task list JSON (findings counts, goals, tokens) as single-line evidence
TASKS_JSON=$(curl -s -m 20 -H "$AUTH" $API/api/tasks)
emit "TASKS_JSON=$TASKS_JSON"
TASK_JSON=$(curl -s -m 20 -H "$AUTH" "$API/api/tasks/$TASK_ID")
emit "TASK_JSON=$TASK_JSON"
log "final status=$status"
