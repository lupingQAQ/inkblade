#!/usr/bin/env bash
# =============================================================================
# lab/bench/artex-bench.sh — ARTEX 同靶场 bench 计时脚本（交付脚本 + 说明，本任务不执行）
#
# 依据：Trident 设计 spec 第 11 节（对标 ARTEX）与 11.2 方法——
#   「bench 脚本化：资源采样、端到端计时、断言写入对比报告；
#     ARTEX 侧用其 docker-compose.bench.yml 同靶场跑（遵循其 AGPL，只测不改造）」。
#
# 用途：在 WSL Ubuntu 实验室对 ARTEX（本地备份 .slim/clonedeps/repos/RuoJi6__ARTEX，
#   v0.3.23，Go + PostgreSQL + Next.js）做黑盒计时，与 Trident（lab/bench/bench.py
#   smoke，同靶场同路由集）对比，数据进 BENCH-RESULT.md / 交付附录「选型对比」。
#
# 公平性约定：
#   - 同一 mock 靶场（lab/mock_targets.py，vulnerable 姿态，同端口同路由）；
#   - ARTEX 原样运行（AGPL：零代码复用、零改造，仅计时与资源采样）；
#   - 各自记录硬件与运行环境；冷启动计时从 compose up 到服务健康检查通过。
#
# 用法（WSL 实验室，需 docker + docker compose + curl + jq 可选）：
#   # 1) 先起共享靶场（WSL 或 Windows 侧均可，监听 0.0.0.0 供容器访问）：
#   python3 lab/mock_targets.py --port 18080 --mode vulnerable
#   # 2) 运行本脚本：
#   ARTEX_DIR=/mnt/d/llm-audit-2026-10/.slim/clonedeps/repos/RuoJi6__ARTEX \
#   MOCK_URL=http://host.docker.internal:18080 \
#   bash lab/bench/artex-bench.sh
#
# 输出：lab/bench/out/artex-bench.json + artex-bench.md（冷启动 ms / 容器常驻内存
#   采样 / 端到端任务计时占位；LLM 任务阶段标记 manual，需其管理界面/API 就绪后补测）。
#
# 实验室边界：本仓库 Windows 宿主 WSL2 不可用（HCS_E_HYPERV_NOT_INSTALLED），
# 本脚本未在本任务执行，仅交付脚本与说明。
# =============================================================================
set -euo pipefail

ARTEX_DIR="${ARTEX_DIR:-/mnt/d/llm-audit-2026-10/.slim/clonedeps/repos/RuoJi6__ARTEX}"
MOCK_URL="${MOCK_URL:-http://host.docker.internal:18080}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.bench.yml}"
SAMPLES="${SAMPLES:-10}"
SAMPLE_INTERVAL_S="${SAMPLE_INTERVAL_S:-2}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out}"
mkdir -p "$OUT_DIR"
JSON_OUT="$OUT_DIR/artex-bench.json"
MD_OUT="$OUT_DIR/artex-bench.md"

log() { printf '[artex-bench] %s\n' "$*" >&2; }
now_ms() { date +%s%3N; }

for t in docker date; do
  command -v "$t" >/dev/null 2>&1 || { printf '[artex-bench] 缺少工具: %s\n' "$t" >&2; exit 1; }
done
[ -f "$ARTEX_DIR/$COMPOSE_FILE" ] || {
  printf '[artex-bench] 未找到 %s/%s（ARTEX_DIR 环境变量指定仓库位置）\n' "$ARTEX_DIR" "$COMPOSE_FILE" >&2
  exit 1
}
log "ARTEX=$ARTEX_DIR compose=$COMPOSE_FILE 靶场=$MOCK_URL"

# --- 1) 靶场连通性自检（对照 Trident smoke 的同一路由集） --------------------
probe_ms() {  # probe_ms <path> <method>
  local t0
  t0="$(now_ms)"
  if [ "$2" = "POST" ]; then
    curl -fsS -o /dev/null -m 5 -X POST -H 'Content-Type: application/json' -d '{}' "$MOCK_URL$1" || return 1
  else
    curl -fsS -o /dev/null -m 5 "$MOCK_URL$1" || return 1
  fi
  printf '%s' "$(( $(now_ms) - t0 ))"
}
ROUTES_JSON='[]'
for entry in "/__routes__ GET" "/api/jobs/ GET" "/plugins/list GET" "/v1/models GET" "/pause POST"; do
  set -- $entry
  ms="$(probe_ms "$1" "$2" || echo -1)"
  ROUTES_JSON="$(printf '%s' "$ROUTES_JSON" | python3 -c \
    "import json,sys; a=json.load(sys.stdin); a.append({'path':'$1','method':'$2','ms':$ms}); print(json.dumps(a))")"
done
log "靶场五路由连通性（-1=不可达）：$ROUTES_JSON"

# --- 2) 冷启动计时：compose down -> up（到容器 running） ----------------------
cd "$ARTEX_DIR"
docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
T_START="$(now_ms)"
docker compose -f "$COMPOSE_FILE" up -d >/dev/null
# 等待全部容器 running（健康检查若存在则等待 healthy，上限 WAIT_TIMEOUT_S）
WAIT_TIMEOUT_S="${WAIT_TIMEOUT_S:-300}"
for _ in $(seq 1 "$WAIT_TIMEOUT_S"); do
  n_total="$(docker compose -f "$COMPOSE_FILE" ps -q | wc -l)"
  n_running="$(docker compose -f "$COMPOSE_FILE" ps --status running -q | wc -l)"
  [ "$n_total" -gt 0 ] && [ "$n_total" = "$n_running" ] && break
  sleep 1
done
T_UP_MS=$(( $(now_ms) - T_START ))

# --- 3) 常驻内存采样（docker stats --no-stream 轮询，原文存档供 MD/JSON 引用） --
MEM_SAMPLES="$OUT_DIR/artex-mem-samples.txt"
: > "$MEM_SAMPLES"
for i in $(seq 1 "$SAMPLES"); do
  printf '== sample %s ==\n' "$i" >> "$MEM_SAMPLES"
  docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}' >> "$MEM_SAMPLES" || true
  sleep "$SAMPLE_INTERVAL_S"
done
log "内存采样 $SAMPLES 轮已存 $MEM_SAMPLES（汇总进 BENCH-RESULT.md 时取各容器峰值之和）"

# --- 4) 端到端任务计时（LLM 驱动，黑盒） --------------------------------------
# ARTEX 为 LLM 步进式探索：如已配置其管理 API/TOKEN，可在此提交指向 $MOCK_URL 的
# 同靶场任务并计时；未配置则标记 manual（人工经 Web UI 发起同靶场任务并回填）。
TASK_PHASE="${TASK_PHASE:-manual}"
TASK_MS=-1

# --- 5) 汇总输出 --------------------------------------------------------------
TASK_PHASE="$TASK_PHASE" TASK_MS="$TASK_MS" ROUTES_JSON="$ROUTES_JSON" T_UP_MS="$T_UP_MS" \
python3 - "$JSON_OUT" "$MD_OUT" <<'PY'
import json, os, sys
from datetime import datetime, timezone

json_out, md_out = sys.argv[1], sys.argv[2]
data = {
    "bench": "artex-same-target",
    "target": os.environ.get("MOCK_URL", ""),
    "cold_start_ms": int(os.environ["T_UP_MS"]),
    "task_phase": os.environ["TASK_PHASE"],
    "task_ms": int(os.environ["TASK_MS"]),
    "routes": json.loads(os.environ["ROUTES_JSON"]),
    "samples": int(os.environ.get("SAMPLES", "10")),
    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(json_out, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
md = [
    "# ARTEX 同靶场 bench 结果（脚本产出）",
    "",
    f"- 靶场：{data['target']}（与 Trident lab/bench/bench.py smoke 同一路由集）",
    f"- 冷启动（compose down→up 到全部 running）：{data['cold_start_ms']} ms",
    f"- 端到端任务计时：{data['task_ms']} ms（阶段 {data['task_phase']}；LLM 驱动需按 11.2 黑盒计时）",
    f"- 时间：{data['timestamp_utc']}",
    "",
    "| 路由 | 方法 | 可达 | ms |",
    "|---|---|---|---|",
]
for r in data["routes"]:
    md.append(f"| {r['path']} | {r['method']} | {'是' if r['ms'] >= 0 else '否'} | {r['ms']} |")
md += ["", "内存采样原文见同目录 `artex-mem-samples.txt`（docker stats 逐轮）；汇总进 BENCH-RESULT.md。", ""]
with open(md_out, "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(json.dumps(data, ensure_ascii=False))
PY

log "完成：$JSON_OUT / $MD_OUT（task_phase=$TASK_PHASE；请回填 BENCH-RESULT.md 对比表）"
docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
