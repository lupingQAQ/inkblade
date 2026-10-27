#!/usr/bin/env bash
# InkBlade one-command install (Linux / macOS).
#
#   bash scripts/install.sh                 # install this checkout, then run `inkblade up`
#   bash scripts/install.sh --no-start      # install only
#   bash scripts/install.sh -- --port 9000  # extra args go to `inkblade up`
#
# Everything stays local: no CDN, no telemetry, no remote shell scripts.
# Prefers uv when it is installed, and falls back to `python -m pip`.
set -euo pipefail

NO_START=0
FORCE_UV="${INKBLADE_FORCE_UV:-0}"
LOCAL_SRC="${INKBLADE_SRC:-}"
UP_ARGS=()

usage() {
  cat <<'EOF'
InkBlade installer (Linux / macOS)

Usage: bash scripts/install.sh [options] [-- up-options]

Options:
  --no-start        install only; do not run `inkblade up`
  --local PATH      install from a local checkout or wheel directory
  --uv              require uv (exit 1 when uv is not installed)
  -h, --help        show this help

Environment:
  INKBLADE_PYTHON   interpreter to use (default: python3.12/3.11/3.10/python3/python)
  INKBLADE_SRC      same as --local
  INKBLADE_FORCE_UV set to 1 to require uv (fails when uv is missing)

Examples:
  bash scripts/install.sh -- --port 9000 --no-browser
  INKBLADE_PYTHON=.venv/bin/python bash scripts/install.sh --no-start
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-start) NO_START=1; shift ;;
    --local)
      if [ $# -lt 2 ] || [ -z "$2" ]; then
        echo "install.sh: --local 需要路径" >&2
        exit 2
      fi
      LOCAL_SRC="$2"; shift 2 ;;
    --uv) FORCE_UV=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; UP_ARGS=("$@"); break ;;
    *)
      # Unknown flags are forwarded to `inkblade up` (e.g. --port, --home).
      UP_ARGS+=("$1"); shift ;;
  esac
done

PY="${INKBLADE_PYTHON:-}"
if [ -z "$PY" ]; then
  for cand in python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      PY="$cand"
      break
    fi
  done
fi
if [ -z "$PY" ]; then
  echo "install.sh: 找不到 Python 3.10+。" >&2
  echo "  安装 Python 3.10+ 后重试，或指定解释器：INKBLADE_PYTHON=/path/to/python3.12 bash scripts/install.sh" >&2
  exit 1
fi
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  echo "install.sh: $PY 版本低于 3.10。" >&2
  echo "  换一个解释器：INKBLADE_PYTHON=python3.12 bash scripts/install.sh" >&2
  exit 1
fi
PY_PATH="$("$PY" -c 'import sys; print(sys.executable)')"

py_in_venv=0
if [ -n "${VIRTUAL_ENV:-}" ]; then
  case "$PY_PATH" in
    "$VIRTUAL_ENV"/*) py_in_venv=1 ;;
  esac
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "$LOCAL_SRC" ] && [ -f "$HERE/pyproject.toml" ]; then
  LOCAL_SRC="$HERE"
fi

if [ -n "$LOCAL_SRC" ]; then
  if [ ! -e "$LOCAL_SRC" ]; then
    echo "install.sh: --local 路径不存在：$LOCAL_SRC" >&2
    exit 2
  fi
  if [ -d "$LOCAL_SRC/dist" ] && compgen -G "$LOCAL_SRC/dist/*.whl" >/dev/null 2>&1; then
    TARGET=(--find-links "$LOCAL_SRC/dist" inkblade)
  elif [ -f "$LOCAL_SRC/pyproject.toml" ]; then
    TARGET=(-e "$LOCAL_SRC")
  else
    TARGET=("$LOCAL_SRC")
  fi
else
  TARGET=(inkblade)
fi

echo "==> 解释器：$PY_PATH"
echo "==> 安装来源：${LOCAL_SRC:-PyPI（inkblade）}"

install_with_uv() {
  uv_bin="$1"
  if [ "$py_in_venv" = "1" ]; then
    "$uv_bin" pip install --python "$PY_PATH" "${TARGET[@]}"
  else
    "$uv_bin" pip install --system --python "$PY_PATH" "${TARGET[@]}"
  fi
}

installed=0
UV_BIN=""
if command -v uv >/dev/null 2>&1; then
  UV_BIN="$(command -v uv)"
elif [ "$FORCE_UV" = "1" ]; then
  echo "install.sh: 指定了 --uv / INKBLADE_FORCE_UV=1，但 PATH 中没有 uv。" >&2
  exit 1
fi

if [ -n "$UV_BIN" ]; then
  echo "==> 使用 uv：$UV_BIN"
  if install_with_uv "$UV_BIN"; then
    installed=1
  else
    echo "install.sh: uv 安装失败，改用 pip 重试。" >&2
  fi
fi

if [ "$installed" != "1" ]; then
  echo "==> 使用 pip：$PY_PATH -m pip"
  "$PY_PATH" -m pip install --upgrade --disable-pip-version-check "${TARGET[@]}"
fi

if [ "$NO_START" = "1" ]; then
  echo
  echo "已安装。下一步："
  echo "  1. inkblade up"
  echo "  2. 浏览器打开 http://127.0.0.1:8765/ 并用首次打印的 admin 密码登录"
  echo "  3. inkblade down 停止；inkblade status 查看状态"
  exit 0
fi

echo "==> 启动：inkblade up"
exec "$PY_PATH" -m inkblade up ${UP_ARGS[@]+"${UP_ARGS[@]}"}
