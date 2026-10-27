#!/usr/bin/env bash
# InkBlade one-command Docker run.
#
#   bash scripts/run-docker.sh
#   INKBLADE_PORT=9000 bash scripts/run-docker.sh
#   INKBLADE_IMAGE=ghcr.io/example/inkblade:0.2.0 bash scripts/run-docker.sh
#
# The container only exposes 127.0.0.1 on the host, keeps state in the
# `inkblade-data` volume (or INKBLADE_VOLUME=<host dir>), and runs
# `inkblade up --foreground` so the first-run admin password appears in the log.
set -euo pipefail

IMAGE="${INKBLADE_IMAGE:-inkblade:latest}"
PORT="${INKBLADE_PORT:-8765}"
NAME="${INKBLADE_NAME:-inkblade}"
VOLUME="${INKBLADE_VOLUME:-inkblade-data}"

if ! command -v docker >/dev/null 2>&1; then
  echo "run-docker.sh: 未找到 docker。" >&2
  echo "  安装 Docker Desktop / Docker Engine 后重试；或不用容器直接运行：bash scripts/install.sh" >&2
  exit 1
fi

case "$PORT" in
  ''|*[!0-9]*)
    echo "run-docker.sh: INKBLADE_PORT 必须是数字（当前：$PORT）" >&2
    exit 2
    ;;
esac

TTY_ARGS=(-i)
if [ -t 0 ] && [ -t 1 ]; then
  TTY_ARGS=(-it)
fi

echo "==> 镜像：$IMAGE"
echo "==> 端口：http://127.0.0.1:${PORT}/"
echo "==> 数据卷：$VOLUME -> /data"
echo "==> 首次启动会在日志里打印一次 admin 密码（Ctrl+C 停止）"

set +e
docker run --rm "${TTY_ARGS[@]}" --name "$NAME" \
  -p "127.0.0.1:${PORT}:8765" \
  -v "${VOLUME}:/data" \
  "$IMAGE" --home /data up --host 0.0.0.0 --port 8765 --foreground --no-browser
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  echo "run-docker.sh: docker run 退出码 $rc" >&2
  echo "  端口被占用时换一个：INKBLADE_PORT=9000 bash scripts/run-docker.sh" >&2
  echo "  镜像不存在时先构建：docker build -t inkblade:latest ." >&2
  echo "  容器名冲突时：docker rm -f $NAME 后重试，或设置 INKBLADE_NAME=inkblade-2" >&2
fi
exit "$rc"
