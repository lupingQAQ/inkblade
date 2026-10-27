#!/usr/bin/env bash
# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup
set -euo pipefail
cd "$(dirname "$0")"
exec python3 poc.py "$@"
