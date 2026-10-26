#!/usr/bin/env bash
# Sign release artifacts with cosign keyless (Sigstore Fulcio + Rekor).
# Skips with exit 0 when cosign is not installed.
#   bash scripts/release/sign.sh [dist] [--verify]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="${1:-dist}"
MODE="${2:-}"
PY="${PYTHON:-python3}"

cd "$REPO"
if [ "$MODE" = "--verify" ]; then
  "$PY" scripts/release/sign.py --dist "$DIST" --verify
else
  "$PY" scripts/release/sign.py --dist "$DIST"
fi
