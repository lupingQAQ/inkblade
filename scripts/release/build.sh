#!/usr/bin/env bash
# Build wheel + sdist (+ SBOM + checksums) for InkBlade.
#   bash scripts/release/build.sh [dist] [--clean]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-dist}"
CLEAN="${2:-}"
PY="${PYTHON:-python3}"

echo "build: repo=$REPO out=$OUT"
cd "$REPO"

ARGS=(scripts/release/build.py --out "$OUT")
if [ "$CLEAN" = "--clean" ]; then ARGS+=(--clean); fi
"$PY" "${ARGS[@]}"

"$PY" scripts/release/sbom.py --dist "$OUT" --out "$OUT/sbom.cdx.json"

rm -f "$OUT/SHA256SUMS"
( cd "$OUT" && sha256sum *.whl *.tar.gz sbom.cdx.json > SHA256SUMS && cat SHA256SUMS )
echo "build: artifacts in $OUT"
