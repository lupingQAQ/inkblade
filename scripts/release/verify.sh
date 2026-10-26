#!/usr/bin/env bash
# Pre-release self-audit: byte-compile, public-tree hygiene, vendor checksums,
# plugin SDK contract and the release hygiene gate.
#   bash scripts/release/verify.sh [--full]
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PYTHON:-python3}"
FULL="${1:-}"
cd "$REPO"

failed=()
run_step() {
  local name="$1"; shift
  echo
  echo "=== $name ==="
  if "$@"; then
    echo "ok: $name"
  else
    echo "FAILED: $name"
    failed+=("$name")
  fi
}

run_step compile     "$PY" scripts/release/compile-check.py
run_step public-tree "$PY" scripts/check-public-tree.py --root .
run_step vendor      "$PY" -m unittest tests.test_vendor_checksums -v
run_step sdk         "$PY" -m unittest tests.test_sdk -v
run_step hygiene     "$PY" scripts/release/verify.py
if [ "$FULL" = "--full" ]; then
  run_step tests "$PY" -m unittest discover -s tests -t .
fi

if [ ${#failed[@]} -gt 0 ]; then
  echo
  echo "verify: FAILED -> ${failed[*]}"
  exit 1
fi
echo
echo "verify: all checks passed"
