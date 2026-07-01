#!/bin/sh
# Local validation for LightIPAM — see docs/agent/VALIDATION.md.
#
# Usage:
#   scripts/verify.sh            # Tier 0: CSS build, go build/vet/test, gofmt
#   scripts/verify.sh --docker   # Tier 0 + Tier 1 container builds (app + scanner)
#
# Exits non-zero on the first failing step so CI and humans get a clear signal.
set -eu

run_docker=0
if [ "${1:-}" = "--docker" ]; then
  run_docker=1
fi

# Run from the repo root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "==> npm run build:css"
npm run build:css

echo "==> go build ./..."
go build ./...

echo "==> go vet ./..."
go vet ./...

echo "==> go test ./..."
go test ./...

echo "==> gofmt -l internal cmd (must be empty)"
unformatted="$(gofmt -l internal cmd)"
if [ -n "$unformatted" ]; then
  echo "gofmt found unformatted files:" >&2
  echo "$unformatted" >&2
  echo "Run: gofmt -w <files>" >&2
  exit 1
fi

if [ "$run_docker" -eq 1 ]; then
  echo "==> docker compose build"
  docker compose build
  echo "==> docker compose --profile scanner build"
  docker compose --profile scanner build
fi

echo "==> OK"
