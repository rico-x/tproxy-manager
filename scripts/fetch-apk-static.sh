#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-$ROOT/.apk-tools/apk.static}"

command -v docker >/dev/null 2>&1 || {
  echo "docker is required to bootstrap apk.static" >&2
  exit 1
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$(dirname "$DEST")"

docker run --rm -v "$TMPDIR:/out" alpine:edge sh -euxc '
  apk add --no-cache apk-tools-static
  cp /sbin/apk.static /out/apk.static
'

install -m 0755 "$TMPDIR/apk.static" "$DEST"
printf '%s\n' "$DEST"
