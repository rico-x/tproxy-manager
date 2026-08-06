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

# Пин на конкретный дайджест стабильного релиза Alpine вместо "живого" тега
# edge: apk-tools-static из edge непредсказуемо меняется между запусками CI и
# подписывает релизный apk-фид (см. build-packages.yml), так что нужна
# воспроизводимая, а не "текущая на момент сборки" версия инструмента.
ALPINE_IMAGE="alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

docker run --rm -v "$TMPDIR:/out" "$ALPINE_IMAGE" sh -euxc '
  apk add --no-cache apk-tools-static
  cp /sbin/apk.static /out/apk.static
'

install -m 0755 "$TMPDIR/apk.static" "$DEST"
printf '%s\n' "$DEST"
