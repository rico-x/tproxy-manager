#!/usr/bin/env bash
set -euo pipefail

FEED_DIR="${1:?usage: index-ipk-feed.sh <feed-dir>}"

[ -d "$FEED_DIR" ] || {
  echo "feed directory not found: $FEED_DIR" >&2
  exit 1
}

cd "$FEED_DIR"
: > Packages

get_control() {
  local ipk="$1"
  local ctrl=""

  if tar tzf "$ipk" >/dev/null 2>&1; then
    if tar tzf "$ipk" | grep -q '^./control.tar.gz$'; then
      ctrl="$(tar -xOzf "$ipk" ./control.tar.gz | tar -xOzf - ./control 2>/dev/null || tar -xOzf - control 2>/dev/null || true)"
    elif tar tzf "$ipk" | grep -q '^./control.tar.xz$'; then
      ctrl="$(tar -xOzf "$ipk" ./control.tar.xz | tar -xOJf - ./control 2>/dev/null || tar -xOJf - control 2>/dev/null || true)"
    fi
  fi

  if [ -z "$ctrl" ]; then
    if ar t "$ipk" 2>/dev/null | grep -q '^control.tar.gz$'; then
      ctrl="$(ar p "$ipk" control.tar.gz | tar -xOzf - ./control 2>/dev/null || tar -xOzf - control 2>/dev/null || true)"
    elif ar t "$ipk" 2>/dev/null | grep -q '^control.tar.xz$'; then
      ctrl="$(ar p "$ipk" control.tar.xz | tar -xOJf - ./control 2>/dev/null || tar -xOJf - control 2>/dev/null || true)"
    fi
  fi

  [ -n "$ctrl" ] && printf "%s" "$ctrl"
  return 0
}

shopt -s nullglob
for ipk in *.ipk; do
  ctrl="$(get_control "$ipk")" || true
  if [ -z "$ctrl" ]; then
    echo "cannot read control from $ipk" >&2
    exit 1
  fi

  printf "%s\n" "$ctrl" >> Packages
  size=$(stat -c%s "$ipk" 2>/dev/null || wc -c < "$ipk")
  sha256=$(sha256sum "$ipk" | awk '{print $1}')
  echo "Filename: $ipk" >> Packages
  echo "Size: $size" >> Packages
  echo "SHA256sum: $sha256" >> Packages
  echo >> Packages
done
gzip -9fk Packages
