#!/usr/bin/env bash
set -euo pipefail

FEED_DIR="${1:?usage: index-apk-feed.sh <feed-dir> <apk-tool> [private-key] [description]}"
APK_TOOL="${2:?usage: index-apk-feed.sh <feed-dir> <apk-tool> [private-key] [description]}"
PRIVATE_KEY="${3:-}"
DESCRIPTION="${4:-TPROXY-Manager custom feed}"

[ -d "$FEED_DIR" ] || {
  echo "feed directory not found: $FEED_DIR" >&2
  exit 1
}
[ -x "$APK_TOOL" ] || {
  echo "apk tool not found or not executable: $APK_TOOL" >&2
  exit 1
}

shopt -s nullglob
packages=( "$FEED_DIR"/*.apk )
[ "${#packages[@]}" -gt 0 ] || {
  echo "no apk packages found in $FEED_DIR" >&2
  exit 1
}

"$APK_TOOL" mkndx \
  --allow-untrusted \
  --description "$DESCRIPTION" \
  --output "$FEED_DIR/packages.adb" \
  "${packages[@]}"

if [ -n "$PRIVATE_KEY" ] && [ -f "$PRIVATE_KEY" ]; then
  "$APK_TOOL" --sign-key "$PRIVATE_KEY" adbsign "$FEED_DIR/packages.adb"
fi
