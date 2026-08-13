#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/package-common.sh
. "$ROOT/scripts/package-common.sh"

PKG_DIR="${1:-$ROOT/pkg/tproxy-manager}"
OUT_DIR="${2:-$ROOT/dist/24.10}"
PKG_VERSION="${3:?usage: build-ipk.sh <pkg-dir> <out-dir> <version> [ipkg-build]}"
IPKG_BUILD="${4:-${IPKG_BUILD:-$ROOT/ipkg-build}}"

[ -x "$IPKG_BUILD" ] || {
  echo "ipkg-build not found or not executable: $IPKG_BUILD" >&2
  exit 1
}
[ -d "$PKG_DIR" ] || {
  echo "package directory not found: $PKG_DIR" >&2
  exit 1
}

PKG_DIR="$(cd "$PKG_DIR" && pwd)"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
PACKAGE_NAME="$(control_field Package "$PKG_DIR/CONTROL/control")"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

STAGE_DIR="$WORKDIR/pkg"
mkdir -p "$STAGE_DIR"

copy_payload_tree "$PKG_DIR" "$STAGE_DIR"
copy_control_tree "$PKG_DIR" "$STAGE_DIR"
compile_luci_i18n "$PKG_DIR" "$STAGE_DIR"
normalize_tree "$STAGE_DIR"
inject_control_version "$STAGE_DIR/CONTROL/control" "$PKG_VERSION"

"$IPKG_BUILD" "$STAGE_DIR" "$OUT_DIR"

IPK_FILE="$(find "$OUT_DIR" -maxdepth 1 -type f -name "${PACKAGE_NAME}_${PKG_VERSION}_*.ipk" | sort | tail -n 1)"
[ -n "$IPK_FILE" ] && [ -f "$IPK_FILE" ] || {
  echo "ipk package was not created" >&2
  exit 1
}

IPK_SIZE="$(wc -c < "$IPK_FILE" | tr -d '[:space:]')"
if [ "${IPK_SIZE:-0}" -lt 1024 ]; then
  echo "ipk package is unexpectedly small ($IPK_SIZE bytes): $IPK_FILE" >&2
  echo "If building on macOS, install GNU tar and run with TAR=gtar." >&2
  exit 1
fi

printf '%s\n' "$IPK_FILE"
