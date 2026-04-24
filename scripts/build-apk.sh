#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/package-common.sh
. "$ROOT/scripts/package-common.sh"

PKG_DIR="${1:-$ROOT/pkg/tproxy-manager}"
OUT_DIR="${2:-$ROOT/dist/25.12}"
PKG_VERSION="${3:?usage: build-apk.sh <pkg-dir> <out-dir> <version> [apk-tool]}"
APK_TOOL="${4:-${APK_TOOL:-$ROOT/.apk-tools/apk.static}}"
CONTROL_FILE="$PKG_DIR/CONTROL/control"

[ -x "$APK_TOOL" ] || {
  echo "apk tool not found or not executable: $APK_TOOL" >&2
  exit 1
}
[ -f "$CONTROL_FILE" ] || {
  echo "control file not found: $CONTROL_FILE" >&2
  exit 1
}

PKG_DIR="$(cd "$PKG_DIR" && pwd)"
OUT_DIR_ABS="$OUT_DIR"
mkdir -p "$OUT_DIR_ABS"
OUT_DIR_ABS="$(cd "$OUT_DIR_ABS" && pwd)"
CONTROL_FILE="$PKG_DIR/CONTROL/control"

PACKAGE_NAME="$(control_field Package "$CONTROL_FILE")"
ARCH_RAW="$(control_field Architecture "$CONTROL_FILE")"
MAINTAINER="$(control_field Maintainer "$CONTROL_FILE")"
DESCRIPTION="$(control_field Description "$CONTROL_FILE")"
DEPENDS_RAW="$(control_field Depends "$CONTROL_FILE")"
APK_ARCH="$(apk_arch_from_control "$ARCH_RAW")"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BUILDROOT="$WORKDIR/buildroot"
SCRIPTDIR="$WORKDIR/scripts"
OUT_FILE="$OUT_DIR_ABS/${PACKAGE_NAME}-${PKG_VERSION}.apk"

mkdir -p "$BUILDROOT" "$SCRIPTDIR"

copy_payload_tree "$PKG_DIR" "$BUILDROOT"
normalize_tree "$BUILDROOT"

cp "$PKG_DIR/CONTROL/postinst" "$SCRIPTDIR/post-install.sh"
cp "$PKG_DIR/CONTROL/postinst" "$SCRIPTDIR/post-upgrade.sh"
cp "$PKG_DIR/CONTROL/prerm" "$SCRIPTDIR/pre-deinstall.sh"
{
  echo '#!/bin/sh'
  echo 'export PKG_UPGRADE=1'
  cat "$PKG_DIR/CONTROL/prerm"
} > "$SCRIPTDIR/pre-upgrade.sh"

chmod 0755 \
  "$SCRIPTDIR/post-install.sh" \
  "$SCRIPTDIR/post-upgrade.sh" \
  "$SCRIPTDIR/pre-deinstall.sh" \
  "$SCRIPTDIR/pre-upgrade.sh"

MKPKG_ARGS=(
  mkpkg
  --files "$BUILDROOT"
  --output "$OUT_FILE"
  --info "name:$PACKAGE_NAME"
  --info "version:$PKG_VERSION"
  --info "arch:$APK_ARCH"
  --info "description:$DESCRIPTION"
  --info "maintainer:$MAINTAINER"
  --info "origin:$PACKAGE_NAME"
  --info "url:https://github.com/rico-x/tproxy-manager"
  --script "post-install:$SCRIPTDIR/post-install.sh"
  --script "post-upgrade:$SCRIPTDIR/post-upgrade.sh"
  --script "pre-deinstall:$SCRIPTDIR/pre-deinstall.sh"
)

while IFS= read -r dep; do
  MKPKG_ARGS+=( --info "depends:$dep" )
done < <(split_depends_csv "$DEPENDS_RAW")

MKPKG_ARGS+=( --script "pre-upgrade:$SCRIPTDIR/pre-upgrade.sh" )

"$APK_TOOL" "${MKPKG_ARGS[@]}"

find "$OUT_DIR" -maxdepth 1 -type f -name '*.apk' | sort
