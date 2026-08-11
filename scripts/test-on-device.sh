#!/usr/bin/env bash
#
# Run the repository's on-device test suites against the WORKING TREE.
#
#   scripts/test-on-device.sh root@192.168.1.1 [ssh args...]
#
# The suites need nixio and the LuCI Lua tree, so they cannot run on a
# developer machine; they run on a router. What they must NOT do is test
# whatever happens to be installed there, so this script stages the working
# tree — the LuCI modules, the shared tproxy_manager libraries AND the usr/bin
# scripts — into a temporary directory on the target, points package.path at it
# and tells the suites where the staged executables are. The installed package is
# never written to, and nothing outside the staging directory and the suite's own
# temp root is touched — which is what makes this safe to run against a live
# router.
#
# Shell suites resolve their scripts through TPM_STAGE_BIN, falling back to
# /usr/bin when it is unset. That fallback is why a suite run by hand still says
# which file it exercised: without the variable it checks the INSTALLED package,
# which can be an older release than the tree being prepared.
#
# Exit status is the suites' own: non-zero if any case failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_DIR="$ROOT/pkg/tproxy-manager/usr/lib/lua/luci/model/cbi/tproxy_manager"
LIB_DIR="$ROOT/pkg/tproxy-manager/usr/lib/lua/tproxy_manager"
BIN_DIR="$ROOT/pkg/tproxy-manager/usr/bin"
TESTS_DIR="$ROOT/tests"
STAGE="/tmp/tpm-test-stage"

if [ "$#" -lt 1 ]; then
  echo "usage: $(basename "$0") <ssh-target> [ssh args...]" >&2
  echo "example: $(basename "$0") root@192.168.1.1 -p 22" >&2
  exit 2
fi

TARGET="$1"
shift

# scp takes -P for the port where ssh takes -p; translate so callers can pass
# the ssh form for both. The ${arr[@]+...} guards keep this working with an
# empty argument list under `set -u` on bash 3.2 (the macOS default), where a
# bare "${arr[@]}" on an empty array is an unbound-variable error.
SSH_ARGS=()
SCP_ARGS=()
for arg in "$@"; do
  SSH_ARGS+=("$arg")
  case "$arg" in
    -p) SCP_ARGS+=("-P") ;;
    *)  SCP_ARGS+=("$arg") ;;
  esac
done

run() { ssh ${SSH_ARGS[@]+"${SSH_ARGS[@]}"} "$TARGET" "$@"; }
copy() { scp ${SCP_ARGS[@]+"${SCP_ARGS[@]}"} -q "$@"; }

echo "== staging the working tree on $TARGET =="
run "rm -rf $STAGE && mkdir -p $STAGE/lua/luci/model/cbi/tproxy_manager $STAGE/lua/tproxy_manager $STAGE/bin $STAGE/tests"
copy "$MODULE_DIR"/*.lua "$TARGET:$STAGE/lua/luci/model/cbi/tproxy_manager/"
copy "$LIB_DIR"/*.lua "$TARGET:$STAGE/lua/tproxy_manager/"
copy "$BIN_DIR"/* "$TARGET:$STAGE/bin/"
copy "$TESTS_DIR"/*.lua "$TESTS_DIR"/*.sh "$TARGET:$STAGE/tests/"
# scp does not carry the executable bit unless asked; the suites run these
# directly.
run "chmod +x $STAGE/bin/*"
echo "ok"

# Staged modules first, system default (";;") after, so luci.sys/nixio still come
# from the installed tree while everything under test is the working copy.
STAGED_LUA_PATH="$STAGE/lua/?.lua;;"

status=0
for suite in "$TESTS_DIR"/*.lua "$TESTS_DIR"/*.sh; do
  [ -e "$suite" ] || continue
  name="$(basename "$suite")"
  echo
  echo "== $name =="
  case "$name" in
    *.lua)
      if ! run "LUA_PATH='$STAGED_LUA_PATH' TPM_TEST_BASE=/tmp/tpm-test-run lua $STAGE/tests/$name"; then
        status=1
      fi
      ;;
    *.sh)
      # Shell suites drive the usr/bin scripts. They get the staged copies, and
      # the staged LUA_PATH so those scripts load the working tree's own
      # libraries rather than the installed ones — otherwise a suite could pass
      # against a release that is already on the router while the change being
      # prepared is untested.
      if ! run "LUA_PATH='$STAGED_LUA_PATH' TPM_STAGE_BIN=$STAGE/bin TPM_TEST_BASE=/tmp/tpm-test-run-sh sh $STAGE/tests/$name"; then
        status=1
      fi
      ;;
  esac
done

echo
echo "== cleaning up =="
run "rm -rf $STAGE /tmp/tpm-test-run /tmp/tpm-test-run-sh"
echo "ok"

if [ "$status" -ne 0 ]; then
  echo
  echo "one or more suites failed" >&2
fi
exit "$status"
