#!/usr/bin/env bash
#
# Run the repository's on-device test suites against the WORKING TREE.
#
#   scripts/test-on-device.sh root@192.168.1.1 [ssh args...]
#
# The suites need nixio and the LuCI Lua tree, so they cannot run on a
# developer machine; they run on a router. What they must NOT do is test
# whatever happens to be installed there, so this script stages the working
# tree's Lua modules into a temporary directory on the target and points
# package.path at it. The installed package is never written to, and nothing
# outside the staging directory and the suite's own temp root is touched —
# which is what makes this safe to run against a live router.
#
# Exit status is the suites' own: non-zero if any case failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_DIR="$ROOT/pkg/tproxy-manager/usr/lib/lua/luci/model/cbi/tproxy_manager"
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
run "rm -rf $STAGE && mkdir -p $STAGE/lua/luci/model/cbi/tproxy_manager $STAGE/tests"
copy "$MODULE_DIR"/*.lua "$TARGET:$STAGE/lua/luci/model/cbi/tproxy_manager/"
copy "$TESTS_DIR"/*.lua "$TESTS_DIR"/*.sh "$TARGET:$STAGE/tests/"
echo "ok"

status=0
for suite in "$TESTS_DIR"/*.lua "$TESTS_DIR"/*.sh; do
  [ -e "$suite" ] || continue
  name="$(basename "$suite")"
  echo
  echo "== $name =="
  case "$name" in
    *.lua)
      # The staged path comes FIRST so `require` resolves the module under test
      # to the working-tree copy; ";;" appends the system default so luci.sys,
      # nixio and friends still come from the installed tree.
      if ! run "LUA_PATH='$STAGE/lua/?.lua;;' TPM_TEST_BASE=/tmp/tpm-test-run lua $STAGE/tests/$name"; then
        status=1
      fi
      ;;
    *.sh)
      # Shell suites exercise the shipped /usr/bin scripts as installed, so they
      # get no staged LUA_PATH - what they test is the package's own behaviour.
      if ! run "TPM_TEST_BASE=/tmp/tpm-test-run-sh sh $STAGE/tests/$name"; then
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
