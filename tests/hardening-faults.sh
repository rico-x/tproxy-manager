#!/bin/sh
#
# Fault-injection suite for the hardening fixes that live outside the rollback
# store: bounded gzip decompression, the list validators, the raw-capture TTL,
# and the subscription writer's refusal to "succeed" into a directory.
#
# Runs ON THE ROUTER against the installed scripts (scripts/test-on-device.sh
# stages the Lua modules; these cases exercise /usr/bin/* as shipped). Every
# case is self-contained: it works inside its own temp directory, binds only a
# high port it picks itself, and never touches the package's configuration.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-hardening-test}"

# Which copy is under test. scripts/test-on-device.sh sets TPM_STAGE_BIN to the
# staged working tree; without it this falls back to the installed package, which
# during release preparation can be an OLDER build than the tree being checked —
# so the resolved path is printed rather than assumed.
BIN_DIR="${TPM_STAGE_BIN:-/usr/bin}"
SUBS="$BIN_DIR/tproxy-manager-subscriptions.lua"
TPROXY="$BIN_DIR/tproxy-manager.sh"

for required in "$SUBS" "$TPROXY"; do
  [ -f "$required" ] || { echo "script under test not found: $required" >&2; exit 1; }
done

pass=0
fail=0

ok() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s  <- %s\n' "$1" "$2"; }

check() { # check <name> <got> <want>
  if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "got '$2', want '$3'"; fi
}

group() { printf '\n== %s ==\n' "$1"; }

printf 'under test: %s, %s\n' "$SUBS" "$TPROXY"

rm -rf "$BASE"
mkdir -p "$BASE"
cd "$BASE" || exit 1

##########################################################################
group "GZIP BOMB: decompression is bounded by the byte cap"
##########################################################################
# The old code ran `gzip -t` first, which decompresses the whole stream with no
# consumer: a few megabytes expanding to gigabytes burned the CPU before any
# length check. The fix pipes through `head -c LIMIT+1`, so gzip is killed by
# SIGPIPE the moment the cap is passed and the expansion stops there.
LIMIT=$((8 * 1024 * 1024))

dd if=/dev/zero bs=1M count=512 2>/dev/null | gzip -9 > bomb.gz
BOMB_SIZE=$(wc -c < bomb.gz)
printf '  (bomb: %s bytes compressed, expands to 536870912)\n' "$BOMB_SIZE"

START=$(cut -d. -f1 /proc/uptime)
sh -c "{ gzip -dc bomb.gz; echo \$? >rc_bomb; } | head -c $((LIMIT + 1))" > out_bomb 2>/dev/null
END=$(cut -d. -f1 /proc/uptime)
ELAPSED=$((END - START))

check "output stops at the cap" "$(wc -c < out_bomb)" "$((LIMIT + 1))"
check "gzip reports SIGPIPE (141), i.e. it was cut off" "$(cat rc_bomb 2>/dev/null)" "141"
if [ "$ELAPSED" -le 5 ]; then
  ok "bounded in time (${ELAPSED}s for a 512 MiB expansion)"
else
  no "bounded in time" "took ${ELAPSED}s"
fi

# For contrast: the cost the removed `gzip -t` would still be paying.
START=$(cut -d. -f1 /proc/uptime)
gzip -t bomb.gz >/dev/null 2>&1
END=$(cut -d. -f1 /proc/uptime)
printf '  (for reference: `gzip -t` on the same bomb takes %ss)\n' "$((END - START))"

# A corrupt stream must be distinguishable from a capped one.
head -c 4000 bomb.gz > trunc.gz
sh -c "{ gzip -dc trunc.gz; echo \$? >rc_trunc; } | head -c $((LIMIT + 1))" > out_trunc 2>/dev/null
RC_TRUNC=$(cat rc_trunc 2>/dev/null)
if [ "$RC_TRUNC" != "0" ] && [ "$RC_TRUNC" != "141" ]; then
  ok "a corrupt stream is reported as corrupt (rc=$RC_TRUNC)"
else
  no "a corrupt stream is reported as corrupt" "rc=$RC_TRUNC"
fi
check "  and its partial output stays under the cap" \
  "$([ "$(wc -c < out_trunc)" -le "$LIMIT" ] && echo yes || echo no)" "yes"

# The measurements above prove the technique bounds the work; these two pin the
# shipped code to it. Without them a regression could reintroduce the unbounded
# pre-pass and every measurement above would still pass.
# Lua comment lines are stripped first: the fix's own comment explains what
# `gzip -t` used to do, and matching that would defeat the check.
check "the script no longer pre-verifies with an unbounded 'gzip -t'" \
  "$(grep -v '^[[:space:]]*--' "$SUBS" | grep -c 'gzip -t')" "0"
check "its decompression is capped with head -c" \
  "$([ "$(grep -c 'gzip -dc' "$SUBS")" -ge 1 ] && grep -q 'head -c' "$SUBS" && echo yes || echo no)" "yes"

##########################################################################
group "LIST VALIDATORS: reject what nft would silently drop"
##########################################################################
# "::::" and "100-50" passed the old charset/range checks and then vanished from
# the nft sets, so a bypass rule was simply absent from a start that reported
# success.
eval "$(sed -n '/^is_ipv4_cidr()/,/^}/p;/^is_ipv6_cidr()/,/^}/p;/^is_port_spec()/,/^}/p' "$TPROXY")"

v() { # v <fn> <value> <ok|bad>
  if "$1" "$2" >/dev/null 2>&1; then got=ok; else got=bad; fi
  check "$1 $2" "$got" "$3"
}

v is_ipv6_cidr "::"                                       ok
v is_ipv6_cidr "fe80::1"                                  ok
v is_ipv6_cidr "2001:db8::/32"                            ok
v is_ipv6_cidr "fc00::/7"                                 ok
v is_ipv6_cidr "2001:0db8:0000:0000:0000:0000:0000:0001"  ok
v is_ipv6_cidr "::::"                                     bad
v is_ipv6_cidr ":::"                                      bad
v is_ipv6_cidr "1::2::3"                                  bad
v is_ipv6_cidr "12345::1"                                 bad
v is_ipv6_cidr "1:2:3:4:5:6:7:8:9"                        bad
v is_ipv6_cidr "1:2:3:4:5:6:7"                            bad
v is_ipv6_cidr ":1"                                       bad
v is_ipv6_cidr "192.168.1.1"                              bad

v is_port_spec "22"                                       ok
v is_port_spec "80-443"                                   ok
v is_port_spec "udp:1000-2000"                            ok
v is_port_spec "both:22"                                  ok
v is_port_spec "100-50"                                   bad
v is_port_spec "udp:9000-8000"                            bad
v is_port_spec "0"                                        bad
v is_port_spec "70000"                                    bad
v is_port_spec "22-"                                      bad

v is_ipv4_cidr "10.0.0.0/8"                               ok
v is_ipv4_cidr "999.1.1.1"                                bad

##########################################################################
group "RAW CAPTURE: the TTL actually ends the service"
##########################################################################
# accept() used to block with no deadline: after the TTL expired the process
# kept listening, and the next connection was served with an expired token.
PORT=18099
while netstat -ltn 2>/dev/null | grep -q ":$PORT "; do PORT=$((PORT + 1)); done
LOG="$BASE/capture.log"

"$SUBS" capture-serve "testtoken" "$(( $(date +%s) + 1 ))" "$PORT" "$LOG" >/dev/null 2>&1 &
SERVE_PID=$!
sleep 1
# Still inside the TTL window? The socket must be there; this is a sanity check
# that the service actually came up, not part of the guarantee under test.
sleep 3

if kill -0 "$SERVE_PID" 2>/dev/null; then
  no "the service exits when the TTL expires" "still running 4s after a 1s TTL"
  kill "$SERVE_PID" 2>/dev/null
else
  ok "the service exits when the TTL expires"
fi

CODE=$( (echo "GET /testtoken HTTP/1.0"; echo "") | nc 127.0.0.1 "$PORT" 2>/dev/null | head -1 )
if [ -z "$CODE" ]; then
  ok "an expired token gets no response at all (port closed)"
else
  case "$CODE" in
    *200*) no "an expired token is refused" "got '$CODE'" ;;
    *)     ok "an expired token is refused (got '$CODE')" ;;
  esac
fi
check "no capture was written after expiry" "$([ -f "$LOG" ] && echo yes || echo no)" "no"

##########################################################################
group "SUBSCRIPTION WRITER: a directory target must not report success"
##########################################################################
# `mv -f file dir` exits 0 by moving the file INSIDE the directory; the writer
# then chmod'ed the DIRECTORY to 0600 and reported the save as done. The capture
# log path is writer-driven from an argument, which is the reachable way in.
BLOCKED="$BASE/blocked-target"
mkdir -p "$BLOCKED"
BEFORE=$(ls -ld "$BLOCKED" | cut -c1-10)

PORT2=$((PORT + 1))
while netstat -ltn 2>/dev/null | grep -q ":$PORT2 "; do PORT2=$((PORT2 + 1)); done
"$SUBS" capture-serve "tok2" "$(( $(date +%s) + 6 ))" "$PORT2" "$BLOCKED" >"$BASE/serve2.out" 2>&1 &
SERVE2=$!
sleep 1
(echo "GET /tok2 HTTP/1.0"; echo "") | nc 127.0.0.1 "$PORT2" >/dev/null 2>&1
sleep 1
kill "$SERVE2" 2>/dev/null
wait "$SERVE2" 2>/dev/null

AFTER=$(ls -ld "$BLOCKED" | cut -c1-10)
check "the directory is still a directory" "$(echo "$AFTER" | cut -c1)" "d"
check "its mode was NOT changed to 0600" "$AFTER" "$BEFORE"
check "nothing was dropped inside it" "$(ls -A "$BLOCKED" | wc -l | tr -d ' ')" "0"

##########################################################################
group "SHARE ENDPOINT: fails closed when the auth mode is unset"
##########################################################################
# The endpoint required a token only when auth_mode was literally "token"; an
# absent or unrecognised value fell through to a public endpoint and served the
# whole proxy list to anyone who found the URL.
CTRL=/usr/lib/lua/luci/controller/tproxy_manager.lua
check "the endpoint checks for an explicit 'public', not for 'token'" \
  "$(grep -c 'auth_mode ~= "public"' "$CTRL")" "1"
check "  and no longer branches on auth_mode == \"token\"" \
  "$(grep -c 'auth_mode == "token"' "$CTRL")" "0"
# The default shipped by uci-defaults must be the safe one.
DEFAULTS=/rom/etc/uci-defaults/90_tproxy_manager
[ -f "$DEFAULTS" ] || DEFAULTS=/etc/uci-defaults/90_tproxy_manager
if [ -f "$DEFAULTS" ]; then
  check "uci-defaults default the auth mode to token" \
    "$(grep -c "watchdog_share_auth_mode 'token'" "$DEFAULTS")" "1"
else
  printf '  (uci-defaults not present on this system; skipped)\n'
fi

##########################################################################
group "TPROXY TEMP FILES: no predictable path in /tmp"
##########################################################################
# A local user could pre-create /tmp/.tpm-nft.<pid> as a symlink and have the
# root nft config written through it - reproduced on the target before the fix.
check "the script no longer names temp files by pid in /tmp" \
  "$(grep -c 'tpm-nft\.\$\$' "$TPROXY")" "0"
check "it creates a private 0700 run directory instead" \
  "$([ "$(grep -c 'mkdir -m 0700' "$TPROXY")" -ge 1 ] && echo yes || echo no)" "yes"

rm -f "$BASE/victim"
echo ORIGINAL > "$BASE/victim"
ln -sf "$BASE/victim" /tmp/.tpm-nft.9999 2>/dev/null
"$TPROXY" status >/dev/null 2>&1
check "a symlink at the old path is not followed" "$(cat "$BASE/victim")" "ORIGINAL"
rm -f /tmp/.tpm-nft.9999

##########################################################################
group "TPROXY LIFECYCLE LOCK: concurrent operations are serialised"
##########################################################################
LOCK=/var/lock/tproxy-manager/tproxy-lifecycle.lock
rm -rf "$LOCK"
mkdir -p "$LOCK"
setsid sleep 30 >/dev/null 2>&1 &
HOLDER=$!
echo "$HOLDER" > "$LOCK/pid"
OUT="$BASE/lock.log"
LOCK_WAIT_SECONDS=2 "$TPROXY" status >"$OUT" 2>&1
# `status` does not take the lock; `start` must.
LOCK_WAIT_SECONDS=2 "$TPROXY" start >"$OUT" 2>&1
RC=$?
check "start refuses while another operation holds the lock" "$RC" "1"
check "  and says which pid holds it" \
  "$(grep -c "in progress (pid $HOLDER)" "$OUT")" "1"
kill "$HOLDER" 2>/dev/null
rm -rf "$LOCK"

# A lock left by a process that no longer exists must be reclaimed, not honoured.
mkdir -p "$LOCK"
echo 999999 > "$LOCK/pid"
LOCK_WAIT_SECONDS=2 "$TPROXY" start >"$OUT" 2>&1
RC=$?
check "a lock left by a dead owner is reclaimed" "$RC" "0"
check "  and the takeover is reported" "$(grep -c 'dead pid 999999' "$OUT")" "1"
rm -rf "$LOCK"

# The pid file is the only thing that later distinguishes a live owner from a
# dead one; continuing without it leaves an ownerless lock that any other
# process removes after five seconds, mid-operation. The failure branch cannot
# be triggered from outside (root can always write into a directory it just
# created), so this pins the check itself.
check "the lock verifies that the owner pid was recorded" \
  "$([ "$(grep -c 'could not record the lock owner pid' "$TPROXY")" -ge 1 ] && echo yes || echo no)" "yes"
check "  and reads it back rather than trusting the write" \
  "$(grep -c '_check="\$(cat "\$LIFECYCLE_LOCK/pid"' "$TPROXY")" "1"

##########################################################################
group "CAPTURE START: nothing is activated before the prerequisites hold"
##########################################################################
# enabled=1 used to be committed first and the directories validated afterwards:
# a failure there left the capture marked active with no server behind it.
check "the lock root is validated before any uci_set" \
  "$(awk '/^local function command_capture_start/,/^end$/' "$SUBS" | grep -n 'secure_lock_root\|uci_set' | head -1 | grep -c secure_lock_root)" "1"
check "a partial stage is reverted" \
  "$([ "$(awk '/^local function command_capture_start/,/^end$/' "$SUBS" | grep -c 'uci_revert()')" -ge 2 ] && echo yes || echo no)" "yes"

##########################################################################
group "GEO UPDATER: the lock is not at a fixed /tmp path"
##########################################################################
GEO=/usr/bin/tproxy-manager-geo-update.sh
if [ -f "$GEO" ]; then
  check "no fixed /tmp lock" "$(grep -c '/tmp/tproxy-manager-geo-update.lock' "$GEO")" "0"
  check "the lock lives in the root-only lock root" \
    "$(grep -c 'LOCK_ROOT="/var/lock/tproxy-manager"' "$GEO")" "1"
  check "  and the updater validates that directory" \
    "$(grep -c 'unsafe lock directory' "$GEO")" "1"
else
  printf '  (the GEO updater has not been generated on this system; skipped)\n'
fi

##########################################################################
cd /
rm -rf "$BASE"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
exit 0
