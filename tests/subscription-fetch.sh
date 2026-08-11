#!/bin/sh
#
# End-to-end suite for subscription fetching, driven through the real CLI against
# a local HTTP server. It exists because of a bug that no unit-level check would
# have caught and that browser testing surfaced only through a line in logread:
#
#   /usr/bin/tproxy-manager-subscriptions.lua:700: bad argument #2 to 'tonumber'
#
# `trim()` returned `gsub`'s result directly, so it yielded TWO values (the text
# and the replacement count). `tonumber(trim(x))` therefore read that count as
# the numeric base, and a count of 0 or 1 is not a legal base — an outright
# error. The call site was the gzip branch's exit-status check, so EVERY
# subscription served with gzip could not be fetched at all, while plain-text
# ones kept working and hid it.
#
# The cases below run the whole path — curl, gzip detection, decompression, the
# byte cap, link extraction, the database write — for a gzip body, a plain body,
# a corrupt stream and a bomb.
#
# Runs ON THE ROUTER, against the staged working tree when TPM_STAGE_BIN is set
# and against the installed package otherwise (the resolved path is printed).
# Safe on a live router: both file paths the script uses are redirected into a
# temp directory via TPROXY_MANAGER_SUBSCRIPTIONS_FILE / TPROXY_MANAGER_LINKS_FILE,
# so the package's own subscription database and links file are never opened —
# which the last group asserts by fingerprinting them.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-subscription-test}"

# Which copy is under test. scripts/test-on-device.sh sets TPM_STAGE_BIN to the
# staged working tree; without it this falls back to the installed package, which
# during release preparation can be an OLDER build than the tree being checked —
# so the resolved path is printed rather than assumed.
BIN_DIR="${TPM_STAGE_BIN:-/usr/bin}"
SUBS="$BIN_DIR/tproxy-manager-subscriptions.lua"

if [ ! -f "$SUBS" ]; then
  echo "script under test not found: $SUBS" >&2
  exit 1
fi

pass=0
fail=0

ok() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s  <- %s\n' "$1" "$2"; }

check() { # check <name> <got> <want>
  if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "got '$2', want '$3'"; fi
}

contains() { # contains <name> <haystack> <needle>
  case "$2" in
    *"$3"*) ok "$1" ;;
    *) no "$1" "'$2' does not contain '$3'" ;;
  esac
}

group() { printf '\n== %s ==\n' "$1"; }

printf 'under test: %s\n' "$SUBS"

rm -rf "$BASE"
mkdir -p "$BASE/www"
cd "$BASE" || exit 1

LINK1='vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=example.com&fp=chrome&pbk=AAAA&type=tcp#probe-one'
LINK2='vless://22222222-2222-2222-2222-222222222222@203.0.113.11:443?security=reality&sni=example.org&fp=chrome&pbk=BBBB&type=tcp#probe-two'

printf '%s\n%s\n' "$LINK1" "$LINK2" > www/plain.txt
gzip -c www/plain.txt > www/gzipped.bin

# A stream that announces gzip by its magic bytes and then is not gzip at all.
printf '\037\213garbage-not-a-gzip-stream' > www/corrupt.bin

# Highly compressible payload: ~256 MiB of zeros in a few hundred KB. The cap is
# 8 MiB, so a correct implementation stops there instead of expanding it all.
dd if=/dev/zero bs=1M count=256 2>/dev/null | gzip -9 > www/bomb.bin

# uhttpd is the router's own web server and serves a static directory happily.
# Pick a high port and make sure nothing else holds it.
PORT=0
for candidate in 18731 18732 18733 18734 18735; do
  if ! netstat -ln 2>/dev/null | grep -q ":$candidate "; then PORT=$candidate; break; fi
done
if [ "$PORT" = 0 ]; then
  echo "no free port for the local HTTP server" >&2
  exit 1
fi

uhttpd -f -p "127.0.0.1:$PORT" -h "$BASE/www" >/dev/null 2>&1 &
HTTPD_PID=$!
cleanup() { kill "$HTTPD_PID" 2>/dev/null; }
trap cleanup EXIT INT TERM

# Wait for it to accept connections rather than guessing with a fixed sleep.
served=0
i=0
while [ "$i" -lt 40 ]; do
  i=$((i + 1))
  if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/plain.txt" >/dev/null 2>&1; then served=1; break; fi
  sleep 1
done
if [ "$served" != 1 ]; then
  echo "local HTTP server did not come up on port $PORT" >&2
  exit 1
fi

DB="$BASE/subscriptions.json"
LINKS="$BASE/links"

# Fingerprint the router's real files BEFORE anything runs, so the isolation
# claim at the end is a measurement rather than an assumption. Read straight
# from the shipped defaults: the env overrides below must keep these untouched.
LIVE_DB=/etc/tproxy-manager/watchdog-subscriptions.json
LIVE_LINKS=/etc/tproxy-manager/watchdog.links
live_db_fingerprint() { [ -f "$LIVE_DB" ] && md5sum < "$LIVE_DB" || echo absent; }
live_links_fingerprint() { [ -f "$LIVE_LINKS" ] && md5sum < "$LIVE_LINKS" || echo absent; }
LIVE_DB_BEFORE="$(live_db_fingerprint)"
LIVE_LINKS_BEFORE="$(live_links_fingerprint)"

export TPROXY_MANAGER_SUBSCRIPTIONS_FILE="$DB"
export TPROXY_MANAGER_LINKS_FILE="$LINKS"

write_db() { # write_db <path-on-server>
  cat > "$DB" <<EOF
{
  "subscriptions": [
    {
      "id": 1,
      "name": "Probe",
      "type": "happ",
      "enabled": true,
      "url": "http://127.0.0.1:$PORT/$1"
    }
  ]
}
EOF
  rm -f "$LINKS"
}

fetch() { # fetch -> prints output, sets FETCH_RC
  FETCH_OUT="$("$SUBS" fetch 1 2>&1)"
  FETCH_RC=$?
}

link_count() {
  if [ -f "$LINKS" ]; then grep -c 'vless://' "$LINKS" 2>/dev/null || echo 0; else echo 0; fi
}

##########################################################################
group "GZIP BODY: the regression case"
##########################################################################
# This is the exact shape that failed: the response is a gzip stream, so the
# decompression branch runs and checks gzip's exit status through tonumber().
write_db gzipped.bin
fetch
check "fetch of a gzip-compressed subscription succeeds" "$FETCH_RC" 0
check "  both links were extracted" "$(link_count)" 2
if [ -f "$LINKS" ]; then
  contains "  the first link landed verbatim" "$(cat "$LINKS")" "203.0.113.10"
  contains "  the second link landed verbatim" "$(cat "$LINKS")" "203.0.113.11"
else
  no "  the first link landed verbatim" "no links file"
  no "  the second link landed verbatim" "no links file"
fi
# The failure was a Lua error, not a clean "false" — assert the traceback shape
# can never come back, whatever the message wording becomes.
case "$FETCH_OUT" in
  *"bad argument"*|*".lua:"*) no "  no Lua error in the output" "$FETCH_OUT" ;;
  *) ok "  no Lua error in the output" ;;
esac

##########################################################################
group "PLAIN BODY: the path that kept working and hid the bug"
##########################################################################
write_db plain.txt
fetch
check "fetch of an uncompressed subscription succeeds" "$FETCH_RC" 0
check "  both links were extracted" "$(link_count)" 2

##########################################################################
group "CORRUPT STREAM: gzip magic bytes, garbage behind them"
##########################################################################
# gzip's exit status is neither 0 nor 141 here, so the response must be refused.
# With the old code this hit the same tonumber() error and was reported as a Lua
# crash instead of as a bad stream.
write_db corrupt.bin
fetch
check "fetch of a corrupt gzip stream fails" "$FETCH_RC" 1
contains "  it is reported as an invalid gzip stream" "$FETCH_OUT" "gzip"
check "  nothing was written to the links file" "$(link_count)" 0

##########################################################################
group "BOMB: expansion stays bounded and is refused"
##########################################################################
write_db bomb.bin
START=$(cut -d. -f1 /proc/uptime)
fetch
END=$(cut -d. -f1 /proc/uptime)
ELAPSED=$((END - START))
check "fetch of a decompression bomb fails" "$FETCH_RC" 1
contains "  it is reported as exceeding the size limit" "$FETCH_OUT" "limit"
check "  nothing was written to the links file" "$(link_count)" 0
printf '  (256 MiB bomb refused in %s s)\n' "$ELAPSED"
if [ "$ELAPSED" -le 20 ]; then
  ok "  the whole stream was never expanded"
else
  no "  the whole stream was never expanded" "took ${ELAPSED}s"
fi

##########################################################################
group "WORKING DIRECTORIES: no orphans, and old ones get swept"
##########################################################################
# The download directory is removed on every normal exit, but a fault inside the
# fetch used to abort the function and skip that cleanup. Running once a minute
# from the watchdog, one repeating fault left 802 directories holding 110 MB of a
# 243 MB /tmp on the test router. Two defences are asserted: a fetch leaves
# nothing of its own behind, and a stale directory from an earlier run is swept.
# Compared by NAME, not by count: the same code path also sweeps orphans left by
# earlier runs, so the total may legitimately drop while a fetch is in progress.
# What must never happen is a NEW directory surviving the fetch.
list_workdirs() { ls -d /tmp/.tpm-sub.* 2>/dev/null | sort; }

snapshot_workdirs() { # snapshot_workdirs <file>
  # The sentinel keeps the pattern file non-empty on purpose. `comm` is not part
  # of this busybox build, so the difference is taken with grep -f — and busybox
  # grep treats an EMPTY pattern file as matching every line, which with -v
  # prints nothing and quietly turns the comparison below into "no leaks, ever".
  # That is exactly how an injected leak went undetected once.
  { echo "__no_such_workdir__"; list_workdirs; } > "$1"
}

new_workdirs() { # new_workdirs <before-file>
  list_workdirs > "$BASE/work.after"
  grep -vxF -f "$1" "$BASE/work.after" | wc -l | tr -d ' '
}

# Prove the comparison can fail before trusting it: same expression, a line that
# is definitely not in the snapshot.
snapshot_workdirs "$BASE/work.selftest"
printf '%s\n' "/tmp/.tpm-sub.selftest-must-be-seen" > "$BASE/work.after"
check "the leak comparison detects a new directory (self-test)" \
  "$(grep -vxF -f "$BASE/work.selftest" "$BASE/work.after" | wc -l | tr -d ' ')" 1

snapshot_workdirs "$BASE/work.before"
write_db plain.txt
fetch
check "a successful fetch leaves no working directory behind" "$(new_workdirs "$BASE/work.before")" 0

snapshot_workdirs "$BASE/work.before2"
write_db corrupt.bin
fetch
check "  a rejected fetch leaves none either" "$(new_workdirs "$BASE/work.before2")" 0

# An orphan older than the cut-off must go; one from a possibly-running fetch
# must not be touched.
STALE=/tmp/.tpm-sub.999000.999001
FRESH=/tmp/.tpm-sub.999000.999002
rm -rf "$STALE" "$FRESH"
mkdir -m 0700 "$STALE" "$FRESH"
: > "$STALE/body"
: > "$FRESH/body"
touch -t 200001010000 "$STALE" 2>/dev/null || touch -d "2000-01-01 00:00" "$STALE"
write_db plain.txt
fetch
check "  a stale orphan is swept" "$([ -d "$STALE" ] && echo present || echo gone)" "gone"
check "  a fresh directory is left alone" "$([ -d "$FRESH" ] && echo present || echo gone)" "present"
rm -rf "$STALE" "$FRESH"

##########################################################################
group "EARLY FAILURE: every exit path removes the working directory"
##########################################################################
# Creating the download files can fail — a full filesystem, or a name an attacker
# managed to pre-create so O_EXCL refuses. That branch returns early, and it used
# to return BEFORE the cleanup closure was even defined, so those directories
# survived until the hourly sweep. Nothing makes an exclusive create fail for root
# on demand, so the fault is injected into a COPY of the script; the file under
# test is never modified.
INJECTED="$BASE/subs-early-fail.lua"
sed 's|local fd = nixio.open(path, flags, "600")|local fd = nil|' "$SUBS" > "$INJECTED"
if grep -q 'local fd = nil' "$INJECTED"; then
  snapshot_workdirs "$BASE/work.before3"
  write_db plain.txt
  INJ_OUT="$(lua "$INJECTED" fetch 1 2>&1)"
  INJ_RC=$?
  check "the injected create failure is reported, not crashed" "$INJ_RC" 1
  contains "  it names the temp file as the problem" "$INJ_OUT" "private temp file"
  check "  and no working directory is left behind" "$(new_workdirs "$BASE/work.before3")" 0
else
  # Better to say nothing was checked than to report a pass for a no-op.
  no "the injected create failure is reported, not crashed" \
     "could not inject: the nixio open call was not found in $SUBS"
fi
rm -f "$INJECTED"

##########################################################################
group "ISOLATION: the router's own files were untouched"
##########################################################################
# A suite that quietly rewrote the live subscription database or links file
# would be worse than no suite, so this is asserted rather than assumed. The
# fingerprints were taken before the first fetch ran.
check "the live subscription database is byte-identical" \
  "$(live_db_fingerprint)" "$LIVE_DB_BEFORE"
check "  the live links file is byte-identical" \
  "$(live_links_fingerprint)" "$LIVE_LINKS_BEFORE"

cleanup
trap - EXIT INT TERM

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
