#!/bin/sh
#
# Unit suite for the TPROXY delta model in usr/bin/tproxy-manager.sh.
#
# The delta model is what decides which policy rules and route tables a run
# creates, which ones a previous run left behind, and which of those may be
# removed. Its identity keys are the whole point:
#
#   a rule  is (family, mark, table, priority)
#   a route is (family, table)
#
# Get any of that wrong and a start either duplicates rules it already owns or
# deletes rules that still serve the other protocol. None of it touches the
# network, so it is all exercised directly here: the functions are pulled out of
# the shipped script with sed and driven against temp files.
#
# Runs ON THE ROUTER (it needs the installed script and a real /etc/iproute2),
# but changes nothing: no ip, nft or service command is invoked.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-state-test}"
# Which copy is under test. scripts/test-on-device.sh sets TPM_STAGE_BIN to the
# staged working tree; without it this falls back to the installed package, which
# during release preparation can be an OLDER build than the tree being checked —
# so the resolved path is printed rather than assumed.
BIN_DIR="${TPM_STAGE_BIN:-/usr/bin}"
TPROXY="$BIN_DIR/tproxy-manager.sh"

[ -f "$TPROXY" ] || { echo "script under test not found: $TPROXY" >&2; exit 1; }
printf 'under test: %s\n' "$TPROXY"

pass=0
fail=0
ok() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s  <- %s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "got '$2', want '$3'"; fi; }
group() { printf '\n== %s ==\n' "$1"; }

rm -rf "$BASE"
mkdir -p "$BASE"
cd "$BASE" || exit 1

# say() is used by the extracted functions for diagnostics; keep it quiet.
say() { :; }

# Pull the pure parts of the delta model out of the shipped script. Extracting
# rather than reimplementing is the point: the assertions below run the same code
# the router runs.
# One-liners are taken as single lines. Using a `/^fn()/,/^}/` range for them
# would run to the closing brace of a LATER function and swallow everything in
# between - which is exactly how rt_alias ended up undefined the first time.
eval "$(sed -n \
  -e '/^ip_fam()/p' \
  -e '/^norm_mark()/p' \
  "$TPROXY")"

# Multi-line functions: `(){` on its own line, closing `}` in column 0.
for _fn in rt_alias table_still_used desired_rules state_rules \
           state_source state_get state_get_from; do
  eval "$(sed -n "/^${_fn}()/,/^}/p" "$TPROXY")"
done

STATE_FILE="$BASE/state"
RECOVERY_FILE="$BASE/state.recovery"
RULESET_NEW="$BASE/ruleset.new"

##########################################################################
group "MARK NORMALISATION: ip(8) prints hex, UCI accepts either"
##########################################################################
# A config with fwmark_tcp='1' used to make every rule lookup miss, so each
# start added another copy of a rule it already owned.
check "decimal 1"    "$(norm_mark 1)"    "0x1"
check "hex 0x1"      "$(norm_mark 0x1)"  "0x1"
check "upper 0X1"    "$(norm_mark 0X1)"  "0x1"
check "decimal 255"  "$(norm_mark 255)"  "0xff"
check "hex 0xff"     "$(norm_mark 0xff)" "0xff"
check "decimal 2"    "$(norm_mark 2)"    "0x2"

check "ip_fam 4" "$(ip_fam 4)" "-4"
check "ip_fam 6" "$(ip_fam 6)" "-6"

##########################################################################
group "ROUTE TABLE ALIASES: ip(8) prints the name when one exists"
##########################################################################
# Matching on the number while ip prints the alias made rule_present() always
# answer "absent" and duplicate the rule on every start.
if grep -qE '^[[:space:]]*254[[:space:]]' /etc/iproute2/rt_tables 2>/dev/null; then
  check "254 resolves to its name" "$(rt_alias 254)" "main"
  check "255 resolves to its name" "$(rt_alias 255)" "local"
else
  printf '  (rt_tables has no standard entries here; alias cases skipped)\n'
fi
check "an unnamed table stays numeric" "$(rt_alias 100)" "100"
# Prefix collisions must not resolve: "12" is not "128 prelocal".
check "12 does not match 128"  "$(rt_alias 12)" "12"
check "25 does not match 254" "$(rt_alias 25)" "25"

##########################################################################
group "DESIRED RULES: what the current configuration must own"
##########################################################################
FWMARK_TCP=0x1; FWMARK_UDP=0x2
RTTAB_TCP=100;  RTTAB_UDP=101
RULE_PRIO_TCP=10000; RULE_PRIO_UDP=10001
IPV6_ENABLED=1
check "four rules with IPv6 on" "$(desired_rules | wc -l | tr -d ' ')" "4"
check "  v4 tcp line" "$(desired_rules | sed -n 1p)" "4 0x1 100 10000"
check "  v4 udp line" "$(desired_rules | sed -n 2p)" "4 0x2 101 10001"
check "  v6 tcp line" "$(desired_rules | sed -n 3p)" "6 0x1 100 10000"

IPV6_ENABLED=0
check "two rules with IPv6 off" "$(desired_rules | wc -l | tr -d ' ')" "2"
check "  and no v6 family at all" "$(desired_rules | grep -c '^6 ')" "0"

# A decimal mark in UCI must produce the same canonical identity as the hex one,
# or the delta comparison would see a change that is not one.
FWMARK_TCP=1; FWMARK_UDP=2; IPV6_ENABLED=1
check "a decimal mark yields the canonical identity" "$(desired_rules | sed -n 1p)" "4 0x1 100 10000"
FWMARK_TCP=0x1; FWMARK_UDP=0x2

##########################################################################
group "STATE RULES: what the PREVIOUS run actually created"
##########################################################################
# These come from the state file, not from current UCI - that difference is the
# whole reason orphaned objects can be removed after the identifiers change.
cat > "$STATE_FILE" <<'EOF'
NFT_TABLE=tp_mgr
FWMARK_TCP=0x4
FWMARK_UDP=0x8
RTTAB_TCP=200
RTTAB_UDP=201
RULE_PRIO_TCP=10000
RULE_PRIO_UDP=10001
IPV6_ENABLED=1
EOF
rm -f "$RECOVERY_FILE"
check "state_source picks the main file" "$(state_source)" "$STATE_FILE"
check "state_get reads a field" "$(state_get NFT_TABLE)" "tp_mgr"
check "four rules from the recorded state" "$(state_rules | wc -l | tr -d ' ')" "4"
check "  they use the RECORDED mark, not the current one" "$(state_rules | sed -n 1p)" "4 0x4 200 10000"

# Recovery takes precedence: it is written exactly when the main state could not
# be, so it is the newer record.
cat > "$RECOVERY_FILE" <<'EOF'
NFT_TABLE=tp_alt
FWMARK_TCP=0x10
FWMARK_UDP=0x20
RTTAB_TCP=300
RTTAB_UDP=301
RULE_PRIO_TCP=10000
RULE_PRIO_UDP=10001
IPV6_ENABLED=0
EOF
check "recovery wins over the main state" "$(state_source)" "$RECOVERY_FILE"
check "  and its values are used" "$(state_get NFT_TABLE)" "tp_alt"
check "  IPv6 off there means two rules" "$(state_rules | wc -l | tr -d ' ')" "2"
rm -f "$RECOVERY_FILE"

# A damaged state must not turn into a bogus identity: a mark that is not a
# number is skipped rather than normalised into 0x0, which would "match" nothing
# and quietly drop the object from cleanup.
cat > "$STATE_FILE" <<'EOF'
NFT_TABLE=tp_mgr
FWMARK_TCP=notanumber
FWMARK_UDP=0x8
RTTAB_TCP=200
RTTAB_UDP=201
RULE_PRIO_TCP=10000
RULE_PRIO_UDP=10001
IPV6_ENABLED=0
EOF
check "a non-numeric recorded mark is skipped" "$(state_rules | grep -c '0x0')" "0"
check "  and the valid pair still comes through" "$(state_rules | wc -l | tr -d ' ')" "1"
check "  which is the UDP one" "$(state_rules)" "4 0x8 201 10001"

# The charset filter in state_get is what keeps a tampered state file from
# reaching a shell command.
printf 'NFT_TABLE=tp_mgr\nEVIL=a;rm -rf /\n' > "$STATE_FILE"
check "state_get_from rejects an unsafe value" "$(state_get_from "$STATE_FILE" EVIL)" ""
check "  while a safe one passes" "$(state_get_from "$STATE_FILE" NFT_TABLE)" "tp_mgr"
check "  and a missing key is empty" "$(state_get_from "$STATE_FILE" NOPE)" ""
check "  a missing file is empty too" "$(state_get_from "$BASE/nofile" NFT_TABLE)" ""

##########################################################################
group "SHARED ROUTE TABLE: it may only be flushed once nobody needs it"
##########################################################################
# TCP and UDP can point at the same table. Removing one rule must not flush the
# table while the other still uses it - that is what table_still_used guards.
printf '4 0x1 300 10000\n4 0x2 300 10001\n' > "$RULESET_NEW"
if table_still_used 4 300; then ok "a table used by both protocols is still needed"; else no "a table used by both protocols is still needed" "said no"; fi
printf '4 0x1 300 10000\n' > "$RULESET_NEW"
if table_still_used 4 300; then ok "still needed while one rule remains"; else no "still needed while one rule remains" "said no"; fi
if table_still_used 4 301; then no "an unused table is reported as needed" "said yes"; else ok "an unused table is not needed"; fi
if table_still_used 6 300; then no "the family is ignored" "matched the wrong family"; else ok "the family is part of the key"; fi
: > "$RULESET_NEW"
if table_still_used 4 300; then no "an empty ruleset claims a table" "said yes"; else ok "an empty ruleset needs nothing"; fi

##########################################################################
group "DELTA: identity strings must compare exactly"
##########################################################################
# remove_iprules_delta() compares the four-field strings verbatim, so any
# difference in spacing or normalisation between the two producers would delete
# a live rule or keep a dead one. Same inputs must give byte-identical lines.
cat > "$STATE_FILE" <<'EOF'
NFT_TABLE=tp_mgr
FWMARK_TCP=1
FWMARK_UDP=2
RTTAB_TCP=100
RTTAB_UDP=101
RULE_PRIO_TCP=10000
RULE_PRIO_UDP=10001
IPV6_ENABLED=1
EOF
FWMARK_TCP=0x1; FWMARK_UDP=0x2; RTTAB_TCP=100; RTTAB_UDP=101; IPV6_ENABLED=1
desired_rules | sort > "$BASE/d.txt"
state_rules   | sort > "$BASE/s.txt"
if cmp -s "$BASE/d.txt" "$BASE/s.txt"; then
  ok "hex config and decimal state produce the same identities"
else
  no "hex config and decimal state produce the same identities" "$(diff "$BASE/d.txt" "$BASE/s.txt" | tr '\n' ' ')"
fi

# And a genuine change must show as one.
RTTAB_UDP=999
desired_rules | sort > "$BASE/d2.txt"
if cmp -s "$BASE/d2.txt" "$BASE/s.txt"; then
  no "a changed table shows up as a difference" "compared equal"
else
  ok "a changed table shows up as a difference"
fi

##########################################################################
cd /
rm -rf "$BASE"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
exit 0
