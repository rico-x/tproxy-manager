#!/bin/sh
#
# Regression suite for the Mihomo converter's proxy names and YAML quoting.
#
# Runs ON THE ROUTER: the last group feeds every generated config to the real
# `mihomo -t`, which is the only authority on whether mihomo will accept it.
# Use scripts/test-on-device.sh to stage the working tree and run this against it.
#
# Two failures this pins down, both of which killed EVERY link at once because
# mihomo rejects a config as a whole:
#
#   * the internal proxy name was the link's remark, so two subscriptions shipping
#     the same label produced "proxy ... is the duplicate name";
#   * values were emitted bare when they matched a "safe" character class that
#     included "@", and a remark like "@home" gave `name: @home` -- YAML reserved
#     indicator, "found character that cannot start any token".
#
# Safe on a live router: everything happens in the suite's own temp directory and
# no service, config or link list is touched.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-mihomo-names-test}"
CONV="${TPM_STAGE_BIN:-/usr/bin}/proxy2mihomo.lua"
SHARE="${TPM_STAGE_SHARE:-/etc/tproxy-manager}"
MIHOMO="$(command -v mihomo || echo /usr/bin/mihomo)"

rm -rf "$BASE"
mkdir -p "$BASE" || exit 1

pass=0
fail=0
skipped=0
failures=""

check() {
    _name="$1"; _got="$2"; _want="$3"
    if [ "$_got" = "$_want" ]; then
        pass=$((pass + 1))
        printf '  PASS %s\n' "$_name"
    else
        fail=$((fail + 1))
        failures="$failures
  - $_name (got '$_got', want '$_want')"
        printf '  FAIL %s  <- got %s, want %s\n' "$_name" "'$_got'" "'$_want'"
    fi
}

group() { printf '\n== %s ==\n' "$1"; }

VLESS_TAIL='?security=reality&type=tcp&sni=x.example.org&pbk=5LrlEovjbmti-hjY1nnUqSBq3gHUuJXCkklcqVdbJkg&fp=chrome'
UUID=d3f3797f-0086-4735-bdde-6382b1702946

# One vless link per host, with the remark supplied percent-encoded so this file
# stays plain ASCII.
link() { printf 'vless://%s@%s:443%s#%s\n' "$UUID" "$1" "$VLESS_TAIL" "$2"; }

# Only the proxies. A generated config also carries `- name:` for the proxy group
# and, in batch mode, one per listener -- counting those inflated every tally and
# made the group's own literal name look like an unquoted proxy name.
names_of() {
    awk '
      /^[a-z][a-z0-9-]*:/ { section = $1; sub(":", "", section) }
      section == "proxies" && /^  - name: / { sub(/^  - name: /, ""); print }
    ' "$1"
}

# What each listener is pinned to, in the order the listeners appear.
listener_bindings() {
    awk '
      /^[a-z][a-z0-9-]*:/ { section = $1; sub(":", "", section) }
      section == "listeners" && /^    proxy: / { sub(/^    proxy: /, ""); print }
    ' "$1"
}

printf '(converter under test: %s)\n' "$CONV"
[ -x "$CONV" ] || { printf 'converter not executable: %s\n' "$CONV"; exit 1; }

##########################################################################
group "DUPLICATE REMARKS: mihomo rejects a config with two proxies alike"
##########################################################################
L="$BASE/dup.txt"
{
    link a.example.org "Same%20Name"
    link b.example.org "Same%20Name"
    link c.example.org "Same%20Name"
} > "$L"

"$CONV" -r "$L" --runtime --tproxy-port 61219 > "$BASE/dup-runtime.yaml" 2>"$BASE/err"
check "the converter succeeds" "$?" "0"
check "three proxies emitted" "$(names_of "$BASE/dup-runtime.yaml" | wc -l | tr -d ' ')" "3"
check "  with three DISTINCT names" "$(names_of "$BASE/dup-runtime.yaml" | sort -u | wc -l | tr -d ' ')" "3"
check "  the first keeps the remark as written" \
    "$(names_of "$BASE/dup-runtime.yaml" | sed -n 1p)" "'Same Name'"
# The group must reference the same names, or mihomo cannot resolve the selector.
check "the proxy group references every proxy" \
    "$(grep -cE '^      - ' "$BASE/dup-runtime.yaml")" "3"
check "  and those references match the proxy names" \
    "$(grep -E '^      - ' "$BASE/dup-runtime.yaml" | sed 's/^      - //' | sort | tr '\n' '|')" \
    "$(names_of "$BASE/dup-runtime.yaml" | sort | tr '\n' '|')"

# A link whose remark already looks like the suffix a collision would produce must
# also be moved, or the rename just relocates the clash.
{
    link a.example.org "dup"
    link b.example.org "dup"
    link c.example.org "dup%20%232"
} > "$BASE/dup2.txt"
"$CONV" -r "$BASE/dup2.txt" --runtime --tproxy-port 61219 > "$BASE/dup2.yaml" 2>/dev/null
check "a remark that collides with a generated suffix is moved too" \
    "$(names_of "$BASE/dup2.yaml" | sort -u | wc -l | tr -d ' ')" "3"

##########################################################################
group "REMARKS ARE NOT IDENTIFIERS: every value is quoted"
##########################################################################
# Each of these produced either invalid YAML or a value of the wrong TYPE when
# emitted bare. "no" is the quiet one: unquoted it is the boolean false.
{
    link a.example.org "%40home"
    link b.example.org "It%27s%20%22quoted%22"
    link c.example.org "100%25%20percent"
    link d.example.org "-%20leading%20dash"
    link e.example.org "no"
    link f.example.org "key%3A%20value"
    link g.example.org "%23hash"
    link h.example.org "%2A%20star"
    link i.example.org "0755"
} > "$BASE/nasty.txt"
"$CONV" -r "$BASE/nasty.txt" --runtime --tproxy-port 61219 > "$BASE/nasty.yaml" 2>/dev/null

check "at is quoted" "$(names_of "$BASE/nasty.yaml" | sed -n 1p)" "'@home'"
check "a single quote is doubled, not escaped" \
    "$(names_of "$BASE/nasty.yaml" | sed -n 2p)" "'It''s \"quoted\"'"
check "percent survives verbatim" "$(names_of "$BASE/nasty.yaml" | sed -n 3p)" "'100% percent'"
check "a leading dash cannot start a sequence" \
    "$(names_of "$BASE/nasty.yaml" | sed -n 4p)" "'- leading dash'"
check "a YAML boolean stays a string" "$(names_of "$BASE/nasty.yaml" | sed -n 5p)" "'no'"
check "a colon cannot split a mapping" "$(names_of "$BASE/nasty.yaml" | sed -n 6p)" "'key: value'"
check "a hash cannot start a comment" "$(names_of "$BASE/nasty.yaml" | sed -n 7p)" "'#hash'"
check "a star cannot start an alias" "$(names_of "$BASE/nasty.yaml" | sed -n 8p)" "'* star'"
check "a numeric-looking name stays a string" "$(names_of "$BASE/nasty.yaml" | sed -n 9p)" "'0755'"
check "no name is emitted bare" \
    "$(names_of "$BASE/nasty.yaml" | grep -cv "^'")" "0"

# A remark carrying a newline or tab would end the YAML line it sits on.
printf 'vless://%s@z.example.org:443%s#a%%09b%%0Ac\n' "$UUID" "$VLESS_TAIL" > "$BASE/ctrl.txt"
"$CONV" -r "$BASE/ctrl.txt" --runtime --tproxy-port 61219 > "$BASE/ctrl.yaml" 2>/dev/null
check "control characters are folded to spaces" \
    "$(names_of "$BASE/ctrl.yaml" | sed -n 1p)" "'a b c'"
check "  so the name stays on one line" "$(names_of "$BASE/ctrl.yaml" | wc -l | tr -d ' ')" "1"

##########################################################################
group "EVERY MODE: provider, runtime, test and batch agree"
##########################################################################
"$CONV" -r "$BASE/nasty.txt" --provider > "$BASE/nasty-provider.yaml" 2>/dev/null
check "provider names are unique" \
    "$(names_of "$BASE/nasty-provider.yaml" | sort -u | wc -l | tr -d ' ')" "9"
check "  and identical to the runtime ones" \
    "$(names_of "$BASE/nasty-provider.yaml" | tr '\n' '|')" \
    "$(names_of "$BASE/nasty.yaml" | tr '\n' '|')"

TT="$SHARE/watchdog-mihomo-test-config.template.yaml"
BT="$SHARE/watchdog-mihomo-batch-test-config.template.yaml"
if [ -f "$TT" ]; then
    "$CONV" -r "$BASE/nasty.txt" --test --port 61990 --template "$TT" > "$BASE/nasty-test.yaml" 2>/dev/null
    check "test-mode names are unique" \
        "$(names_of "$BASE/nasty-test.yaml" | sort -u | wc -l | tr -d ' ')" "9"
    # Template substitution goes through gsub, where an unescaped "%" in the
    # replacement would be read as a capture reference.
    check "  and percent is not mangled by the template" \
        "$(grep -c "100% percent" "$BASE/nasty-test.yaml")" "1"
else
    skipped=$((skipped + 2))
    printf '  SKIP test-mode template not present at %s\n' "$TT"
fi

: > "$BASE/ports.tsv"
port=61900
while IFS= read -r l; do
    port=$((port + 1))
    printf '%s\t%s\n' "$port" "$l" >> "$BASE/ports.tsv"
done < "$BASE/nasty.txt"

if [ -f "$BT" ]; then
    "$CONV" -r "$BASE/nasty.txt" --batch --ports "$BASE/ports.tsv" --template "$BT" \
        > "$BASE/nasty-batch.yaml" 2>/dev/null
    check "batch names are unique" \
        "$(names_of "$BASE/nasty-batch.yaml" | sort -u | wc -l | tr -d ' ')" "9"
    # Each listener pins one proxy by name. A listener quoting a name differently
    # from the proxy block silently falls through to the DIRECT default and the
    # link is measured over a direct connection.
    check "  one listener per link" \
        "$(listener_bindings "$BASE/nasty-batch.yaml" | wc -l | tr -d ' ')" "9"
    check "  every listener binding matches a proxy name" \
        "$(listener_bindings "$BASE/nasty-batch.yaml" | sort | tr '\n' '|')" \
        "$(names_of "$BASE/nasty-batch.yaml" | sort | tr '\n' '|')"
else
    skipped=$((skipped + 2))
    printf '  SKIP batch template not present at %s\n' "$BT"
fi

##########################################################################
group "MIHOMO ITSELF: the generated configs are accepted"
##########################################################################
if [ -x "$MIHOMO" ]; then
    for f in "$BASE/dup-runtime.yaml" "$BASE/nasty.yaml" "$BASE/ctrl.yaml" \
             "$BASE/nasty-test.yaml" "$BASE/nasty-batch.yaml"; do
        [ -f "$f" ] || continue
        out="$("$MIHOMO" -t -f "$f" 2>&1)"
        case "$out" in
            *"test is successful"*) verdict=accepted ;;
            *) verdict="REJECTED: $(printf '%s' "$out" | grep -oE 'msg=.*' | head -1)" ;;
        esac
        check "mihomo -t accepts $(basename "$f")" "$verdict" "accepted"
    done
else
    skipped=$((skipped + 5))
    printf '  SKIP mihomo binary not present\n'
fi

rm -rf "$BASE"

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
if [ "$fail" -gt 0 ]; then
    printf 'failures:%s\n' "$failures"
    exit 1
fi
exit 0
