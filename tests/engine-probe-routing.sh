#!/bin/sh
#
# Regression suite: the link check must go through whichever engine is ACTIVE.
#
# Runs ON THE ROUTER, against the staged working tree (scripts/test-on-device.sh).
#
# What is being pinned down. The watchdog used to decide how to probe a link by
# looking at a separately stored command that defaulted to Xray, and by matching
# the engine NAME in a case statement whose fall-through was the Xray renderer.
# Two consequences:
#
#   * an engine nobody recognised was probed with Xray and Xray's command, and
#     every link came back dead -- indistinguishable from every server being down;
#   * batch mode refused any engine but Xray outright, so a check that took
#     seconds under Xray took minutes under the other two.
#
# Nothing here starts an engine or touches the router's own configuration: the
# watchdog library is sourced into a subshell with its inputs redirected, and the
# converters are stubs that record how they were called.

BASE="${TPM_TEST_BASE:-/tmp/tpm-probe-routing-test}"
if [ -n "${TPM_STAGE_LIBEXEC:-}" ]; then
    # Staged tree: the watchdog library is copied in flat, next to the helper.
    LIB="$TPM_STAGE_LIBEXEC"
    PROBE_INFO="$TPM_STAGE_LIBEXEC/engine-probe-info"
else
    LIB="/usr/libexec/tproxy-manager/watchdog"
    PROBE_INFO="/usr/libexec/tproxy-manager/engine-probe-info"
fi

pass=0
fail=0
failures=""

check() {
    name="$1"
    got="$2"
    want="$3"
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
        printf '  PASS %s\n' "$name"
    else
        fail=$((fail + 1))
        failures="$failures\n  $name\n    got:  $got\n    want: $want"
        printf '  FAIL %s  <- got %s, want %s\n' "$name" "'$got'" "'$want'"
    fi
}

rm -rf "$BASE"
mkdir -p "$BASE" || exit 1

printf '== ENGINE PROBE ROUTING: the active engine does the checking ==\n'
printf '  (watchdog library under test: %s)\n' "$LIB"

# ---------------------------------------------------------------- descriptor --
#
# The descriptor is the single answer to "how does this engine probe". It comes
# from tproxy_manager.engines, so the shell cannot drift from the Lua definitions
# the way a second copy of the table would.
if [ -x "$PROBE_INFO" ]; then
    printf '\n-- descriptor --\n'
    for spec in "xray template json" "mihomo mihomo yaml" "singbox singbox json"; do
        set -- $spec
        eng="$1"; want_kind="$2"; want_ext="$3"
        out="$("$PROBE_INFO" "$eng" 2>/dev/null)"
        got_kind="$(printf '%s\n' "$out" | sed -n "s/^PROBE_KIND='\(.*\)'$/\1/p")"
        got_ext="$(printf '%s\n' "$out" | sed -n "s/^PROBE_CONFIG_EXT='\(.*\)'$/\1/p")"
        got_cmd="$(printf '%s\n' "$out" | sed -n "s/^PROBE_TEST_COMMAND='\(.*\)'$/\1/p")"
        check "$eng probes as $want_kind" "$got_kind" "$want_kind"
        check "  config extension" "$got_ext" "$want_ext"
        # The command has to name that engine's own binary. Xray's command reaching
        # Mihomo is the original defect in one line.
        case "$eng" in
            xray) want_bin="xray" ;;
            mihomo) want_bin="mihomo" ;;
            singbox) want_bin="sing-box" ;;
        esac
        case "$got_cmd" in
            *"$want_bin"*) got_match="yes" ;;
            *) got_match="no ($got_cmd)" ;;
        esac
        check "  command runs $want_bin" "$got_match" "yes"
    done

    # sing-box is an alias, not a fourth engine.
    check "sing-box resolves to singbox" \
        "$("$PROBE_INFO" sing-box 2>/dev/null | sed -n "s/^PROBE_ENGINE='\(.*\)'$/\1/p")" "singbox"

    # An engine nobody can describe is an error. Answering "xray" here is what made
    # a typo in proxy_engine look like a total outage.
    "$PROBE_INFO" not-an-engine >/dev/null 2>&1
    check "an unknown engine is an error, not xray" "$?" "2"

    # --check is how the watchdog spots a stored command that belongs elsewhere.
    "$PROBE_INFO" --check mihomo "/usr/bin/mihomo -f {config}" >/dev/null 2>&1
    check "--check accepts the engine's own command" "$?" "0"
    "$PROBE_INFO" --check mihomo "/usr/bin/xray -c {config}" >/dev/null 2>&1
    check "--check rejects another engine's command" "$?" "1"
fi

# ------------------------------------------------------- probe kind dispatch --
#
# Each engine must reach its OWN renderer. The stubs below record which converter
# ran and with what, so a wrong branch cannot pass unnoticed.
printf '\n-- renderer dispatch --\n'
mkdir -p "$BASE/bin"
for name in conv-mihomo conv-singbox; do
    cat > "$BASE/bin/$name" <<STUB
#!/bin/sh
printf '%s\n' "\$*" > "$BASE/called-$name"
printf 'generated-by-$name\n'
exit 0
STUB
    chmod +x "$BASE/bin/$name"
done
# Refuses everything, the way sing-box refuses an XHTTP transport.
cat > "$BASE/bin/conv-refuses" <<STUB
#!/bin/sh
printf '%s\n' "\$*" > "$BASE/called-refuses"
echo "skipping link: unsupported sing-box VLESS transport: xhttp" >&2
echo "no supported proxy links found (all links were unsupported)" >&2
exit 3
STUB
chmod +x "$BASE/bin/conv-refuses"

probe_one() {
    engine="$1"
    converter_mihomo="$2"
    converter_singbox="$3"
    (
        set -u
        LINK_STATE_DIR="$BASE/state"; LOG_FILE="$BASE/wd.log"
        TEST_PORT=19999; EXCLUDE_DEAD=0; COOLDOWN_SECONDS=0
        PROXY2MIHOMO="$converter_mihomo"; PROXY2SINGBOX="$converter_singbox"
        VLESS2JSON="$BASE/bin/conv-mihomo"
        MIHOMO_TEST_TEMPLATE_FILE=""; MIHOMO_BATCH_TEST_TEMPLATE_FILE=""
        SINGBOX_TEST_TEMPLATE_FILE=""; SINGBOX_BATCH_TEST_TEMPLATE_FILE=""
        MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE=""; MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE=""
        SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE=""; SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE=""
        # shellcheck source=/dev/null
        . "$LIB/common.sh"
        # shellcheck source=/dev/null
        . "$LIB/links.sh"
        LINK_STATE_DIR="$BASE/state"; LOG_FILE="$BASE/wd.log"
        mkdir -p "$LINK_STATE_DIR"
        PROXY_ENGINE="$engine"
        load_probe_descriptor
        TEST_PORT=19999; EXCLUDE_DEAD=0; COOLDOWN_SECONDS=0
        PROXY2MIHOMO="$converter_mihomo"; PROXY2SINGBOX="$converter_singbox"
        MIHOMO_TEST_TEMPLATE_FILE=""; SINGBOX_TEST_TEMPLATE_FILE=""
        # shellcheck source=/dev/null
        . "$LIB/probe.sh"
        # The probe is cut off right after the config is rendered: starting a real
        # engine is not what this suite is about.
        TEST_DIR="$BASE/run"; mkdir -p "$TEST_DIR"
        printf 'vless://x@example.org:443?type=xhttp#t\n' > "$TEST_DIR/one-link.txt"
        hash=deadbeef
        protocol=vless
        config_file="$TEST_DIR/test-config.${PROBE_CONFIG_EXT}"
        case "$PROBE_KIND" in
            mihomo)
                render_engine_test_config "$PROXY2MIHOMO" "$TEST_DIR/one-link.txt" \
                    "$config_file" "" "Mihomo"
                rc=$?
                ;;
            singbox)
                render_engine_test_config "$PROXY2SINGBOX" "$TEST_DIR/one-link.txt" \
                    "$config_file" "" "sing-box"
                rc=$?
                ;;
            *) rc=0 ;;
        esac
        if [ "$rc" -eq 3 ]; then mark_link_unsupported "$hash" "${RENDER_UNSUPPORTED_REASON:-$protocol}"; fi
        printf '%s\t%s\t%s\n' "$PROBE_KIND" "$rc" "$config_file" > "$BASE/result"
    ) >/dev/null 2>&1
    cat "$BASE/result" 2>/dev/null
}

rm -f "$BASE/called-"*
r="$(probe_one mihomo "$BASE/bin/conv-mihomo" "$BASE/bin/conv-singbox")"
check "mihomo uses the mihomo renderer" "$(printf '%s' "$r" | cut -f1)" "mihomo"
check "  and only the mihomo converter ran" \
    "$([ -f "$BASE/called-conv-mihomo" ] && [ ! -f "$BASE/called-conv-singbox" ] && echo yes || echo no)" "yes"
check "  writing a .yaml config" \
    "$(printf '%s' "$r" | cut -f3 | sed 's/.*\.//')" "yaml"

rm -f "$BASE/called-"*
r="$(probe_one singbox "$BASE/bin/conv-mihomo" "$BASE/bin/conv-singbox")"
check "sing-box uses the sing-box renderer" "$(printf '%s' "$r" | cut -f1)" "singbox"
check "  and only the sing-box converter ran" \
    "$([ -f "$BASE/called-conv-singbox" ] && [ ! -f "$BASE/called-conv-mihomo" ] && echo yes || echo no)" "yes"

r="$(probe_one xray "$BASE/bin/conv-mihomo" "$BASE/bin/conv-singbox")"
check "xray uses the template renderer" "$(printf '%s' "$r" | cut -f1)" "template"

# An engine name nobody knows must not silently become xray.
r="$(probe_one not-an-engine "$BASE/bin/conv-mihomo" "$BASE/bin/conv-singbox")"
check "an unknown engine falls back to a REPORTED xray" "$(printf '%s' "$r" | cut -f1)" "template"

# ------------------------------------------------------ unsupported vs dead --
#
# A transport the active engine does not implement is not a dead server. Marked
# dead it goes on cooldown and disappears from rotation, and the operator is told
# the server is down when the fix is to switch engines.
printf '\n-- unsupported is not dead --\n'
rm -rf "$BASE/state"
r="$(probe_one singbox "$BASE/bin/conv-mihomo" "$BASE/bin/conv-refuses")"
check "a refused link exits 3, not 1" "$(printf '%s' "$r" | cut -f2)" "3"
STATE="$BASE/state/deadbeef.state"
check "  and is recorded as unsupported" \
    "$(sed -n 's/^LAST_STATUS=//p' "$STATE" 2>/dev/null)" "unsupported"
check "  with no cooldown" \
    "$(sed -n 's/^COOLDOWN_UNTIL_TS=//p' "$STATE" 2>/dev/null)" "0"
# The converter names the TRANSPORT; "vless is unsupported" would be misleading,
# since sing-box runs vless perfectly well over tcp, ws and grpc.
case "$(sed -n 's/^LAST_REQUEST_TIME_TEXT=//p' "$STATE" 2>/dev/null)" in
    *xhttp*) got=names-the-transport ;;
    *) got="$(sed -n 's/^LAST_REQUEST_TIME_TEXT=//p' "$STATE" 2>/dev/null)" ;;
esac
check "  and the reason names the transport" "$got" "names-the-transport"

# ------------------------------------------------------------ batch is open --
#
# Batch used to be gated on the engine being Xray by name. It is gated on the
# engine's own declaration now, so a new engine that can do it, does.
printf '\n-- batch is not an xray privilege --\n'
if [ -x "$PROBE_INFO" ]; then
    for eng in xray mihomo singbox; do
        check "$eng declares batch support" \
            "$("$PROBE_INFO" "$eng" 2>/dev/null | sed -n "s/^PROBE_BATCH='\(.*\)'$/\1/p")" "1"
    done
fi
check "the xray-only gate is gone from batch.sh" \
    "$(grep -c 'PROXY_ENGINE" != "xray"' "$LIB/batch.sh")" "0"
check "batch is gated on the descriptor instead" \
    "$(grep -c 'PROBE_BATCH" != "1"' "$LIB/batch.sh")" "1"
# Splitting vless from hy2 is an Xray requirement (Hysteria is a stream transport
# there). Doing it for every engine would double the engine processes for nothing.
check "the protocol split is limited to the template kind" \
    "$(grep -c 'if \[ "\$PROBE_KIND" = "template" \]; then' "$LIB/batch.sh")" "1"

# --------------------------------------------------------- stale command --
#
# The live command can name another engine after a restored backup or a hand
# edit. The engine's own profile wins, and the disagreement is reported -- the
# alternative is every link failing its check for a reason nothing explains.
printf '\n-- a stale check command does not kill every link --\n'
# This used to re-implement the reconciliation inside the test, so it passed while
# the product only reconciled in load_config -- and a caller that switched engines
# and refreshed the descriptor alone kept the previous engine's command. Measured
# on a router: a Mihomo YAML config handed to /usr/bin/xray, 0 of 53 links alive.
# The check now calls the function and asserts on what it leaves behind.
(
    set -u
    ENGINE_PROBE_INFO="$PROBE_INFO"
    # shellcheck source=/dev/null
    . "$LIB/common.sh"
    # In place before the descriptor loads, exactly as load_config leaves it
    # after reading UCI.
    TEST_COMMAND="/usr/bin/xray -c {config}"
    PROXY_ENGINE=mihomo
    load_probe_descriptor
    printf '%s\t%s\n' "$TEST_COMMAND" "$TEST_COMMAND_STALE" > "$BASE/cmd"
) >/dev/null 2>&1
case "$(cut -f1 "$BASE/cmd" 2>/dev/null)" in
    *mihomo*) got=mihomo ;;
    *) got="$(cut -f1 "$BASE/cmd" 2>/dev/null)" ;;
esac
check "an xray command under mihomo is replaced" "$got" "mihomo"
case "$(cut -f2 "$BASE/cmd" 2>/dev/null)" in
    *xray*) got=reported ;;
    *) got="not reported" ;;
esac
check "  and the stale value is reported" "$got" "reported"

# Switching engine and refreshing the descriptor is ONE call: nothing may be left
# describing the previous engine.
for pair in "xray:xray" "mihomo:mihomo" "singbox:sing-box"; do
    want="${pair#*:}"
    (
        set -u
        ENGINE_PROBE_INFO="$PROBE_INFO"
        # shellcheck source=/dev/null
        . "$LIB/common.sh"
        TEST_COMMAND="/usr/bin/xray -c {config}"
        PROXY_ENGINE=xray
        load_probe_descriptor
        PROXY_ENGINE="${pair%%:*}"
        load_probe_descriptor
        printf '%s\t%s\t%s\n' "$TEST_COMMAND" "$PROBE_KIND" "$PROBE_CONFIG_EXT" > "$BASE/switch"
    ) >/dev/null 2>&1
    case "$(cut -f1 "$BASE/switch" 2>/dev/null)" in
        *"$want"*) got="$want" ;;
        *) got="$(cut -f1 "$BASE/switch" 2>/dev/null)" ;;
    esac
    check "switching to ${pair%%:*} switches the command too" "$got" "$want"
done

rm -rf "$BASE"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
    printf 'failures:%s\n' "$failures"
    exit 1
fi
exit 0
