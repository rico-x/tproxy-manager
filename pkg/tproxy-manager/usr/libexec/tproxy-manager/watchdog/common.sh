PKG="tproxy-manager"

STATE_FILE="/tmp/tproxy-manager-watchdog.state"
LINK_STATE_DIR="/tmp/tproxy-manager-watchdog-links"
LOCK_DIR="/tmp/tproxy-manager-watchdog.lock"
LOG_FILE="/tmp/tproxy-manager-watchdog.log"
LOG_TAG_DEFAULT="tproxy-manager-watchdog"

CHECK_URL_DEFAULT="https://ifconfig.me/ip"
PROXY_URL_DEFAULT="socks5h://127.0.0.1:10808"
INTERVAL_DEFAULT="60"
FAIL_THRESHOLD_DEFAULT="3"
CONNECT_TIMEOUT_DEFAULT="15"
MAX_TIME_DEFAULT="20"
LINKS_FILE_DEFAULT="/etc/tproxy-manager/watchdog.links"
TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-outbound.template.jsonc"
TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-test-config.template.jsonc"
OUTBOUND_FILE_DEFAULT="/etc/xray/04_outbounds.json"
VLESS2JSON_DEFAULT="/usr/bin/vless2json.sh"
SERVICE_PATH_DEFAULT="/etc/init.d/xray"
RESTART_CMD_DEFAULT="restart"
TEST_COMMAND_DEFAULT="/usr/bin/xray -c {config}"
SELECTION_MODE_DEFAULT="random"
EXCLUDE_DEAD_DEFAULT="0"
COOLDOWN_HOURS_DEFAULT="0"
COOLDOWN_MINUTES_DEFAULT="0"
TEST_PORT_DEFAULT="10881"
BACKGROUND_CHECK_ENABLED_DEFAULT="0"
BACKGROUND_CHECK_INTERVAL_DEFAULT="1800"

TEST_PID=""
TEST_DIR=""

usage() {
    cat <<EOF
Использование:
  $0 once
  $0 run
  $0 status
  $0 reset
  $0 test-rotate
  $0 test-link <line_hash>
  $0 apply-link <line_hash>
  $0 check-all
  $0 help
EOF
}

log_msg() {
    msg="$*"
    ts="$(now_human)"
    printf '%s %s\n' "$ts" "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t "$LOG_TAG" "$msg" 2>/dev/null || true
    printf '%s\n' "$msg" >&2
}

trim_text() {
    printf '%s' "$1" | sed -e 's/\r//g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

validate_number() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

require_number_or_default() {
    value="$1"
    fallback="$2"
    if validate_number "$value"; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$fallback"
    fi
}

shellescape() {
    case "$1" in
        '')
            printf "''"
            ;;
        *)
            printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
            ;;
    esac
}

now_ts() {
    date '+%s' 2>/dev/null || echo 0
}

now_human() {
    date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown_time
}

ensure_runtime_dirs() {
    [ -d "$LINK_STATE_DIR" ] || mkdir -p "$LINK_STATE_DIR"
    : >> "$LOG_FILE" 2>/dev/null || true
}

uci_get() {
    key="$1"
    uci -q get "$PKG.main.$key" 2>/dev/null || true
}

load_config() {
    CHECK_URL="$(uci_get watchdog_check_url)"
    PROXY_URL="$(uci_get watchdog_proxy_url)"
    INTERVAL="$(uci_get watchdog_interval)"
    FAIL_THRESHOLD="$(uci_get watchdog_fail_threshold)"
    CONNECT_TIMEOUT="$(uci_get watchdog_connect_timeout)"
    MAX_TIME="$(uci_get watchdog_max_time)"
    LINKS_FILE="$(uci_get watchdog_links_file)"
    TEMPLATE_FILE="$(uci_get watchdog_template_file)"
    TEST_TEMPLATE_FILE="$(uci_get watchdog_test_template_file)"
    OUTBOUND_FILE="$(uci_get watchdog_outbound_file)"
    VLESS2JSON="$(uci_get watchdog_vless2json)"
    SERVICE_PATH="$(uci_get watchdog_service_path)"
    RESTART_CMD="$(uci_get watchdog_restart_cmd)"
    TEST_COMMAND="$(uci_get watchdog_test_command)"
    SELECTION_MODE="$(uci_get watchdog_selection_mode)"
    EXCLUDE_DEAD="$(uci_get watchdog_exclude_dead)"
    COOLDOWN_HOURS="$(uci_get watchdog_dead_cooldown_hours)"
    COOLDOWN_MINUTES="$(uci_get watchdog_dead_cooldown_minutes)"
    TEST_PORT="$(uci_get watchdog_test_port)"
    BACKGROUND_CHECK_ENABLED="$(uci_get watchdog_background_check_enabled)"
    BACKGROUND_CHECK_INTERVAL="$(uci_get watchdog_background_check_interval)"
    LOG_TAG="$(uci_get watchdog_log_tag)"

    [ -n "$CHECK_URL" ] || CHECK_URL="$CHECK_URL_DEFAULT"
    [ -n "$PROXY_URL" ] || PROXY_URL="$PROXY_URL_DEFAULT"
    [ -n "$LINKS_FILE" ] || LINKS_FILE="$LINKS_FILE_DEFAULT"
    [ -n "$TEMPLATE_FILE" ] || TEMPLATE_FILE="$TEMPLATE_FILE_DEFAULT"
    [ -n "$TEST_TEMPLATE_FILE" ] || TEST_TEMPLATE_FILE="$TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$OUTBOUND_FILE" ] || OUTBOUND_FILE="$OUTBOUND_FILE_DEFAULT"
    [ -n "$VLESS2JSON" ] || VLESS2JSON="$VLESS2JSON_DEFAULT"
    [ -n "$SERVICE_PATH" ] || SERVICE_PATH="$SERVICE_PATH_DEFAULT"
    [ -n "$RESTART_CMD" ] || RESTART_CMD="$RESTART_CMD_DEFAULT"
    [ -n "$TEST_COMMAND" ] || TEST_COMMAND="$TEST_COMMAND_DEFAULT"
    [ -n "$LOG_TAG" ] || LOG_TAG="$LOG_TAG_DEFAULT"

    INTERVAL="$(require_number_or_default "$INTERVAL" "$INTERVAL_DEFAULT")"
    FAIL_THRESHOLD="$(require_number_or_default "$FAIL_THRESHOLD" "$FAIL_THRESHOLD_DEFAULT")"
    CONNECT_TIMEOUT="$(require_number_or_default "$CONNECT_TIMEOUT" "$CONNECT_TIMEOUT_DEFAULT")"
    MAX_TIME="$(require_number_or_default "$MAX_TIME" "$MAX_TIME_DEFAULT")"
    COOLDOWN_HOURS="$(require_number_or_default "$COOLDOWN_HOURS" "$COOLDOWN_HOURS_DEFAULT")"
    COOLDOWN_MINUTES="$(require_number_or_default "$COOLDOWN_MINUTES" "$COOLDOWN_MINUTES_DEFAULT")"
    TEST_PORT="$(require_number_or_default "$TEST_PORT" "$TEST_PORT_DEFAULT")"
    BACKGROUND_CHECK_INTERVAL="$(require_number_or_default "$BACKGROUND_CHECK_INTERVAL" "$BACKGROUND_CHECK_INTERVAL_DEFAULT")"

    [ "$INTERVAL" -ge 1 ] || INTERVAL="$INTERVAL_DEFAULT"
    [ "$FAIL_THRESHOLD" -ge 1 ] || FAIL_THRESHOLD="$FAIL_THRESHOLD_DEFAULT"
    [ "$CONNECT_TIMEOUT" -ge 1 ] || CONNECT_TIMEOUT="$CONNECT_TIMEOUT_DEFAULT"
    [ "$MAX_TIME" -ge "$CONNECT_TIMEOUT" ] || MAX_TIME="$MAX_TIME_DEFAULT"
    [ "$MAX_TIME" -ge "$CONNECT_TIMEOUT" ] || MAX_TIME="$CONNECT_TIMEOUT"
    [ "$TEST_PORT" -ge 1 ] && [ "$TEST_PORT" -le 65535 ] || TEST_PORT="$TEST_PORT_DEFAULT"
    [ "$BACKGROUND_CHECK_INTERVAL" -ge 1 ] || BACKGROUND_CHECK_INTERVAL="$BACKGROUND_CHECK_INTERVAL_DEFAULT"

    case "$SELECTION_MODE" in
        random|ordered) : ;;
        *) SELECTION_MODE="$SELECTION_MODE_DEFAULT" ;;
    esac
    case "$EXCLUDE_DEAD" in
        0|1) : ;;
        *) EXCLUDE_DEAD="$EXCLUDE_DEAD_DEFAULT" ;;
    esac
    case "$BACKGROUND_CHECK_ENABLED" in
        0|1) : ;;
        *) BACKGROUND_CHECK_ENABLED="$BACKGROUND_CHECK_ENABLED_DEFAULT" ;;
    esac

    COOLDOWN_SECONDS=$((COOLDOWN_HOURS * 3600 + COOLDOWN_MINUTES * 60))

    ensure_runtime_dirs
}

state_get() {
    key="$1"
    if [ -f "$STATE_FILE" ]; then
        sed -n "s/^${key}=//p" "$STATE_FILE" 2>/dev/null | tail -n 1
    fi
}

state_snapshot() {
    OVERALL_FAILCOUNT="$(state_get FAILCOUNT)"
    validate_number "$OVERALL_FAILCOUNT" || OVERALL_FAILCOUNT=0
    OVERALL_LAST_HTTP_CODE="$(state_get LAST_HTTP_CODE)"
    OVERALL_LAST_STATUS="$(state_get LAST_STATUS)"
    OVERALL_LAST_TS="$(state_get LAST_TS)"
    OVERALL_LAST_HUMAN="$(state_get LAST_TS_HUMAN)"
    OVERALL_LAST_SUCCESS_HASH="$(state_get LAST_SUCCESS_HASH)"
    OVERALL_LAST_APPLIED_HASH="$(state_get LAST_APPLIED_HASH)"
    OVERALL_LAST_LINK_SCAN_TS="$(state_get LAST_LINK_SCAN_TS)"
    OVERALL_LAST_LINK_SCAN_HUMAN="$(state_get LAST_LINK_SCAN_HUMAN)"
    OVERALL_LAST_LINK_SCAN_STATUS="$(state_get LAST_LINK_SCAN_STATUS)"
    OVERALL_LAST_LINK_SCAN_ALIVE="$(state_get LAST_LINK_SCAN_ALIVE)"
    OVERALL_LAST_LINK_SCAN_TOTAL="$(state_get LAST_LINK_SCAN_TOTAL)"

    [ -n "$OVERALL_LAST_HTTP_CODE" ] || OVERALL_LAST_HTTP_CODE="-"
    [ -n "$OVERALL_LAST_STATUS" ] || OVERALL_LAST_STATUS="-"
    [ -n "$OVERALL_LAST_TS" ] || OVERALL_LAST_TS="0"
    [ -n "$OVERALL_LAST_HUMAN" ] || OVERALL_LAST_HUMAN="-"
    validate_number "$OVERALL_LAST_LINK_SCAN_TS" || OVERALL_LAST_LINK_SCAN_TS=0
    [ -n "$OVERALL_LAST_LINK_SCAN_HUMAN" ] || OVERALL_LAST_LINK_SCAN_HUMAN="-"
    [ -n "$OVERALL_LAST_LINK_SCAN_STATUS" ] || OVERALL_LAST_LINK_SCAN_STATUS="-"
    validate_number "$OVERALL_LAST_LINK_SCAN_ALIVE" || OVERALL_LAST_LINK_SCAN_ALIVE=0
    validate_number "$OVERALL_LAST_LINK_SCAN_TOTAL" || OVERALL_LAST_LINK_SCAN_TOTAL=0
}

state_write() {
    cat > "$STATE_FILE" <<EOF
FAILCOUNT=$OVERALL_FAILCOUNT
LAST_HTTP_CODE=$OVERALL_LAST_HTTP_CODE
LAST_STATUS=$OVERALL_LAST_STATUS
LAST_TS=$OVERALL_LAST_TS
LAST_TS_HUMAN=$OVERALL_LAST_HUMAN
LAST_SUCCESS_HASH=$OVERALL_LAST_SUCCESS_HASH
LAST_APPLIED_HASH=$OVERALL_LAST_APPLIED_HASH
LAST_LINK_SCAN_TS=$OVERALL_LAST_LINK_SCAN_TS
LAST_LINK_SCAN_HUMAN=$OVERALL_LAST_LINK_SCAN_HUMAN
LAST_LINK_SCAN_STATUS=$OVERALL_LAST_LINK_SCAN_STATUS
LAST_LINK_SCAN_ALIVE=$OVERALL_LAST_LINK_SCAN_ALIVE
LAST_LINK_SCAN_TOTAL=$OVERALL_LAST_LINK_SCAN_TOTAL
EOF
}

set_failcount() {
    state_snapshot
    OVERALL_FAILCOUNT="$1"
    state_write
}

set_last_result() {
    code="$1"
    status="$2"
    state_snapshot
    OVERALL_LAST_HTTP_CODE="$code"
    OVERALL_LAST_STATUS="$status"
    OVERALL_LAST_TS="$(now_ts)"
    OVERALL_LAST_HUMAN="$(now_human)"
    state_write
}

set_last_success_hash() {
    state_snapshot
    OVERALL_LAST_SUCCESS_HASH="$1"
    state_write
}

set_last_applied_hash() {
    state_snapshot
    OVERALL_LAST_APPLIED_HASH="$1"
    state_write
}

set_last_link_scan() {
    status="$1"
    alive="$2"
    total="$3"
    state_snapshot
    OVERALL_LAST_LINK_SCAN_TS="$(now_ts)"
    OVERALL_LAST_LINK_SCAN_HUMAN="$(now_human)"
    OVERALL_LAST_LINK_SCAN_STATUS="$status"
    OVERALL_LAST_LINK_SCAN_ALIVE="$alive"
    OVERALL_LAST_LINK_SCAN_TOTAL="$total"
    state_write
}

read_failcount() {
    state_snapshot
    echo "$OVERALL_FAILCOUNT"
}

reset_failcount() {
    state_snapshot
    OVERALL_FAILCOUNT=0
    state_write
}

read_last_success_hash() {
    state_snapshot
    printf '%s\n' "$OVERALL_LAST_SUCCESS_HASH"
}

link_state_file() {
    printf '%s/%s.state\n' "$LINK_STATE_DIR" "$1"
}

link_state_get() {
    hash="$1"
    key="$2"
    file="$(link_state_file "$hash")"
    if [ -f "$file" ]; then
        sed -n "s/^${key}=//p" "$file" 2>/dev/null | tail -n 1
    fi
}

write_link_state() {
    hash="$1"
    status="$2"
    code="$3"
    checked_ts="$4"
    checked_human="$5"
    cooldown_ts="$6"
    cooldown_human="$7"
    cat > "$(link_state_file "$hash")" <<EOF
LINK_HASH=$hash
LAST_STATUS=$status
LAST_HTTP_CODE=$code
LAST_CHECKED_TS=$checked_ts
LAST_CHECKED_HUMAN=$checked_human
COOLDOWN_UNTIL_TS=$cooldown_ts
COOLDOWN_UNTIL_HUMAN=$cooldown_human
EOF
}

mark_link_alive() {
    hash="$1"
    code="$2"
    ts="$(now_ts)"
    human="$(now_human)"
    write_link_state "$hash" "alive" "$code" "$ts" "$human" "0" "-"
}

mark_link_dead() {
    hash="$1"
    code="$2"
    ts="$(now_ts)"
    human="$(now_human)"
    cooldown_ts=0
    cooldown_human="-"
    if [ "$EXCLUDE_DEAD" = "1" ] && [ "$COOLDOWN_SECONDS" -gt 0 ]; then
        cooldown_ts=$((ts + COOLDOWN_SECONDS))
        cooldown_human="$(date -d "@$cooldown_ts" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$cooldown_ts")"
    fi
    write_link_state "$hash" "dead" "$code" "$ts" "$human" "$cooldown_ts" "$cooldown_human"
}

cooldown_active() {
    hash="$1"
    [ "$EXCLUDE_DEAD" = "1" ] || return 1
    until_ts="$(link_state_get "$hash" COOLDOWN_UNTIL_TS)"
    validate_number "$until_ts" || return 1
    [ "$until_ts" -gt "$(now_ts)" ]
}

cleanup_test_instance() {
    if [ -n "$TEST_PID" ]; then
        kill "$TEST_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$TEST_PID" 2>/dev/null || true
        TEST_PID=""
    fi
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
        TEST_DIR=""
    fi
}

acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK_DIR/pid" 2>/dev/null || true
        return 0
    fi
    if [ -f "$LOCK_DIR/pid" ]; then
        holder_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
        if ! validate_number "$holder_pid" || ! kill -0 "$holder_pid" 2>/dev/null; then
            rm -f "$LOCK_DIR/pid" 2>/dev/null || true
            rmdir "$LOCK_DIR" 2>/dev/null || true
            if mkdir "$LOCK_DIR" 2>/dev/null; then
                printf '%s\n' "$$" > "$LOCK_DIR/pid" 2>/dev/null || true
                log_msg "обнаружен stale lock, выполнено восстановление"
                return 0
            fi
        fi
    fi
    log_msg "watchdog занят другой операцией"
    return 1
}

release_lock() {
    cleanup_test_instance
    rm -f "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || true
}

with_lock_begin() {
    acquire_lock || return 1
}

with_lock_end() {
    release_lock
}
