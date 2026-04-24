#!/bin/sh

PATH="/usr/sbin:/usr/bin:/sbin:/bin"

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

link_hash() {
    printf '%s' "$1" | md5sum 2>/dev/null | awk '{print $1}'
}

split_link_comment() {
    raw="$1"
    SPLIT_LINK=""
    SPLIT_COMMENT=""
    case "$raw" in
        *" # "*)
            SPLIT_LINK="${raw%%" # "*}"
            SPLIT_COMMENT="${raw#*" # "}"
            ;;
        *)
            SPLIT_LINK="$raw"
            SPLIT_COMMENT=""
            ;;
    esac
    SPLIT_LINK="$(trim_text "$SPLIT_LINK")"
    SPLIT_COMMENT="$(trim_text "$SPLIT_COMMENT")"
}

valid_link() {
    case "$1" in
        vless://*) return 0 ;;
        *) return 1 ;;
    esac
}

build_links_index() {
    [ -f "$LINKS_FILE" ] || return 0
    lineno=0
    while IFS= read -r raw || [ -n "$raw" ]; do
        lineno=$((lineno + 1))
        line="$(trim_text "$raw")"
        [ -n "$line" ] || continue
        case "$line" in
            \#*) continue ;;
        esac
        split_link_comment "$line"
        valid_link "$SPLIT_LINK" || continue
        hash="$(link_hash "$SPLIT_LINK")"
        comment="$(printf '%s' "$SPLIT_COMMENT" | tr '\t' ' ')"
        printf '%s\t%s\t%s\t%s\n' "$hash" "$SPLIT_LINK" "$comment" "$lineno"
    done < "$LINKS_FILE"
}

find_link_by_hash() {
    want="$1"
    build_links_index | awk -F '\t' -v target="$want" '$1 == target { print; exit }'
}

probe_proxy_url() {
    proxy_url="$1"
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        --proxy "$proxy_url" \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        "$CHECK_URL" 2>/dev/null)"
    if [ $? -ne 0 ] || ! validate_number "$http_code"; then
        http_code="000"
    fi
    printf '%s\n' "$http_code"
}

generate_rendered_config() {
    single_links_file="$1"
    rendered_file="$2"

    if [ ! -x "$VLESS2JSON" ]; then
        log_msg "ошибка: не найден исполняемый скрипт $VLESS2JSON"
        return 1
    fi
    if [ ! -f "$single_links_file" ]; then
        log_msg "ошибка: не найден файл ссылок $single_links_file"
        return 1
    fi
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найден файл шаблона $TEMPLATE_FILE"
        return 1
    fi

    if "$VLESS2JSON" -r "$single_links_file" -t "$TEMPLATE_FILE" > "$rendered_file"; then
        if grep -q '^[[:space:]]*\[[[:space:]]*$\|^[[:space:]]*\[' "$rendered_file" 2>/dev/null || grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
            return 0
        fi
        log_msg "ошибка: конвертер вернул неожидаемый формат шаблона/outbounds"
        return 1
    fi

    log_msg "ошибка: не удалось сгенерировать конфиг через $VLESS2JSON"
    return 1
}

extract_outbounds_array() {
    rendered_file="$1"
    array_file="$2"

    if grep -q '^[[:space:]]*\[' "$rendered_file" 2>/dev/null; then
        cp "$rendered_file" "$array_file"
        return 0
    fi

    if grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
        tmp_array="${array_file}.tmp.$$"
        if jsonfilter -i "$rendered_file" -e '@.outbounds' > "$tmp_array" 2>/dev/null && grep -q '^[[:space:]]*\[' "$tmp_array" 2>/dev/null; then
            mv "$tmp_array" "$array_file"
            return 0
        fi
        rm -f "$tmp_array"
    fi

    log_msg "ошибка: в сгенерированном конфиге нет валидного массива outbounds"
    return 1
}

first_outbound_tag() {
    tag="$(jsonfilter -i "$1" -e '@.outbounds[0].tag' 2>/dev/null | sed -n '1p')"
    [ -n "$tag" ] || tag="$(jsonfilter -a -i "$1" -e '@[0].tag' 2>/dev/null | sed -n '1p')"
    [ -n "$tag" ] || tag="$(grep -o '"tag"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null | sed -n '1{s/.*:[[:space:]]*"\([^"]*\)"/\1/p}')"
    printf '%s\n' "$tag"
}

write_wrapped_outbounds() {
    rendered_file="$1"
    target_file="$2"
    tmp_file="${target_file}.tmp.$$"

    if grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
        cp "$rendered_file" "$tmp_file"
    else
        {
            printf '{\n'
            printf '  "outbounds": '
            cat "$rendered_file"
            printf '\n}\n'
        } > "$tmp_file"
    fi
    mv "$tmp_file" "$target_file"
}

render_test_config() {
    array_file="$1"
    config_file="$2"
    port="$3"

    if [ ! -f "$TEST_TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найден тестовый шаблон $TEST_TEMPLATE_FILE"
        return 1
    fi

    first_tag="$(first_outbound_tag "$array_file")"
    [ -n "$first_tag" ] || first_tag="proxy"
    port_esc="$(printf '%s' "$port" | sed 's/[\/&]/\\&/g')"
    tag_esc="$(printf '%s' "$first_tag" | sed 's/[\/&]/\\&/g')"
    : > "$config_file"
    while IFS= read -r line || [ -n "$line" ]; do
        rendered_line="$(printf '%s\n' "$line" | sed \
            -e "s/__TEST_PORT__/$port_esc/g" \
            -e "s/__OUTBOUND_TAG__/$tag_esc/g")"
        case "$rendered_line" in
            *"__OUTBOUNDS__"*)
                prefix="${rendered_line%%__OUTBOUNDS__*}"
                suffix="${rendered_line#*__OUTBOUNDS__}"
                printf '%s' "$prefix" >> "$config_file"
                cat "$array_file" >> "$config_file"
                printf '%s\n' "$suffix" >> "$config_file"
                ;;
            *)
                printf '%s\n' "$rendered_line" >> "$config_file"
                ;;
        esac
    done < "$TEST_TEMPLATE_FILE"
}

build_test_command() {
    config_file="$1"
    config_q="$(shellescape "$config_file")"
    case "$TEST_COMMAND" in
        *"{config}"*)
            printf '%s' "$TEST_COMMAND" | sed "s|{config}|$config_q|g"
            ;;
        *)
            printf '%s %s' "$TEST_COMMAND" "$config_q"
            ;;
    esac
}

start_test_instance() {
    config_file="$1"
    log_file="$2"
    cmd="$(build_test_command "$config_file")"
    if [ -z "$cmd" ]; then
        log_msg "ошибка: не задана команда запуска test-instance"
        return 1
    fi

    sh -c "$cmd" > "$log_file" 2>&1 &
    TEST_PID="$!"
    sleep 2
    if ! kill -0 "$TEST_PID" 2>/dev/null; then
        log_msg "ошибка: test-instance Xray завершился преждевременно"
        return 1
    fi
    return 0
}

probe_link_runtime() {
    hash="$1"
    link="$2"

    TEST_DIR="$(mktemp -d /tmp/tproxy-manager-watchdog-test.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$TEST_DIR" ] || [ ! -d "$TEST_DIR" ]; then
        log_msg "ошибка: не удалось создать временный каталог для test-instance"
        return 1
    fi

    single_links_file="$TEST_DIR/one-link.txt"
    rendered_file="$TEST_DIR/rendered.json"
    array_file="$TEST_DIR/outbounds.json"
    config_file="$TEST_DIR/test-config.json"
    log_file="$TEST_DIR/xray-test.log"

    printf '%s\n' "$link" > "$single_links_file"

    generate_rendered_config "$single_links_file" "$rendered_file" || return 1
    extract_outbounds_array "$rendered_file" "$array_file" || return 1
    render_test_config "$array_file" "$config_file" "$TEST_PORT" || return 1
    start_test_instance "$config_file" "$log_file" || return 1

    code="$(probe_proxy_url "socks5h://127.0.0.1:$TEST_PORT")"
    if [ "$code" = "200" ]; then
        mark_link_alive "$hash" "$code"
        return 0
    fi

    mark_link_dead "$hash" "$code"
    return 1
}

apply_generated_outbounds() {
    rendered_file="$1"
    outdir="$(dirname "$OUTBOUND_FILE")"
    if [ ! -d "$outdir" ]; then
        log_msg "ошибка: каталог для outbounds не найден: $outdir"
        return 1
    fi
    write_wrapped_outbounds "$rendered_file" "$OUTBOUND_FILE" || return 1
    if [ ! -x "$SERVICE_PATH" ]; then
        log_msg "ошибка: сервис не найден или не исполняем: $SERVICE_PATH"
        return 1
    fi
    if "$SERVICE_PATH" "$RESTART_CMD"; then
        return 0
    fi
    log_msg "ошибка: команда рестарта завершилась неуспешно: $SERVICE_PATH $RESTART_CMD"
    return 1
}

apply_link_runtime() {
    hash="$1"
    link="$2"

    probe_link_runtime "$hash" "$link" || {
        log_msg "ссылка $hash не прошла тест, применение отменено"
        return 1
    }

    rendered_file="$TEST_DIR/rendered.json"
    [ -f "$rendered_file" ] || return 1
    apply_generated_outbounds "$rendered_file" || return 1
    set_last_success_hash "$hash"
    set_last_applied_hash "$hash"
    return 0
}

reorder_random() {
    awk 'BEGIN{srand()} {printf "%.12f\t%s\n", rand(), $0}' "$1" | sort -n | cut -f2-
}

reorder_ordered() {
    input_file="$1"
    last_hash="$(read_last_success_hash)"
    last_line=""
    if [ -n "$last_hash" ]; then
        last_line="$(build_links_index | awk -F '\t' -v target="$last_hash" '$1 == target { print $4; exit }')"
    fi
    if [ -n "$last_hash" ] && awk -F '\t' -v target="$last_hash" '$1 == target { found = 1 } END { exit(found ? 0 : 1) }' "$input_file"; then
        awk -F '\t' -v target="$last_hash" '
            { lines[NR] = $0; if ($1 == target) idx = NR; n = NR }
            END {
                if (n == 0) exit
                start = 1
                if (idx > 0) {
                    start = idx + 1
                    if (start > n) start = 1
                }
                for (i = start; i <= n; i++) print lines[i]
                for (i = 1; i < start; i++) print lines[i]
            }
        ' "$input_file"
        return 0
    fi

    if validate_number "$last_line"; then
        awk -F '\t' -v target_line="$last_line" '
            { lines[NR] = $0; if (($4 + 0) > target_line && start == 0) start = NR; n = NR }
            END {
                if (n == 0) exit
                if (start == 0) start = 1
                for (i = start; i <= n; i++) print lines[i]
                for (i = 1; i < start; i++) print lines[i]
            }
        ' "$input_file"
        return 0
    fi

    cat "$input_file"
}

build_candidate_file() {
    temp_file="$1"
    build_links_index > "$temp_file"
    if [ "$EXCLUDE_DEAD" = "1" ]; then
        filtered_file="${temp_file}.filtered"
        : > "$filtered_file"
        while IFS="$(printf '\t')" read -r hash link comment lineno; do
            [ -n "$hash" ] || continue
            if cooldown_active "$hash"; then
                continue
            fi
            printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$filtered_file"
        done < "$temp_file"
        mv "$filtered_file" "$temp_file"
    fi
}

rotate_candidates() {
    temp_file="$(mktemp /tmp/tproxy-manager-watchdog-candidates.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$temp_file" ]; then
        log_msg "ошибка: не удалось создать временный список кандидатов"
        return 1
    fi

    build_candidate_file "$temp_file"
    if [ ! -s "$temp_file" ]; then
        rm -f "$temp_file"
        log_msg "живые кандидаты для ротации отсутствуют"
        return 1
    fi

    ordered_file="${temp_file}.ordered"
    case "$SELECTION_MODE" in
        ordered)
            reorder_ordered "$temp_file" > "$ordered_file"
            ;;
        *)
            reorder_random "$temp_file" > "$ordered_file"
            ;;
    esac

    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        if apply_link_runtime "$hash" "$link"; then
            rm -f "$temp_file" "$ordered_file"
            log_msg "выбрана и применена ссылка $hash"
            return 0
        fi
        cleanup_test_instance
    done < "$ordered_file"

    rm -f "$temp_file" "$ordered_file"
    log_msg "не удалось найти рабочую ссылку для ротации"
    return 1
}

check_current_proxy() {
    log_msg "check start: proxy=$PROXY_URL url=$CHECK_URL"
    code="$(probe_proxy_url "$PROXY_URL")"

    if [ "$code" = "200" ]; then
        old_failcount="$(read_failcount)"
        if [ "$old_failcount" -ne 0 ]; then
            log_msg "проверка успешна, код=200, сброс счётчика ошибок $old_failcount -> 0"
        fi
        set_last_result "$code" "OK"
        reset_failcount
        return 0
    fi

    failcount="$(read_failcount)"
    failcount=$((failcount + 1))
    set_failcount "$failcount"
    set_last_result "$code" "FAIL"
    log_msg "ошибка проверки, код=$code, счётчик=$failcount/$FAIL_THRESHOLD, url=$CHECK_URL"

    if [ "$failcount" -ge "$FAIL_THRESHOLD" ]; then
        log_msg "достигнут порог ошибок, выполняется смена outbound"
        if rotate_candidates; then
            set_last_result "$code" "ROTATED"
            reset_failcount
            return 0
        fi
        set_last_result "$code" "ROTATE_FAILED"
        return 1
    fi

    return 1
}

run_once() {
    with_lock_begin || return 1
    check_current_proxy
    rc=$?
    with_lock_end
    return $rc
}

test_rotate() {
    with_lock_begin || return 1
    rotate_candidates
    rc=$?
    if [ $rc -eq 0 ]; then
        set_last_result "-" "ROTATED"
        reset_failcount
    fi
    with_lock_end
    return $rc
}

run_test_link() {
    hash="$1"
    entry="$(find_link_by_hash "$hash")"
    if [ -z "$entry" ]; then
        log_msg "ошибка: ссылка $hash не найдена"
        return 1
    fi
    link="$(printf '%s\n' "$entry" | awk -F '\t' '{print $2}')"

    with_lock_begin || return 1
    probe_link_runtime "$hash" "$link"
    rc=$?
    with_lock_end
    return $rc
}

run_apply_link() {
    hash="$1"
    entry="$(find_link_by_hash "$hash")"
    if [ -z "$entry" ]; then
        log_msg "ошибка: ссылка $hash не найдена"
        return 1
    fi
    link="$(printf '%s\n' "$entry" | awk -F '\t' '{print $2}')"

    with_lock_begin || return 1
    apply_link_runtime "$hash" "$link"
    rc=$?
    if [ $rc -eq 0 ]; then
        set_last_result "200" "APPLIED"
        reset_failcount
    fi
    with_lock_end
    return $rc
}

run_check_all() {
    with_lock_begin || return 1
    tmp_file="$(mktemp /tmp/tproxy-manager-watchdog-all.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$tmp_file" ]; then
        with_lock_end
        log_msg "ошибка: не удалось создать временный список ссылок"
        return 1
    fi

    build_links_index > "$tmp_file"
    total=0
    alive=0
    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        total=$((total + 1))
        if probe_link_runtime "$hash" "$link"; then
            alive=$((alive + 1))
        fi
        cleanup_test_instance
    done < "$tmp_file"

    rm -f "$tmp_file"
    set_last_link_scan "OK" "$alive" "$total"
    log_msg "проверка всех ссылок завершена: alive=$alive total=$total"
    with_lock_end
    return 0
}

maybe_run_background_check() {
    [ "$BACKGROUND_CHECK_ENABLED" = "1" ] || return 1
    state_snapshot
    now="$(now_ts)"
    last="$OVERALL_LAST_LINK_SCAN_TS"
    validate_number "$last" || last=0
    if [ "$last" -gt 0 ] && [ $((now - last)) -lt "$BACKGROUND_CHECK_INTERVAL" ]; then
        return 1
    fi
    log_msg "запуск фоновой проверки ссылок по таймеру"
    run_check_all
}

show_status() {
    state_snapshot
    if [ -x /etc/init.d/tproxy-manager-watchdog ] && /etc/init.d/tproxy-manager-watchdog status >/dev/null 2>&1; then
        running="yes"
    else
        running="no"
    fi
    cat <<EOF
RUNNING=$running
CHECK_URL=$CHECK_URL
PROXY_URL=$PROXY_URL
INTERVAL=$INTERVAL
FAIL_THRESHOLD=$FAIL_THRESHOLD
CONNECT_TIMEOUT=$CONNECT_TIMEOUT
MAX_TIME=$MAX_TIME
LINKS_FILE=$LINKS_FILE
TEMPLATE_FILE=$TEMPLATE_FILE
TEST_TEMPLATE_FILE=$TEST_TEMPLATE_FILE
OUTBOUND_FILE=$OUTBOUND_FILE
VLESS2JSON=$VLESS2JSON
SERVICE_PATH=$SERVICE_PATH
RESTART_CMD=$RESTART_CMD
TEST_COMMAND=$TEST_COMMAND
SELECTION_MODE=$SELECTION_MODE
EXCLUDE_DEAD=$EXCLUDE_DEAD
DEAD_COOLDOWN_HOURS=$COOLDOWN_HOURS
DEAD_COOLDOWN_MINUTES=$COOLDOWN_MINUTES
TEST_PORT=$TEST_PORT
BACKGROUND_CHECK_ENABLED=$BACKGROUND_CHECK_ENABLED
BACKGROUND_CHECK_INTERVAL=$BACKGROUND_CHECK_INTERVAL
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
STATE_FILE=$STATE_FILE
LINK_STATE_DIR=$LINK_STATE_DIR
LOG_FILE=$LOG_FILE
LOG_TAG=$LOG_TAG
EOF
}

loop_run() {
    log_msg "watchdog запущен, интервал=${INTERVAL}s, фоновая проверка ссылок=${BACKGROUND_CHECK_ENABLED}, таймер=${BACKGROUND_CHECK_INTERVAL}s"
    trap 'release_lock; exit 0' INT TERM
    while true; do
        run_once
        maybe_run_background_check >/dev/null 2>&1 || true
        sleep "$INTERVAL"
    done
}

MODE="${1:-help}"

load_config

case "$MODE" in
    once)
        run_once
        ;;
    run)
        loop_run
        ;;
    status)
        show_status
        ;;
    reset)
        reset_failcount
        log_msg "счётчик ошибок сброшен"
        ;;
    test-rotate)
        test_rotate
        ;;
    test-link)
        [ -n "${2:-}" ] || { usage >&2; exit 1; }
        run_test_link "$2"
        ;;
    apply-link)
        [ -n "${2:-}" ] || { usage >&2; exit 1; }
        run_apply_link "$2"
        ;;
    check-all)
        run_check_all
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
